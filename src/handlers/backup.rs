use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::OwnedSemaphorePermit;
use tracing::error;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::backup::{BackupManager, CommandResult};
use crate::logs::write::{error_diagnostics, error_logs_error};

#[derive(Clone, Copy, Debug)]
enum BackupOperation {
    Full,
    Diff,
    Incr,
    Check,
}

impl BackupOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Diff => "diff",
            Self::Incr => "incr",
            Self::Check => "check",
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateBackupJobRequest {
    #[serde(rename = "type")]
    backup_type: String,
    #[serde(default)]
    remark: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct BackupJobQuery {
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupJobResponse {
    id: Uuid,
    operation: String,
    source: String,
    status: String,
    requested_by: Option<i32>,
    requested_by_name: Option<String>,
    remark: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
}

fn require_admin(req: &HttpRequest, pool: &Pool, user: &UserBaseI, action: &str) -> bool {
    if user.role == 1 {
        return true;
    }
    let mut event = AuditEvent::user("authorization", action, "denied", user);
    event.response_status = Some(403);
    event.reason_code = Some("administrator_required".to_owned());
    let context = AuditContext::from_request(req);
    let pool = pool.clone();
    tokio::spawn(async move {
        write_standalone(&pool, &context, &event).await;
    });
    false
}

fn parse_backup_type(value: &str) -> Result<BackupOperation, &'static str> {
    match value {
        "full" => Ok(BackupOperation::Full),
        "diff" => Ok(BackupOperation::Diff),
        "incr" => Ok(BackupOperation::Incr),
        _ => Err("type 必须是 full、diff 或 incr"),
    }
}

fn normalize_remark(value: Option<&str>) -> Result<Option<String>, &'static str> {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    match value {
        Some(value) if value.chars().count() > 500 => Err("备注不能超过 500 个字符"),
        Some(value) => Ok(Some(value.to_owned())),
        None => Ok(None),
    }
}

fn job_from_row(row: tokio_postgres::Row, include_logs: bool) -> BackupJobResponse {
    BackupJobResponse {
        id: row.get("id"),
        operation: row.get("operation"),
        source: row.get("source"),
        status: row.get("status"),
        requested_by: row.get("requested_by"),
        requested_by_name: row.get("requested_by_name"),
        remark: row.get("remark"),
        created_at: row.get("created_at"),
        started_at: row.get("started_at"),
        finished_at: row.get("finished_at"),
        exit_code: row.get("exit_code"),
        stdout: include_logs.then(|| row.get("stdout")),
        stderr: include_logs.then(|| row.get("stderr")),
    }
}

#[get("/api/admin/backups/summary")]
pub(crate) async fn backup_summary(
    req: HttpRequest,
    pool: web::Data<Pool>,
    manager: web::Data<BackupManager>,
    user: UserBaseI,
) -> impl Responder {
    if !require_admin(&req, pool.get_ref(), &user, "backup.query") {
        return HttpResponse::Forbidden()
            .json(json!({"success": false, "message": "仅管理员可以管理备份"}));
    }

    if !manager.enabled() {
        return HttpResponse::Ok().json(json!({
            "success": true,
            "enabled": false,
            "available": false,
            "stanza": manager.stanza(),
            "executionMode": if manager.run_as_user().is_some() { "sudo" } else { "direct" },
            "runAsUser": manager.run_as_user(),
            "operationRunning": manager.operation_running(),
            "stanzas": [],
            "message": "pgBackRest 管理功能未启用"
        }));
    }

    match manager.info().await {
        Ok(stanzas) => HttpResponse::Ok().json(json!({
            "success": true,
            "enabled": true,
            "available": true,
            "stanza": manager.stanza(),
            "executionMode": if manager.run_as_user().is_some() { "sudo" } else { "direct" },
            "runAsUser": manager.run_as_user(),
            "operationRunning": manager.operation_running(),
            "stanzas": stanzas
        })),
        Err(message) => HttpResponse::Ok().json(json!({
            "success": true,
            "enabled": true,
            "available": false,
            "stanza": manager.stanza(),
            "executionMode": if manager.run_as_user().is_some() { "sudo" } else { "direct" },
            "runAsUser": manager.run_as_user(),
            "operationRunning": manager.operation_running(),
            "stanzas": [],
            "message": message
        })),
    }
}

#[get("/api/admin/backups/jobs")]
pub(crate) async fn list_backup_jobs(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<BackupJobQuery>,
    user: UserBaseI,
) -> impl Responder {
    if !require_admin(&req, pool.get_ref(), &user, "backup.job.query") {
        return HttpResponse::Forbidden().finish();
    }
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs_error(
                &req,
                "BackupJobPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let total: i64 = match client
        .query_one("SELECT COUNT(*) FROM backup_job", &[])
        .await
    {
        Ok(row) => row.get(0),
        Err(error_value) => {
            error_logs_error(
                &req,
                "BackupJobQueryError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let rows = match client
        .query(
            "SELECT j.id, j.operation, j.source, j.status, j.requested_by, \
                    u.username AS requested_by_name, j.remark, j.created_at, j.started_at, \
                    j.finished_at, j.exit_code, j.stdout, j.stderr \
             FROM backup_job j LEFT JOIN users u ON u.id = j.requested_by \
             ORDER BY j.created_at DESC LIMIT $1 OFFSET $2",
            &[&page_size, &offset],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs_error(
                &req,
                "BackupJobQueryError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let items: Vec<_> = rows
        .into_iter()
        .map(|row| job_from_row(row, false))
        .collect();
    HttpResponse::Ok().json(json!({
        "success": true,
        "items": items,
        "pagination": {"page": page, "pageSize": page_size, "total": total}
    }))
}

#[get("/api/admin/backups/jobs/{job_id}")]
pub(crate) async fn get_backup_job(
    req: HttpRequest,
    pool: web::Data<Pool>,
    job_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    if !require_admin(&req, pool.get_ref(), &user, "backup.job.query") {
        return HttpResponse::Forbidden().finish();
    }
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs_error(
                &req,
                "BackupJobPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    match client
        .query_opt(
            "SELECT j.id, j.operation, j.source, j.status, j.requested_by, \
                    u.username AS requested_by_name, j.remark, j.created_at, j.started_at, \
                    j.finished_at, j.exit_code, j.stdout, j.stderr \
             FROM backup_job j LEFT JOIN users u ON u.id = j.requested_by WHERE j.id = $1",
            &[&job_id.into_inner()],
        )
        .await
    {
        Ok(Some(row)) => {
            HttpResponse::Ok().json(json!({"success": true, "data": job_from_row(row, true)}))
        }
        Ok(None) => {
            HttpResponse::NotFound().json(json!({"success": false, "message": "备份任务不存在"}))
        }
        Err(error_value) => {
            error_logs_error(
                &req,
                "BackupJobQueryError",
                "database_operation",
                &error_value,
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/api/admin/backups/jobs")]
pub(crate) async fn create_backup_job(
    req: HttpRequest,
    pool: web::Data<Pool>,
    manager: web::Data<BackupManager>,
    body: web::Json<CreateBackupJobRequest>,
    user: UserBaseI,
) -> impl Responder {
    if !require_admin(&req, pool.get_ref(), &user, "backup.run") {
        return HttpResponse::Forbidden().finish();
    }
    let operation = match parse_backup_type(&body.backup_type) {
        Ok(operation) => operation,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let remark = match normalize_remark(body.remark.as_deref()) {
        Ok(remark) => remark,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    enqueue_job(req, pool, manager, &user, operation, remark).await
}

#[post("/api/admin/backups/check")]
pub(crate) async fn create_backup_check(
    req: HttpRequest,
    pool: web::Data<Pool>,
    manager: web::Data<BackupManager>,
    user: UserBaseI,
) -> impl Responder {
    if !require_admin(&req, pool.get_ref(), &user, "backup.check") {
        return HttpResponse::Forbidden().finish();
    }
    enqueue_job(req, pool, manager, &user, BackupOperation::Check, None).await
}

async fn enqueue_job(
    req: HttpRequest,
    pool: web::Data<Pool>,
    manager: web::Data<BackupManager>,
    user: &UserBaseI,
    operation: BackupOperation,
    remark: Option<String>,
) -> HttpResponse {
    if !manager.enabled() {
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "pgBackRest 管理功能未启用"}));
    }
    let permit = match manager.try_acquire_operation() {
        Ok(permit) => permit,
        Err(message) => {
            return HttpResponse::Conflict().json(json!({"success": false, "message": message}));
        }
    };
    let job_id = Uuid::now_v7();
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs_error(
                &req,
                "BackupJobPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    if let Err(error_value) = client
        .execute(
            "INSERT INTO backup_job (id, operation, source, status, requested_by, remark) \
             VALUES ($1, $2, 'manual', 'queued', $3, $4)",
            &[&job_id, &operation.as_str(), &user.id, &remark],
        )
        .await
    {
        error_logs_error(
            &req,
            "BackupJobInsertError",
            "database_operation",
            &error_value,
        );
        return if error_value
            .as_db_error()
            .is_some_and(|value| value.constraint() == Some("idx_backup_job_single_active"))
        {
            HttpResponse::Conflict()
                .json(json!({"success": false, "message": "已有备份任务正在运行"}))
        } else {
            HttpResponse::InternalServerError().finish()
        };
    }

    let context = AuditContext::from_request(&req);
    let mut event = AuditEvent::user("backup", "backup.job.create", "success", user)
        .resource("backup_job", job_id.to_string());
    event.response_status = Some(202);
    event.changes = Some(json!({"operation": operation.as_str(), "remark": remark}));
    write_standalone(pool.get_ref(), &context, &event).await;

    tokio::spawn(run_job(
        pool.get_ref().clone(),
        manager.get_ref().clone(),
        permit,
        job_id,
        operation,
        context,
        user.clone(),
    ));

    HttpResponse::Accepted().json(json!({
        "success": true,
        "message": "任务已提交",
        "jobId": job_id
    }))
}

async fn run_job(
    pool: Pool,
    manager: BackupManager,
    _permit: OwnedSemaphorePermit,
    job_id: Uuid,
    operation: BackupOperation,
    audit_context: AuditContext,
    actor: UserBaseI,
) {
    update_job_started(&pool, job_id).await;
    let result = match operation {
        BackupOperation::Full | BackupOperation::Diff | BackupOperation::Incr => {
            manager.run_backup(operation.as_str()).await
        }
        BackupOperation::Check => manager.run_check().await,
    };
    let succeeded = result
        .as_ref()
        .is_ok_and(|command_result| command_result.success);
    let exit_code = result
        .as_ref()
        .ok()
        .and_then(|command_result| command_result.exit_code);
    update_job_finished(&pool, job_id, result).await;

    let mut event = AuditEvent::user(
        "backup",
        "backup.job.complete",
        if succeeded { "success" } else { "failure" },
        &actor,
    )
    .resource("backup_job", job_id.to_string());
    event.reason_code = (!succeeded).then(|| "pgbackrest_command_failed".to_owned());
    event.metadata = json!({"operation": operation.as_str(), "exit_code": exit_code});
    write_standalone(&pool, &audit_context, &event).await;
}

async fn update_job_started(pool: &Pool, job_id: Uuid) {
    match pool.get().await {
        Ok(client) => {
            if let Err(error_value) = client
                .execute(
                    "UPDATE backup_job SET status = 'running', started_at = NOW() WHERE id = $1",
                    &[&job_id],
                )
                .await
            {
                log_backup_job_database_error(
                    "BackupJobStartUpdateError",
                    "mark_backup_job_running",
                    job_id,
                    "queued",
                    &error_value,
                );
            }
        }
        Err(error_value) => {
            log_backup_job_database_error(
                "BackupJobPoolError",
                "acquire_backup_job_connection",
                job_id,
                "queued",
                &error_value,
            );
        }
    }
}

async fn update_job_finished(pool: &Pool, job_id: Uuid, result: Result<CommandResult, String>) {
    let (status, exit_code, stdout, stderr) = match result {
        Ok(result) => (
            if result.success {
                "succeeded"
            } else {
                "failed"
            },
            result.exit_code,
            result.stdout,
            result.stderr,
        ),
        Err(message) => ("failed", None, String::new(), message),
    };
    match pool.get().await {
        Ok(client) => {
            if let Err(error_value) = client
                .execute(
                    "UPDATE backup_job SET status = $2, finished_at = NOW(), exit_code = $3, \
                     stdout = $4, stderr = $5 WHERE id = $1",
                    &[&job_id, &status, &exit_code, &stdout, &stderr],
                )
                .await
            {
                log_backup_job_database_error(
                    "BackupJobFinishUpdateError",
                    "mark_backup_job_finished",
                    job_id,
                    status,
                    &error_value,
                );
            }
        }
        Err(error_value) => {
            log_backup_job_database_error(
                "BackupJobPoolError",
                "acquire_backup_job_connection",
                job_id,
                status,
                &error_value,
            );
        }
    }
}

fn log_backup_job_database_error(
    event: &'static str,
    operation: &'static str,
    job_id: Uuid,
    job_status: &str,
    error_value: &(dyn std::error::Error + 'static),
) {
    let diagnostics = error_diagnostics(error_value);
    error!(
        event,
        operation,
        error_kind = "database",
        error_code = %format!("{operation}_failed"),
        error_message = %diagnostics.error_message,
        error_chain = %diagnostics.error_chain,
        root_cause = %diagnostics.root_cause,
        error_truncated = diagnostics.error_truncated,
        retryable = false,
        outcome = "backup_job_state_unknown",
        job_id = %job_id,
        job_status,
    );
}

#[cfg(test)]
mod tests {
    use super::{normalize_remark, parse_backup_type};

    #[test]
    fn backup_type_is_allowlisted() {
        assert!(parse_backup_type("full").is_ok());
        assert!(parse_backup_type("diff").is_ok());
        assert!(parse_backup_type("incr").is_ok());
        assert!(parse_backup_type("--config=/tmp/evil").is_err());
    }

    #[test]
    fn remarks_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_remark(Some("  release  ")),
            Ok(Some("release".to_owned()))
        );
        assert_eq!(normalize_remark(Some("  ")), Ok(None));
        assert!(normalize_remark(Some(&"x".repeat(501))).is_err());
    }
}
