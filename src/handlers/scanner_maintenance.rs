use actix_web::{HttpRequest, HttpResponse, Responder, get, patch, post, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use tracing::error;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::config::SecurityConfig;
use crate::scanner_maintenance::{
    DEFAULT_RETRY_AFTER_SECONDS, MaintenanceSnapshot, ScannerMaintenanceState, active_task_count,
};
use crate::{ApplyTaskError, validate_scanner_credentials};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterMaintenanceRequest {
    message: String,
    expected_end_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMaintenanceRequest {
    message: String,
    expected_end_at: Option<DateTime<Utc>>,
    revision: i64,
}

#[derive(Deserialize)]
pub struct ExitMaintenanceRequest {
    revision: i64,
}

#[derive(Deserialize)]
pub struct ScannerMaintenanceQuery {
    scannerid: Uuid,
}

fn require_admin(user: &UserBaseI) -> Result<(), HttpResponse> {
    if user.role == 1 {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以管理扫描服务维护模式"
        })))
    }
}

fn validate_message(message: &str) -> Result<String, HttpResponse> {
    let message = message.trim();
    if message.is_empty() {
        return Err(HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "请输入维护说明"
        })));
    }
    if message.chars().count() > 500 {
        return Err(HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "维护说明不能超过 500 个字符"
        })));
    }
    Ok(message.to_owned())
}

async fn status_response(pool: &Pool, snapshot: MaintenanceSnapshot) -> HttpResponse {
    match active_task_count(pool).await {
        Ok(running_tasks) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": snapshot,
            "running_tasks": running_tasks,
        })),
        Err(error_value) => {
            error!(event = "ScannerMaintenanceCountError", message = %error_value);
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "读取运行任务数量失败"
            }))
        }
    }
}

#[get("/api/admin/scanner-maintenance")]
pub async fn get_maintenance_status(
    pool: web::Data<Pool>,
    state: web::Data<ScannerMaintenanceState>,
    user: UserBaseI,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    status_response(pool.get_ref(), state.snapshot().await).await
}

#[post("/api/admin/scanner-maintenance/enter")]
pub async fn enter_maintenance(
    req: HttpRequest,
    pool: web::Data<Pool>,
    state: web::Data<ScannerMaintenanceState>,
    user: UserBaseI,
    body: web::Json<EnterMaintenanceRequest>,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let message = match validate_message(&body.message) {
        Ok(message) => message,
        Err(response) => return response,
    };
    if body
        .expected_end_at
        .is_some_and(|value| value <= Utc::now())
    {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "预计结束时间必须晚于当前时间"
        }));
    }

    let maintenance_id = Uuid::now_v7();
    let mut client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error!(event = "ScannerMaintenancePoolError", message = %error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match client.transaction().await {
        Ok(transaction) => transaction,
        Err(error_value) => {
            error!(event = "ScannerMaintenanceTransactionError", message = %error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let row = match transaction
        .query_opt(
            "UPDATE scanner_maintenance_state SET enabled = TRUE, phase = 'draining', \
             maintenance_id = $1, message = $2, expected_end_at = $3, retry_after_seconds = $4, \
             started_at = NOW(), started_by = $5, updated_at = NOW(), exited_at = NULL, \
             exited_by = NULL, revision = revision + 1 WHERE singleton = TRUE AND enabled = FALSE \
             RETURNING enabled, phase, maintenance_id, message, expected_end_at, \
             retry_after_seconds, started_at, updated_at, revision;",
            &[
                &maintenance_id,
                &message,
                &body.expected_end_at,
                &DEFAULT_RETRY_AFTER_SECONDS,
                &user.id,
            ],
        )
        .await
    {
        Ok(row) => row,
        Err(error_value) => {
            error!(event = "ScannerMaintenanceEnterError", message = %error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let Some(row) = row else {
        return HttpResponse::Conflict().json(json!({
            "success": false,
            "message": "扫描服务已经处于维护模式"
        }));
    };
    let snapshot = MaintenanceSnapshot::from_row(&row);
    let mut audit = AuditEvent::user(
        "configuration",
        "scanner.maintenance.enter",
        "success",
        &user,
    )
    .resource("scanner_maintenance", maintenance_id.to_string());
    audit.response_status = Some(200);
    audit.changes = Some(json!({
        "phase": "draining",
        "message": message,
        "expected_end_at": body.expected_end_at,
        "retry_after_seconds": DEFAULT_RETRY_AFTER_SECONDS,
    }));
    if let Err(error_value) =
        write_audit(&transaction, &AuditContext::from_request(&req), &audit).await
    {
        error!(event = "ScannerMaintenanceAuditError", message = %error_value);
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error_value) = transaction.commit().await {
        error!(event = "ScannerMaintenanceCommitError", message = %error_value);
        return HttpResponse::InternalServerError().finish();
    }
    state.replace(snapshot.clone()).await;
    status_response(pool.get_ref(), snapshot).await
}

#[patch("/api/admin/scanner-maintenance")]
pub async fn update_maintenance(
    req: HttpRequest,
    pool: web::Data<Pool>,
    state: web::Data<ScannerMaintenanceState>,
    user: UserBaseI,
    body: web::Json<UpdateMaintenanceRequest>,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let message = match validate_message(&body.message) {
        Ok(message) => message,
        Err(response) => return response,
    };
    if body
        .expected_end_at
        .is_some_and(|value| value <= Utc::now())
    {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "预计结束时间必须晚于当前时间"
        }));
    }
    let mut client = match pool.get().await {
        Ok(client) => client,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let transaction = match client.transaction().await {
        Ok(transaction) => transaction,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let row = match transaction
        .query_opt(
            "UPDATE scanner_maintenance_state SET message = $1, expected_end_at = $2, \
             updated_at = NOW(), revision = revision + 1 WHERE singleton = TRUE \
             AND enabled = TRUE AND revision = $3 RETURNING enabled, phase, maintenance_id, \
             message, expected_end_at, retry_after_seconds, started_at, updated_at, revision;",
            &[&message, &body.expected_end_at, &body.revision],
        )
        .await
    {
        Ok(row) => row,
        Err(error_value) => {
            error!(event = "ScannerMaintenanceUpdateError", message = %error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let Some(row) = row else {
        return HttpResponse::Conflict().json(json!({
            "success": false,
            "message": "维护状态已变化，请刷新后重试"
        }));
    };
    let snapshot = MaintenanceSnapshot::from_row(&row);
    let mut audit = AuditEvent::user(
        "configuration",
        "scanner.maintenance.update",
        "success",
        &user,
    );
    audit.resource_type = Some("scanner_maintenance".to_owned());
    audit.resource_id = snapshot.maintenance_id.map(|value| value.to_string());
    audit.response_status = Some(200);
    audit.changes = Some(json!({
        "message": message,
        "expected_end_at": body.expected_end_at,
    }));
    if write_audit(&transaction, &AuditContext::from_request(&req), &audit)
        .await
        .is_err()
        || transaction.commit().await.is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    state.replace(snapshot.clone()).await;
    status_response(pool.get_ref(), snapshot).await
}

#[post("/api/admin/scanner-maintenance/exit")]
pub async fn exit_maintenance(
    req: HttpRequest,
    pool: web::Data<Pool>,
    state: web::Data<ScannerMaintenanceState>,
    user: UserBaseI,
    body: web::Json<ExitMaintenanceRequest>,
) -> impl Responder {
    if let Err(response) = require_admin(&user) {
        return response;
    }
    let previous = state.snapshot().await;
    let mut client = match pool.get().await {
        Ok(client) => client,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let transaction = match client.transaction().await {
        Ok(transaction) => transaction,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let row = match transaction
        .query_opt(
            "UPDATE scanner_maintenance_state SET enabled = FALSE, phase = 'off', \
             maintenance_id = NULL, message = '', expected_end_at = NULL, started_at = NULL, \
             updated_at = NOW(), exited_at = NOW(), exited_by = $1, revision = revision + 1 \
             WHERE singleton = TRUE AND enabled = TRUE AND revision = $2 \
             RETURNING enabled, phase, maintenance_id, message, expected_end_at, \
             retry_after_seconds, started_at, updated_at, revision;",
            &[&user.id, &body.revision],
        )
        .await
    {
        Ok(row) => row,
        Err(error_value) => {
            error!(event = "ScannerMaintenanceExitError", message = %error_value);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let Some(row) = row else {
        return HttpResponse::Conflict().json(json!({
            "success": false,
            "message": "维护状态已变化，请刷新后重试"
        }));
    };
    let snapshot = MaintenanceSnapshot::from_row(&row);
    let mut audit = AuditEvent::user(
        "configuration",
        "scanner.maintenance.exit",
        "success",
        &user,
    );
    audit.resource_type = Some("scanner_maintenance".to_owned());
    audit.resource_id = previous.maintenance_id.map(|value| value.to_string());
    audit.response_status = Some(200);
    audit.changes = Some(json!({"phase": "off"}));
    if write_audit(&transaction, &AuditContext::from_request(&req), &audit)
        .await
        .is_err()
        || transaction.commit().await.is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    state.replace(snapshot.clone()).await;
    status_response(pool.get_ref(), snapshot).await
}

#[get("/api/scanner/maintenance")]
pub async fn scanner_maintenance_probe(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    state: web::Data<ScannerMaintenanceState>,
    query: web::Query<ScannerMaintenanceQuery>,
) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    match validate_scanner_credentials(
        pool.get_ref(),
        query.scannerid,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(()) => HttpResponse::Ok().json(json!({
            "success": true,
            "maintenance": state.snapshot().await,
            "server_time": Utc::now(),
        })),
        Err(ApplyTaskError::ScannerUnauthorized) => {
            HttpResponse::Unauthorized().body("unauthorized")
        }
        Err(error_value) => {
            error!(event = "ScannerMaintenanceProbeError", message = %error_value);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_message;

    #[test]
    fn maintenance_message_is_trimmed_and_bounded() {
        assert_eq!(validate_message("  upgrade  ").unwrap(), "upgrade");
        assert!(validate_message("   ").is_err());
        assert!(validate_message(&"x".repeat(501)).is_err());
    }
}
