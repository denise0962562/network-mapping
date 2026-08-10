use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::config::SecurityConfig;
use crate::logs::write::error_logs;
use crate::{generate_scanner_token, hash_scanner_token};
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, put, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

fn is_admin(user: &UserBaseI) -> bool {
    user.role == 1
}

async fn audit(
    transaction: &deadpool_postgres::Transaction<'_>,
    req: &HttpRequest,
    user: &UserBaseI,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    detail: Value,
) -> Result<(), tokio_postgres::Error> {
    let mut event =
        AuditEvent::user("task", action, "success", user).resource(resource_type, resource_id);
    if resource_type == "scanner" {
        event.category = "scanner".to_owned();
    }
    event.changes = Some(detail);
    event.response_status = Some(200);
    write_audit(transaction, &AuditContext::from_request(req), &event).await
}

#[post("/api/task/{task_id}/cancel")]
pub(crate) async fn cancel_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    task_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "CancelTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "CancelTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let id = task_id.into_inner().to_string();
    let row = match transaction
        .query_opt(
            "SELECT task_status FROM scan_task WHERE task_id = $1 AND ($2 = 1 OR user_id = $3) FOR UPDATE;",
            &[&id, &user.role, &user.id],
        )
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().json(json!({"success": false, "message": "task not found"})),
        Err(error) => {
            error_logs(&req, "CancelTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let status: String = row.get("task_status");
    match status.as_str() {
        "pending" | "running" => {}
        _ => {
            return HttpResponse::Conflict()
                .json(json!({"success": false, "message": "task is already finished"}));
        }
    }
    let now = crate::get_unix_epoch_ms();
    let task_pk: i32 = match transaction
        .query_one("SELECT id FROM scan_task WHERE task_id = $1", &[&id])
        .await
    {
        Ok(row) => row.get("id"),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    if let Err(error) = transaction.execute(
        "UPDATE scan_task_execution SET execution_status = CASE WHEN execution_status = 'pending' THEN 'cancelled' ELSE execution_status END, \
         cancel_requested = (execution_status = 'running'), task_end_time = CASE WHEN execution_status = 'pending' THEN $1 ELSE task_end_time END, \
         lease_expires_at = CASE WHEN execution_status = 'pending' THEN NULL ELSE lease_expires_at END \
         WHERE task_id = $2 AND execution_status IN ('pending', 'running');", &[&now, &task_pk]).await {
        error_logs(&req, "CancelTaskDatabaseError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = crate::refresh_task_aggregate(&transaction, task_pk).await {
        error_logs(&req, "CancelTaskDatabaseError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    let aggregate = match transaction
        .query_one(
            "SELECT task_status, cancel_requested FROM scan_task WHERE id = $1;",
            &[&task_pk],
        )
        .await
    {
        Ok(row) => row,
        Err(error) => {
            error_logs(&req, "CancelTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let aggregate_status: String = aggregate.get("task_status");
    let cancel_requested: bool = aggregate.get("cancel_requested");
    if let Err(error) = audit(
        &transaction,
        &req,
        &user,
        "task.cancel",
        "task",
        &id,
        json!({"previous_status": status}),
    )
    .await
    {
        error_logs(&req, "CancelTaskAuditError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        error_logs(&req, "CancelTaskDatabaseError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(
        json!({"success": true, "status": aggregate_status, "cancel_requested": cancel_requested}),
    )
}

#[post("/api/task/{task_id}/retry")]
pub(crate) async fn retry_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    task_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "RetryTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "RetryTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let source_id = task_id.into_inner().to_string();
    let source = match transaction
        .query_opt(
            "SELECT id, user_id, task_target, task_port, task_level, remarks, task_status, dispatch_mode FROM scan_task \
             WHERE task_id = $1 AND ($2 = 1 OR user_id = $3) FOR UPDATE;",
            &[&source_id, &user.role, &user.id],
        )
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().json(json!({"success": false, "message": "task not found"})),
        Err(error) => {
            error_logs(&req, "RetryTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let status: String = source.get("task_status");
    if !matches!(
        status.as_str(),
        "failed" | "cancelled" | "succeeded" | "partial"
    ) {
        return HttpResponse::Conflict()
            .json(json!({"success": false, "message": "only finished tasks can be retried"}));
    }
    let new_id = Uuid::now_v7().to_string();
    let owner_id: i32 = source.get("user_id");
    let targets: Vec<cidr::IpInet> = source.get("task_target");
    let port: String = source.get("task_port");
    let level: i32 = source.get("task_level");
    let remarks: Option<String> = source.get("remarks");
    let dispatch_mode: String = source.get("dispatch_mode");
    let source_pk: i32 = source.get("id");
    let new_task_pk: i32 = match transaction.query_one(
        "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks, retry_of_task_id, dispatch_mode) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id;",
        &[&owner_id, &new_id, &user.username, &targets, &port, &level, &remarks, &source_id, &dispatch_mode]).await {
        Ok(row) => row.get("id"),
        Err(error) => { error_logs(&req, "RetryTaskDatabaseError", &error.to_string()); return HttpResponse::InternalServerError().finish(); }
    };
    let source_executions = match transaction
        .query(
            "SELECT requested_scanner_id FROM scan_task_execution WHERE task_id = $1 \
             AND execution_status <> 'superseded' ORDER BY id;",
            &[&source_pk],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            error_logs(&req, "RetryTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    for execution in source_executions {
        let execution_id = Uuid::now_v7().to_string();
        let requested_scanner_id: Option<String> = execution.get("requested_scanner_id");
        if let Err(error) = transaction
            .execute(
                "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) VALUES ($1, $2, $3);",
                &[&execution_id, &new_task_pk, &requested_scanner_id],
            )
            .await
        {
            error_logs(&req, "RetryTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    }
    if let Err(error) = audit(
        &transaction,
        &req,
        &user,
        "task.retry",
        "task",
        &new_id,
        json!({"source_task_id": source_id}),
    )
    .await
    {
        error_logs(&req, "RetryTaskAuditError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        error_logs(&req, "RetryTaskDatabaseError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true, "data": {"task_id": new_id}}))
}

#[derive(Deserialize)]
pub(crate) struct ExportQuery {
    format: Option<String>,
}

fn csv_cell(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[get("/api/task/{task_id}/export")]
pub(crate) async fn export_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    task_id: web::Path<Uuid>,
    query: web::Query<ExportQuery>,
    user: UserBaseI,
) -> impl Responder {
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "ExportTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let id = task_id.into_inner().to_string();
    let rows = match connection
        .query(
            "SELECT e.execution_id, e.assigned_scanner_id, COALESCE(s.name, e.assigned_scanner_id) AS scanner_name, \
             host(i.ip_address) AS ip, i.asn, i.isp, p.port, latest.protocol, latest.service, latest.banner, latest.scan_time \
             FROM scan_task t JOIN scan_task_execution e ON e.task_id = t.id JOIN ips i ON i.execution_id = e.id \
             LEFT JOIN scanner_info s ON s.scanner_id = e.assigned_scanner_id LEFT JOIN ports p ON p.ip_id = i.ip_id \
             LEFT JOIN LATERAL (SELECT protocol, service, banner, scan_time FROM scaninfo WHERE port_id = p.port_id ORDER BY scan_time DESC LIMIT 1) latest ON true \
             WHERE t.task_id = $1 AND e.execution_status <> 'superseded' \
             AND ($2 = 1 OR t.user_id = $3) ORDER BY i.ip_address, p.port;",
            &[&id, &user.role, &user.id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            error_logs(&req, "ExportTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    if query.format.as_deref() == Some("json") {
        let data: Vec<Value> = rows.iter().map(|row| json!({
            "execution_id": row.get::<_, String>("execution_id"), "scanner_id": row.get::<_, Option<String>>("assigned_scanner_id"),
            "scanner_name": row.get::<_, Option<String>>("scanner_name"), "ip": row.get::<_, String>("ip"), "asn": row.get::<_, Option<String>>("asn"),
            "isp": row.get::<_, Option<String>>("isp"), "port": row.get::<_, Option<i32>>("port"),
            "protocol": row.get::<_, Option<String>>("protocol"), "service": row.get::<_, Option<String>>("service"),
            "banner": row.get::<_, Option<String>>("banner"), "scan_time": row.get::<_, Option<i64>>("scan_time")
        })).collect();
        return HttpResponse::Ok().json(json!({"task_id": id, "results": data}));
    }
    let mut csv = String::from(
        "execution_id,scanner_id,scanner_name,ip,asn,isp,port,protocol,service,banner,scan_time\n",
    );
    for row in rows {
        let values = [
            row.get::<_, String>("execution_id"),
            row.get::<_, Option<String>>("assigned_scanner_id")
                .unwrap_or_default(),
            row.get::<_, Option<String>>("scanner_name")
                .unwrap_or_default(),
            row.get::<_, String>("ip"),
            row.get::<_, Option<String>>("asn").unwrap_or_default(),
            row.get::<_, Option<String>>("isp").unwrap_or_default(),
            row.get::<_, Option<i32>>("port")
                .map(|v| v.to_string())
                .unwrap_or_default(),
            row.get::<_, Option<String>>("protocol").unwrap_or_default(),
            row.get::<_, Option<String>>("service").unwrap_or_default(),
            row.get::<_, Option<String>>("banner").unwrap_or_default(),
            row.get::<_, Option<i64>>("scan_time")
                .map(|v| v.to_string())
                .unwrap_or_default(),
        ];
        csv.push_str(
            &values
                .iter()
                .map(|value| csv_cell(value))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    HttpResponse::Ok()
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=task-{id}.csv"),
        ))
        .content_type("text/csv; charset=utf-8")
        .body(csv)
}

#[get("/api/dashboard/overview")]
pub(crate) async fn dashboard_overview(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "DashboardDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let summary = match connection.query_one(
        "SELECT COUNT(*) FILTER (WHERE task_status = 'pending')::BIGINT AS pending, \
         COUNT(*) FILTER (WHERE task_status = 'running')::BIGINT AS running, \
         COUNT(*) FILTER (WHERE task_status = 'succeeded')::BIGINT AS succeeded, \
         COUNT(*) FILTER (WHERE task_status = 'failed')::BIGINT AS failed, \
         COUNT(*) FILTER (WHERE task_status = 'cancelled')::BIGINT AS cancelled, \
         COALESCE(AVG(task_end_time - task_start_time) FILTER (WHERE task_status = 'succeeded'), 0)::BIGINT AS avg_duration_ms \
         FROM scan_task WHERE ($1 = 1 OR user_id = $2);", &[&user.role, &user.id]).await {
        Ok(row) => row,
        Err(error) => { error_logs(&req, "DashboardDatabaseError", &error.to_string()); return HttpResponse::InternalServerError().finish(); }
    };
    let online: i64 = match connection.query_one(
        "SELECT COUNT(*)::BIGINT AS count FROM scanner_info WHERE deleted_at IS NULL AND is_enable = true \
         AND runtime_state <> 'stopping' AND last_seen_at >= NOW() - INTERVAL '90 seconds';", &[]).await {
        Ok(row) => row.get("count"),
        Err(error) => { error_logs(&req, "DashboardDatabaseError", &error.to_string()); return HttpResponse::InternalServerError().finish(); }
    };
    let trend_rows = match connection.query(
        "SELECT to_char(days.day, 'YYYY-MM-DD') AS day, COALESCE(s.name, t.assigned_scanner_id, '未分配') AS scanner, COUNT(t.id)::BIGINT AS count \
         FROM generate_series(CURRENT_DATE - INTERVAL '6 days', CURRENT_DATE, INTERVAL '1 day') days(day) \
         LEFT JOIN scan_task t ON to_timestamp(t.task_create_time / 1000.0)::date = days.day::date AND ($1 = 1 OR t.user_id = $2) \
         LEFT JOIN scanner_info s ON s.scanner_id = t.assigned_scanner_id GROUP BY days.day, scanner ORDER BY days.day, scanner;",
        &[&user.role, &user.id]).await {
        Ok(rows) => rows,
        Err(error) => { error_logs(&req, "DashboardDatabaseError", &error.to_string()); return HttpResponse::InternalServerError().finish(); }
    };
    let task_rows = match connection.query(
        "SELECT t.task_id, t.task_target::text[], t.task_initiator, t.task_status, t.remarks, COALESCE(s.name, t.assigned_scanner_id) AS scanner_name \
         FROM scan_task t LEFT JOIN scanner_info s ON s.scanner_id = t.assigned_scanner_id \
         WHERE t.task_status IN ('pending', 'running') AND ($1 = 1 OR t.user_id = $2) ORDER BY t.task_level DESC, t.task_create_time LIMIT 10;",
        &[&user.role, &user.id]).await {
        Ok(rows) => rows,
        Err(error) => { error_logs(&req, "DashboardDatabaseError", &error.to_string()); return HttpResponse::InternalServerError().finish(); }
    };
    let trend: Vec<Value> = trend_rows.iter().map(|row| json!({"day": row.get::<_, String>("day"), "scanner": row.get::<_, String>("scanner"), "count": row.get::<_, i64>("count")})).collect();
    let tasks: Vec<Value> = task_rows.iter().map(|row| json!({
        "task_id": row.get::<_, String>("task_id"), "target": row.get::<_, Vec<String>>("task_target"),
        "initiator": row.get::<_, String>("task_initiator"), "status": row.get::<_, String>("task_status"),
        "remark": row.get::<_, Option<String>>("remarks"), "scanner": row.get::<_, Option<String>>("scanner_name")
    })).collect();
    HttpResponse::Ok().json(json!({"success": true, "data": {
        "online_scanners": online,
        "tasks": {"pending": summary.get::<_, i64>("pending"), "running": summary.get::<_, i64>("running"), "succeeded": summary.get::<_, i64>("succeeded"), "failed": summary.get::<_, i64>("failed"), "cancelled": summary.get::<_, i64>("cancelled")},
        "avg_duration_ms": summary.get::<_, i64>("avg_duration_ms"), "trend": trend, "current_tasks": tasks
    }}))
}

#[derive(Deserialize)]
pub(crate) struct ScannerUpdate {
    name: String,
    location: Option<String>,
    remark: Option<String>,
    tag: Option<String>,
}

#[put("/api/scanner/{scanner_id}")]
pub(crate) async fn update_scanner(
    req: HttpRequest,
    pool: web::Data<Pool>,
    scanner_id: web::Path<Uuid>,
    body: web::Json<ScannerUpdate>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 50 {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "name must contain 1-50 characters"}));
    }
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "UpdateScannerDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "UpdateScannerDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let id = scanner_id.into_inner().to_string();
    let changed = transaction.execute("UPDATE scanner_info SET name = $1, location = $2, remark = $3, tag = $4, update_time = NOW() WHERE scanner_id = $5 AND deleted_at IS NULL;", &[&name, &body.location, &body.remark, &body.tag, &id]).await;
    match changed {
        Ok(1) => {}
        Ok(_) => return HttpResponse::NotFound().finish(),
        Err(error) => {
            error_logs(&req, "UpdateScannerDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    }
    if audit(
        &transaction,
        &req,
        &user,
        "scanner.update",
        "scanner",
        &id,
        json!({"name": name}),
    )
    .await
    .is_err()
        || transaction.commit().await.is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true}))
}

#[derive(Deserialize)]
pub(crate) struct ScannerEnabled {
    enabled: bool,
}

async fn release_scanner_tasks(
    transaction: &tokio_postgres::Transaction<'_>,
    scanner_id: &str,
    reason: &str,
) -> Result<u64, tokio_postgres::Error> {
    let rows = transaction.query(
        "UPDATE scan_task_execution SET execution_status = 'pending', assigned_scanner_id = NULL, lease_expires_at = NULL, \
         task_start_time = NULL, cancel_requested = false, failure_reason = $1 \
         WHERE assigned_scanner_id = $2 AND execution_status = 'running' RETURNING task_id;", &[&reason, &scanner_id]).await?;
    let task_ids: std::collections::HashSet<i32> =
        rows.iter().map(|row| row.get("task_id")).collect();
    for task_id in task_ids {
        crate::refresh_task_aggregate(transaction, task_id).await?;
    }
    Ok(rows.len() as u64)
}

#[post("/api/scanner/{scanner_id}/enabled")]
pub(crate) async fn set_scanner_enabled(
    req: HttpRequest,
    pool: web::Data<Pool>,
    scanner_id: web::Path<Uuid>,
    body: web::Json<ScannerEnabled>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "SetScannerEnabledError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let id = scanner_id.into_inner().to_string();
    let changed = transaction.execute("UPDATE scanner_info SET is_enable = $1, runtime_state = CASE WHEN $1 THEN runtime_state ELSE 'offline' END, is_run = CASE WHEN $1 THEN is_run ELSE false END, update_time = NOW() WHERE scanner_id = $2 AND deleted_at IS NULL;", &[&body.enabled, &id]).await;
    match changed {
        Ok(1) => {}
        Ok(_) => return HttpResponse::NotFound().finish(),
        Err(error) => {
            error_logs(&req, "SetScannerEnabledError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    }
    let released = if body.enabled {
        0
    } else {
        match release_scanner_tasks(&transaction, &id, "scanner disabled by administrator").await {
            Ok(count) => count,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        }
    };
    if audit(
        &transaction,
        &req,
        &user,
        if body.enabled {
            "scanner.enable"
        } else {
            "scanner.disable"
        },
        "scanner",
        &id,
        json!({"released_tasks": released}),
    )
    .await
    .is_err()
        || transaction.commit().await.is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true, "released_tasks": released}))
}

#[post("/api/scanner/{scanner_id}/reissue-token")]
pub(crate) async fn reissue_scanner_token(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    scanner_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let token = match generate_scanner_token("nm_reg") {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let token_hash = match hash_scanner_token(&token, &security.scanner_token_pepper) {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "ReissueScannerTokenError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let id = scanner_id.into_inner().to_string();
    let changed = transaction.execute(
        "UPDATE scanner_info SET registration_token_hash = $1, registration_token_expires_at = NOW() + INTERVAL '24 hours', registration_consumed_at = NULL, runtime_token_hash = NULL, is_enable = false, is_run = false, runtime_state = 'offline', update_time = NOW() WHERE scanner_id = $2 AND deleted_at IS NULL;", &[&token_hash, &id]).await;
    match changed {
        Ok(1) => {}
        Ok(_) => return HttpResponse::NotFound().finish(),
        Err(error) => {
            error_logs(&req, "ReissueScannerTokenError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    }
    let released =
        match release_scanner_tasks(&transaction, &id, "scanner credentials revoked").await {
            Ok(value) => value,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };
    if audit(
        &transaction,
        &req,
        &user,
        "scanner.token.reissue",
        "scanner",
        &id,
        json!({"released_tasks": released}),
    )
    .await
    .is_err()
        || transaction.commit().await.is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok()
        .json(json!({"success": true, "data": {"scanner_id": id, "registration_token": token}}))
}

#[delete("/api/scanner/{scanner_id}")]
pub(crate) async fn delete_scanner(
    req: HttpRequest,
    pool: web::Data<Pool>,
    scanner_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().finish();
    }
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "DeleteScannerError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let id = scanner_id.into_inner().to_string();
    let released =
        match release_scanner_tasks(&transaction, &id, "scanner deleted by administrator").await {
            Ok(value) => value,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };
    let changed = transaction.execute("UPDATE scanner_info SET deleted_at = NOW(), is_enable = false, is_run = false, runtime_state = 'offline', registration_token_hash = NULL, runtime_token_hash = NULL, update_time = NOW() WHERE scanner_id = $1 AND deleted_at IS NULL;", &[&id]).await;
    match changed {
        Ok(1) => {}
        Ok(_) => return HttpResponse::NotFound().finish(),
        Err(error) => {
            error_logs(&req, "DeleteScannerError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    }
    if audit(
        &transaction,
        &req,
        &user,
        "scanner.delete",
        "scanner",
        &id,
        json!({"released_tasks": released}),
    )
    .await
    .is_err()
        || transaction.commit().await.is_err()
    {
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true}))
}

#[cfg(test)]
mod tests {
    use super::csv_cell;

    #[test]
    fn csv_cell_escapes_quotes_and_commas() {
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hello\""), "\"say \"\"hello\"\"\"");
    }
}
