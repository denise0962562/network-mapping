use crate::admin::UserBaseI;
use crate::config::SecurityConfig;
use crate::logs::write::{error_logs, info_logs};
use crate::maxmind::MaxMindState;
use crate::middlewares::render_500;
use crate::{
    ApplyTaskError, ApplyTaskQuery, CreateTask, ReceiveTaskItemQueryInfo, STask, TargetIP,
    TaskItemJson, apply_task, get_task_item, validate_scanner_credentials,
};
use crate::{Permission, TEXT_HTML_UTF_8, TemplatesInit};
use crate::{SaveScannerResultsError, ScannerResultUpload, save_scanner_results};
use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::error;
use uuid::Uuid;

const TASK_LEASE_MS: i64 = 90_000;

#[derive(Deserialize)]
pub struct ScannerSystemInfo {
    os_name: String,
    os_version: String,
    cpu_model: String,
    cpu_cores: u32,
    ram_total_mb: u64,
    uptime_seconds: u64,
}

#[derive(Deserialize)]
pub struct ScannerHeartbeat {
    scanner_id: Uuid,
    state: String,
    active_task_id: Option<Uuid>,
    scanner_version: String,
    system: ScannerSystemInfo,
}

#[derive(Deserialize)]
pub struct ScannerTaskFailure {
    scanner_id: Uuid,
    task_id: Uuid,
    error: String,
    #[serde(default = "default_retryable")]
    retryable: bool,
}

#[derive(Deserialize)]
pub struct ScannerTaskCancelled {
    scanner_id: Uuid,
    task_id: Uuid,
}

fn default_retryable() -> bool {
    true
}

fn bearer_token(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

#[derive(Deserialize)]
pub struct TaskDetailQuery {
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Serialize)]
struct TaskResultPort {
    port: i32,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    other: Option<Value>,
    scan_time: Option<i64>,
}

#[derive(Serialize)]
struct TaskResultIp {
    ip: String,
    asn: Option<String>,
    isp: Option<String>,
    ports: Vec<TaskResultPort>,
}

fn task_result_pagination(page: Option<i64>, page_size: Option<i64>) -> (i64, i64, i64) {
    let page = page.unwrap_or(1).max(1);
    let page_size = page_size.unwrap_or(20).clamp(1, 100);
    (page, page_size, (page - 1) * page_size)
}

#[post("/api/scanner/heartbeat")]
pub(crate) async fn scanner_heartbeat_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    heartbeat: web::Json<ScannerHeartbeat>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    if !matches!(heartbeat.state.as_str(), "idle" | "scanning" | "stopping") {
        return HttpResponse::BadRequest().body("invalid scanner state");
    }
    if let Err(error) = validate_scanner_credentials(
        pool.get_ref(),
        heartbeat.scanner_id,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        return match error {
            ApplyTaskError::ScannerUnauthorized => {
                HttpResponse::Unauthorized().body("unauthorized")
            }
            _ => HttpResponse::InternalServerError().finish(),
        };
    }

    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs(&req, "ScannerHeartbeatDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(transaction) => transaction,
        Err(error) => {
            error_logs(&req, "ScannerHeartbeatDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let scanner_id = heartbeat.scanner_id.to_string();
    let system_version = format!(
        "{} {}",
        heartbeat.system.os_name, heartbeat.system.os_version
    );
    let cpu_cores = i32::try_from(heartbeat.system.cpu_cores).unwrap_or(i32::MAX);
    let ram_mb = i32::try_from(heartbeat.system.ram_total_mb).unwrap_or(i32::MAX);
    let uptime = i32::try_from(heartbeat.system.uptime_seconds).unwrap_or(i32::MAX);
    let ip_address = req.peer_addr().map(|address| address.ip().to_string());
    let update = transaction
        .execute(
            "UPDATE scanner_info SET system_version = $1, scanner_version = $2, cpu_model = $3, \
             cpus = $4, ram = $5, uptime = $6, runtime_state = $7, last_seen_at = NOW(), \
             update_time = NOW(), is_run = ($7 <> 'stopping'), \
             ip_address = COALESCE($8::text::inet, ip_address) WHERE scanner_id = $9;",
            &[
                &system_version,
                &heartbeat.scanner_version,
                &heartbeat.system.cpu_model,
                &cpu_cores,
                &ram_mb,
                &uptime,
                &heartbeat.state,
                &ip_address,
                &scanner_id,
            ],
        )
        .await;
    if let Err(error) = update {
        error_logs(&req, "ScannerHeartbeatDatabaseError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    let mut cancel_task_id = None;
    if let Some(task_id) = heartbeat.active_task_id {
        let lease_expires_at = crate::get_unix_epoch_ms() + TASK_LEASE_MS;
        if let Err(error) = transaction
            .execute(
                "UPDATE scan_task SET lease_expires_at = $1 WHERE task_id = $2 \
                 AND assigned_scanner_id = $3 AND task_status = 'running';",
                &[&lease_expires_at, &task_id.to_string(), &scanner_id],
            )
            .await
        {
            error_logs(&req, "ScannerLeaseRenewError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
        match transaction
            .query_opt(
                "SELECT task_id FROM scan_task WHERE task_id = $1 AND assigned_scanner_id = $2 \
                 AND task_status = 'running' AND cancel_requested = true;",
                &[&task_id.to_string(), &scanner_id],
            )
            .await
        {
            Ok(Some(_)) => cancel_task_id = Some(task_id),
            Ok(None) => {}
            Err(error) => {
                error_logs(&req, "ScannerCancelCommandError", &error.to_string());
                return HttpResponse::InternalServerError().finish();
            }
        }
    }
    if let Err(error) = transaction.commit().await {
        error_logs(&req, "ScannerHeartbeatDatabaseError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "command": cancel_task_id.map(|task_id| serde_json::json!({
            "type": "cancel_task",
            "task_id": task_id,
        }))
    }))
}

#[post("/api/scanner/task/fail")]
pub(crate) async fn scanner_task_failure_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    failure: web::Json<ScannerTaskFailure>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    if validate_scanner_credentials(
        pool.get_ref(),
        failure.scanner_id,
        token,
        &security.scanner_token_pepper,
    )
    .await
    .is_err()
    {
        return HttpResponse::Unauthorized().body("unauthorized");
    }
    let connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs(&req, "ScannerTaskFailureDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let scanner_id = failure.scanner_id.to_string();
    let task_id = failure.task_id.to_string();
    let reason: String = failure.error.chars().take(1000).collect();
    let force_terminal = !failure.retryable;
    let changed = connection
        .query_opt(
            "UPDATE scan_task SET task_status = CASE WHEN $1 OR attempt_count >= 3 THEN 'failed' ELSE 'pending' END, \
             task_end_time = CASE WHEN $1 OR attempt_count >= 3 THEN $2 ELSE NULL END, task_start_time = NULL, \
             assigned_scanner_id = NULL, lease_expires_at = NULL, failure_reason = $3, cancel_requested = false \
             WHERE task_id = $4 AND assigned_scanner_id = $5 AND task_status = 'running' \
             RETURNING task_status;",
            &[
                &force_terminal,
                &crate::get_unix_epoch_ms(),
                &reason,
                &task_id,
                &scanner_id,
            ],
        )
        .await;
    match changed {
        Ok(Some(row)) => {
            let status: String = row.get("task_status");
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "retryable": status == "pending",
                "status": status,
            }))
        }
        Ok(None) => HttpResponse::Conflict().body("task is not owned by scanner"),
        Err(error) => {
            error_logs(&req, "ScannerTaskFailureDatabaseError", &error.to_string());
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/api/scanner/task/cancelled")]
pub(crate) async fn scanner_task_cancelled_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    cancelled: web::Json<ScannerTaskCancelled>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    if validate_scanner_credentials(
        pool.get_ref(),
        cancelled.scanner_id,
        token,
        &security.scanner_token_pepper,
    )
    .await
    .is_err()
    {
        return HttpResponse::Unauthorized().body("unauthorized");
    }
    let connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs(
                &req,
                "ScannerTaskCancelledDatabaseError",
                &error.to_string(),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let changed = connection
        .execute(
            "UPDATE scan_task SET task_status = 'cancelled', task_end_time = $1, \
             lease_expires_at = NULL, cancel_requested = false, failure_reason = NULL \
             WHERE task_id = $2 AND assigned_scanner_id = $3 AND task_status = 'running' AND cancel_requested = true;",
            &[&crate::get_unix_epoch_ms(), &cancelled.task_id.to_string(), &cancelled.scanner_id.to_string()],
        )
        .await;
    match changed {
        Ok(1) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
        Ok(_) => HttpResponse::Conflict().body("task cancellation was not requested"),
        Err(error) => {
            error_logs(
                &req,
                "ScannerTaskCancelledDatabaseError",
                &error.to_string(),
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/api/task/{task_id}")]
async fn get_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    task_id: web::Path<Uuid>,
    query: web::Query<TaskDetailQuery>,
    user: UserBaseI,
) -> impl Responder {
    let connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs(&req, "GetTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task_id = task_id.into_inner().to_string();
    let task = match connection
        .query_opt(
            "SELECT t.id, t.task_id, t.task_target::text[], t.task_port, t.task_initiator, \
             t.task_level, t.task_create_time, t.task_start_time, t.task_end_time, \
             t.task_status, t.assigned_scanner_id, t.lease_expires_at, t.attempt_count, \
             t.failure_reason, t.cancel_requested, t.retry_of_task_id, t.remarks, s.name AS scanner_name \
             FROM scan_task t LEFT JOIN scanner_info s ON s.scanner_id = t.assigned_scanner_id \
             WHERE t.task_id = $1 AND ($2 = 1 OR t.user_id = $3) LIMIT 1;",
            &[&task_id, &user.role, &user.id],
        )
        .await
    {
        Ok(Some(task)) => task,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "success": false,
                "message": "task not found",
            }));
        }
        Err(error) => {
            error_logs(&req, "GetTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let task_pk: i32 = task.get("id");
    let (page, page_size, offset) = task_result_pagination(query.page, query.page_size);
    let summary = match connection
        .query_one(
            "SELECT COUNT(DISTINCT i.ip_id)::BIGINT AS ip_count, \
             COUNT(DISTINCT p.port_id)::BIGINT AS port_count, \
             COUNT(si.scan_info_id)::BIGINT AS result_count \
             FROM ips i LEFT JOIN ports p ON p.ip_id = i.ip_id \
             LEFT JOIN scaninfo si ON si.port_id = p.port_id WHERE i.task_id = $1;",
            &[&task_pk],
        )
        .await
    {
        Ok(summary) => summary,
        Err(error) => {
            error_logs(&req, "GetTaskSummaryError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let ip_rows = match connection
        .query(
            "SELECT ip_id, ip_address::text AS ip, asn, isp FROM ips \
             WHERE task_id = $1 ORDER BY ip_address LIMIT $2 OFFSET $3;",
            &[&task_pk, &page_size, &offset],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            error_logs(&req, "GetTaskResultsError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let ip_ids: Vec<i32> = ip_rows.iter().map(|row| row.get("ip_id")).collect();
    let mut ports_by_ip: HashMap<i32, Vec<TaskResultPort>> = HashMap::new();
    if !ip_ids.is_empty() {
        let port_rows = match connection
            .query(
                "SELECT p.ip_id, p.port, latest.protocol, latest.service, latest.banner, \
                 latest.other, latest.scan_time FROM ports p \
                 LEFT JOIN LATERAL (SELECT protocol, service, banner, other, scan_time \
                    FROM scaninfo WHERE port_id = p.port_id ORDER BY scan_time DESC LIMIT 1) latest ON true \
                 WHERE p.ip_id = ANY($1) ORDER BY p.ip_id, p.port;",
                &[&ip_ids],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                error_logs(&req, "GetTaskPortsError", &error.to_string());
                return HttpResponse::InternalServerError().finish();
            }
        };
        for row in port_rows {
            ports_by_ip
                .entry(row.get("ip_id"))
                .or_default()
                .push(TaskResultPort {
                    port: row.get("port"),
                    protocol: row.get("protocol"),
                    service: row.get("service"),
                    banner: row.get("banner"),
                    other: row.get("other"),
                    scan_time: row.get("scan_time"),
                });
        }
    }
    let results: Vec<TaskResultIp> = ip_rows
        .into_iter()
        .map(|row| {
            let ip_id: i32 = row.get("ip_id");
            TaskResultIp {
                ip: row.get("ip"),
                asn: row.get("asn"),
                isp: row.get("isp"),
                ports: ports_by_ip.remove(&ip_id).unwrap_or_default(),
            }
        })
        .collect();
    let ip_count: i64 = summary.get("ip_count");
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "task_id": task.get::<_, String>("task_id"),
            "task_target": task.get::<_, Vec<String>>("task_target"),
            "task_port": task.get::<_, String>("task_port"),
            "task_initiator": task.get::<_, String>("task_initiator"),
            "task_level": task.get::<_, i32>("task_level"),
            "task_create_time": task.get::<_, i64>("task_create_time"),
            "task_start_time": task.get::<_, Option<i64>>("task_start_time"),
            "task_end_time": task.get::<_, Option<i64>>("task_end_time"),
            "task_status": task.get::<_, String>("task_status"),
            "scanner_id": task.get::<_, Option<String>>("assigned_scanner_id"),
            "scanner_name": task.get::<_, Option<String>>("scanner_name"),
            "lease_expires_at": task.get::<_, Option<i64>>("lease_expires_at"),
            "attempt_count": task.get::<_, i32>("attempt_count"),
            "failure_reason": task.get::<_, Option<String>>("failure_reason"),
            "cancel_requested": task.get::<_, bool>("cancel_requested"),
            "retry_of_task_id": task.get::<_, Option<String>>("retry_of_task_id"),
            "remarks": task.get::<_, Option<String>>("remarks"),
            "summary": {
                "ip_count": ip_count,
                "port_count": summary.get::<_, i64>("port_count"),
                "result_count": summary.get::<_, i64>("result_count"),
            },
            "results": results,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": ip_count,
                "total_pages": if ip_count == 0 { 1 } else { (ip_count + page_size - 1) / page_size },
            }
        }
    }))
}

#[post("/api/task/create")]
async fn create_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    create_data: web::Json<CreateTask>,
    page_template: web::Data<TemplatesInit>,
    user_base_i: UserBaseI,
) -> impl Responder {
    match create_data.level {
        0..5 => (),
        _ => {
            info_logs(
                &req,
                "InvalidParams",
                format!("任务优先级level不符合要求{}", create_data.level).as_str(),
            );
            return HttpResponse::BadRequest().body("400 Bad Request");
        }
    }

    let database_conn = pool.get_ref();
    let user_id = user_base_i.id;
    let user_name = user_base_i.username;

    let task_info = STask::new(
        TargetIP::S(&create_data.ip),
        &user_name,
        Some(&create_data.port),
        create_data.remark.as_deref(),
    );

    match task_info {
        Ok(o) => {
            if let Err(e) = o
                .add(database_conn, create_data.level as i32, user_id)
                .await
            {
                error_logs(&req, "AddTaskError", e.to_string().as_str());
                return HttpResponse::InternalServerError().body("500");
            }
            return HttpResponse::Ok()
                .content_type(TEXT_HTML_UTF_8)
                .body("创建成功");
        }
        Err(e) => {
            error_logs(&req, "STASK-ERROR", &e.to_string());
            return render_500(&req, &page_template, &e.to_string());
        }
    }
}

/// 用于扫描器申请一个扫描目标
#[get("/api/task/apply")]
async fn apply_task_handler(
    req: HttpRequest,
    scanner_id: web::Query<ApplyTaskQuery>,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
) -> impl Responder {
    let database_conn = pool.get_ref();
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(token) = token else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };

    if scanner_id.dryrun.unwrap_or(false) {
        return match validate_scanner_credentials(
            database_conn,
            scanner_id.scannerid,
            token,
            &security.scanner_token_pepper,
        )
        .await
        {
            Ok(()) => HttpResponse::Ok().finish(),
            Err(ApplyTaskError::ScannerUnauthorized) => {
                HttpResponse::Unauthorized().body("unauthorized")
            }
            Err(ApplyTaskError::NoTask) => HttpResponse::NotFound().finish(),
            Err(ApplyTaskError::Database(e)) => {
                error_logs(&req, "ScannerCredentialCheckError", &e.to_string());
                HttpResponse::InternalServerError().finish()
            }
        };
    }

    match apply_task(
        database_conn,
        scanner_id.scannerid,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(a_t) => HttpResponse::Ok().json(a_t),
        Err(ApplyTaskError::ScannerUnauthorized) => {
            HttpResponse::Unauthorized().body("unauthorized")
        }
        Err(ApplyTaskError::NoTask) => HttpResponse::NotFound()
            .content_type(TEXT_HTML_UTF_8)
            .body("没有可领取的任务"),
        Err(ApplyTaskError::Database(e)) => {
            error_logs(&req, "ApplyTaskError", &e.to_string());
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 用于扫描器上传扫描结果。
#[post("/api/scanner/result")]
async fn upload_scanner_result_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    maxmind: web::Data<MaxMindState>,
    security: web::Data<SecurityConfig>,
    upload_data: web::Json<ScannerResultUpload>,
) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(token) = token else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };

    match save_scanner_results(
        pool.get_ref(),
        maxmind.get_ref(),
        &upload_data,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(saved) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "saved": saved,
        })),
        Err(e) => {
            error_logs(&req, "SaveScannerResultError", &e.to_string());
            match e {
                SaveScannerResultsError::InvalidIp { .. } => {
                    HttpResponse::BadRequest().body("invalid ip")
                }
                SaveScannerResultsError::ScannerUnauthorized => {
                    HttpResponse::Unauthorized().body("unauthorized")
                }
                SaveScannerResultsError::TaskNotFound => {
                    HttpResponse::NotFound().body("task not found")
                }
                SaveScannerResultsError::TaskNotOwned => {
                    HttpResponse::Conflict().body("task is not owned by scanner")
                }
                SaveScannerResultsError::Database(_) => {
                    HttpResponse::InternalServerError().body("500")
                }
            }
        }
    }
}

/// 获取所有任务接口
///
/// 分为管理员权限和普通用户权限
#[get("/api/task/all")]
async fn get_all_task_handler(
    _req: HttpRequest,
    query_info: web::Query<ReceiveTaskItemQueryInfo>,
    pool: web::Data<Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let p = pool.get_ref();

    let user_id = user_base_i.id;
    let user_role = user_base_i.role;

    let permi = match user_role {
        1 => Permission::Administrator(user_id),
        2 => Permission::Users(user_id),
        _ => {
            error!(
                event = "UserRoleValueInvalid",
                path = "fn get_all_task_handler",
                message = format!("用户角色值为：{}", user_role)
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let (tmp_result, total_count, item_count, start_index) =
        match get_task_item(p, query_info.count.unwrap_or(5), query_info.start, permi).await {
            Ok(o) => o,
            Err(e) => {
                error!(
                    event = "GetTaskError",
                    path = "fn get_all_task_handler",
                    message = %e
                );
                return HttpResponse::InternalServerError().body("500");
            }
        };

    let tmp_json = TaskItemJson {
        total_c: total_count,
        item_c: item_count,
        start_id: start_index,
        task_item: tmp_result,
    };

    HttpResponse::Ok().json(tmp_json)
}

#[cfg(test)]
mod tests {
    use super::task_result_pagination;

    #[test]
    fn task_result_pagination_uses_safe_bounds() {
        assert_eq!(task_result_pagination(None, None), (1, 20, 0));
        assert_eq!(task_result_pagination(Some(-5), Some(0)), (1, 1, 0));
        assert_eq!(task_result_pagination(Some(3), Some(500)), (3, 100, 200));
    }
}
