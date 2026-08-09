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
use tracing::error;
use uuid::Uuid;

/// TODO 让我想想这个接口是干啥的
#[get("/api/task/{task_id}")]
async fn get_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    task_id: web::Path<Uuid>,
) -> impl Responder {
    let c = pool.get_ref().get().await;

    match &c {
        Ok(o) => {
            let rows = o
                .query_one(
                    "SELECT * FROM scan_task WHERE task_id = $1",
                    &[&task_id.to_string()],
                )
                .await;
            match rows {
                Ok(row) => {
                    let r: String = row.get("");
                    return HttpResponse::Ok().body(r);
                }
                Err(e) => {
                    error_logs(&req, "DATABASE-QUERY-ERROR", e.to_string().as_str());
                    return HttpResponse::InternalServerError().finish();
                }
            }
        }
        Err(e) => {
            error_logs(&req, "DATABASE-ERROR", &(e.to_string()));
            HttpResponse::InternalServerError().finish()
        }
    }
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
