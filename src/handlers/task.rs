use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use uuid::Uuid;
use deadpool_postgres::{Pool};
use tracing::error;
use crate::logs::write::{error_logs, info_logs};
use crate::{FrontEndErrorInfo, front_end_error_page, TemplatesInit, TEXT_HTML_UTF_8};
use crate::{CreateTask, STask, TargetIP, apply_task, ApplyTaskQuery, get_task_item, TaskItemJson, ReceiveTaskItemQueryInfo};
use crate::middlewares::{render_403, render_500};
use crate::admin::get_user_id_and_name;

#[get("/api/task/{task_id}")]
async fn get_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    task_id: web::Path<Uuid>,
    page_template: web::Data<TemplatesInit>
) -> impl Responder {
    let c = pool.get_ref().get().await;

    match &c {
        Ok(o) =>{
            let rows = o.query_one("SELECT * FROM scan_task WHERE task_id = $1", &[&task_id.to_string()]).await;
            match rows {
                Ok(row) =>{
                    let r: String = row.get("");
                    return HttpResponse::Ok().body(r)
                },
                Err(e) =>{
                    error_logs(&req, "DATABASE-QUERY-ERROR", e.to_string().as_str());
                    return HttpResponse::InternalServerError().content_type(TEXT_HTML_UTF_8).body("ERROR")
                }
            }
        },
        Err(e) =>{
            error_logs(&req, "DATABASE-ERROR", &(e.to_string()));
            let info = FrontEndErrorInfo{
                status_code: 500,
                error_title: "Internal Server Error",
                error_message: "内部服务器错误"
            };
            let body = front_end_error_page(&info, &page_template);
            return HttpResponse::InternalServerError()
                .content_type(TEXT_HTML_UTF_8)
                .body(body)
        }
    }
}

#[post("/api/task/create")]
async fn create_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    create_data: web::Json<CreateTask>,
    page_template: web::Data<TemplatesInit>
) -> impl Responder {

    match create_data.level {
        0..5 => (),
        _ => {
            info_logs(&req, "InvalidParams", format!("任务优先级level不符合要求{}",create_data.level).as_str(), false);
            return HttpResponse::BadRequest()
                .body("400 Bad Request")
        }
    }

    let session_option = &req.cookie("session");
    let session_str = match session_option {
        Some(s) => s.value(),
        None => ""
    };

    let database_conn = pool.get_ref();

    let (user_id, user_name) = match get_user_id_and_name(session_str, database_conn).await {
        Ok(o) => o,
        Err(e) => {
            error_logs(&req, "SEARCH-USER-ERROR", &e.to_string());
            return render_403(&req, &page_template, "未找到相关的用户 id")
        }
    };

    let task_info = STask::new(TargetIP::S(&create_data.ip), &user_name,Some(&create_data.port), create_data.remark.as_deref());
    
    match task_info {
        Ok(o) => {
            if let Err(e) = o.add(database_conn, create_data.level as i32, user_id).await {
                error_logs(&req, "AddTaskError", e.to_string().as_str());
                return HttpResponse::InternalServerError()
                    .body("500")
            }
            return HttpResponse::Ok()
                .content_type(TEXT_HTML_UTF_8)
                .body("创建成功")
                
        },
        Err(e) => {
            error_logs(&req, "STASK-ERROR", &e.to_string());
            return render_500(&req, &page_template, &e.to_string())
        }
    }
}

/// 用于扫描器申请一个扫描目标
#[get("/api/task/apply")]
async fn apply_task_handler(
    _req: HttpRequest,
    scanner_id: web::Query<ApplyTaskQuery>,
    pool: web::Data<Pool>
) -> impl Responder {
    let database_conn = pool.get_ref();
    let task_data = apply_task(database_conn, scanner_id).await;

    if task_data.is_ok() {
        task_data.map(|a_t| {
            HttpResponse::Ok()
                .json(a_t)
        }).unwrap()
    }
    else {
        HttpResponse::NotFound()
            .content_type(TEXT_HTML_UTF_8)
            .body("没有找到或内部错误")
    }
    
}

#[get("/api/task/all")]
async fn get_all_task_handler(
    req: HttpRequest,
    query_info: web::Query<ReceiveTaskItemQueryInfo>,
    pool: web::Data<Pool>
) -> impl Responder {
    let p = pool.get_ref();
    let t_session = match &req.cookie("session") {
        Some(c) => c.value().to_string(),
        None => String::new()
    };
    let client = match p.get().await {
        Ok(o) => o,
        Err(e) => {
            error!(
                event = "GetPoolError",
                path = "fn get_all_task_handler",
                message = %e
            );
            return HttpResponse::InternalServerError()
                .body("500")
        }
    };

    let user_id = match client.query_opt(
        "SELECT user_id FROM session WHERE token = $1 LIMIT 1;",
        &[&t_session]
    ).await {
        Ok(Some(o)) => {
            o.get::<_, i32>("user_id") 
        },
        Ok(None) => {
            info_logs(&req, "NotFoundSession", "获取用户ID失败", false);
            return HttpResponse::Unauthorized()
                .body("401")
        }
        Err(e) => {
            error_logs(&req, "SELECTError", e.to_string().as_str());
            return HttpResponse::InternalServerError()
                .body("500")
        }
    };


    let (tmp_result, total_count, item_count, start_index) = match get_task_item(
        p, 
        query_info.count.unwrap_or(5), 
        query_info.start,
        crate::Permission::Administrator(user_id)
    ).await {
        Ok(o) => o,
        Err(e) => {
            error!(
                event = "GetTaskError",
                path = "fn get_all_task_handler",
                message = %e
            );
            return HttpResponse::InternalServerError()
                .body("500")
        }
    };

    let tmp_json = TaskItemJson {
        total_c: total_count,
        item_c: item_count,
        start_id: start_index,
        task_item: tmp_result
    };

    HttpResponse::Ok()
        .json(tmp_json)
}