use actix_web::rt::task;
use actix_web::{HttpRequest, HttpResponse, Responder, body, get, post, web, http::header};
use uuid::Uuid;
use deadpool_postgres::{Manager, Pool, Object};
use crate::logs::write::{info_logs, warn_logs, error_logs};
use crate::{FrontEndErrorInfo, front_end_error_page, TemplatesInit, TEXT_HTML_UTF_8, APPLICATION_JSON};
use crate::{CreateTask, STask, TargetIP, TargetPort, apply_task, ApplyTask, ApplyTaskQuery};
use crate::smiddleware::{render_403, render_500};
use crate::admin::get_user_id;

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
    let p = pool.get().await;
    let user_id:i32;
    let session_str:String;
    let t_cookie = req.cookie("session");
    
    //t_cookie.map(|c| session_str = c.value());


    match t_cookie {
        Some(t_session) => {
            session_str = t_session.value().to_string();
        },
        None => {
            return HttpResponse::MovedPermanently()
                .insert_header((header::LOCATION, "/login"))
                .finish()
        }
    };


    let task_info = STask::new(TargetIP::S(&create_data.ip), "admin", Some(&create_data.port), create_data.remark.as_deref());

    user_id = match get_user_id(&session_str, &pool).await {
        Ok(o) => o,
        Err(e) => {
            error_logs(&req, "SEARCH-USER-ERROR", &e.to_string());
            return render_403(&req, &page_template, "未找到相关的用户 id")
        }
    };
    
    match task_info {
        Ok(o) => {
            o.add(pool, user_id).await.map_err(|e| render_500(&req, &page_template, &e.to_string()));
            return HttpResponse::Ok().finish()
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
    req: HttpRequest,
    scanner_id: web::Query<ApplyTaskQuery>,
    pool: web::Data<Pool>
) -> impl Responder {
    let task_data = apply_task(pool, scanner_id).await;

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
