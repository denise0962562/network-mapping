use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use uuid::Uuid;
use deadpool_postgres::{Pool};
use tracing::error;
use crate::logs::write::{error_logs, info_logs};
use crate::{TemplatesInit, TEXT_HTML_UTF_8, Permission};
use crate::{CreateTask, STask, TargetIP, apply_task, ApplyTaskQuery, get_task_item, TaskItemJson, ReceiveTaskItemQueryInfo};
use crate::middlewares::{render_500};
use crate::admin::{UserBaseI};

/// TODO 让我想想这个接口是干啥的
#[get("/api/task/{task_id}")]
async fn get_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    task_id: web::Path<Uuid>,
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
                    return HttpResponse::InternalServerError().finish()
                }
            }
        },
        Err(e) =>{
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
            info_logs(&req, "InvalidParams", format!("任务优先级level不符合要求{}",create_data.level).as_str());
            return HttpResponse::BadRequest()
                .body("400 Bad Request")
        }
    }

    let database_conn = pool.get_ref();
    let user_id = user_base_i.id;
    let user_name = user_base_i.username;

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
            return HttpResponse::InternalServerError().finish()
        }
    };

    let (tmp_result, total_count, item_count, start_index) = match get_task_item(
        p, 
        query_info.count.unwrap_or(5), 
        query_info.start,
        permi
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