use std::sync::{Arc, Mutex};

use actix_web::{web, get, post, Responder, HttpRequest, HttpResponse};
use crate::{front_end_error_page, FrontEndErrorInfo, TemplatesInit, logs};
use crate::{TEXT_HTML_UTF_8, APPLICATION_JSON};
use crate::{SystemResource};
use sysinfo;
use crate::{Systems, login::{LoginToken}};
use crate::config::DatabaseConfig;

use std::fs;
use tracing::{error, warn, info};
// #[get("/api/data/saa/")]
// async fn get_saa_data(req: HttpRequest, conn: ConnectionInfo) -> impl Responder {

// }


#[get("/api/data/system-data/")]
async fn get_system_data(
    req: HttpRequest, 
    page_template: web::Data<TemplatesInit>,
    sys: web::Data<Systems>,
    pool: web::Data<deadpool_postgres::Pool>,
    db_config: web::Data<DatabaseConfig>
) -> impl Responder {

    // 定义 403 错误页面的闭包，接受一个 &str 类型的参数，该参数用于写入日志
    // let render_403 = | message | {
    //     logs::write::warn_logs(&req, "SessionAuthFailed", message);
    //     let error_info = FrontEndErrorInfo { status_code: 403, error_title: "Forbidden", error_message: "您已被屏蔽" };
    //     HttpResponse::Forbidden()
    //         .content_type(TEXT_HTML_UTF_8)
    //         .body(front_end_error_page(&error_info, &page_template))
    // };

    // let tmp_c = &req.cookie("session");
    // let session = match tmp_c {
    //     Some(s) => s,
    //     None => return render_403("没有获取到 Session")
    // };

    // // 检查获取到的 session 是否有效
    // let session_value = session.value();
    // let token = LoginToken {pool: pool.get_ref().clone()};
    // match token.check_token(session_value).await {
    //     Ok(true) => (),
    //     Ok(false) => {
    //         return render_403("数据库中未找到符合条件的 Session")
    //     },
    //     Err(e) => {
    //         let error_m = e.to_string();
    //         return render_403(&error_m)
    //     }
    // };

    let sys = sys.get_ref().clone();
    let pool = pool.get_ref().clone();
    // let mut sys = sys.lock().unwrap();
    // sys.refresh_all();
    let db_name = db_config.db_name.clone();
    let s = SystemResource::new(sys, pool, db_name).await;
    HttpResponse::Ok().json(s)
}

#[get("/dashboard")]
async fn render_dashboard_page(
    req: HttpRequest
) -> impl Responder {
    match fs::read_to_string("./frontend/dashboard/index.html") {
        Ok(f) => {
            HttpResponse::Ok()
                .content_type(TEXT_HTML_UTF_8)
                .body(f)
        },
        Err(e) => {
            error!(
                event = "ReadFileError",
                path = "",
                message = %e
            );
            HttpResponse::NotFound()
                .content_type(TEXT_HTML_UTF_8)
                .body("")
        }
    }
}