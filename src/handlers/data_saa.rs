use actix_web::{web, get, Responder, HttpRequest, HttpResponse};
use crate::{ReceiveSystemStatusInfo, TEXT_HTML_UTF_8};
use crate::{SystemStatusJson, get_system_status_info};
use std::fs;
use tracing::{error};
// #[get("/api/data/saa/")]
// async fn get_saa_data(req: HttpRequest, conn: ConnectionInfo) -> impl Responder {

// }


#[get("/api/data/system-data")]
async fn get_system_data_handler(
    _req: HttpRequest, 
    query_info: web::Query<ReceiveSystemStatusInfo>,
    pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    let p = pool.get_ref();

    let (t, c) = match get_system_status_info(query_info.start_at, query_info.end_at, query_info.count.unwrap_or(1), p).await {
        Ok(o) => o,
        Err(e) => {
            error!(
                event = "GetSystemStatusError",
                path = "fn get_system_data_handler",
                message = %e
            );
            return HttpResponse::InternalServerError()
                .body("500 Internal Serve rError")
        }
    };

    let t_json = SystemStatusJson {
        total_c: c,
        status_item: t
    };

    HttpResponse::Ok().json(t_json)
}

#[get("/dashboard")]
async fn render_dashboard_page(
    _req: HttpRequest
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