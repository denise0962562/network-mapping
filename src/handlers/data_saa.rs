use actix_web::{web, get, Responder, HttpRequest, HttpResponse};
use tracing::{error};

use crate::{ReceiveSystemStatusInfo};
use crate::{SystemStatusJson, get_system_status_info};


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