use std::sync::{Arc, Mutex};

use actix_web::{web, get, post, Responder, dev::ConnectionInfo, HttpRequest, HttpResponse};
use crate::{front_end_error_page, FrontEndErrorInfo, TemplatesInit, logs};
use crate::{TEXT_HTML_UTF_8, APPLICATION_JSON};
use crate::{SystemResource, SystemCPU, SystemRAM, SystemDisk, };
use sysinfo;
use crate::get_unix_epoch_ms;
use crate::Systems;

// #[get("/api/data/saa/")]
// async fn get_saa_data(req: HttpRequest, conn: ConnectionInfo) -> impl Responder {

// }

// pub struct Receive{
//     data
// }

// #[get("/api/data/system-data/")]
// async fn get_system_data(
//     req: HttpRequest, 
//     conn_info: ConnectionInfo,
//     pool: deadpool_postgres::Pool,
//     // datainfo: web::Query<>
//     page_template: web::Data<TemplatesInit>,
//     sys_info: &Systems
// ) -> impl Responder {
//     let mut client = pool.get().await;
//     match client {
//         Ok(p) => {


//         },
//         Err(e) => {
//             let message = format!("无法从连接池中拿到连接 {}", e);
//             logs::write::error_logs(&req, &conn_info, "SYSTEMERROR", &message);
//             HttpResponse::InternalServerError()
//                 .content_type(TEXT_HTML_UTF_8)
//                 .body("error")
//         }
//     }
// }


use crate::config::DatabaseConfig;

#[get("/api/data/system-data/")]
async fn get_system_data(
    req: HttpRequest, 
    conn_info: ConnectionInfo,
    // datainfo: web::Query<>
    page_template: web::Data<TemplatesInit>,
    // sys_info: web::Data<Arc<Mutex<sysinfo::System>>>
    sys: web::Data<Systems>,
    pool: web::Data<deadpool_postgres::Pool>,
    db_config: web::Data<DatabaseConfig>
) -> impl Responder {
    let start_t = get_unix_epoch_ms();
    let sys = sys.get_ref().clone();
    let pool = pool.get_ref().clone();
    // let mut sys = sys.lock().unwrap();
    // sys.refresh_all();
    let db_name = db_config.db_name.clone();
    let s = SystemResource::new(sys, pool, db_name).await;

    let result = get_unix_epoch_ms() - start_t;
    println!("所耗时间{}", result);
    HttpResponse::Ok().json(s)
}