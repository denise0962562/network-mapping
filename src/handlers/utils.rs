
use actix_web::{web, get, HttpRequest, HttpResponse, Responder, dev::ConnectionInfo};
// use crate::handlers::{ScanTargetDone, ScanTargetGet};
use crate::target_generated::{ScanTargetGetResponse, targetgenerated::{random_generate_target, sequence_generate_target}};
use crate::{TEXT_HTML_UTF_8};
use std::{path::PathBuf, fs};
use crate::{logs, ReadFile, get_file_suffix, mime_system, FrontEndErrorInfo, front_end_error_page, TemplatesInit};

//基准测试
use crate::{Systems, benchmark};


#[get("/scanner/get_target")]
async fn get_scan_target(
    req: HttpRequest, 
    conn_info: ConnectionInfo, 
    // get_target: web::Query<ScanTargetGet>, 
    // target_generated: web::Data<ScanTargetConfig>
) -> web::Json<ScanTargetGetResponse> {

    // let mut rng = rand::rng();
    
    // println!("扫描器ID: {}, a = {}", get_target.scanner_id, get_target.test);
    // let port_list = vec![80, 5000];
    // web::Json(
    //     ScanTargetGetResponse{
    //         mode: format!("SCAN"),
    //         ip: format!("{}.{}.{}.1", rng.random_range(1..=255), rng.random_range(0..=255), rng.random_range(0..=255)),
    //         port: rust_web_test::target_generated::port_type::Vertor(port_list),
    //         rate: 1000
    //     }
    // )
    logs::write::info_logs(&req, "ReceivedRequests", "GenerateTarget", false);
    random_generate_target()
}

#[get("/")]
///# 即将弃用
async fn file_read_test(req: HttpRequest, conn_info: ConnectionInfo, file: web::Data<ReadFile>) -> impl Responder {
    //tag 过一段时间弃用该函数
    let read_file_name = &file.file_name;
    let _file_root = &file.file_root_directory;
    match fs::read_to_string(read_file_name) {
        Ok(file_content) => {
            logs::write::info_logs(&req, "ReceivedRequests", "ReceivedRequests", false);
            HttpResponse::Ok().content_type(TEXT_HTML_UTF_8).body(file_content)
        },
        Err(_) => {
            logs::write::warn_logs(&req, "ReceivedRequests", "FileNotFound");
            HttpResponse::NotFound().body("File_NotFound!")
        },
    }
}


//TAG 即将弃用
//静态文件路由
#[get("/staticfile/{filename:.*}")]
async fn static_file_system(req: HttpRequest, conn_info: ConnectionInfo, file_path: web::Path<String>, page_template: web::Data<TemplatesInit>) -> impl Responder {
    // mark 过一段时间看是用actix files还是自己的
    let relative_path = file_path.into_inner();
    println!("{relative_path}");

    let base_path = "staticfile";
    println!("{base_path}");
    let full_path = PathBuf::from(base_path).join(&relative_path);
    let file_suffix = match get_file_suffix(&full_path) {
        Ok(ov) => ov,
        Err(ev) => ev,
    };
    let f_mime = mime_system(file_suffix);

    if !full_path.starts_with(base_path) {

        logs::write::warn_logs(&req, "AttackRequests", "非法的路径访问");

        let error_info = FrontEndErrorInfo{ status_code: 403, error_title: "Forbidden", error_message: "因您的请求包含非法路径，所以服务器拒绝了您的请求！"};
        let body = front_end_error_page(&error_info, &page_template);
        return HttpResponse::Forbidden()
            .content_type(TEXT_HTML_UTF_8)
            .body(body)
    }

    match fs::read_to_string(&full_path) {
        Ok(file_content) => HttpResponse::Ok().content_type(f_mime).body(file_content),
        Err(_) => {
            let error_info = FrontEndErrorInfo{status_code: 404, error_title: "File NotFound", error_message: "File NotFound!"};
            let body = front_end_error_page(&error_info, &page_template);
            HttpResponse::NotFound().content_type(TEXT_HTML_UTF_8).body(body)
        }
    }
}

use crate::config::DatabaseConfig;

///获取系统信息基准测试
#[get("/benchmark")]
async fn benchmark_route(sys: web::Data<Systems>, pool: web::Data<deadpool_postgres::Pool>, db_config: web::Data<DatabaseConfig>) -> impl Responder {
    benchmark(sys, pool, db_config.db_name.clone()).await;
    "Benchmark finished, check server logs."
}