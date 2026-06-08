
use actix_web::{web, get, post, HttpRequest, HttpResponse, Responder, dev::ConnectionInfo};
use tracing::error;
use lettre::{Message, message::Mailbox, message::header::ContentType};

use crate::admin::{get_config_from_database, get_user_id_and_name, get_user_info, send_email};
use crate::{target_generated::{ScanTargetGetResponse, targetgenerated::random_generate_target}};
use crate::{TEXT_HTML_UTF_8};
use crate::{logs::write::{error_logs, info_logs}, FrontEndErrorInfo, front_end_error_page, TemplatesInit};
use crate::rir::get_rir_data;
use crate::config::{GetConfig, EmailConfig};
use crate::login::{get_session_from_req};

//基准测试
use crate::{Systems, benchmark};


#[get("/scanner/target")]
async fn get_scan_target(
    _req: HttpRequest, 
    _conn_info: ConnectionInfo, 
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
    random_generate_target()
}


//TAG 即将弃用
//静态文件路由
// #[get("/staticfile/{filename:.*}")]
// async fn static_file_system(req: HttpRequest, _conn_info: ConnectionInfo, file_path: web::Path<String>, page_template: web::Data<TemplatesInit>) -> impl Responder {
//     // mark 过一段时间看是用actix files还是自己的
//     let relative_path = file_path.into_inner();
//     println!("{relative_path}");

//     let base_path = "staticfile";
//     println!("{base_path}");
//     let full_path = PathBuf::from(base_path).join(&relative_path);
//     let file_suffix = match get_file_suffix(&full_path) {
//         Ok(ov) => ov,
//         Err(ev) => ev,
//     };
//     let f_mime = mime_system(file_suffix);

//     if !full_path.starts_with(base_path) {

//         warn_logs(&req, "AttackRequests", "非法的路径访问");

//         let error_info = FrontEndErrorInfo{ status_code: 403, error_title: "Forbidden", error_message: "因您的请求包含非法路径，所以服务器拒绝了您的请求！"};
//         let body = front_end_error_page(&error_info, &page_template);
//         return HttpResponse::Forbidden()
//             .content_type(TEXT_HTML_UTF_8)
//             .body(body)
//     }

//     match fs::read_to_string(&full_path) {
//         Ok(file_content) => HttpResponse::Ok().content_type(f_mime).body(file_content),
//         Err(_) => {
//             let error_info = FrontEndErrorInfo{status_code: 404, error_title: "File NotFound", error_message: "File NotFound!"};
//             let body = front_end_error_page(&error_info, &page_template);
//             HttpResponse::NotFound().content_type(TEXT_HTML_UTF_8).body(body)
//         }
//     }
// }

use crate::config::DatabaseConfig;

///获取系统信息基准测试
#[get("/benchmark")]
async fn benchmark_route(sys: web::Data<Systems>, pool: web::Data<&deadpool_postgres::Pool>, db_config: web::Data<DatabaseConfig>) -> impl Responder {
    benchmark(sys, pool, db_config.db_name.clone()).await;
    "Benchmark finished, check server logs."
}

pub async fn not_found(
    page_template: web::Data<TemplatesInit>
) -> impl Responder {
    let error_info = FrontEndErrorInfo {
        status_code: 404,
        error_title: "NotFound",
        error_message: "没有找到对应的资源"
    };
    HttpResponse::NotFound()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, &page_template))
}


/// 用于启动加载 RIR 数据
#[get("/api/updaterir")]
async fn update_rir(
    pool: web::Data<deadpool_postgres::Pool>
) -> impl  Responder {
    let c = pool.get_ref();
    get_rir_data(c, "/home/wsj/project/RIR-DATA").await;
    HttpResponse::Ok()
        .body("成功")
}


/// 获取配置
/// 
#[get("/api/config/get")]
async fn get_config_h(
    _req: HttpRequest,
    conf_q: web::Query<GetConfig>,
    pool: web::Data<deadpool_postgres::Pool>
) -> impl Responder {
    let pool_ref = pool.get_ref();

    let con = match get_config_from_database(pool_ref, &conf_q.item_type, conf_q.key.as_deref()).await {
        Ok(o) => o,
        Err(e) => {
            error!(
                event = "GetConfigError",
                path = "fn get_config_h",
                message = e.to_string()
            );
            return HttpResponse::InternalServerError().finish()
        }
    };
    HttpResponse::Ok().json(con)
}


/// 测试 SMTP 邮件服务器
/// 
/// 如果接口调用者没有传递参数，那么直接使用数据库中所存储的数据测试
#[post("/api/mail/smtp/test")]
async fn test_mail_server_h(
    req: HttpRequest,
    test_data: Option<web::Json<EmailConfig>>,
    mail_config: web::Data<Option<EmailConfig>>,
    pool: web::Data<deadpool_postgres::Pool>
) -> impl Responder {
    let pool_ref = pool.get_ref();

    if let Some(session) = get_session_from_req(&req, "session") {

        let (_id, u_role, username) = match get_user_id_and_name(&session, pool_ref).await {
            Ok(o) => o,
            Err(e) => {
                error_logs(&req, "GetUserIdandNameError", &e.to_string());
                return HttpResponse::InternalServerError().finish();
            }
        };

        if u_role != 1 {
            info_logs(&req, "UserPermissionDenied", "用户权限不足，操作请求已被拒绝。", false);
            return HttpResponse::Forbidden().finish()
        }

        let info = match get_user_info(u_role, Some(&username), Some(1), pool_ref).await {

            // 为 UserInfo 实现了 Default ，然后使用 unwrap_or_default() 函数使用默认值
            Ok(o) => o.into_iter().next().unwrap_or_default(),
            Err(e) => {
                error!(
                    event = "GetUserInfoError",
                    path = "fn test_mail_server_h",
                    message = e.to_string()
                );
                return HttpResponse::InternalServerError().finish()
            }
        };

        let user_mail = info.email.unwrap_or(String::new());

        let mail_context = String::from("这是一封测试邮件，用于测试您设置的邮件服务器是否正常工作。如果您没有发送测试邮件请忽略此封邮件。");
        let mail_title = String::from("Test");
        let mail_account_name = Some(String::from("Network Mapping"));

        let mail_config = match test_data.as_deref() {
            Some(td) => td,
            None => {
                match mail_config.as_ref() {
                    Some(e) => e,
                    None => {
                        return HttpResponse::Ok()
                            .content_type(TEXT_HTML_UTF_8)
                            .body("未从数据库中找到相关配置")
                    }
                }
            }
        };

        let mail_message = Message::builder()
            .from(Mailbox::new(mail_account_name, (mail_config.account_username).to_string().parse().unwrap()))
            .to(Mailbox::new(None, user_mail.parse().unwrap()))
            .subject(mail_title)
            .header(ContentType::TEXT_PLAIN)
            .body(mail_context)
            .unwrap();
        send_email(mail_config, mail_message).await;
        HttpResponse::Ok().finish()

    }
    else {
        HttpResponse::Unauthorized().finish()
    }
}