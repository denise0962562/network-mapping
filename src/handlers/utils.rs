use actix_web::{HttpRequest, HttpResponse, Responder, dev::ConnectionInfo, get, post, web};
use lettre::{Message, message::Mailbox, message::header::ContentType};
use tracing::error;

use crate::TEXT_HTML_UTF_8;
use crate::admin::{UserBaseI, get_config_from_database, get_user_info, send_email};
use crate::config::{DatabaseConfig, EmailConfig, GetConfig};
use crate::target_generated::{ScanTargetGetResponse, targetgenerated::random_generate_target};
use crate::{FrontEndErrorInfo, TemplatesInit, front_end_error_page, logs::write::info_logs};

#[cfg(feature = "rir")]
use crate::rir::get_rir_data;

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

///获取系统信息基准测试
#[get("/benchmark")]
async fn benchmark_route(
    sys: web::Data<Systems>,
    pool: web::Data<&deadpool_postgres::Pool>,
    db_config: web::Data<DatabaseConfig>,
) -> impl Responder {
    benchmark(sys, pool, db_config.db_name.clone()).await;
    "Benchmark finished, check server logs."
}

pub async fn not_found(page_template: web::Data<TemplatesInit>) -> impl Responder {
    let error_info = FrontEndErrorInfo {
        status_code: 404,
        error_title: "NotFound",
        error_message: "没有找到对应的资源",
    };
    HttpResponse::NotFound()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, &page_template))
}

/// 用于启动加载 RIR 数据
#[cfg(feature = "rir")]
#[get("/api/updaterir")]
async fn update_rir(pool: web::Data<deadpool_postgres::Pool>) -> impl Responder {
    let c = pool.get_ref();
    get_rir_data(c, "/home/wsj/project/RIR-DATA").await;
    HttpResponse::Ok().body("成功")
}

/// 获取配置
///
#[get("/api/config/get")]
async fn get_config_h(
    _req: HttpRequest,
    conf_q: web::Query<GetConfig>,
    pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    let pool_ref = pool.get_ref();

    let con =
        match get_config_from_database(pool_ref, &conf_q.item_type, conf_q.key.as_deref()).await {
            Ok(o) => o,
            Err(e) => {
                error!(
                    event = "GetConfigError",
                    path = "fn get_config_h",
                    message = e.to_string()
                );
                return HttpResponse::InternalServerError().finish();
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
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let pool_ref = pool.get_ref();
    let u_role = user_base_i.role;
    let username = user_base_i.username;

    if u_role != 1 {
        info_logs(
            &req,
            "UserPermissionDenied",
            "用户权限不足，操作请求已被拒绝。",
        );
        return HttpResponse::Forbidden().finish();
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
            return HttpResponse::InternalServerError().finish();
        }
    };

    let user_mail = info.email.unwrap_or(String::new());

    let mail_context = String::from(
        "这是一封测试邮件，用于测试您设置的邮件服务器是否正常工作。如果您没有发送测试邮件请忽略此封邮件。",
    );
    let mail_title = String::from("Test");
    let mail_account_name = Some(String::from("Network Mapping"));

    let mail_config = match test_data.as_deref() {
        Some(td) => td,
        None => match mail_config.as_ref() {
            Some(e) => e,
            None => {
                return HttpResponse::Ok()
                    .content_type(TEXT_HTML_UTF_8)
                    .body("未从数据库中找到相关配置");
            }
        },
    };

    let mail_message = Message::builder()
        .from(Mailbox::new(
            mail_account_name,
            (mail_config.account_username).to_string().parse().unwrap(),
        ))
        .to(Mailbox::new(None, user_mail.parse().unwrap()))
        .subject(mail_title)
        .header(ContentType::TEXT_PLAIN)
        .body(mail_context)
        .unwrap();
    send_email(mail_config, mail_message).await;
    HttpResponse::Ok().finish()
}
