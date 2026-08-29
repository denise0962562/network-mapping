use actix_web::{HttpRequest, HttpResponse, Responder, get, post, web};
use lettre::{Message, message::Mailbox, message::header::ContentType};
use serde_json::json;
use tracing::error;

use crate::TEXT_HTML_UTF_8;
use crate::admin::{
    MailRetryPolicy, UserBaseI, UserSession, get_config_from_database,
    get_mail_sender_key_from_database, get_mail_settings_from_database,
    get_scan_settings_from_database, get_session_settings_from_database, smtp_send_error_message,
    try_send_email, write_mail_settings_to_database, write_scan_settings_to_database,
    write_session_settings_to_database,
};
use crate::audit::{AuditContext, AuditEvent, write_standalone};
use crate::config::{
    DatabaseConfig, EmailConfig, GetConfig, MailSettingsRequest, MailTestRequest,
    ScanSettingsRequest, ServerConfig, SessionSettingsRequest, session_ttl_seconds_from_minutes,
};
use crate::trusted_proxy::{
    MAX_CLIENT_IP_HEADER_LENGTH, MAX_TRUSTED_PROXY_CIDRS, TrustedProxySettings, TrustedProxyState,
    validate_settings, write_settings_to_database,
};
use crate::{
    FrontEndErrorInfo, TemplatesInit, front_end_error_page,
    logs::write::{info_logs, request_id},
};

#[cfg(feature = "rir")]
use crate::rir::get_rir_data;

//基准测试
use crate::{Systems, benchmark};

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

pub async fn not_found(
    req: HttpRequest,
    page_template: web::Data<TemplatesInit>,
) -> impl Responder {
    if req.path() == "/api" || req.path().starts_with("/api/") {
        return HttpResponse::NotFound().json(serde_json::json!({
            "success": false,
            "message": "not found",
            "request_id": request_id(&req).to_string(),
        }));
    }

    let error_info = FrontEndErrorInfo {
        status_code: 404,
        error_title: "NotFound",
        error_message: "没有找到对应的资源",
        request_id: request_id(&req).to_string(),
    };
    HttpResponse::NotFound()
        .content_type(TEXT_HTML_UTF_8)
        .body(front_end_error_page(&error_info, &page_template))
}

/// 获取服务端版本号
#[get("/api/version")]
async fn get_server_version() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "success": true,
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// 获取当前 Web 监听配置（只读）
#[get("/api/config/server")]
pub async fn get_server_config_h(
    server_config: web::Data<ServerConfig>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取 Web 监听配置"
        }));
    }

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "host": server_config.host.as_str(),
            "port": server_config.port
        }
    }))
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
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取系统配置"
        }));
    }
    let pool_ref = pool.get_ref();

    let mut con =
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
    for config in &mut con {
        if config.item_type == "smtp" && config.key == "sender_key" {
            config.value.clear();
        }
    }
    HttpResponse::Ok().json(con)
}

fn validate_mail_settings(
    test_recipient: &str,
    smtp_host: &str,
    smtp_port: u16,
    sender: &str,
    sender_key: &str,
) -> Result<(), &'static str> {
    if test_recipient.trim().parse::<Mailbox>().is_err() {
        return Err("测试收件人邮箱格式不正确");
    }
    let smtp_host = smtp_host.trim();
    if smtp_host.is_empty()
        || smtp_host.len() > 255
        || smtp_host.chars().any(|character| character.is_control())
    {
        return Err("邮件服务器地址不正确");
    }
    if smtp_port == 0 {
        return Err("邮件服务器端口必须在 1 到 65535 之间");
    }
    if sender.trim().parse::<Mailbox>().is_err() {
        return Err("发件人邮箱格式不正确");
    }
    if sender_key.len() > 4096 {
        return Err("发件邮箱密钥过长");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use actix_web::{App, HttpMessage, http::StatusCode, test as actix_test, web};
    use serde_json::{Value, json};

    use super::{get_server_config_h, validate_mail_settings};
    use crate::{admin::UserBaseI, config::ServerConfig};

    fn test_server_config() -> ServerConfig {
        ServerConfig {
            host: "127.0.0.1".to_owned(),
            port: 9443,
            encrypt_key: "test".to_owned(),
            max_body_size: 1024,
        }
    }

    fn test_user(role: i32) -> UserBaseI {
        UserBaseI {
            id: 1,
            username: "tester".to_owned(),
            role,
            email: None,
            limit_login: false,
            enable_2fa: false,
        }
    }

    #[actix_web::test]
    async fn server_config_returns_only_read_only_listen_fields_for_admin() {
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(test_server_config()))
                .service(get_server_config_h),
        )
        .await;
        let request = actix_test::TestRequest::get()
            .uri("/api/config/server")
            .to_request();
        request.extensions_mut().insert(test_user(1));

        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(
            body,
            json!({
                "success": true,
                "data": { "host": "127.0.0.1", "port": 9443 }
            })
        );
    }

    #[actix_web::test]
    async fn server_config_rejects_non_admin_users() {
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(test_server_config()))
                .service(get_server_config_h),
        )
        .await;
        let request = actix_test::TestRequest::get()
            .uri("/api/config/server")
            .to_request();
        request.extensions_mut().insert(test_user(0));

        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn valid_mail_settings_are_accepted() {
        assert!(
            validate_mail_settings(
                "security@example.com",
                "smtp.example.com",
                465,
                "scanner@example.com",
                "app-password",
            )
            .is_ok()
        );
    }

    #[test]
    fn invalid_mail_settings_are_rejected() {
        assert!(
            validate_mail_settings(
                "not-an-email",
                "smtp.example.com",
                465,
                "scanner@example.com",
                "app-password",
            )
            .is_err()
        );
        assert!(
            validate_mail_settings(
                "security@example.com",
                "smtp.example.com",
                0,
                "scanner@example.com",
                "app-password",
            )
            .is_err()
        );
    }
}

#[get("/api/config/mail")]
async fn get_mail_settings_h(
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取邮件配置"
        }));
    }
    match get_mail_settings_from_database(pool.get_ref()).await {
        Ok(settings) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": settings
        })),
        Err(error_value) => {
            error!(
                event = "GetMailSettingsError",
                path = "fn get_mail_settings_h",
                message = %error_value
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "邮件配置暂时无法读取"
            }))
        }
    }
}

#[get("/api/config/security/session")]
async fn get_session_settings_h(
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取会话策略"
        }));
    }
    match get_session_settings_from_database(pool.get_ref()).await {
        Ok(settings) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": settings
        })),
        Err(error_value) => {
            error!(
                event = "GetSessionSettingsError",
                path = "fn get_session_settings_h",
                message = %error_value
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "会话策略暂时无法读取"
            }))
        }
    }
}

#[post("/api/config/security/session")]
async fn save_session_settings_h(
    req: HttpRequest,
    settings: web::Json<SessionSettingsRequest>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
    user_session: UserSession,
) -> impl Responder {
    if user_base_i.role != 1 {
        let mut audit_event = AuditEvent::user(
            "configuration",
            "configuration.session_policy_update",
            "failure",
            &user_base_i,
        );
        audit_event.response_status = Some(403);
        audit_event.reason_code = Some("insufficient_role".to_owned());
        write_standalone(
            pool.get_ref(),
            &AuditContext::from_request(&req),
            &audit_event,
        )
        .await;
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以修改会话策略"
        }));
    }
    if let Err(message) = session_ttl_seconds_from_minutes(settings.session_ttl_minutes) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": message
        }));
    }

    match write_session_settings_to_database(pool.get_ref(), &settings, &user_session.session).await
    {
        Ok(saved_settings) => {
            let mut audit_event = AuditEvent::user(
                "configuration",
                "configuration.session_policy_update",
                "success",
                &user_base_i,
            )
            .resource("setting", "security.session_ttl_seconds");
            audit_event.response_status = Some(200);
            audit_event.changes = Some(json!({
                "session_ttl_minutes": saved_settings.session_ttl_minutes,
                "invalidate_other_sessions": settings.invalidate_other_sessions,
                "invalidated_session_count": saved_settings.invalidated_session_count
            }));
            write_standalone(
                pool.get_ref(),
                &AuditContext::from_request(&req),
                &audit_event,
            )
            .await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "message": "会话策略已保存",
                "data": saved_settings
            }))
        }
        Err(error_value) => {
            error!(
                event = "SaveSessionSettingsError",
                path = "fn save_session_settings_h",
                message = %error_value
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "会话策略保存失败"
            }))
        }
    }
}

#[get("/api/config/security/trusted-proxies")]
async fn get_trusted_proxy_settings_h(
    trusted_proxies: web::Data<TrustedProxyState>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以读取可信代理配置"
        }));
    }
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": trusted_proxies.settings().await,
        "limits": {
            "maximumCidrs": MAX_TRUSTED_PROXY_CIDRS,
            "maximumHeaderNameLength": MAX_CLIENT_IP_HEADER_LENGTH,
            "supportsCustomHeader": true
        }
    }))
}

#[post("/api/config/security/trusted-proxies")]
async fn save_trusted_proxy_settings_h(
    req: HttpRequest,
    settings: web::Json<TrustedProxySettings>,
    pool: web::Data<deadpool_postgres::Pool>,
    trusted_proxies: web::Data<TrustedProxyState>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        let mut audit_event = AuditEvent::user(
            "configuration",
            "configuration.trusted_proxies_update",
            "failure",
            &user_base_i,
        );
        audit_event.response_status = Some(403);
        audit_event.reason_code = Some("insufficient_role".to_owned());
        write_standalone(
            pool.get_ref(),
            &AuditContext::from_request(&req),
            &audit_event,
        )
        .await;
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以修改可信代理配置"
        }));
    }

    let validated = match validate_settings(settings.into_inner()) {
        Ok(settings) => settings,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": message
            }));
        }
    };
    let saved_settings = validated.settings.clone();
    if let Err(error_value) = write_settings_to_database(pool.get_ref(), &saved_settings).await {
        error!(
            event = "SaveTrustedProxySettingsError",
            path = "fn save_trusted_proxy_settings_h",
            message = %error_value
        );
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "可信代理配置保存失败"
        }));
    }
    trusted_proxies.replace(validated).await;

    let mut audit_event = AuditEvent::user(
        "configuration",
        "configuration.trusted_proxies_update",
        "success",
        &user_base_i,
    )
    .resource("setting", "network.trusted_proxies");
    audit_event.response_status = Some(200);
    audit_event.changes = Some(json!({
        "trusted_proxy_cidrs": &saved_settings.trusted_proxy_cidrs,
        "client_ip_header": &saved_settings.client_ip_header
    }));
    write_standalone(
        pool.get_ref(),
        &AuditContext::from_request(&req),
        &audit_event,
    )
    .await;

    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "可信代理配置已保存并立即生效",
        "data": saved_settings,
        "limits": {
            "maximumCidrs": MAX_TRUSTED_PROXY_CIDRS,
            "maximumHeaderNameLength": MAX_CLIENT_IP_HEADER_LENGTH,
            "supportsCustomHeader": true
        }
    }))
}

#[get("/api/config/scan")]
async fn get_scan_settings_h(
    pool: web::Data<deadpool_postgres::Pool>,
    _user_base_i: UserBaseI,
) -> impl Responder {
    match get_scan_settings_from_database(pool.get_ref()).await {
        Ok(settings) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": settings
        })),
        Err(error_value) => {
            error!(
                event = "GetScanSettingsError",
                path = "fn get_scan_settings_h",
                message = %error_value
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "扫描设置暂时无法读取"
            }))
        }
    }
}

#[post("/api/config/scan")]
async fn save_scan_settings_h(
    req: HttpRequest,
    settings: web::Json<ScanSettingsRequest>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        let mut audit_event = AuditEvent::user(
            "configuration",
            "configuration.scan_settings_update",
            "failure",
            &user_base_i,
        );
        audit_event.response_status = Some(403);
        audit_event.reason_code = Some("insufficient_role".to_owned());
        write_standalone(
            pool.get_ref(),
            &AuditContext::from_request(&req),
            &audit_event,
        )
        .await;
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以修改扫描设置"
        }));
    }
    let requested_profile = settings.default_scan_profile.trim().to_lowercase();
    if crate::build_scan_plan(&requested_profile).is_err() {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "不支持的默认扫描模式"
        }));
    }

    match write_scan_settings_to_database(pool.get_ref(), &settings).await {
        Ok(saved_settings) => {
            let mut audit_event = AuditEvent::user(
                "configuration",
                "configuration.scan_settings_update",
                "success",
                &user_base_i,
            )
            .resource("setting", "scan.default_profile");
            audit_event.response_status = Some(200);
            audit_event.changes = Some(json!({
                "default_scan_profile": saved_settings.default_scan_profile
            }));
            write_standalone(
                pool.get_ref(),
                &AuditContext::from_request(&req),
                &audit_event,
            )
            .await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "message": "扫描设置已保存",
                "data": saved_settings
            }))
        }
        Err(error_value) => {
            error!(
                event = "SaveScanSettingsError",
                path = "fn save_scan_settings_h",
                message = %error_value
            );
            HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "扫描设置保存失败"
            }))
        }
    }
}

#[post("/api/config/mail")]
async fn save_mail_settings_h(
    req: HttpRequest,
    settings: web::Json<MailSettingsRequest>,
    pool: web::Data<deadpool_postgres::Pool>,
    server_config: web::Data<ServerConfig>,
    user_base_i: UserBaseI,
) -> impl Responder {
    if user_base_i.role != 1 {
        let mut audit_event = AuditEvent::user(
            "configuration",
            "configuration.mail_update",
            "failure",
            &user_base_i,
        );
        audit_event.response_status = Some(403);
        audit_event.reason_code = Some("insufficient_role".to_owned());
        write_standalone(
            pool.get_ref(),
            &AuditContext::from_request(&req),
            &audit_event,
        )
        .await;
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "仅管理员可以修改邮件配置"
        }));
    }
    if let Err(message) = validate_mail_settings(
        &settings.recipient,
        &settings.smtp_host,
        settings.smtp_port,
        &settings.sender,
        &settings.sender_key,
    ) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": message
        }));
    }
    if settings.sender_key.is_empty() {
        match get_mail_sender_key_from_database(pool.get_ref(), &server_config.encrypt_key).await {
            Ok(Some(_)) => (),
            Ok(None) => {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "首次保存时必须填写发件邮箱密钥"
                }));
            }
            Err(error_value) => {
                error!(
                    event = "ReadMailSecretError",
                    path = "fn save_mail_settings_h",
                    message = %error_value
                );
                return HttpResponse::InternalServerError().json(json!({
                    "success": false,
                    "message": "已保存的邮箱密钥无法读取"
                }));
            }
        }
    }

    if let Err(error_value) =
        write_mail_settings_to_database(pool.get_ref(), &settings, &server_config.encrypt_key).await
    {
        error!(
            event = "SaveMailSettingsError",
            path = "fn save_mail_settings_h",
            message = %error_value
        );
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "邮件配置保存失败"
        }));
    }

    let saved_settings = match get_mail_settings_from_database(pool.get_ref()).await {
        Ok(saved_settings) => saved_settings,
        Err(error_value) => {
            error!(
                event = "ReloadMailSettingsError",
                path = "fn save_mail_settings_h",
                message = %error_value
            );
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "邮件配置已写入，但重新读取失败"
            }));
        }
    };
    let mut audit_event = AuditEvent::user(
        "configuration",
        "configuration.mail_update",
        "success",
        &user_base_i,
    )
    .resource("setting", "smtp");
    audit_event.response_status = Some(200);
    audit_event.changes = Some(json!({
        "test_recipient": &saved_settings.recipient,
        "smtp_host": &saved_settings.smtp_host,
        "smtp_port": saved_settings.smtp_port,
        "sender": &saved_settings.sender,
        "sender_key_changed": !settings.sender_key.is_empty(),
        "notification_preferences": &saved_settings.notification_prefs
    }));
    write_standalone(
        pool.get_ref(),
        &AuditContext::from_request(&req),
        &audit_event,
    )
    .await;

    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "邮件配置已保存",
        "data": saved_settings
    }))
}

/// 测试 SMTP 邮件服务器
#[post("/api/mail/smtp/test")]
async fn test_mail_server_h(
    req: HttpRequest,
    test_data: web::Json<MailTestRequest>,
    server_config: web::Data<ServerConfig>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let pool_ref = pool.get_ref();
    let u_role = user_base_i.role;

    if u_role != 1 {
        info_logs(
            &req,
            "UserPermissionDenied",
            "用户权限不足，操作请求已被拒绝。",
        );
        return HttpResponse::Forbidden().finish();
    }

    if let Err(message) = validate_mail_settings(
        &test_data.recipient,
        &test_data.smtp_host,
        test_data.smtp_port,
        &test_data.sender,
        &test_data.sender_key,
    ) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": message
        }));
    }
    let sender_key = if test_data.sender_key.is_empty() {
        match get_mail_sender_key_from_database(pool_ref, &server_config.encrypt_key).await {
            Ok(Some(sender_key)) => sender_key,
            Ok(None) => {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "请填写发件邮箱密钥，或先保存邮件配置"
                }));
            }
            Err(error_value) => {
                error!(
                    event = "ReadMailSecretError",
                    path = "fn test_mail_server_h",
                    message = %error_value
                );
                return HttpResponse::InternalServerError().json(json!({
                    "success": false,
                    "message": "已保存的邮箱密钥无法读取"
                }));
            }
        }
    } else {
        test_data.sender_key.clone()
    };

    let mail_context = String::from(
        "这是一封测试邮件，用于测试您设置的邮件服务器是否正常工作。如果您没有发送测试邮件请忽略此封邮件。",
    );
    let mail_title = String::from("Test");
    let mail_account_name = Some(String::from("Network Mapping"));

    let mail_config = EmailConfig {
        host: test_data.smtp_host.trim().to_owned(),
        account_username: test_data.sender.trim().to_owned(),
        account_password: sender_key,
    };

    let mail_message = match Message::builder()
        .from(Mailbox::new(
            mail_account_name,
            match mail_config.account_username.parse() {
                Ok(address) => address,
                Err(_) => {
                    return HttpResponse::BadRequest().json(json!({
                        "success": false,
                        "message": "发件人邮箱格式不正确"
                    }));
                }
            },
        ))
        .to(match test_data.recipient.trim().parse::<Mailbox>() {
            Ok(mailbox) => mailbox,
            Err(_) => {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "测试收件人邮箱格式不正确"
                }));
            }
        })
        .subject(mail_title)
        .message_id(None)
        .header(ContentType::TEXT_PLAIN)
        .body(mail_context)
    {
        Ok(message) => message,
        Err(error_value) => {
            error!(
                event = "BuildTestMailError",
                path = "fn test_mail_server_h",
                message = %error_value
            );
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "测试邮件内容构造失败"
            }));
        }
    };
    match try_send_email(
        &mail_config,
        test_data.smtp_port,
        mail_message,
        MailRetryPolicy::Interactive,
    )
    .await
    {
        Ok(()) => {
            let mut audit_event = AuditEvent::user(
                "configuration",
                "configuration.mail_test",
                "success",
                &user_base_i,
            )
            .resource("setting", "smtp");
            audit_event.response_status = Some(200);
            audit_event.metadata = json!({"recipient": test_data.recipient.trim()});
            write_standalone(pool_ref, &AuditContext::from_request(&req), &audit_event).await;
            HttpResponse::Ok().json(json!({
                "success": true,
                "message": "测试邮件已发送"
            }))
        }
        Err(error_value) => {
            error!(
                event = "TestMailSendError",
                path = "fn test_mail_server_h",
                attempts = error_value.attempts(),
                retryable = error_value.is_retryable(),
                message = %error_value
            );
            HttpResponse::BadGateway().json(json!({
                "success": false,
                "message": smtp_send_error_message(&error_value),
                "detail": error_value.to_string()
            }))
        }
    }
}
