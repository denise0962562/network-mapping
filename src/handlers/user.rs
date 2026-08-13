use actix_web::cookie::time::OffsetDateTime;
use actix_web::{HttpRequest, HttpResponse, Responder, cookie, cookie::Cookie, get, post, web};
use deadpool_postgres::Pool;
use serde_json::json;
use std::ops::Deref;
use std::time::Instant;
use tracing::error;

use crate::TEXT_HTML_UTF_8;
use crate::TemplatesInit;
use crate::admin::{
    AddScanner, GetUserInfoH, ScannerRegisterData, UserBaseI, UserBaseInfo, UserSession,
    check_twofa_bind, get_user_info, totp_verify_status_change, update_user_info,
};
use crate::audit::{AuditContext, AuditEvent, write as write_audit, write_standalone};
use crate::config::{PasswordHashConfig, SecurityConfig, ServerConfig};
use crate::handlers::ReceiveLoginInfo;
use crate::login::user_login;
use crate::logs::write::{error_logs, info_logs};
use crate::mail_template::send_login_notification;
use crate::middlewares::render_500;
use crate::{AddUserInfo, admin, generate_hash_password, log_out, verify_password};
use admin::{
    ReceiveAddUserInfo, Unbind2FAH, VerifyTotp, bind_twofa, confirm_twofa_binding, get_scanner,
    get_scanners, scanner_register, totp_struct, totp_token_verify, unbind_2fa, web_add_scanner,
};
use uuid::Uuid;

fn expired_auth_cookies(session: &str, csrf_token: &str) -> (Cookie<'static>, Cookie<'static>) {
    let session_cookie = Cookie::build("session", session.to_owned())
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(cookie::SameSite::Strict)
        .expires(OffsetDateTime::UNIX_EPOCH)
        .finish();
    let csrf_cookie = Cookie::build("csrf_token", csrf_token.to_owned())
        .path("/")
        .secure(true)
        .same_site(cookie::SameSite::Strict)
        .expires(OffsetDateTime::UNIX_EPOCH)
        .finish();
    (session_cookie, csrf_cookie)
}

fn request_source_ip(req: &HttpRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_owned()
}

fn queue_login_notification(
    pool: deadpool_postgres::Pool,
    encryption_key: String,
    username: String,
    source_ip: String,
) {
    tokio::spawn(async move {
        if let Err(error_value) =
            send_login_notification(&pool, &encryption_key, &username, &source_ip).await
        {
            error!(
                event = "SendLoginNotificationError",
                username,
                message = %error_value
            );
        }
    });
}
#[derive(serde::Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}
// BUG 暂时使用 bug 标签用于提示
/// 该接口为测试阶段接口，用于快速创建账号，在生产环境下必须删除
#[get("/test/adduser")]
async fn first_add_user(
    pool: web::Data<deadpool_postgres::Pool>,
    query_info: web::Query<ReceiveAddUserInfo>,
    pwd_hash_config: web::Data<PasswordHashConfig>,
) -> impl Responder {
    let p = pool.get_ref();

    match admin::is_user_exist(&query_info.username, p).await {
        Ok(true) => HttpResponse::FailedDependency()
            .content_type(TEXT_HTML_UTF_8)
            .body("用户已存在"),
        Ok(false) => {
            match generate_hash_password(&query_info.password, pwd_hash_config.get_ref().clone()) {
                Ok(o) => {
                    let userinfo = AddUserInfo {
                        username: &query_info.username,
                        password_hash: o.as_str(),
                        role: query_info.role,
                    };
                    match admin::add_user(userinfo, p).await {
                        Ok(_) => {
                            println!(
                                "添加用户：{}:{}",
                                &query_info.username, &query_info.password
                            );
                            HttpResponse::Ok()
                                .content_type(TEXT_HTML_UTF_8)
                                .body("用户添加成功")
                        }
                        Err(e) => {
                            println!(
                                "添加用户失败：{}:{}\n错误：{}",
                                &query_info.username,
                                &query_info.password,
                                e.to_string()
                            );
                            HttpResponse::InternalServerError()
                                .content_type(TEXT_HTML_UTF_8)
                                .body("添加用户失败")
                        }
                    }
                }
                Err(e) => {
                    error!(
                        event = "GeneratePasswordHashError",
                        path = "fn first_add_user",
                        message = %e
                    );
                    HttpResponse::InternalServerError().body("500")
                }
            }
        }
        Err(e) => {
            error!(
                event = "CheckUserError",
                path = "fn first_add_user",
                message = %e
            );
            HttpResponse::InternalServerError().body("500")
        }
    }
}

/// 登录接口
#[post("/api/login")]
async fn user_login_h(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    server_config: web::Data<ServerConfig>,
    receiveinfo: web::Json<ReceiveLoginInfo>,
) -> impl Responder {
    println!("================= Benchmark =================");
    let total_start = Instant::now(); // 总的开始时间
    let start = Instant::now(); // 登录函数开始时间
    let p = pool.get_ref();
    let (t_session, csrf_token, enable_twofa, session_ttl_seconds) =
        match user_login(&receiveinfo.username, &receiveinfo.password, p).await {
            Ok(o) => o,
            Err(e) => {
                let mut audit_event =
                    AuditEvent::anonymous("authentication", "auth.login", "failure");
                audit_event.response_status = Some(401);
                audit_event.reason_code = Some("invalid_credentials".to_owned());
                audit_event.metadata = json!({"attempted_username": receiveinfo.username});
                write_standalone(p, &AuditContext::from_request(&req), &audit_event).await;
                let log_event = "LoginFaild";
                let log_message = &receiveinfo.username;
                error_logs(&req, log_event, log_message.as_str());
                error!(
                    event = "UserLoginError",
                    path = "fn user_login_h",
                    message = %e
                );
                let body = json!({
                    "success": false,
                    "message": "登录失败"
                });
                let total_es = total_start.elapsed();
                let login_function = start.elapsed();
                println!("Total   : {:>6} ms", total_es.as_millis());
                println!("Login_f : {:>6} ms", login_function.as_millis());
                println!("=============================================");
                return HttpResponse::Unauthorized().json(body);
            }
        };

    let cookies = Cookie::build("session", &t_session)
        .path("/")
        .http_only(true)
        .secure(true)
        .max_age(cookie::time::Duration::seconds(i64::from(
            session_ttl_seconds,
        )))
        .same_site(cookie::SameSite::Strict)
        .finish();
    let cookie_csrf_token = Cookie::build("csrf_token", &csrf_token)
        .path("/")
        .secure(true)
        .max_age(cookie::time::Duration::seconds(i64::from(
            session_ttl_seconds,
        )))
        .same_site(cookie::SameSite::Strict)
        .finish();

    let total_es = total_start.elapsed();
    let login_function = start.elapsed();

    println!("Total   : {:>6} ms", total_es.as_millis());
    println!("Login_f : {:>6} ms", login_function.as_millis());
    println!("=============================================");
    let mut audit_event = AuditEvent::anonymous(
        "authentication",
        if enable_twofa {
            "auth.password_verify"
        } else {
            "auth.login"
        },
        "success",
    );
    audit_event.actor_type = "user".to_owned();
    audit_event.actor_name = Some(receiveinfo.username.clone());
    audit_event.response_status = Some(if enable_twofa { 401 } else { 200 });
    audit_event.metadata = json!({"totp_required": enable_twofa});
    write_standalone(p, &AuditContext::from_request(&req), &audit_event).await;

    if !enable_twofa {
        queue_login_notification(
            p.clone(),
            server_config.encrypt_key.clone(),
            receiveinfo.username.clone(),
            request_source_ip(&req),
        );
    }

    match enable_twofa {
        true => {
            // 使用 401 Unauthorized 表示还需要继续验证 TOTP Token
            HttpResponse::Unauthorized()
                .cookie(cookies)
                .cookie(cookie_csrf_token)
                .json(json!({
                    "success": true,
                    "message": "请验证 2FA 验证码"
                }))
        }
        false => HttpResponse::Ok()
            .cookie(cookies)
            .cookie(cookie_csrf_token)
            .json(json!({
                "success": true,
                "message": "登录成功"
            })),
    }
}

/// 注销会话接口
#[get("/logout")]
async fn user_logout(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    page_template: web::Data<TemplatesInit>,
    session: UserSession,
    user: UserBaseI,
) -> impl Responder {
    let tmp_csrf_t = match &req.headers().get("X-CSRF-Token") {
        Some(s) => s.to_str().unwrap_or(""),
        None => "",
    };

    let p = pool.get_ref();
    let c_s = session.session;

    match log_out(&c_s, p).await {
        Ok(_) => {
            let mut audit_event =
                AuditEvent::user("authentication", "auth.logout", "success", &user);
            audit_event.response_status = Some(200);
            write_standalone(p, &AuditContext::from_request(&req), &audit_event).await;
            let cookies = Cookie::build("session", &c_s)
                .path("/")
                .http_only(true)
                .secure(true)
                .expires(OffsetDateTime::UNIX_EPOCH)
                .finish();
            let cookie_csrf_token = Cookie::build("csrf_token", tmp_csrf_t)
                .path("/")
                .secure(true)
                .expires(OffsetDateTime::UNIX_EPOCH)
                .finish();
            HttpResponse::Ok()
                .cookie(cookies)
                .cookie(cookie_csrf_token)
                .finish()
        }
        Err(e) => {
            error_logs(&req, "注销会话错误", e.to_string().as_str());
            let page = page_template.get_ref();
            render_500(&req, page, "注销会话错误")
        }
    }
}

/// totp 配置
///
#[get("/api/totp/get")]
async fn totp_config_h(
    req: HttpRequest,
    user_base_i: UserBaseI,
    pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    let pool_r = pool.get_ref();

    match check_twofa_bind(&user_base_i.username, pool_r).await {
        Ok(true) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "已绑定"
        })),
        Ok(false) => HttpResponse::Ok().json(json!({
            "success": false,
            "message": "未绑定"
        })),
        Err(e) => {
            error_logs(&req, "CheckTwofa", &e.to_string());
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 绑定 2FA 验证器
///
/// 直接返回 optauth url
#[get("/api/totp/bind")]
async fn bind_twofa_h(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
    session: UserSession,
    s_config: web::Data<ServerConfig>,
) -> impl Responder {
    let pool_r = pool.get_ref();

    match bind_twofa(
        user_base_i.username,
        &session.session,
        pool_r,
        &s_config.encrypt_key,
    )
    .await
    {
        Ok(tmp) => return HttpResponse::Ok().json(json!({"success": true, "data": tmp})),
        Err(e) => {
            error_logs(&req, "CreateOptauthUrlError", &e.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    }
}

/// 验证 TOTP Token 接口
#[post("/api/totp/verify")]
async fn verify_totp_h(
    info: web::Json<VerifyTotp>,
    pool: web::Data<deadpool_postgres::Pool>,
    req: HttpRequest,
    session: UserSession,
    user_base_i: UserBaseI,
    s_config: web::Data<ServerConfig>,
) -> impl Responder {
    let database_conn = pool.get_ref();
    let username = user_base_i.username.clone();

    if !user_base_i.enable_2fa {
        return match confirm_twofa_binding(
            &username,
            &session.session,
            &info.token,
            database_conn,
            &s_config.encrypt_key,
        )
        .await
        {
            Ok(true) => {
                let mut audit_event =
                    AuditEvent::user("user_security", "user.totp_bind", "success", &user_base_i)
                        .resource("user", user_base_i.id.to_string());
                audit_event.response_status = Some(200);
                write_standalone(
                    database_conn,
                    &AuditContext::from_request(&req),
                    &audit_event,
                )
                .await;
                let csrf_token = req
                    .headers()
                    .get("X-CSRF-Token")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                let (session_cookie, csrf_cookie) =
                    expired_auth_cookies(&session.session, csrf_token);
                HttpResponse::Ok()
                    .cookie(session_cookie)
                    .cookie(csrf_cookie)
                    .json(json!({"success": true, "message": "2FA 绑定成功，请重新登录"}))
            }
            Ok(false) => {
                let mut audit_event =
                    AuditEvent::user("user_security", "user.totp_bind", "failure", &user_base_i);
                audit_event.response_status = Some(401);
                audit_event.reason_code = Some("invalid_totp".to_owned());
                write_standalone(
                    database_conn,
                    &AuditContext::from_request(&req),
                    &audit_event,
                )
                .await;
                HttpResponse::Unauthorized()
                    .json(json!({"success": false, "message": "验证码无效或绑定已过期"}))
            }
            Err(e) => {
                error_logs(&req, "ConfirmTotpBindingError", &e.to_string());
                HttpResponse::InternalServerError().finish()
            }
        };
    }

    let totp = match totp_struct(username, &s_config.encrypt_key, database_conn).await {
        Ok(Some(tmp)) => tmp,
        Ok(None) => {
            info_logs(&req, "TOTPSecretNotFound", "查找用户的 totp secret 错误");
            return HttpResponse::NotFound().finish();
        }
        Err(e) => {
            error_logs(&req, "生成 TOTP 结构体错误", &e.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    match totp_token_verify(totp, &info.token).await {
        Ok(true) => match totp_verify_status_change(&session.session, database_conn).await {
            Ok(_) => {
                let mut audit_event = AuditEvent::user(
                    "authentication",
                    "auth.totp_verify",
                    "success",
                    &user_base_i,
                );
                audit_event.response_status = Some(200);
                write_standalone(
                    database_conn,
                    &AuditContext::from_request(&req),
                    &audit_event,
                )
                .await;
                queue_login_notification(
                    database_conn.clone(),
                    s_config.encrypt_key.clone(),
                    user_base_i.username.clone(),
                    request_source_ip(&req),
                );
                HttpResponse::Ok().finish()
            }
            Err(error_value) => {
                error_logs(&req, "TotpSessionUpdateError", &error_value.to_string());
                HttpResponse::InternalServerError().finish()
            }
        },
        Ok(false) => {
            let mut audit_event = AuditEvent::user(
                "authentication",
                "auth.totp_verify",
                "failure",
                &user_base_i,
            );
            audit_event.response_status = Some(401);
            audit_event.reason_code = Some("invalid_totp".to_owned());
            write_standalone(
                database_conn,
                &AuditContext::from_request(&req),
                &audit_event,
            )
            .await;
            info_logs(&req, "TOTPTokenVerifyFaild", "TOTP Token 验证不通过");
            HttpResponse::Unauthorized().finish()
        }
        Err(e) => {
            error_logs(&req, "TOTPTokenVerifyError", &e.to_string());
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 解绑 2FA ，该操作只能由管理员设置
///
#[post("/api/totp/unbind")]
async fn unbind_2fa_h(
    req: HttpRequest,
    unbind_info: web::Json<Unbind2FAH>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
    session: UserSession,
) -> impl Responder {
    let pool_c = pool.get_ref();

    if user_base_i.role != 1 {
        return HttpResponse::Forbidden().finish();
    };
    match unbind_2fa(&unbind_info.username, pool_c).await {
        Ok(true) => {
            let mut audit_event =
                AuditEvent::user("user_security", "user.totp_unbind", "success", &user_base_i)
                    .resource("user", unbind_info.username.clone());
            audit_event.response_status = Some(200);
            write_standalone(pool_c, &AuditContext::from_request(&req), &audit_event).await;
            info_logs(&req, "Unbind2FASuccessful", "解绑 2FA 成功");
            if unbind_info.username == user_base_i.username {
                let csrf_token = req
                    .headers()
                    .get("X-CSRF-Token")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                let (session_cookie, csrf_cookie) =
                    expired_auth_cookies(&session.session, csrf_token);
                HttpResponse::Ok()
                    .cookie(session_cookie)
                    .cookie(csrf_cookie)
                    .json(json!({"success": true, "message": "2FA 已解绑，请重新登录"}))
            } else {
                HttpResponse::Ok().json(json!({"success": true, "message": "2FA 已解绑"}))
            }
        }
        Ok(false) => HttpResponse::NotFound().finish(),
        Err(e) => {
            error_logs(&req, "Unbind2FAfaild", &e.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    }
}

/// 获取用户信息
///
#[get("/api/userinfo/get")]
async fn get_user_info_h(
    req: HttpRequest,
    info: web::Query<GetUserInfoH>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let pool_ref = pool.get_ref();
    let u_role = user_base_i.role;
    let username = user_base_i.username;

    let t_username = if info.list.unwrap_or(false) {
        // 当 list 存在且为 true 时不会指定用户名
        None
    } else if u_role == 1 {
        // 管理员可以查询所有用户，如果没有指定则查询自己的信息
        Some(info.username.as_deref().unwrap_or(username.as_str()))
    } else if u_role == 2 {
        // 普通用户只能查询自己的信息
        Some(username.as_str())
    } else {
        error_logs(
            &req,
            "GetUserInfoError",
            format!("role: {}, 错误的权限", u_role).as_str(),
        );
        return HttpResponse::InternalServerError().finish();
    };

    match get_user_info(u_role, t_username, info.count.map(|c| c as i64), pool_ref).await {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => {
            error_logs(&req, "GetUserInfoError", &e.to_string());
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 更新用户信息
///
#[post("/api/userinfo/update")]
async fn update_user_info_h(
    req: HttpRequest,
    new_user_i: web::Json<UserBaseInfo>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let pool_ref = pool.get_ref();

    match update_user_info(
        &user_base_i.username,
        user_base_i.role,
        &new_user_i,
        pool_ref,
    )
    .await
    {
        Ok(()) => HttpResponse::Ok(),
        Err(e) => {
            error_logs(&req, "UpdateUserInfoError", &e.to_string());
            HttpResponse::InternalServerError()
        }
    }
}

/// 修改当前登录用户的密码。
///
/// 修改成功后会废止该用户的所有既有 Session，以阻止旧登录态继续访问。
#[post("/api/user/password/update")]
async fn change_password_h(
    req: HttpRequest,
    password_change: web::Json<ChangePasswordRequest>,
    pool: web::Data<Pool>,
    pwd_hash_config: web::Data<PasswordHashConfig>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let current_password = password_change.current_password.as_str();
    let new_password = password_change.new_password.as_str();

    if !matches!(user_base_i.role, 1 | 2) {
        return HttpResponse::Forbidden().json(json!({
            "success": false,
            "message": "当前账户不允许修改密码"
        }));
    }
    if current_password.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "请输入当前密码"
        }));
    }
    let new_password_length = new_password.chars().count();
    if !(12..=128).contains(&new_password_length) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "新密码长度必须在 12 到 128 个字符之间"
        }));
    }
    if current_password == new_password {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "新密码不能与当前密码相同"
        }));
    }

    let mut client = match pool.get_ref().get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs(
                &req,
                "ChangePasswordDatabaseError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "密码修改服务暂时不可用"
            }));
        }
    };
    let transaction = match client.transaction().await {
        Ok(transaction) => transaction,
        Err(error_value) => {
            error_logs(
                &req,
                "ChangePasswordTransactionError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "密码修改服务暂时不可用"
            }));
        }
    };
    let row = match transaction
        .query_opt(
            "SELECT password FROM users WHERE id = $1 AND role IN (1, 2) FOR UPDATE;",
            &[&user_base_i.id],
        )
        .await
    {
        Ok(row) => row,
        Err(error_value) => {
            error_logs(&req, "ChangePasswordQueryError", &error_value.to_string());
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "密码修改服务暂时不可用"
            }));
        }
    };
    let Some(row) = row else {
        return HttpResponse::NotFound().json(json!({
            "success": false,
            "message": "未找到当前用户"
        }));
    };
    let password_hash: String = row.get("password");
    if !verify_password(current_password, &password_hash) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "当前密码不正确"
        }));
    }

    let new_password_hash =
        match generate_hash_password(new_password, pwd_hash_config.get_ref().clone()) {
            Ok(password_hash) => password_hash,
            Err(error_value) => {
                error!(
                    event = "ChangePasswordHashError",
                    path = "fn change_password_h",
                    message = ?error_value
                );
                return HttpResponse::InternalServerError().json(json!({
                    "success": false,
                    "message": "密码修改服务暂时不可用"
                }));
            }
        };
    if let Err(error_value) = transaction
        .execute(
            "UPDATE users SET password = $1, limit_login = false, limit_at = NULL, \
             limit_time = NULL, login_error_count = 0, last_error_at = NULL WHERE id = $2;",
            &[&new_password_hash, &user_base_i.id],
        )
        .await
    {
        error_logs(&req, "ChangePasswordUpdateError", &error_value.to_string());
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "密码修改服务暂时不可用"
        }));
    }
    if let Err(error_value) = transaction
        .execute(
            "UPDATE session SET is_enable = false WHERE user_id = $1 AND is_enable = true;",
            &[&user_base_i.id],
        )
        .await
    {
        error_logs(&req, "ChangePasswordSessionError", &error_value.to_string());
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "密码修改服务暂时不可用"
        }));
    }
    let mut audit_event = AuditEvent::user(
        "user_security",
        "user.password_change",
        "success",
        &user_base_i,
    )
    .resource("user", user_base_i.id.to_string());
    audit_event.response_status = Some(200);
    audit_event.changes = Some(json!({"sessions_invalidated": true}));
    if let Err(error_value) = write_audit(
        &transaction,
        &AuditContext::from_request(&req),
        &audit_event,
    )
    .await
    {
        error_logs(&req, "ChangePasswordAuditError", &error_value.to_string());
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "密码修改服务暂时不可用"
        }));
    }
    if let Err(error_value) = transaction.commit().await {
        error_logs(&req, "ChangePasswordCommitError", &error_value.to_string());
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "密码修改服务暂时不可用"
        }));
    }

    info_logs(
        &req,
        "ChangePasswordSuccessful",
        "用户密码已修改，既有会话已失效",
    );
    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "密码已修改，请重新登录"
    }))
}
/// 添加扫描器
///
/// 主要是 web 端添加用的
#[post("/api/scanner/add")]
async fn web_add_scanner_h(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    user_base_i: UserBaseI,
    add_data: web::Json<AddScanner>,
) -> impl Responder {
    let pool_ref = pool.get_ref();
    let s_id = match web_add_scanner(
        pool_ref,
        &user_base_i,
        &AuditContext::from_request(&req),
        add_data.deref(),
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(ok) => ok,
        Err(e) => {
            error_logs(&req, "AddScannerError", &e.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let res_data = json!({
        "success": true,
        "data": s_id
    });
    HttpResponse::Ok().json(res_data)
}

#[get("/api/scanner/list")]
async fn get_scanners_h(
    req: HttpRequest,
    pool: web::Data<Pool>,
    _user_base_i: UserBaseI,
) -> impl Responder {
    match get_scanners(pool.get_ref()).await {
        Ok(scanners) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": scanners,
        })),
        Err(error) => {
            error_logs(&req, "GetScannersError", &error.to_string());
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/api/scanner/{scanner_id}")]
async fn get_scanner_h(
    req: HttpRequest,
    pool: web::Data<Pool>,
    _user_base_i: UserBaseI,
    scanner_id: web::Path<Uuid>,
) -> impl Responder {
    match get_scanner(pool.get_ref(), scanner_id.into_inner()).await {
        Ok(Some(scanner)) => HttpResponse::Ok().json(json!({
            "success": true,
            "data": scanner,
        })),
        Ok(None) => HttpResponse::NotFound().json(json!({
            "success": false,
            "message": "scanner not found",
        })),
        Err(error) => {
            error_logs(&req, "GetScannerError", &error.to_string());
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 扫描器注册
///
#[post("/api/scanner/register")]
async fn scanner_register_h(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    register_data: web::Json<ScannerRegisterData>,
) -> impl Responder {
    let registration_token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(registration_token) = registration_token else {
        return HttpResponse::Unauthorized().body("missing scanner registration token");
    };

    match scanner_register(
        &pool,
        &register_data,
        registration_token,
        &security.scanner_token_pepper,
        &AuditContext::from_request(&req),
    )
    .await
    {
        Ok(runtime_secret) => HttpResponse::Ok().json(runtime_secret),
        Err(e) => {
            let mut audit_event = AuditEvent::anonymous("scanner", "scanner.register", "failure");
            audit_event.actor_type = "scanner".to_owned();
            audit_event.actor_id = Some(register_data.scanner_id.clone());
            audit_event.resource_type = Some("scanner".to_owned());
            audit_event.resource_id = Some(register_data.scanner_id.clone());
            audit_event.response_status = Some(if e.to_string() == "scanner unauthorized" {
                401
            } else {
                500
            });
            audit_event.reason_code = Some(if e.to_string() == "scanner unauthorized" {
                "invalid_registration_token".to_owned()
            } else {
                "registration_error".to_owned()
            });
            write_standalone(
                pool.get_ref(),
                &AuditContext::from_request(&req),
                &audit_event,
            )
            .await;
            error_logs(&req, "ScannerRegister", &e.to_string());
            if e.to_string() == "scanner unauthorized" {
                return HttpResponse::Unauthorized().finish();
            }
            HttpResponse::InternalServerError().finish()
        }
    }
}

// 扫描器状态
//
// 通过定时接收扫描器发送的请求来判断扫描器是否在线，以及当前状态
// #[post("/api/scanner/health")]
// async fn scanner_health_h(
//     req: HttpRequest,
//     pool: web::Data<Pool>
// ) -> {

// }
