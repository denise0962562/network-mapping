use actix_web::cookie::time::OffsetDateTime;
use actix_web::http::header;
use actix_web::{web, HttpResponse, Responder, HttpRequest, get, post, cookie, cookie::Cookie};
use tracing::error;
use serde_json::json;
use std::time::Instant;

use crate::admin::{GetUserInfoH, get_user_info, totp_verify_status_change};
use crate::middlewares::render_500;
use crate::{admin, generate_hash_password, AddUserInfo, log_out};
use crate::handlers::{ReceiveLoginInfo};
use crate::login::{get_session_from_req, user_login};
use crate::{TEXT_HTML_UTF_8};
use crate::logs::write::{error_logs, info_logs};
use crate::config::{EmailConfig, PasswordHashConfig};
use crate::TemplatesInit;
use admin::{
    ReceiveAddUserInfo, 
    Unbind2FAH, 
    VerifyTotp, 
    bind_twofa, 
    get_user_id_and_name, 
    totp_struct, 
    totp_token_verify, 
    unbind_2fa
};

// BUG 暂时使用 bug 标签用于提示
/// 该接口为测试阶段接口，用于快速创建账号，在生产环境下必须删除
#[get("/test/adduser")]
async fn first_add_user(
    pool: web::Data<deadpool_postgres::Pool>,
    query_info: web::Query<ReceiveAddUserInfo>,
    pwd_hash_config: web::Data<PasswordHashConfig>
) -> impl Responder {
    let p = pool.get_ref();

    match admin::is_user_exist(&query_info.username, p).await {
        Ok(true) => {
            HttpResponse::FailedDependency()
                .content_type(TEXT_HTML_UTF_8)
                .body("用户已存在")
        },
        Ok(false) => {
            match generate_hash_password(&query_info.password, pwd_hash_config.get_ref().clone()) {
                Ok(o) => {
                    let userinfo = AddUserInfo{
                        username: &query_info.username,
                        password_hash: o.as_str(),
                        role: query_info.role

                    };
                    match admin::add_user(userinfo, p).await {
                        Ok(_) => {
                            println!("添加用户：{}:{}", &query_info.username, &query_info.password);
                            HttpResponse::Ok()
                                .content_type(TEXT_HTML_UTF_8)
                                .body("用户添加成功")
                        },
                        Err(e) => {
                            println!("添加用户失败：{}:{}\n错误：{}", &query_info.username, &query_info.password, e.to_string());
                            HttpResponse::InternalServerError()
                                .content_type(TEXT_HTML_UTF_8)
                                .body("添加用户失败")
                        }
                    }
                },
                Err(e) => {
                    error!(
                        event = "GeneratePasswordHashError",
                        path = "fn first_add_user",
                        message = %e
                    );
                    HttpResponse::InternalServerError()
                        .body("500")
                }
            }
        },
        Err(e) => {
            error!(
                event = "CheckUserError",
                path = "fn first_add_user",
                message = %e
            );
            HttpResponse::InternalServerError()
                .body("500")
        }
    }
}


/// 登录接口
#[post("/api/login")]
async fn user_login_h(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    mail_config: web::Data<Option<EmailConfig>>,
    receiveinfo: web::Json<ReceiveLoginInfo>
) -> impl Responder {
    println!("================= Benchmark =================");
    let total_start = Instant::now();                                                  // 总的开始时间
    let start = Instant::now();                                                        // 登录函数开始时间
    let p = pool.get_ref();
    let m_c = mail_config.get_ref().as_ref();
    let (t_session, csrf_token, enable_twofa) = match user_login(&req, &receiveinfo.username, &receiveinfo.password, m_c, p).await {
        Ok(o) => o,
        Err(e) => {
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
            return HttpResponse::Unauthorized()
                .json(body)
        }
    };

    let cookies = Cookie::build("session", &t_session)
        .path("/")
        .http_only(true)
        .secure(true)
        .max_age(cookie::time::Duration::seconds(2700))
        .same_site(cookie::SameSite::Strict)
        .finish();
    let cookie_csrf_token = Cookie::build("csrf_token", &csrf_token)
        .path("/")
        .secure(true)
        .max_age(cookie::time::Duration::seconds(2700))
        .same_site(cookie::SameSite::Strict)
        .finish();

    let total_es = total_start.elapsed();
    let login_function = start.elapsed();

    println!("Total   : {:>6} ms", total_es.as_millis());
    println!("Login_f : {:>6} ms", login_function.as_millis());
    println!("=============================================");
    match enable_twofa {
        true => {
            // 使用 401 Unauthorized 表示还需要继续验证 TOTP Token
            HttpResponse::Unauthorized()
                .cookie(cookies)
                .cookie(cookie_csrf_token)
                .json(
                    json!({
                        "success": true,
                        "message": "请验证 2FA 验证码"
                    })
                )
        },
        false => {
            HttpResponse::Ok()
                .cookie(cookies)
                .cookie(cookie_csrf_token)
                .json(
                    json!({
                        "success": true,
                        "message": "登录成功"
                    })
                )
        }
    }
}


/// 注销会话接口
#[get("/logout")]
async fn user_logout(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>,
    page_template: web::Data<TemplatesInit>
) -> impl Responder {
    let tmp_csrf_t = match &req.headers().get("X-CSRF-Token") {
        Some(s) => s.to_str().unwrap_or(""),
        None => ""
    };
    if let Some(token) = &req.cookie("session") {
        let p = pool.get_ref();
        let tmp_token = token.value();
        match log_out(&tmp_token, p).await {
            Ok(_) => {
                let cookies = Cookie::build("session", tmp_token)
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
            },
            Err(e) => {
                error_logs(&req, "注销会话错误", e.to_string().as_str());
                let page = page_template.get_ref();
                render_500(&req, page, "注销会话错误")
            }
        }
    }
    else {
        HttpResponse::MovedPermanently()
            .insert_header((header::LOCATION, "/login"))
            .finish()
    }
}


/// 绑定 2FA 验证器
/// 
/// 直接返回 optauth url
#[get("/api/totp/bind")]
async fn bind_twofa_h(
    req: HttpRequest,
    pool: web::Data<deadpool_postgres::Pool>
) -> impl Responder {

    let pool_r = pool.get_ref();
    let session = get_session_from_req(&req, "session").unwrap_or(String::new());
    let (_u_id, _u_role, username) = match get_user_id_and_name(&session, pool_r).await {
        Ok(tmp) => tmp,
        Err(e) => {
            error_logs(&req, "GetUserIdandNameError", &e.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    
    match bind_twofa(username, pool_r).await {
        Ok(tmp) => {
            return HttpResponse::ImUsed()
                .json(json!({"success": true, "data": tmp}))
        },
        Err(e) => {
            error_logs(&req, "CreateOptauthUrlError", &e.to_string());
            return HttpResponse::InternalServerError().finish()
        }
    }

}


/// 验证 TOTP Token 接口
#[post("/api/totp/verify")]
async fn verify_totp_h(
    info: web::Json<VerifyTotp>,
    pool: web::Data<deadpool_postgres::Pool>,
    req: HttpRequest
) -> impl Responder {

    if let Some(request_cookie) = get_session_from_req(&req, "session") {
        let database_conn = pool.get_ref();
        let (_, _, username) = match get_user_id_and_name(&request_cookie, database_conn).await {
            Ok(id_and_name) => id_and_name,
            Err(e) => {
                error_logs(&req, "GetUserIdandNameError", &e.to_string());
                return HttpResponse::InternalServerError();
            }
        };
        let totp = match totp_struct(username, database_conn).await {
            Ok(Some(tmp)) => tmp,
            Ok(None) => {
                info_logs(&req, "TOTPSecretNotFound", "查找用户的 totp secret 错误", false);
                return HttpResponse::NotFound();
            },
            Err(e) => {
                error_logs(&req, "生成 TOTP 结构体错误", &e.to_string());
                return HttpResponse::InternalServerError();
            }
        };

        match totp_token_verify(totp, &info.token).await {
            Ok(true) => {
                totp_verify_status_change(&request_cookie, database_conn).await.map(|_| HttpResponse::Ok()).unwrap_or(HttpResponse::InternalServerError())
                // HttpResponse::Ok()
            },
            Ok(false) => {
                info_logs(&req, "TOTPTokenVerifyFaild", "TOTP Token 验证不通过", false);
                HttpResponse::Unauthorized()
            },
            Err(e) => {
                error_logs(&req, "TOTPTokenVerifyError", &e.to_string());
                HttpResponse::InternalServerError()
            }
        }
    } else {
        HttpResponse::Unauthorized()
    }
}

/// 解绑 2FA ，该操作只能由管理员设置
/// 
#[post("/api/totp/unbind")]
async fn unbind_2fa_h(
    req: HttpRequest,
    unbind_info: web::Json<Unbind2FAH>,
    pool: web::Data<deadpool_postgres::Pool>
) -> impl Responder {
    let pool_c = pool.get_ref();

    if let Some(session) = get_session_from_req(&req, "session") {
        let (_id, u_role, _username) = match get_user_id_and_name(&session, pool_c).await {
            Ok(o) => o,
            Err(e) => {
                error_logs(&req, "GetUserIdandNameError", &e.to_string());
                return HttpResponse::InternalServerError();
            }
        };
        if u_role != 1 {
            return HttpResponse::Forbidden();
        };
        match unbind_2fa(&unbind_info.username, pool_c).await {
            Ok(true) => {
                info_logs(&req, "Unbind2FASuccessful", "解绑 2FA 成功", false);
                HttpResponse::Ok()
            },
            Ok(false) => {
                HttpResponse::NotFound()
            },
            Err(e) => {
                error_logs(&req, "Unbind2FAfaild", &e.to_string());
                return HttpResponse::InternalServerError();
            }
        }
    } else {
        HttpResponse::Unauthorized()
    }
    
}

/// 获取用户信息
/// 
#[get("/api/userinfo/get")]
async fn get_user_info_h(
    req: HttpRequest,
    info: web::Query<GetUserInfoH>,
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
            error_logs(&req, "GetUserInfoError", format!("role: {}, 错误的权限", u_role).as_str());
            return HttpResponse::InternalServerError().finish()
        };

        match get_user_info(u_role, t_username, info.count.map(|c| c as i64), pool_ref).await {
            Ok(data) => {
                HttpResponse::Ok()
                    .json(data)
            },
            Err(e) => {
                error_logs(&req, "GetUserInfoError", &e.to_string());
                HttpResponse::InternalServerError().finish()
            }
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}