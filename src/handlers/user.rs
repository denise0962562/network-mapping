use actix_web::cookie::time::OffsetDateTime;
use actix_web::{web, HttpResponse, Responder, HttpRequest, get, post, cookie, cookie::Cookie};
use tracing::error;
use serde_json::json;
use std::ops::Deref;
use std::time::Instant;
use deadpool_postgres::Pool;

use crate::admin::{AddScanner, GetUserInfoH, ScannerRegisterData, UserBaseI, UserBaseInfo, UserSession, check_twofa_bind, get_user_info, totp_verify_status_change, update_user_info};
use crate::middlewares::render_500;
use crate::{admin, generate_hash_password, AddUserInfo, log_out};
use crate::handlers::{ReceiveLoginInfo};
use crate::login::{user_login};
use crate::{TEXT_HTML_UTF_8};
use crate::logs::write::{error_logs, info_logs};
use crate::config::{EmailConfig, PasswordHashConfig, ServerConfig};
use crate::TemplatesInit;
use admin::{
    ReceiveAddUserInfo, 
    Unbind2FAH, 
    VerifyTotp, 
    bind_twofa, 
    totp_struct, 
    totp_token_verify, 
    unbind_2fa,
    web_add_scanner,
    scanner_register
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
    page_template: web::Data<TemplatesInit>,
    session: UserSession
) -> impl Responder {
    let tmp_csrf_t = match &req.headers().get("X-CSRF-Token") {
        Some(s) => s.to_str().unwrap_or(""),
        None => ""
    };

    let p = pool.get_ref();
    let c_s = session.session;

    match log_out(&c_s, p).await {
        Ok(_) => {
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
        },
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
    pool: web::Data<deadpool_postgres::Pool>
) -> impl Responder {
    let pool_r = pool.get_ref();

    match check_twofa_bind(&user_base_i.username, pool_r).await {
        Ok(true) => {
            HttpResponse::Ok().json(
                json!({
                    "success": true,
                    "message": "已绑定"
                })
            )
        },
        Ok(false) => {
            HttpResponse::Ok().json(
                json!({
                    "success": false,
                    "message": "未绑定"
                })
            )
        },
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
    s_config: web::Data<ServerConfig>
) -> impl Responder {
    let pool_r = pool.get_ref();

    match bind_twofa(user_base_i.username, pool_r, &s_config.encrypt_key).await {
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
    req: HttpRequest,
    session: UserSession,
    user_base_i: UserBaseI,
    s_config: web::Data<ServerConfig>
) -> impl Responder {

    let database_conn = pool.get_ref();
    let username = user_base_i.username;

    let totp = match totp_struct(username, &s_config.encrypt_key, database_conn).await {
        Ok(Some(tmp)) => tmp,
        Ok(None) => {
            info_logs(&req, "TOTPSecretNotFound", "查找用户的 totp secret 错误");
            return HttpResponse::NotFound();
        },
        Err(e) => {
            error_logs(&req, "生成 TOTP 结构体错误", &e.to_string());
            return HttpResponse::InternalServerError();
        }
    };

    match totp_token_verify(totp, &info.token).await {
        Ok(true) => {
            totp_verify_status_change(&session.session, database_conn).await
                .map(|_| HttpResponse::Ok())
                .unwrap_or(HttpResponse::InternalServerError())
            // HttpResponse::Ok()
        },
        Ok(false) => {
            info_logs(&req, "TOTPTokenVerifyFaild", "TOTP Token 验证不通过");
            HttpResponse::Unauthorized()
        },
        Err(e) => {
            error_logs(&req, "TOTPTokenVerifyError", &e.to_string());
            HttpResponse::InternalServerError()
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
    user_base_i: UserBaseI
) -> impl Responder {
    let pool_c = pool.get_ref();
    
    if user_base_i.role != 1 {
        return HttpResponse::Forbidden();
    };
    match unbind_2fa(&unbind_info.username, pool_c).await {
        Ok(true) => {
            info_logs(&req, "Unbind2FASuccessful", "解绑 2FA 成功");
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
}


/// 获取用户信息
/// 
#[get("/api/userinfo/get")]
async fn get_user_info_h(
    req: HttpRequest,
    info: web::Query<GetUserInfoH>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI
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

}


/// 更新用户信息
///
#[post("/api/userinfo/update")]
async fn update_user_info_h(
    req: HttpRequest,
    new_user_i: web::Json<UserBaseInfo>,
    pool: web::Data<deadpool_postgres::Pool>,
    user_base_i: UserBaseI
) -> impl Responder {
    let pool_ref = pool.get_ref();

    match update_user_info(&user_base_i.username, user_base_i.role, &new_user_i, pool_ref).await {
        Ok(()) => {
            HttpResponse::Ok()
        },
        Err(e) => {
            error_logs(&req, "UpdateUserInfoError", &e.to_string());
            HttpResponse::InternalServerError()
        }
    }
}


/// 添加扫描器
/// 
/// 主要是 web 端添加用的
#[post("/api/scanner/add")]
async fn web_add_scanner_h(
    req:HttpRequest,
    pool: web::Data<Pool>,
    user_base_i: UserBaseI,
    add_data: web::Json<AddScanner>
) -> impl Responder {
    let pool_ref = pool.get_ref();
    let s_id = match web_add_scanner(pool_ref, user_base_i.id, add_data.deref()).await {
        Ok(ok) => ok,
        Err(e) => {
            error_logs(&req, "AddScannerError", &e.to_string());
            return HttpResponse::InternalServerError().finish()
        }
    };
    let res_data = json!({
        "success": true,
        "data": s_id
    });
    HttpResponse::Ok().json(res_data)
}

/// 扫描器注册
/// 
#[post("/api/scanner/register")]
async fn scanner_register_h(
    req: HttpRequest,
    pool: web::Data<Pool>,
    register_data: web::Json<ScannerRegisterData>
) -> impl Responder {
    
    match scanner_register(&pool, &register_data).await {
        Ok(_) => {
            HttpResponse::Ok()
        },
        Err(e) => {
            error_logs(&req, "ScannerRegister", &e.to_string());
            if e.to_string() == "scanner unauthorized" {
                return HttpResponse::Unauthorized();
            }
            HttpResponse::InternalServerError()
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
