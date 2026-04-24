use crate::middlewares::render_500;
use crate::{admin, generate_hash_password, AddUserInfo, log_out};
use actix_web::cookie::time::OffsetDateTime;
use actix_web::http::header;
use actix_web::{web, HttpResponse, Responder, HttpRequest, get, post, cookie, cookie::Cookie};
use tracing::error;
use crate::handlers::{ReceiveLoginInfo};
use crate::login::user_login;
use crate::{TEXT_HTML_UTF_8};
use crate::logs::write::{error_logs};
use serde_json::json;
use std::time::Instant;
use crate::config::PasswordHashConfig;
use crate::TemplatesInit;
use crate::admin::ReceiveAddUserInfo;

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
                        password_hash: o.as_str()
                    };
                    let _ = admin::add_user(userinfo, p).await;
                    println!("添加用户：{}:{}", &query_info.username, &query_info.password);
                    HttpResponse::Ok()
                        .content_type(TEXT_HTML_UTF_8)
                        .body("用户添加成功")
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
    receiveinfo: web::Json<ReceiveLoginInfo>
) -> impl Responder {
    println!("================= Benchmark =================");
    let total_start = Instant::now();                                                  // 总的开始时间
    let start = Instant::now();                                                        // 登录函数开始时间
    let p = pool.get_ref();
    let (t_session, csrf_token) = match user_login(&req, &receiveinfo.username, &receiveinfo.password, p).await {
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

    let body = json!({
        "success": true,
        "message": "登录成功"
    });
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
    HttpResponse::Ok()
        .cookie(cookies)
        .cookie(cookie_csrf_token)
        // .insert_header(("X-CSRF-Token", csrf_token))
        // .insert_header((header::ACCESS_CONTROL_EXPOSE_HEADERS, "X-CSRF-Token"))
        .json(body)

    
}


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
                error_logs(&req, "注销账号错误", e.to_string().as_str());
                let page = page_template.get_ref();
                render_500(&req, page, "注销账号错误")
            }
        }
    }
    else {
        HttpResponse::MovedPermanently()
            .insert_header((header::LOCATION, "/login"))
            .finish()
    }
}