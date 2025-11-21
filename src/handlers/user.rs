
use crate::{admin, generate_hash_password, AddUserInfo};
use actix_web::{web, HttpResponse, Responder, HttpRequest, dev::ConnectionInfo, get, post, cookie, cookie::Cookie};
use crate::handlers::{ReceiveLoginInfo, ResponseLoginStatus};
use crate::login::user_login;
use crate::{TEXT_HTML_UTF_8};
use crate::logs::write::{error_logs, info_logs, warn_logs};
use serde_json::json;
use std::time;

#[get("/add")]
async fn first_add_user(pool: web::Data<deadpool_postgres::Pool>) -> impl Responder {
    match admin::is_user_exist("admin", pool.clone()).await {
        Ok(o) => {
            if o {
                println!("用户已存在");
                HttpResponse::Ok()
                    .content_type(TEXT_HTML_UTF_8)    
                    .body("用户已存在".to_string())
            }
            else {
                let p_hash = generate_hash_password("admin");
                match p_hash {
                    Ok(o) => {
                        let userinfo = AddUserInfo{
                            username: "admin".to_string(),
                            password_hash: o
                        };
                        let _ = admin::add_user(userinfo, pool).await;
                        HttpResponse::Ok()
                            .content_type(TEXT_HTML_UTF_8)
                            .body("用户添加成功")
                    },
                    Err(e) => HttpResponse::BadRequest().body(format!("系统错误，生成密码hash错误\n{}", e))
                }
            }
        },
        Err(e) => HttpResponse::BadRequest().body(format!("系统错误\n{}", e))
    }
}


/// 登录接口
#[post("/api/login")]
async fn user_login_h(
    req: HttpRequest,
    conn_info: ConnectionInfo,
    pool: web::Data<deadpool_postgres::Pool>,
    receiveinfo: web::Json<ReceiveLoginInfo>
) -> impl Responder {

    match user_login(&req, conn_info, &receiveinfo.username, &receiveinfo.password, pool).await {
        Ok(session) => {

            let body = json!({
                "success": true,
                "message": "登录成功"
            });
            let cookies = Cookie::build("session", &session)
                .path("/")
                .http_only(true)
                .secure(true)
                .max_age(cookie::time::Duration::seconds(2700))
                .finish();
            HttpResponse::Ok()
                .cookie(cookies)
                .json(body)
        },
        Err(e) => {
            let log_event = "LoginFaild";
            let log_message = &receiveinfo.username;
            error_logs(&req, log_event, log_message.as_str());
            let body = json!({
                "success": false,
                "message": "登录失败"
            });
            HttpResponse::Ok()
                .json(body)
        }
    }
}

