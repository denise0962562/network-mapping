
use crate::{admin, generate_hash_password, AddUserInfo};
use actix_web::{web, HttpResponse, Responder, HttpRequest, dev::ConnectionInfo, get, post};
use crate::handlers::{ReceiveLoginInfo, ResponseLoginStatus};
use crate::login::user_login;
use crate::{TEXT_HTML_UTF_8};

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

#[post("/api/login")]
async fn user_login_h(
    req: HttpRequest,
    conn_info: ConnectionInfo,
    pool: web::Data<deadpool_postgres::Pool>,
    receiveinfo: web::Json<ReceiveLoginInfo>
) -> web::Json<ResponseLoginStatus> {

    match user_login(req, conn_info, &receiveinfo.username, &receiveinfo.password, pool).await {
        Ok(_) => {
            web::Json(
                ResponseLoginStatus { success: true, message: "登录成功".to_string() }
            )
        },
        Err(_) => {
            web::Json(
                ResponseLoginStatus { success: false, message: "用户名或密码错误".to_string() }
            )
        }
    }
}

