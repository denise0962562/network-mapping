
use actix_web::{HttpRequest, dev::ConnectionInfo};
use actix_web::web;
use tracing::{warn, info, error};
// use actix_session::storage::{SessionStore, SessionKey};
use uuid::Uuid;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use crate::{get_conn_ip, login};
use crate::{
    get_unix_epoch_ms, 
    verify_password, 
    logs::LoginLog,
    logs::{write::login_logs_to_db}, 
    get_password_and_id_from_database
};

pub struct LoginToken {
    pub pool: deadpool_postgres::Pool,
}


pub struct SessionInfo<'a> {
    session: String,
    create_time: i64,
    ttl: i32,
    username: &'a str,
}

impl LoginToken {
//TODO 明天完善此处
    ///生成一个session并保存
    pub async fn create_session<'a>(&self, ttl: i32, u_name: &'a str) -> (SessionInfo<'a>, i32, i32) {
        let session = SessionInfo { 
            session: Uuid::new_v4().to_string(), 
            create_time: get_unix_epoch_ms(), 
            ttl: ttl, 
            username: u_name 
        };
        match self.save(&session).await {
            Ok(o) => {
                info!(
                    event = "SuccessfulSaveSession",
                    message = "Successful Save Session "
                );
                (session, o.0, o.1)
            },
            Err(e) => {
                error!(
                    event = "SaveSessionFailed",
                    message = %e
                );
                (SessionInfo {
                    session: "".to_string(),
                    create_time: 0,
                    ttl: 0,
                    username: u_name
                }, 0, 0)
            }
        }
        
    }

    ///将token设置为未启用状态
    pub async fn delete(&self, session: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        let stmt = transaction.prepare("UPDATE session SET is_enable = false WHERE token = $1;").await?;
        transaction.execute(&stmt, &[&session]).await?;
        transaction.commit().await?;
        Ok(())
    }

    ///保存一个token,
    /// 返回result，当成功时为OK
    pub async fn save(&self, sessioninfo: &SessionInfo<'_>) -> Result<(i32, i32), Box<dyn std::error::Error>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        //查找用户的id
        let row = transaction.query_opt(
            "SELECT id FROM users WHERE username = $1;",
            &[&sessioninfo.username]
        ).await?;

        let row = match row {
            Some(o) => o,
            None => {
                info!(
                    event = "SearchUserIDError",
                    message = "未找到用户或其他错误",
                    data = ?row                           //将返回的row结构化的输出到日志中
                );
                return Err("用户不存在或其他错误".into())
            }
        };

        let userid: i32 = row.get("id");
        //插入一条session,其中包括了用户id token 有效时间，创建时间
        if let Some(r_rows) = transaction.query_opt(
            "INSERT INTO session (user_id, token, ttl, create_time) VALUES ( $1, $2, $3, $4 ) RETURNING id, user_id;",
            &[
                &userid,
                &sessioninfo.session,
                &sessioninfo.ttl,
                &sessioninfo.create_time
            ]
        ).await? {
            transaction.commit().await?;
            return Ok((r_rows.get::<_, i32>("id"), r_rows.get::<_, i32>("user_id")))
        }
        else {
            error!(
                event = "INSERTDataError",
                message = "插入session错误，返回值不为一"
            );
            Err("插入数据不正确".into())
        }
    }

    ///检查token是否有效和存在
    /// 
    /// 找到token且token还未过期时返回 true ，未找到或已过期时返回当返回值多于一行时返回错误
    pub async fn check_token(&self, session: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;
        let stmt = client.prepare("SELECT token, ttl, create_time FROM session WHERE token = $1 AND is_enable = true LIMIT 1;").await?;

        if let Some(r_s) = client.query_opt(&stmt, &[&session]).await? {
            let n_t = get_unix_epoch_ms();
            let r_ttl:i32 = r_s.get("ttl");
            let r_create_time:i64 = r_s.get("create_time");
            let end_at = r_create_time + (r_ttl as i64) * 1000;

            if n_t >= end_at {
                warn!(event = "TokenInvaild", message = "Token 无效");
                self.delete(session).await?;
                Ok(false)
            }
            else {
                Ok(true)
            }
        }
        else {
            warn!(event = "TokenInvaild", message = "Token 无效");
            Ok(false)
        }
    }

    // pub async fn update_session_ttl(&self, session: &str) -> Result<(), Box<dyn std::error::Error>> {
    //     let mut client = self.pool.get().await?;
    //     let transaction = client.transaction().await?;
    //     let stmt = transaction.prepare("UPDATE token FROM session WHERE token = $1 AND ").await?;
        
    // }

}


/// 该函数用于处理用户登录，接受一个用户名和密码，如果密码校验成功则返回一个session，失败则传递错误
pub async fn user_login(
    req: &HttpRequest,
    username: &str, 
    password: &str, 
    pool: &deadpool_postgres::Pool
) -> Result<(String, i32, i32), Box<dyn std::error::Error>> {

    let start = Instant::now();

    let (tmp_id, pwd_hash) = get_password_and_id_from_database(pool, username).await?;
    let get_pwd_h = start.elapsed();
    println!("get_p   : {:>6} ms", get_pwd_h.as_millis());

    if verify_password(password, &pwd_hash) {
        let e_ip: IpAddr = match get_conn_ip(&req).parse() {
            Ok(o) => o,
            Err(e) => {
                error!(
                    event = "StringToIpAddrError",
                    path = "fn user_login",
                    message = %e
                );
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))                               //其中 IPV4 地址 0.0.0.0 表示从 String 转换为 IP 地址失败
            }
        };

        let start = Instant::now();
    
        let loginlogs = LoginLog {
            event_ip :  e_ip,
            event_useage_userid: tmp_id,         //MARK 暂时这样，先提交再改
            is_successful: true
        };
        //MARK 暂时这样
        if login_logs_to_db(pool, loginlogs).await {
            ();
        }
        else {
            error!(
                    event = "INSERTDataToDatabaseError",
                    path = "",
                    message = "向数据库中插入登录日志数据错误"
                );
        }
        println!("to_db   : {:>6} ms", start.elapsed().as_millis());
        let start = Instant::now();

        let login_token = LoginToken {pool: pool.clone()};
        let (session, session_id, user_id) = login_token.create_session(2700, username).await;
        println!("c_sess  : {:>6} ms", start.elapsed().as_millis());
        Ok((session.session, session_id, user_id))
    }
    else {
        Err("登录失败".into())
    }

}

/// 该函数用于从 req 中获取 session
/// 
/// **需要注意生命周期，返回一个 Option<&str> ，其生命周期于传入的 cookie_n 一致**
/// 
/// 我认为该函数不需要做日志，日志就交给调用者了
pub fn get_session_from_req(req: &HttpRequest, cookie_n: &str) -> Option<String> {
    match req.cookie(cookie_n) {
        Some(cookie) => Some(cookie.value().to_string()),
        None => None
    }
}
