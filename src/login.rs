
use actix_web::{HttpRequest, dev::ConnectionInfo};
use actix_web::web;
use tracing::{warn, info, error};
// use actix_session::storage::{SessionStore, SessionKey};
use uuid::Uuid;

use crate::{get_conn_ip, login};
use crate::{
    get_unix_epoch_ms, 
    verify_password, 
    logs::LoginLog,
    logs::{write::login_logs_to_db}, 
    get_password_from_database
};

pub struct LoginToken {
    pool: deadpool_postgres::Pool,
}


pub struct SessionInfo<'a> {
    session: String,
    create_time: i64,
    ttl: u32,
    username: &'a str,
}

impl LoginToken {
//TODO 明天完善此处
    ///生成一个session并保存
    pub async fn create_session<'a>(&self, ttl: u32, u_name: &'a str) -> SessionInfo<'a> {
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
                session
            },
            Err(e) => {
                error!(
                    event = "SaveSessionFailed",
                    message = "Save Session Failed"
                );
                SessionInfo {
                    session: "".to_string(),
                    create_time: 0,
                    ttl: 0,
                    username: u_name
                }
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
    pub async fn save(&self, sessioninfo: &SessionInfo<'_>) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        //查找用户的id
        let row = transaction.query_opt(
            "SELECT id FROM session WHERE username = $1;",
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
        let r_rows = transaction.execute(
            "INSERT INTO session (userid, token, ttl, create_time) VALUES ( $1, $2, $3, $4 );",
            &[
                &userid,
                &sessioninfo.session,
                &sessioninfo.ttl,
                &sessioninfo.create_time
            ]
        ).await?;
        if r_rows == 1 {
            transaction.commit().await?;
            Ok(())
        }
        else {
            transaction.rollback();
            error!(
                event = "INSERTDataError",
                message = "插入session错误，返回值不为一"
            );
            Err("插入数据不正确".into())
        }
    }

    ///检查token是否有效和存在
    pub async fn check_token(&self, session: &str) -> Result<(), Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;
        let stmt = client.prepare("SELECT token FROM session WHERE token = $1 AND is_enable = true;").await?;
        if client.query_opt(&stmt, &[&session]).await?.is_some() {
            Ok(())
        }
        else {
            warn!(
                event = "TokenUnvaild",
                message = "token已过期或不存在"
            );
            Err("未找到或已过期".into())
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
    req: HttpRequest,
    conn_info: ConnectionInfo, 
    username: &str, 
    password: &str, 
    pool: web::Data<deadpool_postgres::Pool>
) -> Result<String, Box<dyn std::error::Error>> {

    let pwd_hash = get_password_from_database(pool.get_ref().clone(), username).await?;
    if verify_password(password, pwd_hash.as_str()) {
    
        let loginlogs = LoginLog {
            event_ip : get_conn_ip(&req),
            event_useage_userid: 12121212,         //MARK 暂时这样，先提交再改
            is_successful: true
        };
        //MARK 暂时这样
        if login_logs_to_db(pool.get_ref().clone(), loginlogs).await {
            ();
        }
        else {
            error!(
                    event = "INSERTDataToDatabaseError",
                    path = "",
                    message = ""
                );
        }

        let login_token = LoginToken {pool: pool.get_ref().clone()};
        let session = login_token.create_session(2700, username).await;
        Ok(session.session)
    }
    else {
        Err("错误".into())
    }

    // let client = pool.get.await?;

    // let stmt = client
    //     .prepare("SELECT password FROM users WHERE username = $1")
    //     .await?;
    // if let Some(row) = client.query_opt(&stmt, &[&username]).await? {
    //     let stored_hash: String = row.get(0);

    //     if verify_password(password, &stored_hash) {
    //         logs::write::info_logs(&req, "登录成功", "用户登录成功", false);
    //         let login_token = LoginToken {
    //             pool: pool.get_ref().clone()                                                     // 克隆一份
    //         };
    //         let c_session = login_token.create_session(2700, username);
    //         Ok(())
    //     } else {
    //         logs::write::warn_logs(&req, "登录失败", "用户密码错误");
    //         Err("登录失败".into())
    //     }
    // } else {
    //     logs::write::error_logs(&req, "登录失败", "系统错误或未找到用户名");
    //     Err("LoginError".into())
    // }
}

