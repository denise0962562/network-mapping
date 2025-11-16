
use actix_web::{HttpRequest, dev::ConnectionInfo};
use actix_web::web;
use tracing::{warn, info, error};
// use actix_session::storage::{SessionStore, SessionKey};
use uuid::Uuid;

use crate::{get_unix_epoch_ms, verify_password, logs};

pub struct LoginToken {
    pool: deadpool_postgres::Pool,
}


pub struct SessionInfo {
    session: String,
    create_time: i64,
    ttl: u32,
    username: String,
}

impl LoginToken {
    ///生成一个cookie
    pub fn generate(ttl: u32, u_name: String) -> SessionInfo {
        SessionInfo { 
            session: Uuid::new_v4().to_string(), 
            create_time: get_unix_epoch_ms(), 
            ttl: ttl, 
            username: u_name 
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
    pub async fn save(&self, sessioninfo: SessionInfo) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        //需要返回一行数据
        // if let Some(userid) = transaction.query_opt(
        //     "SELECT id FROM session WHERE username = $1;", 
        //     &[&sessioninfo.username])
        //     .await? {
        //         let stmt = transaction.prepare(
        //     "INSERT INTO session (userid, token, ttl, create_time) VALUES ( $1, $2, $3, $4 );")
        //             .await?;
        //         let r_rows = transaction.execute(
        //             &stmt, 
        //             &[&userid.get::<_, i32>("id"), 
        //             &sessioninfo.session, 
        //             &sessioninfo.ttl, 
        //             &sessioninfo.create_time]
        //         ).await?;
        //         if r_rows == 1{
        //             transaction.commit().await?;
        //             Ok(())
        //         }
        //         else {
        //             Err("插入数据数量不正确".into())
        //         }
        //     }
        //     else {
        //         warn!(
        //             event = "",
        //             message = ""
        //         );
        //         Err("未找到用户或找到多个".into())
        //     }
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



pub async fn user_login(
    req: HttpRequest,
    conn_info: ConnectionInfo, 
    username: &str, 
    password: &str, 
    pool: web::Data<deadpool_postgres::Pool>
) -> Result<(), Box<dyn std::error::Error>> {
    let client = pool.get().await?;

    let stmt = client
        .prepare("SELECT password FROM users WHERE username = $1")
        .await?;
    if let Some(row) = client.query_opt(&stmt, &[&username]).await? {
        let stored_hash: String = row.get(0);

        if verify_password(password, &stored_hash) {
            logs::write::info_logs(&req, "登录成功", "用户登录成功", false);
            Ok(())
        } else {
            logs::write::warn_logs(&req, "登录失败", "用户密码错误");
            Err("登录失败".into())
        }
    } else {
        logs::write::error_logs(&req, "登录失败", "系统错误或未找到用户名");
        Err("登录失败".into())
    }
}

