
use crate::get_unix_epoch_ms;
use crate::verify_password;
use crate::logs;
use actix_web::{HttpRequest, dev::ConnectionInfo};
use actix_web::web;
// use actix_session::storage::{SessionStore, SessionKey};
use uuid::Uuid;

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

    ///保存一个token
    pub async fn save(&self, sessioninfo: SessionInfo) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        //需要恰巧一行返回，否则直接报错
        if let Some(userid) = transaction.query_opt(
            "SELECT id FROM session WHERE username = $1;", 
            &[&sessioninfo.username])
            .await? {
                let stmt = transaction.prepare(
            "INSERT INTO session (userid, token, ttl, create_time) VALUES ( $1, $2, $3, $4 );")
                    .await?;
                let r_rows = transaction.execute(
                    &stmt, 
                    &[&userid.get::<_, i32>("id"), 
                    &sessioninfo.session, 
                    &sessioninfo.ttl, 
                    &sessioninfo.create_time]
                ).await?;
                if r_rows == 1{
                    transaction.commit().await?;
                    Ok(())
                }
                else {
                    Err("插入数据数量不正确".into())
                }
            }
            else {
                
                Err("未找到用户或找到多个".into())
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
            Err("未找到或已过期".into())
        }

    }
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
            logs::write::info_logs(&req, &conn_info, "登录成功", "用户登录成功", false);
            Ok(())
        } else {
            logs::write::warn_logs(&req, &conn_info, "登录失败", "用户密码错误");
            Err("登录失败".into())
        }
    } else {
        logs::write::error_logs(&req, &conn_info, "登录失败", "系统错误或未找到用户名");
        Err("登录失败".into())
    }
}

