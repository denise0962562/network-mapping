use actix_web::HttpRequest;
use lettre::Message;
use lettre::message::{Mailbox, header::ContentType};
use openssl::base64;
use std::time::Instant;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::UserLoginInfo;
use crate::config::EmailConfig;
use crate::{
    admin::send_email, get_password_and_id_from_database, get_unix_epoch_ms, verify_password,
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
    ///生成一个session 和 csrftoken 并保存
    pub async fn create_session<'a>(
        &self,
        ttl: i32,
        u_name: &'a str,
        enable_2fa: bool,
    ) -> Result<(SessionInfo<'a>, String), Box<dyn std::error::Error>> {
        let session = SessionInfo {
            session: Uuid::new_v4().to_string(),
            create_time: get_unix_epoch_ms(),
            ttl: ttl,
            username: u_name,
        };

        let mut tmp_csrf_token_buffer: [u8; 32] = [0; 32];
        let csrf_token_base64 = match openssl::rand::rand_bytes(&mut tmp_csrf_token_buffer) {
            Ok(_) => base64::encode_block(&tmp_csrf_token_buffer),
            Err(e) => {
                error!(
                    event = "GenerateCSRFTokenError",
                    path = "LoginToken => fn create_session",
                    message = %e
                );
                return Err(e.into());
            }
        };
        match self.save(&session, &csrf_token_base64, enable_2fa).await {
            Ok(_o) => {
                info!(
                    event = "SuccessfulSaveSession",
                    message = "Successful Save Session "
                );
                Ok((session, csrf_token_base64))
            }
            Err(e) => {
                error!(
                    event = "SaveSessionFailed",
                    path = "LoginToken => fn create_session => self.save",
                    message = %e
                );
                return Err(e.into());
            }
        }
    }

    ///将token设置为未启用状态
    pub async fn delete(&self, session: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;
        let stmt = transaction
            .prepare("UPDATE session SET is_enable = false WHERE token = $1;")
            .await?;
        transaction.execute(&stmt, &[&session]).await?;
        transaction.commit().await?;
        Ok(())
    }

    ///保存一个token,
    /// 返回result，当成功时为OK
    pub async fn save(
        &self,
        sessioninfo: &SessionInfo<'_>,
        csrftoken: &str,
        enable_2fa: bool,
    ) -> Result<(i32, i32), Box<dyn std::error::Error>> {
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        //查找用户的id
        let row = transaction
            .query_opt(
                "SELECT id FROM users WHERE username = $1;",
                &[&sessioninfo.username],
            )
            .await?;

        let row = match row {
            Some(o) => o,
            None => {
                info!(
                    event = "SearchUserIDError",
                    message = "未找到用户或其他错误",
                    data = ?row                           //将返回的row结构化的输出到日志中
                );
                return Err("用户不存在或其他错误".into());
            }
        };

        let userid: i32 = row.get("id");
        //插入一条session,其中包括了用户id token 有效时间，创建时间
        if let Some(r_rows) = transaction.query_opt(
            "INSERT INTO session (user_id, token, csrf_token, ttl, totp_verify_successful, create_time) VALUES ( $1, $2, $3, $4, $5, $6 ) RETURNING id, user_id;",
            &[
                &userid,
                &sessioninfo.session,
                &csrftoken,
                &sessioninfo.ttl,
                &!enable_2fa,
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
    pub async fn check_token(
        &self,
        session: &str,
        verify_csrf_token: bool,
    ) -> Result<(bool, i32), Box<dyn std::error::Error>> {
        const SELECT_STAT: &str = "SELECT user_id, token, ttl, create_time FROM session WHERE token = $1 AND is_enable = true ";

        let select_stat = match verify_csrf_token {
            true => format!("{} AND totp_verify_successful = true LIMIT 1;", SELECT_STAT),
            false => format!("{} LIMIT 1;", SELECT_STAT),
        };

        let client = self.pool.get().await?;
        let stmt = client.prepare(&select_stat).await?;

        if let Some(r_s) = client.query_opt(&stmt, &[&session]).await? {
            let n_t = get_unix_epoch_ms();
            let r_ttl: i32 = r_s.get("ttl");
            let r_create_time: i64 = r_s.get("create_time");
            let end_at = r_create_time + (r_ttl as i64) * 1000;

            if n_t >= end_at {
                warn!(event = "TokenInvaild", message = "Token 无效");
                self.delete(session).await?;
                Ok((false, -1))
            } else {
                Ok((true, r_s.get("user_id")))
            }
        } else {
            warn!(
                event = "TokenInvaild",
                path = "fn check_token",
                message = "Token 无效"
            );
            Ok((false, -1))
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
    username: &str,
    password: &str,
    mail_config: Option<&EmailConfig>,
    pool: &deadpool_postgres::Pool,
) -> Result<(String, String, bool), Box<dyn std::error::Error>> {
    let l_successful: bool;
    let start = Instant::now();

    // 即使用户名不存在也校验密码，预防时序攻击
    let (_user_id, pwd_hash, user_login_info) = match get_password_and_id_from_database(
        pool, username,
    )
    .await
    {
        Ok(o) => {
            l_successful = true;
            o
        }
        Err(e) => {
            l_successful = false;
            error!(
                event = "GetUserPasswordHashError",
                path = "fn user_login",
                message = %e
            );
            let t = UserLoginInfo {
                username: String::new(),
                role: -1,
                email_address: None,
                twofa: None,
            };
            // FIXME 当用户不存在时会提供一个默认的校验，但是，如果用户自己调整了密码加密参数，则会导致默认提供的参数实际计算时间与用户其他的密码校验时间不一致
            (-1 as i32, "$argon2id$v=19$m=65536,t=2,p=2$nuz5oKNAIFXP1wPaVW3aQw$9piWt9X5WVTIbCnq2DQuNDbGDhW5s2UnTe9rVWtx3II".to_string(), t)
        }
    };
    let get_pwd_h = start.elapsed();
    println!("get_p   : {:>6} ms", get_pwd_h.as_millis());

    // 当用户不存在或者是查找用户错误时使用提供的默认密文校验密码
    if verify_password(password, &pwd_hash) && l_successful {
        let start = Instant::now();
        let enable_2fa = user_login_info.twofa.map(|_| true).unwrap_or(false);

        let login_token = LoginToken { pool: pool.clone() };
        let (session, csrf_token) = login_token
            .create_session(2700, username, enable_2fa)
            .await?;
        println!("c_sess  : {:>6} ms", start.elapsed().as_millis());

        if let Some(m_config) = mail_config {
            match user_login_info.email_address {
                Some(mail_address) => {
                    let mail_message = Message::builder()
                        .from(Mailbox::new(
                            Some("Network Mapping".to_string()),
                            "test@mail.abdc.world".to_string().parse().unwrap(),
                        ))
                        .to(Mailbox::new(None, mail_address.parse().unwrap()))
                        .subject("Test".to_string())
                        .header(ContentType::TEXT_PLAIN)
                        .body("登录成功".to_string())
                        .unwrap();

                    send_email(m_config, mail_message).await;
                }
                None => (),
            };
        }
        Ok((session.session, csrf_token, enable_2fa))
    } else {
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
        None => None,
    }
}
