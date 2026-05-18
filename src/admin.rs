use serde::Deserialize;
use tracing::{info, warn};
use lettre::{Message, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
// use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{AddUserInfo, config::EmailConfig};

/// 该结构体用于接收测试使用的创建用户信息
#[derive(Deserialize)]
pub struct ReceiveAddUserInfo {
    pub username: String,
    pub password: String,
    pub role: i32
}

pub enum UserRole {
    System,
    Administrator,
    User
}

/// TOTP 相关信息
pub struct TotpInfo {
    pub username: String,
    // pub email_address: String,
    pub totp_secret: String
}

#[derive(Deserialize)]
pub struct VerifyTotp {
    pub username: String,
    pub token: String
}


///该函数用于添加用户，且需要调用者处理日志。
pub async fn add_user<'a>(user: AddUserInfo<'a>, pool: &deadpool_postgres::Pool) -> Result<(), Box<dyn std::error::Error>> {
    let _ = user.check()?;
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let stmt = transaction.prepare("INSERT INTO users (username, password, role) VALUES ($1, $2, $3); ").await?;
    let r = transaction.execute(&stmt, &[&user.username, &user.password_hash, &user.role]).await?;
    if r != 1 {
        let message = format!("添加用户时所影响的行数不为 1 ({})", r);
        transaction.rollback().await?;
        Err(message.into())
    }
    else {
        transaction.commit().await?;
        Ok(())
    }
}

///该函数用于检查用户是否存在
/// 
/// 如果用户存在则返回true
pub async fn is_user_exist(username: &str, pool: &deadpool_postgres::Pool) -> Result<bool, Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    let stmt = client.prepare("SELECT username FROM users WHERE username = $1;").await?;
    if  client.query_opt(&stmt, &[&username]).await?.is_some() {
        Ok(true)
    }
    else {
        Ok(false)
    }
}

/// 该函数通过 cookie 获取用户名与其 ID
/// 
/// FIXME 需要解决 pool 类型错误问题
pub async fn get_user_id_and_name<'a>(
    seeion: &'a str,
    pool: &deadpool_postgres::Pool
) -> Result<(i32, String), Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    let row = client.query_one(
        "SELECT s.user_id, u.username FROM session s CROSS JOIN users u WHERE s.token = $1 AND s.is_enable = True AND u.limit_login = False AND s.user_id = u.id;", 
        &[&seeion]
    ).await?;

    Ok((row.get::<_, i32>("user_id"), row.get::<_, String>("username")))
}

/// 检查系统用户数量，该操作在系统启动前执行。
/// 
/// 一个系统只能有一个系统用户，且为必须项，所以该函数出现错误时则应当直接 panic
pub async fn check_system_user(
    pool: &deadpool_postgres::Pool
) {
    let c = &pool.get().await.unwrap();
    match c.query("SELECT * FROM users WHERE role = 0;", &[]).await.unwrap().len() {
        0 => {
            // 创建系统用户
            warn!(
                event = "SystemRoleNotFound",
                path = "fn check_system_role",
                message = "没有找到系统用户，正在创建一个新的系统用户"
            );
            println!("没有找到系统用户，正在创建一个新的系统用户");
            create_system_user(&pool).await;

        },
        1 => {
            println!("找到系统用户")
        },
        _ => {
            panic!("找到多个系统用户，请手动清理多余的系统用户!");
        }
    }
}

/// 创建系统角色
/// 
pub async fn create_system_user(
    pool: &deadpool_postgres::Pool
) {
    let mut c = pool.get().await.unwrap();
    let transaction = c.transaction().await.unwrap();
    transaction.execute(
        "INSERT INTO users (username, password, role, limit_login) VALUES ($1, $2, $3, $4);",
        &[&"system", &"No Password", &0, &true]
    ).await.unwrap();
    info!(
        event = "CreateSystemUser",
        path = "fn create_system_user",
        message = "创建系统用户成功"
    );
    println!("创建系统用户成功");
    transaction.commit().await.unwrap();
}

/// 发送邮件
/// 
pub async fn send_email(
    emailconf: &EmailConfig,
    mail: Message
) {
    let creds = Credentials::new(emailconf.account_username.to_string(), emailconf.account_password.to_string());

    // 使用465端口，且强制加密
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&emailconf.host).unwrap().credentials(creds).build();
    match mailer.send(mail).await {
        Ok(_) => {
            info!(
                event = "SendEmailSuccessfully",
                path = "fn send_email",
                message = "Email sent successfully!"
            );
            println!("Email sent successfully!")
        },
        Err(e) => {
            warn!(
                event = "SendEmailError",
                path = "fn send_email",
                message = format!("Could not send email: {e:?}")
            );
            println!("Could not send email: {e:?}")
        },
    }
}

// 创建 TOTP 结构体
// 
pub async fn totp_struct(
    username: String,
    pool: &deadpool_postgres::Pool
) -> Result<TOTP, Box<dyn std::error::Error>> {
    let c = pool.get().await?;
    if let Some(r) = c.query_opt(
        "SELECT id, totp_secret FROM users WHERE limit_login = false AND enable_2fa = true AND username = $1;",
        &[&username]
    ).await? {
        Ok(
            TOTP::new(
            Algorithm::SHA1, 
            6, 
            1, 
            30, 
            Secret::Encoded(r.get::<_, String>("totp_secret")).to_bytes()?, 
            Some("Network Mapping".to_string()), 
            username
        )?)
    } else {
        Err("查找用户的 totp secret 错误".into())
    }

}

/// 检查 2FA 是否已绑定
/// 
pub async fn check_twofa_bind(
    username: &str,
    pool: &deadpool_postgres::Pool
) -> Result<bool, Box<dyn std::error::Error>> {
    let database_conn = pool.get().await?;
    if let Some(r) = database_conn.query_opt(
        "SELECT username FROM users WHERE username = $1 AND enable_2fa = true AND totp_secret <> NULL;",
        &[&username]
    ).await? {
        return Ok(true)
    } else {
        Ok(false)
    }
}

/// TOTP 密钥创建
/// 
pub async fn bind_twofa(
    username: String,
    pool: &deadpool_postgres::Pool
) -> Result<String, Box<dyn std::error::Error>> {
    let secret32 = Secret::generate_secret();

    let totp = TOTP::new(
        Algorithm::SHA1, 
        6, 
        1, 
        30, 
        secret32.to_bytes()?, 
        Some("Network Mapping".to_string()), 
        (&username).to_string()
    )?;

    let url = totp.get_url();
    let mut c = pool.get().await?;
    let transaction = c.transaction().await?;
    let _r = transaction.execute(
        "INSERT INTO users (totp_secret) VALUES ($1) WHERE username = $2;",

        // 此处的 secret32 是经过 base32 编码后的数据
        &[&secret32.to_encoded().to_string(), &username]
    ).await?;
    println!("otpauth url:{}", url);

    Ok(url)
}

/// 验证 TOTP token
/// 
/// 
pub async fn totp_token_verify(
    totp: TOTP, 
    token: &str
) -> Result<bool, Box<dyn std::error::Error>> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let current_token = totp.generate(seconds);
    println!("当前token：{}", &current_token);
    if totp.check(token, seconds) {
        println!("成功");
        Ok(true)
    }
    else {
        println!("验证失败");
        Ok(false)
    }
}