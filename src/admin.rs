use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use lettre::{Message, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
// use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};
use postgres_from_row::FromRow;
use cidr::IpInet;

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

/// 接受解绑 2FA 信息
#[derive(Deserialize)]
pub struct Unbind2FAH {
    pub username: String
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
    session: &'a str,
    pool: &deadpool_postgres::Pool
) -> Result<(i32, i32, String), Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    let row = client.query_one(
        "SELECT s.user_id, u.username, u.role FROM session s CROSS JOIN users u WHERE s.token = $1 AND s.is_enable = True AND u.limit_login = False AND s.user_id = u.id;", 
        &[&session]
    ).await?;

    Ok((row.get::<_, i32>("user_id"), row.get::<_, i32>("role"), row.get::<_, String>("username")))
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
) -> Result<Option<TOTP>, Box<dyn std::error::Error>> {
    let c = pool.get().await?;

    match c.query_opt(
        "SELECT id, totp_secret FROM users WHERE limit_login = false AND enable_2fa = true AND username = $1;",
        &[&username]
    ).await? {
        Some(r) => {
            Ok(Some(
                TOTP::new(
                Algorithm::SHA1, 
                6, 
                1, 
                30, 
                Secret::Encoded(r.get::<_, String>("totp_secret")).to_bytes()?, 
                Some("Network Mapping".to_string()), 
                username
            )?))
        },
        None => {
            Ok(None)
        }
    }
}

/// 检查 2FA 是否已绑定
/// 
pub async fn check_twofa_bind(
    username: &str,
    pool: &deadpool_postgres::Pool
) -> Result<bool, Box<dyn std::error::Error>> {
    let database_conn = pool.get().await?;
    if let Some(_r) = database_conn.query_opt(
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
        "UPDATE users SET totp_secret = $1 AND enable_2fa = true WHERE username = $2;",

        // 此处的 secret32 是经过 base32 编码后的数据
        &[&secret32.to_encoded().to_string(), &username]
    ).await?;
    transaction.commit().await?;
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

/// totp 验证状态更改
pub async fn totp_verify_status_change(
    session: &str,
    pool: &deadpool_postgres::Pool
) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let db_transaction = conn.transaction().await?;
    let r = db_transaction.execute(
        "UPDATE session SET totp_verify_successful = true WHERE token = $1;",
        &[&session]
    ).await?;
    if r == 0 {
        warn!(
            event = "ChangeTotpStatus",
            path = "fn totp_verify_status_change",
            message = "没有更改 totp verify 状态"
        );
        Ok(())
    } else if r == 1 {
        db_transaction.commit().await?;
        Ok(())
    } else {
        Err(format!("更改 totp verify status 影响 {} 行", r).into())
    }
}

/// 解除 2FA 绑定
/// 
/// **该操作只能由管理员操作**,
/// 且需要调用者做权限判断
pub async fn unbind_2fa(
    username: &str,
    pool: &deadpool_postgres::Pool
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut c = pool.get().await?;
    let db_transaction = c.transaction().await?;
    let r =  db_transaction.execute(
        "UPDATE users SET enable_2fa = false AND totp_secret = NULL WHERE username = $1;",
        &[&username]
    ).await?;
    if r == 1 {
        info!(
            event = "Unbind2FASuccessful",
            path = "fn unbind_2fa",
            message = format!("用户 {} 解绑 2FA 成功", username)
        );
        Ok(true)
    } else if r == 0 {
        warn!(
            event = "Unbind2FAWarning",
            path = "fn unbind_2fa",
            message = format!("用户 {} 没有绑定 2FA", username)
        );
        Ok(false)
    } else {
        error!(
            event = "Unbind2FAfaild",
            path = "fn unbind_2fa",
            message = "数据库更新条目数不等于 0 和 1"
        );
        Err("数据库更新条目数不等于 0 和 1".into())
    }
}

#[derive(Deserialize)]
pub struct GetUserInfoH {
    pub username: Option<String>,
    pub list: Option<bool>,
    pub count: Option<u32>                          // 通过限制数据类型避免负数
}

#[derive(Deserialize, FromRow, Serialize)]
pub struct UserInfo {
    pub id: i32,
    pub username: String,
    pub role: i32,
    pub email: Option<String>,
    pub create_time: i64,
    pub limit_login: bool,
    pub limit_at: Option<i64>,
    pub limit_time: Option<i32>,
    pub enable_2fa: bool,
    pub last_login_at: Option<i64>,
    pub last_login_ip: Option<IpInet>,
    pub login_error_count: Option<i32>,
    pub last_error_at: Option<i64>
}

/// 获取用户信息
/// 
/// 当权限足够时可以通过将 username 设置为 None 来获取所有用户信息，
/// 条目限制默认 5 条
pub async fn get_user_info(
    role: i32,
    username: Option<&str>,
    limit_iteams: Option<i64>,
    pool: &deadpool_postgres::Pool
) -> Result<Vec<UserInfo>, Box<dyn std::error::Error>> {
    let database_conn = pool.get().await?;
    let limit_i = limit_iteams.unwrap_or(5);

    let r = match (role, username) {
        (1, None) => {
            database_conn.query(
                "SELECT id, username, role, email, create_time, limit_login, limit_at, limit_time, enable_2fa, last_login_at, last_login_ip, login_error_count, last_error_at FROM users LIMIT $1;",
                &[&limit_i]
            ).await?
        },
        (1 | 2, Some(username_t)) => {
            database_conn.query(
                "SELECT id, username, role, email, create_time, limit_login, limit_at, limit_time, enable_2fa, last_login_at, last_login_ip, login_error_count, last_error_at FROM users WHERE username = $1 LIMIT 1;",
                &[&username_t]
            ).await?
        },
        _ => return Err("没有对应的权限".into())
    };

    Ok( 
        r.iter().map(|row| -> UserInfo {
            FromRow::from_row(row)
        }).collect()
    )
}