use chrono::{DateTime, Utc};
use cidr::IpInet;
use deadpool_postgres::Pool;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use openssl::rand;
use postgres_from_row::FromRow;
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_postgres::Row;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::{EmailConfig, PasswordHashConfig, SystemConfig};
use crate::{AddUserInfo, generate_hash_password, generate_scanner_token, hash_scanner_token};
use crate::{decrypt_data, encrypt_data};

const DEFAULT_ADMIN_USERNAME: &str = "admin";
const DEFAULT_ADMIN_USERNAME_ENV: &str = "NM_DEFAULT_ADMIN_USERNAME";
const DEFAULT_ADMIN_PASSWORD_LEN: usize = 18;
const DEFAULT_ADMIN_PASSWORD_CHARS: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";

/// 该结构体用于接收测试使用的创建用户信息
#[derive(Deserialize)]
pub struct ReceiveAddUserInfo {
    pub username: String,
    pub password: String,
    pub role: i32,
}

pub enum UserRole {
    System = 0,
    Administrator = 1,
    User = 2,
}

/// TOTP 相关信息
pub struct TotpInfo {
    pub username: String,
    // pub email_address: String,
    pub totp_secret: String,
}

#[derive(Deserialize)]
pub struct VerifyTotp {
    pub token: String,
}

/// 接受解绑 2FA 信息
#[derive(Deserialize)]
pub struct Unbind2FAH {
    pub username: String,
}

/// web 添加扫描器
#[derive(Deserialize)]
pub struct AddScanner {
    pub name: String,
    pub location: Option<String>,
    pub remark: Option<String>,
    pub tag: Option<String>,
}

/// 扫描器注册
#[derive(Deserialize, Serialize)]
pub struct ScannerRegisterData {
    pub scanner_id: String,
}

/// web 端创建扫描器后返回的一次性注册凭据
#[derive(Serialize)]
pub struct ScannerRegisterSecret {
    pub scanner_id: String,
    pub registration_token: String,
}

/// 扫描器注册成功后返回的运行凭据
#[derive(Serialize)]
pub struct ScannerRuntimeSecret {
    pub runtime_token: String,
}

#[derive(Serialize)]
pub struct ScannerInfo {
    pub scanner_id: String,
    pub name: Option<String>,
    pub creator: Option<String>,
    pub location: Option<String>,
    pub ip_address: Option<String>,
    pub system_version: Option<String>,
    pub scanner_version: Option<String>,
    pub cpu_model: Option<String>,
    pub cpus: Option<i32>,
    pub ram: Option<i32>,
    pub uptime: Option<i32>,
    pub create_time: Option<DateTime<Utc>>,
    pub register_time: Option<DateTime<Utc>>,
    pub update_time: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub runtime_state: String,
    pub is_online: bool,
    pub current_task_id: Option<String>,
    pub is_run: Option<bool>,
    pub is_enable: Option<bool>,
    pub remark: Option<String>,
    pub tag: Option<String>,
}

pub enum ScannerEvent {
    Start = 0,
    Shutdown = 1,
    Normal = 2,
}

/// 扫描器健康数据
#[derive(Deserialize)]
pub struct ScannerHealthData {
    pub scanner_id: Uuid,
    pub status: String,
    pub uptime: u32,
    pub event: String,
}

///该函数用于添加用户，且需要调用者处理日志。
pub async fn add_user<'a>(
    user: AddUserInfo<'a>,
    pool: &deadpool_postgres::Pool,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = user.check()?;
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let stmt = transaction
        .prepare("INSERT INTO users (username, password, role) VALUES ($1, $2, $3); ")
        .await?;
    let r = transaction
        .execute(&stmt, &[&user.username, &user.password_hash, &user.role])
        .await?;
    if r != 1 {
        let message = format!("添加用户时所影响的行数不为 1 ({})", r);
        transaction.rollback().await?;
        Err(message.into())
    } else {
        transaction.commit().await?;
        Ok(())
    }
}

///该函数用于检查用户是否存在
///
/// 如果用户存在则返回true
pub async fn is_user_exist(
    username: &str,
    pool: &deadpool_postgres::Pool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    let stmt = client
        .prepare("SELECT username FROM users WHERE username = $1;")
        .await?;
    if client.query_opt(&stmt, &[&username]).await?.is_some() {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// 该函数通过 cookie 获取用户名与其 ID
///
/// FIXME 需要解决 pool 类型错误问题
pub async fn get_user_id_and_name<'a>(
    session: &'a str,
    pool: &deadpool_postgres::Pool,
) -> Result<(i32, i32, String), Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    let row = client.query_one(
        "SELECT s.user_id, u.username, u.role FROM session s CROSS JOIN users u WHERE s.token = $1 AND s.is_enable = True AND u.limit_login = False AND s.user_id = u.id;",
        &[&session]
    ).await?;

    Ok((
        row.get::<_, i32>("user_id"),
        row.get::<_, i32>("role"),
        row.get::<_, String>("username"),
    ))
}

/// 检查系统用户数量，该操作在系统启动前执行。
///
/// 一个系统只能有一个系统用户，且为必须项，所以该函数出现错误时则应当直接 panic
pub async fn check_system_user(pool: &deadpool_postgres::Pool) {
    let c = &pool.get().await.unwrap();
    match c
        .query("SELECT * FROM users WHERE role = 0;", &[])
        .await
        .unwrap()
        .len()
    {
        0 => {
            // 创建系统用户
            warn!(
                event = "SystemRoleNotFound",
                path = "fn check_system_role",
                message = "没有找到系统用户，正在创建一个新的系统用户"
            );
            println!("没有找到系统用户，正在创建一个新的系统用户");
            create_system_user(&pool).await;
        }
        1 => {
            println!("找到系统用户")
        }
        _ => {
            panic!("找到多个系统用户，请手动清理多余的系统用户!");
        }
    }
}

/// 创建系统角色
///
pub async fn create_system_user(pool: &deadpool_postgres::Pool) {
    let mut c = pool.get().await.unwrap();
    let transaction = c.transaction().await.unwrap();
    transaction
        .execute(
            "INSERT INTO users (username, password, role, limit_login) VALUES ($1, $2, $3, $4);",
            &[&"system", &"No Password", &0, &true],
        )
        .await
        .unwrap();
    info!(
        event = "CreateSystemUser",
        path = "fn create_system_user",
        message = "创建系统用户成功"
    );
    println!("创建系统用户成功");
    transaction.commit().await.unwrap();
}

/// 检查管理员用户数量，该操作在系统启动前执行。
///
/// 当没有任何管理员用户时，自动创建一个默认管理员。默认用户名可通过环境变量
/// `NM_DEFAULT_ADMIN_USERNAME` 覆盖，密码会自动生成。
pub async fn check_default_admin_user(
    pool: &deadpool_postgres::Pool,
    pwd_hash_config: PasswordHashConfig,
) {
    let admin_count = {
        let c = pool.get().await.unwrap();
        let row = c
            .query_one("SELECT COUNT(*) AS count FROM users WHERE role = 1;", &[])
            .await
            .unwrap();
        row.get::<_, i64>("count")
    };

    match admin_count {
        0 => {
            warn!(
                event = "AdminRoleNotFound",
                path = "fn check_default_admin_user",
                message = "没有找到管理员用户，正在创建一个默认管理员用户"
            );
            println!("没有找到管理员用户，正在创建一个默认管理员用户");
            create_default_admin_user(pool, pwd_hash_config).await;
        }
        _ => println!("找到管理员用户"),
    }
}

fn default_admin_username() -> String {
    env::var(DEFAULT_ADMIN_USERNAME_ENV)
        .ok()
        .filter(|username| !username.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_ADMIN_USERNAME.to_string())
}

fn generate_admin_password() -> String {
    let mut random_bytes = [0u8; DEFAULT_ADMIN_PASSWORD_LEN];
    rand::rand_bytes(&mut random_bytes).unwrap();

    random_bytes
        .iter()
        .map(|byte| {
            let index = *byte as usize % DEFAULT_ADMIN_PASSWORD_CHARS.len();
            DEFAULT_ADMIN_PASSWORD_CHARS[index] as char
        })
        .collect()
}

/// 重置指定管理员的密码，并使该用户的全部既有会话失效。
///
/// 仅允许重置 `role = 1` 的管理员账户，避免影响系统账户或普通用户。
/// 成功时返回仅应在当前终端显示一次的明文随机密码。
pub async fn reset_admin_password(
    username: &str,
    pool: &deadpool_postgres::Pool,
    pwd_hash_config: PasswordHashConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let password = generate_admin_password();
    let password_hash = generate_hash_password(&password, pwd_hash_config)
        .map_err(|error| format!("生成密码哈希失败：{:?}", error))?;

    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let admin = transaction
        .query_opt(
            "SELECT id FROM users WHERE username = $1 AND role = 1 FOR UPDATE;",
            &[&username],
        )
        .await?;

    let Some(admin) = admin else {
        return Err(format!("未找到管理员用户：{}", username).into());
    };
    let admin_id: i32 = admin.get("id");

    let updated = transaction
        .execute(
            "UPDATE users SET password = $1, limit_login = false, limit_at = NULL, \
             limit_time = NULL, login_error_count = 0, last_error_at = NULL \
             WHERE id = $2 AND role = 1;",
            &[&password_hash, &admin_id],
        )
        .await?;
    if updated != 1 {
        return Err(format!("重置管理员密码影响了 {} 行", updated).into());
    }

    transaction
        .execute(
            "UPDATE session SET is_enable = false WHERE user_id = $1 AND is_enable = true;",
            &[&admin_id],
        )
        .await?;
    transaction.commit().await?;

    info!(
        event = "ResetAdminPassword",
        path = "fn reset_admin_password",
        username,
        message = "管理员密码已重置，既有会话已失效"
    );

    Ok(password)
}
/// 创建默认管理员角色。
///
/// 如果默认用户名已被占用，会使用 admin_1、admin_2 等后缀创建用户，避免修改已有账号。
pub async fn create_default_admin_user(
    pool: &deadpool_postgres::Pool,
    pwd_hash_config: PasswordHashConfig,
) {
    let username_prefix = default_admin_username();
    let password = generate_admin_password();
    let password_hash = generate_hash_password(&password, pwd_hash_config).unwrap();

    let mut c = pool.get().await.unwrap();
    let transaction = c.transaction().await.unwrap();
    transaction
        .execute("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE;", &[])
        .await
        .unwrap();

    let row = transaction
        .query_one("SELECT COUNT(*) AS count FROM users WHERE role = 1;", &[])
        .await
        .unwrap();
    if row.get::<_, i64>("count") > 0 {
        println!("找到管理员用户");
        transaction.commit().await.unwrap();
        return;
    }

    let mut username = username_prefix.clone();

    for index in 0..1000 {
        let candidate = if index == 0 {
            username_prefix.clone()
        } else {
            format!("{}_{}", username_prefix, index)
        };

        if transaction
            .query_opt("SELECT id FROM users WHERE username = $1;", &[&candidate])
            .await
            .unwrap()
            .is_none()
        {
            username = candidate;
            break;
        }

        if index == 999 {
            panic!("默认管理员用户名均已被占用，请调整环境变量 NM_DEFAULT_ADMIN_USERNAME");
        }
    }

    transaction
        .execute(
            "INSERT INTO users (username, password, role, limit_login) VALUES ($1, $2, $3, $4);",
            &[&username, &password_hash, &1, &false],
        )
        .await
        .unwrap();

    info!(
        event = "CreateDefaultAdminUser",
        path = "fn create_default_admin_user",
        username,
        message = "创建默认管理员用户成功"
    );

    println!("创建默认管理员用户成功，用户名：{}", username);
    println!("默认管理员随机初始密码：{}，请登录后尽快修改", password);

    transaction.commit().await.unwrap();
}

/// 发送邮件
///
pub async fn send_email(emailconf: &EmailConfig, mail: Message) {
    let creds = Credentials::new(
        emailconf.account_username.to_string(),
        emailconf.account_password.to_string(),
    );

    // 使用465端口，且强制加密
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&emailconf.host)
        .unwrap()
        .credentials(creds)
        .build();
    match mailer.send(mail).await {
        Ok(_) => {
            info!(
                event = "SendEmailSuccessfully",
                path = "fn send_email",
                message = "Email sent successfully!"
            );
            println!("Email sent successfully!")
        }
        Err(e) => {
            warn!(
                event = "SendEmailError",
                path = "fn send_email",
                message = format!("Could not send email: {e:?}")
            );
            println!("Could not send email: {e:?}")
        }
    }
}

// 创建 TOTP 结构体
//
pub async fn totp_struct(
    username: String,
    d_key: &str,
    pool: &deadpool_postgres::Pool,
) -> Result<Option<TOTP>, Box<dyn std::error::Error>> {
    let c = pool.get().await?;

    match c.query_opt(
        "SELECT id, totp_secret FROM users WHERE limit_login = false AND enable_2fa = true AND username = $1;",
        &[&username]
    ).await? {
        Some(r) => {
            // 从数据库中获取 base64 编码后的数据
            let tmp_secret = r.get::<_, String>("totp_secret");
            let t_d_key = openssl::base64::decode_block(d_key)?;
            // 将 secret 解码
            let decode_secret = openssl::base64::decode_block(&tmp_secret)?;
            // 解密 secret
            let decrypt_result = decrypt_data(&decode_secret, &t_d_key)?;
            Ok(Some(
                TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                decrypt_result,
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
    pool: &deadpool_postgres::Pool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let database_conn = pool.get().await?;
    if let Some(_r) = database_conn.query_opt(
        "SELECT username FROM users WHERE username = $1 AND enable_2fa = true AND totp_secret IS NOT NULL;",
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
    session: &str,
    pool: &deadpool_postgres::Pool,
    e_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let secret32 = Secret::generate_secret();
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret32.to_bytes()?,
        Some("Network Mapping".to_string()),
        username.clone(),
    )?;
    let url = totp.get_url();
    let mut c = pool.get().await?;
    let transaction = c.transaction().await?;
    let encryption_key = openssl::base64::decode_block(e_key)?;
    let (nonce, tag, ciphertext) = encrypt_data(&secret32.to_bytes()?, &encryption_key)?;
    let mut encrypted = Vec::new();
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&tag);
    encrypted.extend_from_slice(&ciphertext);
    let encrypted_secret = openssl::base64::encode_block(&encrypted);
    let expires_at =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64 + 10 * 60 * 1000;
    let updated = transaction
        .execute(
            "UPDATE session SET pending_totp_secret = $1, pending_totp_expires_at = $2 \
         WHERE token = $3 AND is_enable = true AND totp_verify_successful = true \
         AND user_id = (SELECT id FROM users WHERE username = $4 AND enable_2fa = false);",
            &[&encrypted_secret, &expires_at, &session, &username],
        )
        .await?;
    if updated != 1 {
        return Err("当前会话不可用于绑定 2FA，或 2FA 已启用".into());
    }
    transaction.commit().await?;
    Ok(url)
}

/// 验证当前会话中的临时 TOTP 密钥，并在成功后正式启用 2FA。
pub async fn confirm_twofa_binding(
    username: &str,
    session: &str,
    token: &str,
    pool: &deadpool_postgres::Pool,
    d_key: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;
    let row = transaction
        .query_opt(
            "SELECT u.id, s.pending_totp_secret, s.pending_totp_expires_at \
         FROM session s JOIN users u ON u.id = s.user_id \
         WHERE s.token = $1 AND s.is_enable = true AND s.totp_verify_successful = true \
         AND u.username = $2 AND u.enable_2fa = false FOR UPDATE;",
            &[&session, &username],
        )
        .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let Some(pending_secret) = row.get::<_, Option<String>>("pending_totp_secret") else {
        return Ok(false);
    };
    let Some(expires_at) = row.get::<_, Option<i64>>("pending_totp_expires_at") else {
        return Ok(false);
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    if now > expires_at {
        return Ok(false);
    }

    let encrypted_secret = openssl::base64::decode_block(&pending_secret)?;
    let decrypt_key = openssl::base64::decode_block(d_key)?;
    let secret = decrypt_data(&encrypted_secret, &decrypt_key)?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("Network Mapping".to_string()),
        username.to_string(),
    )?;
    if !totp_token_verify(totp, token).await? {
        return Ok(false);
    }

    let user_id: i32 = row.get("id");
    let enabled = transaction.execute(
        "UPDATE users SET totp_secret = $1, enable_2fa = true WHERE id = $2 AND enable_2fa = false;",
        &[&pending_secret, &user_id],
    ).await?;
    if enabled != 1 {
        return Err("启用 2FA 影响的用户数量异常".into());
    }
    invalidate_user_sessions_in_transaction(&transaction, Some(username)).await?;
    transaction.commit().await?;
    Ok(true)
}

async fn invalidate_user_sessions_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
    username: Option<&str>,
) -> Result<u64, tokio_postgres::Error> {
    match username {
        Some(username) => transaction
            .execute(
                "UPDATE session SET is_enable = false WHERE is_enable = true AND user_id = (SELECT id FROM users WHERE username = $1);",
                &[&username],
            )
            .await,
        None => transaction
            .execute(
                "UPDATE session SET is_enable = false WHERE is_enable = true;",
                &[],
            )
            .await,
    }
}

/// 使指定用户（`Some`）或所有用户（`None`）的有效会话失效。
pub async fn invalidate_user_sessions(
    pool: &deadpool_postgres::Pool,
    username: Option<&str>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;
    let affected = invalidate_user_sessions_in_transaction(&transaction, username).await?;
    transaction.commit().await?;
    Ok(affected)
}

/// 验证 TOTP token///
///
pub async fn totp_token_verify(
    totp: TOTP,
    token: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if totp.check(token, seconds) {
        Ok(true)
    } else {
        println!("验证失败");
        Ok(false)
    }
}

/// totp 验证状态更改
pub async fn totp_verify_status_change(
    session: &str,
    pool: &deadpool_postgres::Pool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let db_transaction = conn.transaction().await?;
    let r = db_transaction
        .execute(
            "UPDATE session SET totp_verify_successful = true WHERE token = $1;",
            &[&session],
        )
        .await?;
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
    pool: &deadpool_postgres::Pool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut c = pool.get().await?;
    let db_transaction = c.transaction().await?;
    let r = db_transaction
        .execute(
            "UPDATE users SET enable_2fa = false, totp_secret = NULL WHERE username = $1;",
            &[&username],
        )
        .await?;
    if r == 1 {
        invalidate_user_sessions_in_transaction(&db_transaction, Some(username)).await?;
        info!(
            event = "Unbind2FASuccessful",
            path = "fn unbind_2fa",
            message = format!("用户 {} 解绑 2FA 成功", username)
        );
        db_transaction.commit().await?;
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
    pub count: Option<u32>, // 通过限制数据类型避免负数
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
    pub last_error_at: Option<i64>,
}

impl Default for UserInfo {
    fn default() -> Self {
        Self {
            id: -1,
            username: String::new(),
            role: -1,
            email: None,
            create_time: -1,
            limit_login: true,
            limit_at: None,
            limit_time: None,
            enable_2fa: true,
            last_login_at: None,
            last_login_ip: None,
            login_error_count: None,
            last_error_at: None,
        }
    }
}

/// 获取用户信息
///
/// 当权限足够时可以通过将 username 设置为 None 来获取所有用户信息，
/// 条目限制默认 5 条
pub async fn get_user_info(
    role: i32,
    username: Option<&str>,
    limit_items: Option<i64>,
    pool: &deadpool_postgres::Pool,
) -> Result<Vec<UserInfo>, Box<dyn std::error::Error>> {
    const USER_SELECT_S: &str = "SELECT \
            id, username, role, email, create_time, limit_login, limit_at, limit_time, \
            enable_2fa, last_login_at, last_login_ip, login_error_count, last_error_at \
        FROM users";

    let database_conn = pool.get().await?;
    let limit_i = limit_items.unwrap_or(5);

    let r = match (role, username) {
        (1, None) => {
            database_conn
                .query(&format!("{USER_SELECT_S} LIMIT $1;"), &[&limit_i])
                .await?
        }
        (1 | 2, Some(username_t)) => {
            database_conn
                .query(
                    &format!("{USER_SELECT_S} WHERE username = $1 LIMIT 1;"),
                    &[&username_t],
                )
                .await?
        }
        _ => return Err("没有对应的权限".into()),
    };

    Ok(r.iter()
        .map(|row| -> UserInfo { FromRow::from_row(row) })
        .collect())
}

/// 用户基础信息
#[derive(Deserialize)]
pub struct UserBaseInfo {
    pub username: String,
    pub email: String,
}

/// 更新用户信息
///
pub async fn update_user_info(
    username: &str,
    role: i32,
    new_user_info: &UserBaseInfo,
    pool: &deadpool_postgres::Pool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut database_conn = pool.get().await?;
    let conn_transaction = database_conn.transaction().await?;

    let result = conn_transaction
        .execute(
            "UPDATE users SET username = $1, email = $2 WHERE username = $3 AND role = $4;",
            &[
                &new_user_info.username,
                &new_user_info.email,
                &username,
                &role,
            ],
        )
        .await?;

    match result {
        // 更改成功
        1 => {
            conn_transaction.commit().await?;
            Ok(())
        }

        // 没有更改任何条目
        0 => {
            warn!(
                event = "UpdateUserInfo",
                path = "fn update_user_info",
                message = "没有更改任何条目，可能是该用户不存在或数据异常"
            );
            Ok(())
        }

        // 更改了多行，这是不允许的，所以不会提交事务
        _ => {
            error!(
                event = "UpdateUserInfo",
                path = "fn update_user_info",
                message = "更改了多行"
            );
            Err("更改了多行".into())
        }
    }
}

/// 从数据库中获取系统配置
pub async fn get_config_from_database(
    pool: &deadpool_postgres::Pool,
    item_type: &str,
    key: Option<&str>,
) -> Result<Vec<SystemConfig>, Box<dyn std::error::Error>> {
    const GET_CONFIG_SELECT_S: &str =
        "SELECT item_type, key, value, create_at, update_at FROM setting WHERE item_type = ";

    let conn = pool.get().await?;
    let result = match key {
        Some(k) => {
            conn.query(
                &format!("{GET_CONFIG_SELECT_S} $1 AND key = $2 LIMIT 1;"),
                &[&item_type, &k],
            )
            .await?
        }
        None => {
            conn.query(&format!("{GET_CONFIG_SELECT_S} $1;"), &[&item_type])
                .await?
        }
    };

    if result.is_empty() {
        Ok(vec![SystemConfig::new()])
    } else {
        Ok(result
            .iter()
            .map(SystemConfig::try_from_row)
            .collect::<Result<Vec<_>, _>>()?)
    }
}

/// 向数据库写入系统配置
///
pub async fn write_config_to_database(
    pool: &deadpool_postgres::Pool,
    sys_conf: &SystemConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;

    match transaction
        .execute(
            "INSERT INTO setting (item_type, key, value) VALUES ($1, $2, $3);",
            &[&sys_conf.item_type, &sys_conf.key, &sys_conf.value],
        )
        .await?
    {
        1 => {
            transaction.commit().await?;
            Ok(())
        }

        _ => Err("插入数据异常".into()),
    }
}

/// 用户基础信息，主要用于中间件注入
///
/// 只允许存储常用的基础信息，不会存储机密信息
#[derive(FromRow, Clone)]
pub struct UserBaseI {
    pub id: i32,
    pub username: String,
    pub role: i32,
    pub email: Option<String>,
    pub limit_login: bool,
    pub enable_2fa: bool,
}

#[derive(Clone)]
pub struct UserSession {
    pub session: String,
}

/// 获取用户基础信息，返回的数据主要用于注入请求
pub async fn get_user_base_info(
    pool: &Pool,
    user_id: i32,
) -> Result<UserBaseI, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;

    let row = conn.query_opt(
        "SELECT id, username, role, email, limit_login, enable_2fa From users WHERE id = $1 LIMIT 1;",
        &[&user_id]
    ).await?;

    Ok(row
        .map(|t| FromRow::try_from_row(&t))
        // 此处利用 transpose 将 Option<Result<T,E>> 转换为 Result<Option<T>,E>
        .transpose()?
        .unwrap_or(UserBaseI {
            id: -1,
            username: String::new(),
            role: -1,
            email: None,
            limit_login: true,
            enable_2fa: true,
        }))
}

/// web 端添加扫描器
///
/// 返回 ScannerRegisterData
pub async fn web_add_scanner(
    pool: &Pool,
    user_id: i32,
    add_data: &AddScanner,
    token_pepper: &str,
) -> Result<ScannerRegisterSecret, Box<dyn std::error::Error>> {
    let mut db_conn = pool.get().await?;
    let db_transaction = db_conn.transaction().await?;

    // 生成扫描器 id （uuid v7）
    let scanner_id = Uuid::now_v7().to_string();
    let registration_token = generate_scanner_token("nm_reg")?;
    let registration_token_hash = hash_scanner_token(&registration_token, token_pepper)?;

    match db_transaction.execute(
        "INSERT INTO scanner_info \
         (name, scanner_id, create_user, registration_token_hash, registration_token_expires_at, location, create_time, remark, tag, is_enable) \
         VALUES ($1, $2, $3, $4, NOW() + INTERVAL '24 hours', $5, NOW(), $6, $7, false);",
        &[&add_data.name, &scanner_id, &user_id, &registration_token_hash, &add_data.location, &add_data.remark, &add_data.tag]
    ).await? {
        1 => {
            db_transaction.commit().await?;
            Ok(ScannerRegisterSecret {
                scanner_id: scanner_id,
                registration_token: registration_token
            })
        },
        _ => Err("创建影响多行".into())
    }
}

/// 扫描器注册
///
pub async fn scanner_register(
    pool: &Pool,
    register_data: &ScannerRegisterData,
    registration_token: &str,
    token_pepper: &str,
) -> Result<ScannerRuntimeSecret, Box<dyn std::error::Error>> {
    let mut db_conn = pool.get().await?;
    let db_transaction = db_conn.transaction().await?;
    let registration_token_hash = hash_scanner_token(registration_token, token_pepper)?;

    let row = db_transaction
        .query_opt(
            "SELECT id FROM scanner_info \
         WHERE scanner_id = $1 \
           AND registration_token_hash = $2 \
           AND registration_consumed_at IS NULL \
           AND registration_token_expires_at > NOW() \
         FOR UPDATE;",
            &[&register_data.scanner_id, &registration_token_hash],
        )
        .await?;

    let Some(row) = row else {
        return Err("scanner unauthorized".into());
    };

    let scanner_pk: i32 = row.get("id");
    let runtime_token = generate_scanner_token("nm_run")?;
    let runtime_token_hash = hash_scanner_token(&runtime_token, token_pepper)?;

    match db_transaction
        .execute(
            "UPDATE scanner_info SET \
            registration_token_hash = NULL, \
            registration_consumed_at = NOW(), \
            runtime_token_hash = $1, \
            runtime_token_rotated_at = NOW(), \
            register_time = NOW(), \
            update_time = NOW(), \
            is_enable = true \
         WHERE id = $2;",
            &[&runtime_token_hash, &scanner_pk],
        )
        .await?
    {
        1 => {
            db_transaction.commit().await?;
            Ok(ScannerRuntimeSecret { runtime_token })
        }
        0 => Err("scanner unauthorized".into()),
        _ => Err("更新影响多行".into()),
    }
}

const SCANNER_INFO_SELECT: &str = "\
    SELECT s.scanner_id, s.name, u.username AS creator, s.location, \
           host(s.ip_address) AS ip_address, s.system_version, s.scanner_version, \
           s.cpu_model, s.cpus, s.ram, s.uptime, s.create_time, s.register_time, s.update_time, \
           s.last_seen_at, s.runtime_state, \
           (s.runtime_state <> 'stopping' AND s.last_seen_at IS NOT NULL \
              AND s.last_seen_at >= NOW() - INTERVAL '90 seconds') AS is_online, \
           (SELECT t.task_id FROM scan_task t WHERE t.assigned_scanner_id = s.scanner_id \
              AND t.task_status = 'running' AND t.lease_expires_at > (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT \
              ORDER BY t.task_start_time DESC NULLS LAST LIMIT 1) AS current_task_id, \
           s.is_run, s.is_enable, s.remark, s.tag \
    FROM scanner_info s \
    LEFT JOIN users u ON u.id = s.create_user";

fn scanner_info_from_row(row: &Row) -> ScannerInfo {
    ScannerInfo {
        scanner_id: row.get("scanner_id"),
        name: row.get("name"),
        creator: row.get("creator"),
        location: row.get("location"),
        ip_address: row.get("ip_address"),
        system_version: row.get("system_version"),
        scanner_version: row.get("scanner_version"),
        cpu_model: row.get("cpu_model"),
        cpus: row.get("cpus"),
        ram: row.get("ram"),
        uptime: row.get("uptime"),
        create_time: row.get("create_time"),
        register_time: row.get("register_time"),
        update_time: row.get("update_time"),
        last_seen_at: row.get("last_seen_at"),
        runtime_state: row.get("runtime_state"),
        is_online: row.get("is_online"),
        current_task_id: row.get("current_task_id"),
        is_run: row.get("is_run"),
        is_enable: row.get("is_enable"),
        remark: row.get("remark"),
        tag: row.get("tag"),
    }
}

pub async fn get_scanners(pool: &Pool) -> Result<Vec<ScannerInfo>, Box<dyn std::error::Error>> {
    let connection = pool.get().await?;
    let query = format!("{SCANNER_INFO_SELECT} ORDER BY s.create_time DESC NULLS LAST, s.id DESC;");
    let rows = connection.query(&query, &[]).await?;
    Ok(rows.iter().map(scanner_info_from_row).collect())
}

pub async fn get_scanner(
    pool: &Pool,
    scanner_id: Uuid,
) -> Result<Option<ScannerInfo>, Box<dyn std::error::Error>> {
    let connection = pool.get().await?;
    let query = format!("{SCANNER_INFO_SELECT} WHERE s.scanner_id = $1 LIMIT 1;");
    let row = connection
        .query_opt(&query, &[&scanner_id.to_string()])
        .await?;
    Ok(row.as_ref().map(scanner_info_from_row))
}

// 扫描器健康检查
//
// pub async fn scanner_health(
//     pool: &Pool,

// )
