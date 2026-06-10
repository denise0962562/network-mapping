///web系统配置文件

use actix_web::web;
use postgres_from_row::FromRow;
use std::{path::Path, fs};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use clap::Parser;

use crate::handlers::{self, user, utils};
use crate::{encrypt_data, decrypt_data};


#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub log: LogConfig,
    pub templates: TemplatesConfig,
    pub scan_target_generated: ScanTargetConfig,
    pub database: DatabaseConfig,
    pub pwd_hash: PasswordHashConfig,
    pub email_config: Option<EmailConfig>
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub encrypt_key: String
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    pub directory: String,
    pub file_name: String,
    pub file_rolling: u8,
    pub status_duration: u64
}

#[derive(Debug, Deserialize)]
pub struct TemplatesConfig {
    pub templates_directory: String,
    pub templates_name: String,
}

#[derive(Debug, Deserialize)]
pub struct ScanTargetConfig {
    pub generated_mode: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub host: String,                             //数据库主机地址
    pub port: u16,                                //数据库端口
    pub username: String,                         //用户名
    pub password: String,                         //密码
    pub db_name: String,                          //数据库名
    pub tls: bool,                                //是否使用tls
    pub init_database_file: String,               //初始化数据库表的sql文件
    pub sql_file_path: String,                    //sql文件存放路径（相对）
}

#[derive(Debug, Deserialize, Clone)]
pub struct PasswordHashConfig {
    pub m: u32,                                    // 内存，单位 MiB
    pub t: u32,                                    // 迭代，最大可设置为 4294967295
    pub p: u32                                     // 并行，最大可设置为 4294967295
}

#[derive(Debug, Deserialize, Clone)]
pub struct EmailConfig {
    pub host: String,
    pub account_username: String,
    pub account_password: String
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Self {
        let content = fs::read_to_string(path).expect("无法读取配置文件");
        toml::from_str(&content).expect("配置文件格式错误")
    }
}

pub fn init_routes(cfg: &mut web::ServiceConfig, ) {
    cfg
        .service(user::first_add_user)
        .service(user::user_login_h)
        .service(handlers::utils::get_scan_target)
        .service(handlers::data_saa::get_system_data_handler)
        .service(handlers::utils::benchmark_route)
        .service(handlers::task::create_task)
        .service(handlers::task::apply_task_handler)     //更换了 apply_task_handler 和 get_task的注册顺序
        .service(handlers::task::get_all_task_handler)
        .service(handlers::task::get_task)
        .service(handlers::utils::update_rir)
        .service(user::user_logout)
        .service(user::verify_totp_h)
        .service(user::bind_twofa_h)
        .service(user::get_user_info_h)
        .service(user::update_user_info_h)
        .service(user::totp_config_h)
        .service(user::unbind_2fa_h)
        .service(utils::get_config_h)
        .service(utils::test_mail_server_h)
        .default_service(web::to(handlers::utils::not_found));
}

#[derive(Serialize)]
pub enum ConfigType {
    None,
    SmtpConfig,
}

impl ConfigType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfigType::None => "None",
            ConfigType::SmtpConfig => "smtp",
        }
    }
}

/// 系统配置
#[derive(FromRow, Serialize)]
pub struct SystemConfig {
    pub item_type: String,
    pub key: String,
    pub value: String,
    pub create_at: DateTime<chrono::Utc>,
    pub update_at: Option<DateTime<chrono::Utc>>
}

impl SystemConfig {
    pub fn new() -> Self {
        SystemConfig { 
            item_type: String::new(), 
            key: String::new(), 
            value: String::new(), 
            create_at: DateTime::<Utc>::UNIX_EPOCH, 
            update_at: None 
        }
    }

    /// 该函数返回的值为 nonce + tag + 密文
    /// 
    /// 该函数可以直接更改 value
    pub fn encrypt(mut self, e_key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let tmp_value = self.value;
        if tmp_value.len() <= 0 {
            return Err("空值".into())
        } else {
            let (nonce, tag, ciphertext) = encrypt_data(tmp_value.as_bytes(), e_key.as_bytes())?;

            let mut encrypted = Vec::new();

            encrypted.extend_from_slice(&nonce);
            encrypted.extend_from_slice(&tag);
            encrypted.extend_from_slice(&ciphertext);
            self.value = openssl::base64::encode_block(&encrypted);

            Ok(())
        }
    }

    /// 函数
    pub fn decrypt(mut self, e_key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let tmp_value = self.value;
        if tmp_value.len() <= 0 {
            return Err("空值".into())
        } else {
            let v = openssl::base64::decode_block(&tmp_value)?;
            let t = decrypt_data(&v, e_key.as_bytes())?;
            self.value = openssl::base64::encode_block(&t);
            return Ok(())
        }
    }
}

#[derive(Deserialize)]
pub struct GetConfig {
    pub item_type: String,
    pub key: Option<String>
}

pub struct MailConfig {
    pub server_type: String,
    pub host: String,
    pub account_username: String,
    pub account_password: String,
}


#[derive(Parser, Debug)]
#[command(name = "networkm", version = "0.1.0", about = "这是一个网络测绘系统的服务端，可用于向扫描器分发扫描任务，并接收扫描器上传的数据，然后存入数据库。")]
pub struct Clis {
    /// 配置文件路径
    #[arg(long, default_value = "config.toml")]
    pub config: String,

    /// 调试模式，该模式可以输出详细的信息
    #[arg(short, long, default_value = "false")]
    pub debug_model: bool

}