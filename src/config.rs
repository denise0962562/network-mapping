///web系统配置文件
use actix_web::web;
use chrono::{DateTime, Utc};
use clap::Parser;
use postgres_from_row::FromRow;
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};
use tracing::info;

use crate::handlers::{self, user, utils};
use crate::{decrypt_data, encrypt_data};

pub trait SelfChecking {
    /// 该方法会直接 **Panic**
    fn check(&self);

    /// 该方法返回一个 Result 避免 Panic，
    ///
    /// Ok(true) 表示检验成功（符合预期）
    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>>;
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub log: LogConfig,
    pub templates: TemplatesConfig,
    #[serde(default)]
    pub frontend: FrontendConfig,
    #[serde(default)]
    pub maxmind: MaxMindConfig,
    // pub scan_target_generated: ScanTargetConfig,
    pub database: DatabaseConfig,
    pub pwd_hash: PasswordHashConfig,
    pub security: SecurityConfig,
    pub email_config: Option<EmailConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub certificate_chain_file: PathBuf,
    pub private_key_file: PathBuf,
}

impl TlsConfig {
    fn resolve_relative_to(&mut self, config_path: &Path) {
        let base_directory = config_path.parent().unwrap_or_else(|| Path::new(""));

        if self.certificate_chain_file.is_relative() {
            self.certificate_chain_file = base_directory.join(&self.certificate_chain_file);
        }
        if self.private_key_file.is_relative() {
            self.private_key_file = base_directory.join(&self.private_key_file);
        }
    }
}

impl SelfChecking for Config {
    fn check(&self) {
        let _ = &self.server.check();
        let _ = &self.database.check();
        let _ = &self.security.check();
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        match self.server.try_check() {
            Ok(true) => (),
            Ok(false) => return Ok(false),
            Err(e) => return Err(e),
        }
        match self.database.try_check() {
            Ok(true) => (),
            Ok(false) => return Ok(false),
            Err(e) => return Err(e),
        }
        self.security.try_check()
    }
}

#[derive(Deserialize, Clone)]
pub struct SecurityConfig {
    pub scanner_token_pepper: String,
}

impl fmt::Debug for SecurityConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityConfig")
            .field("scanner_token_pepper", &"[REDACTED]")
            .finish()
    }
}

impl SelfChecking for SecurityConfig {
    fn check(&self) {
        if let Err(error) = self.try_check() {
            panic!("{error}");
        }
        info!(target: "server::startup", component = "security", "配置检查通过");
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.scanner_token_pepper.trim().len() < 32 {
            return Err(
                "scanner_token_pepper 至少需要 32 个字符，请使用 openssl rand -hex 32 生成".into(),
            );
        }
        Ok(true)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub encrypt_key: String,
}

impl SelfChecking for ServerConfig {
    fn check(&self) {
        if self.host.is_empty() {
            panic!("监听地址为空")
        }

        match &self.encrypt_key.len() {
            44 => (),
            0 => panic!("加密密钥为空，请生成 Base64 格式的密钥\n如：openssl rand -base64 32"),
            ..44 => panic!(
                "加密密钥过短，base64 编码后应为 44 个字符,请生成 Base64 格式的密钥\n如：openssl rand -base64 32"
            ),
            45.. => panic!(
                "加密密钥过长，base64 编码后应为 44 个字符,请生成 Base64 格式的密钥\n如：openssl rand -base64 32"
            ),
        }

        info!(target: "server::startup", component = "server", "配置检查通过");
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.host.is_empty() {
            println!("监听地址为空");
            return Ok(false);
        }

        match &self.encrypt_key.len() {
            44 => Ok(true),
            0 => {
                println!("加密密钥为空，请生成 Base64 格式的密钥\n如：openssl rand -base64 32");
                Ok(false)
            }
            ..44 => {
                println!(
                    "加密密钥过短，base64 编码后应为 44 个字符,请生成 Base64 格式的密钥\n如：openssl rand -base64 32"
                );
                Ok(false)
            }
            45.. => {
                println!(
                    "加密密钥过长，base64 编码后应为 44 个字符,请生成 Base64 格式的密钥\n如：openssl rand -base64 32"
                );
                Ok(false)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    pub directory: String,
    pub file_name: String,
    pub file_rolling: u8,
    pub status_duration: u64,
}

#[derive(Debug, Deserialize)]
pub struct TemplatesConfig {
    pub templates_directory: String,
    pub templates_name: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct FrontendConfig {
    /// Vite 生产构建目录；文件缺失时对应页面或资源返回 404。
    pub directory: PathBuf,
}

impl Default for FrontendConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("../network-mapping-vue/dist"),
        }
    }
}

impl FrontendConfig {
    fn resolve_relative_to(&mut self, config_path: &Path) {
        if self.directory.is_relative() {
            let base_directory = config_path.parent().unwrap_or_else(|| Path::new(""));
            self.directory = base_directory.join(&self.directory);
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct MaxMindConfig {
    /// GeoLite2 数据库目录；文件缺失时相关 IP 情报字段保持为空。
    pub directory: PathBuf,
}

impl Default for MaxMindConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("source/maxmind"),
        }
    }
}

impl MaxMindConfig {
    fn resolve_relative_to(&mut self, config_path: &Path) {
        if self.directory.is_relative() {
            let base_directory = config_path.parent().unwrap_or_else(|| Path::new(""));
            self.directory = base_directory.join(&self.directory);
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub host: String,               //数据库主机地址
    pub port: u16,                  //数据库端口
    pub username: String,           //用户名
    pub password: String,           //密码
    pub db_name: String,            //数据库名
    pub tls: bool,                  //是否使用tls
    pub init_database_file: String, //初始化数据库表的sql文件
    pub sql_file_path: String,      //sql文件存放路径（相对）
}

impl SelfChecking for DatabaseConfig {
    fn check(&self) {
        if self.host.is_empty()
            || self.username.is_empty()
            || self.password.is_empty()
            || self.db_name.is_empty()
            || self.init_database_file.is_empty()
        {
            panic!("数据库关键字段为空")
        }

        info!(target: "server::startup", component = "database", "配置检查通过");
    }

    fn try_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        if self.host.is_empty()
            || self.username.is_empty()
            || self.password.is_empty()
            || self.db_name.is_empty()
            || self.init_database_file.is_empty()
        {
            println!("数据库关键字段为空");
            return Ok(false);
        }
        Ok(true)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PasswordHashConfig {
    pub m: u32, // 内存，单位 MiB
    pub t: u32, // 迭代，最大可设置为 4294967295
    pub p: u32, // 并行，最大可设置为 4294967295
}

#[derive(Debug, Deserialize, Clone)]
pub struct EmailConfig {
    pub host: String,
    pub account_username: String,
    pub account_password: String,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref();
        let content = fs::read_to_string(path).expect("无法读取配置文件");
        let mut config: Self = toml::from_str(&content).expect("配置文件格式错误");
        config.tls.resolve_relative_to(path);
        config.frontend.resolve_relative_to(path);
        config.maxmind.resolve_relative_to(path);
        config
    }
}

#[cfg(test)]
mod tests {
    use super::{Clis, FrontendConfig, MaxMindConfig, SecurityConfig, SelfChecking, TlsConfig};
    use clap::Parser;
    use std::path::{Path, PathBuf};

    #[test]
    fn tls_paths_are_resolved_relative_to_config_file() {
        let mut tls = TlsConfig {
            certificate_chain_file: PathBuf::from("ssl/cert.pem"),
            private_key_file: PathBuf::from("ssl/key.pem"),
        };

        tls.resolve_relative_to(Path::new("/etc/network-mapping/config.toml"));

        assert_eq!(
            tls.certificate_chain_file,
            PathBuf::from("/etc/network-mapping/ssl/cert.pem")
        );
        assert_eq!(
            tls.private_key_file,
            PathBuf::from("/etc/network-mapping/ssl/key.pem")
        );
    }

    #[test]
    fn absolute_tls_paths_are_unchanged() {
        let mut tls = TlsConfig {
            certificate_chain_file: PathBuf::from("/run/secrets/cert.pem"),
            private_key_file: PathBuf::from("/run/secrets/key.pem"),
        };

        tls.resolve_relative_to(Path::new("/etc/network-mapping/config.toml"));

        assert_eq!(
            tls.certificate_chain_file,
            PathBuf::from("/run/secrets/cert.pem")
        );
        assert_eq!(tls.private_key_file, PathBuf::from("/run/secrets/key.pem"));
    }

    #[test]
    fn frontend_directory_is_resolved_relative_to_config_file() {
        let mut frontend = FrontendConfig {
            directory: PathBuf::from("../frontend/dist"),
        };

        frontend.resolve_relative_to(Path::new("/etc/network-mapping/config.toml"));

        assert_eq!(
            frontend.directory,
            PathBuf::from("/etc/network-mapping/../frontend/dist")
        );
    }

    #[test]
    fn maxmind_directory_is_resolved_relative_to_config_file() {
        let mut maxmind = MaxMindConfig {
            directory: PathBuf::from("geoip"),
        };

        maxmind.resolve_relative_to(Path::new("/etc/network-mapping/config.toml"));

        assert_eq!(
            maxmind.directory,
            PathBuf::from("/etc/network-mapping/geoip")
        );
    }

    #[test]
    fn scanner_token_pepper_requires_sufficient_length() {
        let short = SecurityConfig {
            scanner_token_pepper: "too-short".into(),
        };
        let valid = SecurityConfig {
            scanner_token_pepper: "0123456789abcdef0123456789abcdef".into(),
        };

        assert!(short.try_check().is_err());
        assert!(valid.try_check().expect("valid pepper"));
    }

    #[test]
    fn terminal_logging_is_concise_by_default() {
        let cli = Clis::try_parse_from(["networkm"]).expect("default CLI should parse");

        assert!(!cli.terminal_verbose);
        assert!(!cli.refresh_ip_intel);
    }

    #[test]
    fn verbose_flag_enables_detailed_terminal_logging() {
        let cli =
            Clis::try_parse_from(["networkm", "--verbose"]).expect("verbose CLI flag should parse");

        assert!(cli.terminal_verbose);
    }

    #[test]
    fn refresh_ip_intel_flag_enables_one_off_refresh() {
        let cli = Clis::try_parse_from(["networkm", "--refresh-ip-intel"])
            .expect("refresh CLI flag should parse");

        assert!(cli.refresh_ip_intel);
    }
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(user::first_add_user)
        .service(user::user_login_h)
        .service(handlers::utils::get_scan_target)
        .service(handlers::data_saa::get_system_data_handler)
        .service(handlers::utils::benchmark_route)
        .service(handlers::open_source::get_open_source_projects)
        .service(handlers::search::search_ip)
        .service(handlers::search::search_network)
        .service(handlers::search::search_port)
        .service(handlers::search::search_service)
        .service(handlers::search::search_banner)
        .service(handlers::task::create_task)
        .service(handlers::task::apply_task_handler) //更换了 apply_task_handler 和 get_task的注册顺序
        .service(handlers::task::scanner_heartbeat_handler)
        .service(handlers::task::scanner_task_failure_handler)
        .service(handlers::task::scanner_task_cancelled_handler)
        .service(handlers::task::upload_scanner_result_handler)
        .service(handlers::task::get_all_task_handler)
        .service(handlers::task::get_task)
        .service(handlers::operations::cancel_task)
        .service(handlers::operations::retry_task)
        .service(handlers::operations::export_task)
        .service(handlers::operations::dashboard_overview)
        .service(handlers::audit::list_audit_events)
        .service(handlers::audit::export_audit_events)
        .service(handlers::audit::get_audit_event)
        .service(user::user_logout)
        .service(user::verify_totp_h)
        .service(user::bind_twofa_h)
        .service(user::get_user_info_h)
        .service(user::update_user_info_h)
        .service(user::change_password_h)
        .service(user::totp_config_h)
        .service(user::unbind_2fa_h)
        .service(user::web_add_scanner_h)
        .service(user::get_scanners_h)
        .service(user::get_scanner_h)
        .service(handlers::operations::update_scanner)
        .service(handlers::operations::set_scanner_enabled)
        .service(handlers::operations::reissue_scanner_token)
        .service(handlers::operations::delete_scanner)
        .service(user::scanner_register_h)
        .service(utils::get_config_h)
        .service(utils::test_mail_server_h);

    #[cfg(feature = "rir")]
    cfg.service(handlers::utils::update_rir);
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
    pub update_at: Option<DateTime<chrono::Utc>>,
}

impl SystemConfig {
    pub fn new() -> Self {
        SystemConfig {
            item_type: String::new(),
            key: String::new(),
            value: String::new(),
            create_at: DateTime::<Utc>::UNIX_EPOCH,
            update_at: None,
        }
    }

    /// 该函数返回的值为 nonce + tag + 密文
    ///
    /// 该函数可以直接更改 value
    pub fn encrypt(mut self, e_key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let tmp_value = self.value;
        if tmp_value.is_empty() {
            return Err("空值".into());
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
        if tmp_value.is_empty() {
            return Err("空值".into());
        } else {
            let v = openssl::base64::decode_block(&tmp_value)?;
            let t = decrypt_data(&v, e_key.as_bytes())?;
            self.value = openssl::base64::encode_block(&t);
            return Ok(());
        }
    }
}

#[derive(Deserialize)]
pub struct GetConfig {
    pub item_type: String,
    pub key: Option<String>,
}

pub struct MailConfig {
    pub server_type: String,
    pub host: String,
    pub account_username: String,
    pub account_password: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "networkm",
    version = "0.1.0",
    about = "这是一个网络测绘系统的服务端，可用于向扫描器分发扫描任务，并接收扫描器上传的数据，然后存入数据库。"
)]
pub struct Clis {
    /// 配置文件路径
    #[arg(long, default_value = "config.toml")]
    pub config: String,

    /// 启用 DEBUG 日志级别和源码位置；完整终端日志还需配合 --verbose
    #[arg(short, long, default_value = "false")]
    pub debug_model: bool,

    /// 在终端输出完整日志；默认仅显示启动摘要、警告和错误
    #[arg(short = 'v', long = "verbose")]
    pub terminal_verbose: bool,

    /// 重置指定管理员的密码，并在终端显示新的随机密码后退出
    #[arg(long, value_name = "USERNAME")]
    pub reset_admin_password: Option<String>,

    /// 使用当前 MaxMind 数据库刷新历史 IP 情报后退出
    #[arg(long)]
    pub refresh_ip_intel: bool,
}
