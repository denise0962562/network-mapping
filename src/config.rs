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
    #[serde(default)]
    pub automatic_target: AutomaticTargetConfig,
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
        if let Err(error) = self.automatic_target.validate() {
            panic!("{error}");
        }
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
        self.security.try_check()?;
        self.automatic_target.validate()?;
        Ok(true)
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

pub const DEFAULT_COMMON_SCAN_PORTS: &str = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017";

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct AutomaticTargetConfig {
    pub enabled: bool,
    pub strategy: String,
    pub interval_seconds: u64,
    pub pending_low_watermark: u32,
    pub pending_high_watermark: u32,
    pub priority: i32,
    pub authorized_cidrs: Vec<String>,
    pub excluded_cidrs: Vec<String>,
    pub ipv4_task_prefix: u8,
    pub ipv6_enabled: bool,
    pub ipv6_authorized_cidrs: Vec<String>,
    pub ipv6_excluded_cidrs: Vec<String>,
    pub ipv6_task_prefix: u8,
    pub ipv6_pending_low_watermark: u32,
    pub ipv6_pending_high_watermark: u32,
    pub common_ports: String,
    pub repeat_after_seconds: u64,
}

impl Default for AutomaticTargetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strategy: "sequential_subnet".to_owned(),
            interval_seconds: 30,
            pending_low_watermark: 2,
            pending_high_watermark: 5,
            priority: 0,
            authorized_cidrs: Vec::new(),
            excluded_cidrs: Vec::new(),
            ipv4_task_prefix: 24,
            ipv6_enabled: false,
            ipv6_authorized_cidrs: Vec::new(),
            ipv6_excluded_cidrs: Vec::new(),
            // 避免把完整 /64 直接交给扫描器；默认每个任务最多覆盖 256 个地址。
            ipv6_task_prefix: 120,
            ipv6_pending_low_watermark: 1,
            ipv6_pending_high_watermark: 2,
            common_ports: DEFAULT_COMMON_SCAN_PORTS.to_owned(),
            repeat_after_seconds: 7 * 24 * 60 * 60,
        }
    }
}

impl AutomaticTargetConfig {
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.strategy != "sequential_subnet" {
            return Err(format!("不支持的自动目标生成策略：{}", self.strategy).into());
        }
        if self.interval_seconds < 5 {
            return Err("automatic_target.interval_seconds 不能小于 5".into());
        }
        if self.pending_low_watermark > self.pending_high_watermark
            || self.pending_high_watermark == 0
            || self.pending_high_watermark > 100
        {
            return Err(
                "automatic_target 队列水位必须满足 0 <= low <= high <= 100 且 high > 0".into(),
            );
        }
        if !(0..=4).contains(&self.priority) {
            return Err("automatic_target.priority 必须在 0 到 4 之间".into());
        }
        if self.ipv4_task_prefix > 32 {
            return Err("automatic_target.ipv4_task_prefix 不能大于 32".into());
        }
        if self.ipv6_task_prefix > 128 {
            return Err("automatic_target.ipv6_task_prefix 不能大于 128".into());
        }
        if self.ipv6_pending_low_watermark > self.ipv6_pending_high_watermark
            || self.ipv6_pending_high_watermark == 0
            || self.ipv6_pending_high_watermark > 100
        {
            return Err("IPv6 自动目标队列水位必须满足 0 <= low <= high <= 100 且 high > 0".into());
        }
        validate_port_list(&self.common_ports)?;
        if self.enabled && self.authorized_cidrs.is_empty() {
            return Err("启用自动目标生成时必须配置 authorized_cidrs".into());
        }
        let mut authorized_networks = Vec::with_capacity(self.authorized_cidrs.len());
        for value in &self.authorized_cidrs {
            let network: ipnet::IpNet = value
                .parse()
                .map_err(|error| format!("无效的自动目标授权 CIDR {value}: {error}"))?;
            let ipnet::IpNet::V4(network) = network else {
                return Err(format!("IPv4 自动目标授权范围包含 IPv6：{value}").into());
            };
            if network.prefix_len() > self.ipv4_task_prefix {
                return Err(format!(
                    "授权范围 {value} 小于配置的 /{} 任务网段",
                    self.ipv4_task_prefix
                )
                .into());
            }
            authorized_networks.push(network);
        }
        if self.ipv6_enabled && self.ipv6_authorized_cidrs.is_empty() {
            return Err("启用 IPv6 自动目标生成时必须配置 ipv6_authorized_cidrs".into());
        }
        let mut authorized_ipv6 = Vec::with_capacity(self.ipv6_authorized_cidrs.len());
        let mut ipv6_total_subnets = 0_u128;
        for value in &self.ipv6_authorized_cidrs {
            let network: ipnet::Ipv6Net = value
                .parse()
                .map_err(|error| format!("无效的 IPv6 自动目标授权 CIDR {value}: {error}"))?;
            if network.prefix_len() > self.ipv6_task_prefix {
                return Err(format!(
                    "IPv6 授权范围 {value} 小于配置的 /{} 任务网段",
                    self.ipv6_task_prefix
                )
                .into());
            }
            let subnet_count = 1_u128
                .checked_shl(u32::from(self.ipv6_task_prefix - network.prefix_len()))
                .ok_or_else(|| {
                    format!(
                        "IPv6 授权范围 {value} 按 /{} 划分将产生 2^128 个任务网段，超出游标容量",
                        self.ipv6_task_prefix
                    )
                })?;
            ipv6_total_subnets = ipv6_total_subnets
                .checked_add(subnet_count)
                .ok_or("IPv6 授权范围的任务网段总数超出 128 位游标容量")?;
            authorized_ipv6.push(network);
        }
        for (index, network) in authorized_ipv6.iter().enumerate() {
            if authorized_ipv6[index + 1..].iter().any(|other| {
                network.contains(&other.network()) || other.contains(&network.network())
            }) {
                return Err(format!("IPv6 自动目标授权 CIDR 存在重复或重叠：{network}").into());
            }
        }
        for (index, network) in authorized_networks.iter().enumerate() {
            if authorized_networks[index + 1..].iter().any(|other| {
                network.contains(&other.network()) || other.contains(&network.network())
            }) {
                return Err(format!("自动目标授权 CIDR 存在重复或重叠：{network}").into());
            }
        }
        validate_excluded_cidrs(&self.excluded_cidrs, false)?;
        validate_excluded_cidrs(&self.ipv6_excluded_cidrs, true)?;
        Ok(())
    }
}

fn validate_excluded_cidrs(
    values: &[String],
    expect_ipv6: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut networks = Vec::with_capacity(values.len());
    for value in values {
        let network: ipnet::IpNet = value
            .parse()
            .map_err(|error| format!("无效的自动目标排除 CIDR {value}: {error}"))?;
        if network.addr().is_ipv6() != expect_ipv6 {
            let family = if expect_ipv6 { "IPv6" } else { "IPv4" };
            return Err(format!("{family} 自动目标排除范围地址族错误：{value}").into());
        }
        networks.push(network);
    }
    for (index, network) in networks.iter().enumerate() {
        if networks[index + 1..]
            .iter()
            .any(|other| network.contains(&other.network()) || other.contains(&network.network()))
        {
            return Err(format!("自动目标排除 CIDR 存在重复或重叠：{network}").into());
        }
    }
    Ok(())
}

fn validate_port_list(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.is_empty() {
        return Err("automatic_target.common_ports 不能为空".into());
    }
    for segment in value.split(',') {
        let mut bounds = segment.split('-');
        let start = bounds
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("无效的自动扫描端口：{segment}"))?;
        let end = bounds
            .next()
            .map(|value| value.parse::<u16>())
            .transpose()
            .map_err(|_| format!("无效的自动扫描端口：{segment}"))?
            .unwrap_or(start);
        if bounds.next().is_some() || end == 0 || start > end {
            return Err(format!("无效的自动扫描端口：{segment}").into());
        }
    }
    Ok(())
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPreferences {
    pub login_notify_enabled: bool,
    pub notify_on_stuck: bool,
    pub notify_on_complete: bool,
    pub report_daily: bool,
    pub report_weekly: bool,
    pub report_monthly: bool,
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            login_notify_enabled: true,
            notify_on_stuck: true,
            notify_on_complete: true,
            report_daily: false,
            report_weekly: true,
            report_monthly: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailSettingsRequest {
    /// 仅用于 SMTP 连通性测试和邮件模板测试，不作为真实通知的收件人。
    pub recipient: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub sender: String,
    #[serde(default)]
    pub sender_key: String,
    #[serde(default)]
    pub notification_prefs: NotificationPreferences,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailSettingsResponse {
    /// 仅用于 SMTP 连通性测试和邮件模板测试，不作为真实通知的收件人。
    pub recipient: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub sender: String,
    pub sender_key_configured: bool,
    pub notification_prefs: NotificationPreferences,
}

pub const DEFAULT_SESSION_TTL_SECONDS: i32 = 45 * 60;
pub const MIN_SESSION_TTL_MINUTES: i32 = 5;
pub const MAX_SESSION_TTL_MINUTES: i32 = 24 * 60;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSettingsRequest {
    pub session_ttl_minutes: i32,
    #[serde(default)]
    pub invalidate_other_sessions: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSettingsResponse {
    pub session_ttl_minutes: i32,
    pub minimum_minutes: i32,
    pub maximum_minutes: i32,
    pub invalidated_session_count: u64,
}

impl SessionSettingsResponse {
    pub fn new(session_ttl_seconds: i32, invalidated_session_count: u64) -> Self {
        Self {
            session_ttl_minutes: session_ttl_seconds / 60,
            minimum_minutes: MIN_SESSION_TTL_MINUTES,
            maximum_minutes: MAX_SESSION_TTL_MINUTES,
            invalidated_session_count,
        }
    }
}

pub fn session_ttl_seconds_from_minutes(minutes: i32) -> Result<i32, &'static str> {
    if !(MIN_SESSION_TTL_MINUTES..=MAX_SESSION_TTL_MINUTES).contains(&minutes) {
        return Err("会话有效期必须在 5 分钟到 24 小时之间");
    }
    minutes.checked_mul(60).ok_or("会话有效期超出允许范围")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailTestRequest {
    pub recipient: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub sender: String,
    #[serde(default)]
    pub sender_key: String,
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
    use super::{
        AutomaticTargetConfig, Clis, FrontendConfig, MaxMindConfig, SecurityConfig, SelfChecking,
        TlsConfig, session_ttl_seconds_from_minutes,
    };
    use clap::Parser;
    use std::path::{Path, PathBuf};

    #[test]
    fn session_ttl_minutes_are_converted_and_bounded() {
        assert_eq!(session_ttl_seconds_from_minutes(45), Ok(2700));
        assert_eq!(session_ttl_seconds_from_minutes(5), Ok(300));
        assert_eq!(session_ttl_seconds_from_minutes(1440), Ok(86_400));
        assert!(session_ttl_seconds_from_minutes(4).is_err());
        assert!(session_ttl_seconds_from_minutes(1441).is_err());
    }

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

    #[test]
    fn automatic_target_requires_authorized_ipv4_ranges_when_enabled() {
        let mut config = AutomaticTargetConfig {
            enabled: true,
            ..AutomaticTargetConfig::default()
        };
        assert!(config.validate().is_err());

        config.authorized_cidrs = vec!["10.20.0.0/16".to_owned()];
        assert!(config.validate().is_ok());

        config.authorized_cidrs = vec!["2001:db8::/32".to_owned()];
        assert!(config.validate().is_err());

        config.authorized_cidrs = vec!["10.20.0.0/16".to_owned(), "10.20.1.0/24".to_owned()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn automatic_target_validates_ipv6_ranges_independently() {
        let mut config = AutomaticTargetConfig {
            ipv6_enabled: true,
            ..AutomaticTargetConfig::default()
        };
        assert!(config.validate().is_err());

        config.ipv6_authorized_cidrs = vec!["2001:db8::/64".to_owned()];
        assert!(config.validate().is_ok());

        config.ipv6_authorized_cidrs = vec!["10.0.0.0/8".to_owned()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn automatic_target_accepts_full_ipv6_range_with_bounded_task_subnets() {
        let config = AutomaticTargetConfig {
            ipv6_enabled: true,
            ipv6_authorized_cidrs: vec!["::/0".to_owned()],
            ipv6_task_prefix: 120,
            ..AutomaticTargetConfig::default()
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn automatic_target_rejects_an_unrepresentable_ipv6_cursor_space() {
        let config = AutomaticTargetConfig {
            ipv6_enabled: true,
            ipv6_authorized_cidrs: vec!["::/0".to_owned()],
            ipv6_task_prefix: 128,
            ..AutomaticTargetConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn automatic_target_validates_exclusion_families_and_overlap() {
        let mut config = AutomaticTargetConfig {
            excluded_cidrs: vec!["10.0.0.0/8".to_owned()],
            ipv6_excluded_cidrs: vec!["fc00::/7".to_owned()],
            ..AutomaticTargetConfig::default()
        };
        assert!(config.validate().is_ok());

        config.excluded_cidrs = vec!["fc00::/7".to_owned()];
        assert!(config.validate().is_err());

        config.excluded_cidrs = vec!["10.0.0.0/8".to_owned(), "10.1.0.0/16".to_owned()];
        assert!(config.validate().is_err());
    }
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(user::user_login_h)
        .service(handlers::data_saa::get_system_data_handler)
        .service(handlers::data_saa::get_analysis_distribution)
        .service(handlers::data_saa::get_analysis_discovery_heatmap)
        .service(handlers::system_resources::get_system_resource_history)
        .service(handlers::system_resources::get_database_size_history)
        .service(handlers::utils::benchmark_route)
        .service(handlers::open_source::get_open_source_projects)
        .service(handlers::search::search_ip)
        .service(handlers::search::search_network)
        .service(handlers::search::search_port)
        .service(handlers::search::search_service)
        .service(handlers::search::search_banner)
        .service(crate::target_generated::automatic_target_status)
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
        .service(handlers::admin_user::list_users)
        .service(handlers::admin_user::create_user)
        .service(handlers::admin_user::set_user_enabled)
        .service(handlers::admin_user::kick_user)
        .service(handlers::admin_user::delete_user)
        .service(handlers::login_record::self_login_records)
        .service(handlers::login_record::admin_login_records)
        .service(handlers::mail_template::list_mail_templates)
        .service(handlers::mail_template::get_mail_template)
        .service(handlers::mail_template::validate_mail_template)
        .service(handlers::mail_template::preview_mail_template)
        .service(handlers::mail_template::save_mail_template_draft)
        .service(handlers::mail_template::publish_mail_template)
        .service(handlers::mail_template::get_mail_template_versions)
        .service(handlers::mail_template::restore_mail_template_version)
        .service(handlers::mail_template::test_mail_template)
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
        .service(utils::get_mail_settings_h)
        .service(utils::save_mail_settings_h)
        .service(utils::get_session_settings_h)
        .service(utils::save_session_settings_h)
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
