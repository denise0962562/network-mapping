#![recursion_limit = "256"]

pub mod admin;
pub mod audit;
pub mod backup;
pub mod client_ip;
pub mod config;
pub mod db;
pub mod elasticsearch;
pub mod frontend;
pub mod handlers;
pub mod login;
pub mod logs;
pub mod mail_template;
pub mod maxmind;
pub mod monitor;
pub mod target_generated;
pub mod tls;
pub mod trusted_proxy;

#[cfg(feature = "rir")]
pub mod rir; // 该模块用于从五大 RIR 获取 ASN 和组织等信息

// 自己的中间件
pub mod middlewares;
pub mod open_source;
pub mod request_log;
pub mod scanner_latency;
pub mod scanner_maintenance;
mod search_content;
pub mod search_projection;

#[cfg(test)]
pub mod test; // 测试模块

use actix_web::{HttpRequest, web};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use cidr::IpInet;
use deadpool_postgres::GenericClient;
use ipnet::{AddrParseError, IpNet};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rand;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, SaltString};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo;
use tera::{Context, Tera};
use tokio_postgres::Row;
use tokio_postgres::types::ToSql;
use tracing::{error, info, warn};
use uuid::Uuid;

use admin::TotpInfo;
use config::PasswordHashConfig;
use db::get_sql_from_file;
use elasticsearch::{ElasticsearchService, ScanBatchContext, scan_batch_payload_checksum};
use logs::write::{database_error_diagnostics, error_chain_diagnostics};
use maxmind::MaxMindState;

//常量
pub const TEXT_HTML_UTF_8: &str = "text/html; charset=utf-8";
pub const TEXT_CSS_UTF_8: &str = "text/css; charset=utf-8";
pub const APPLICATION_JAVASCRIPT_UTF_8: &str = "application/javascript; charset=utf-8";
pub const IMAGE_PNG: &str = "image/png";
pub const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
pub const APPLICATION_JSON: &str = "application/json";
pub const _SYSTEM_TIME_ZONE: &str = "Asia/Shanghai";
pub const TASK_LEASE_MS: i64 = 90_000;

pub fn generate_scanner_token(prefix: &str) -> Result<String, io::Error> {
    let mut token_buffer = [0u8; 36];
    rand::rand_bytes(&mut token_buffer)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(format!(
        "{}_{}",
        prefix,
        openssl::base64::encode_block(&token_buffer)
    ))
}

pub fn hash_scanner_token(token: &str, pepper: &str) -> Result<String, io::Error> {
    let key = PKey::hmac(pepper.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    signer
        .update(token.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let digest = signer
        .sign_to_vec()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    Ok(openssl::base64::encode_block(&digest))
}

struct FrontEndErrorInfo<'a> {
    status_code: u16,
    error_title: &'a str,
    error_message: &'a str,
    request_id: String,
}

pub struct _ProxySetting {
    _status: bool,
    _headers: String,
}

pub struct UserLoginInfo {
    pub username: String,
    pub role: i32,
    pub email_address: Option<String>,
    pub twofa: Option<TotpInfo>,
}

pub struct ReadFile {
    pub file_name: String,
    pub file_root_directory: String,
}

#[derive(Clone)]
pub struct TemplatesInit {
    pub templates_directory: String,
    pub templates_name: String,
}

//以下存储的数据都为约值，会自动舍弃精度
#[derive(Serialize, Deserialize)]
pub struct DbResource {
    pub db_library_size: String,
    pub db_table_size: BTreeMap<String, DbTableSizeInfo>,
    pub db_conn: String,
}

#[derive(Serialize, Deserialize)]
pub struct DbTableSizeInfo {
    pub total: i64,
    pub data: i64,
    pub index: i64,
}

#[derive(Serialize, Deserialize)]
pub struct SystemCPU {
    pub cpu_usage: f32,            //cpu总体使用率
    pub cpu: HashMap<String, f32>, //单个cpu使用率
}

//系统缓存大小，包括swap
#[derive(Serialize, Deserialize)]
pub struct SystemRAM {
    pub total_ram: u64,
    pub used_ram: u64,
    pub ram_usage: f32,
    pub total_swap: u64,
    pub use_swap: u64,
    pub swap_usage: f32,
}

#[derive(Serialize, Deserialize)]
pub struct SystemDisk {
    pub disk_total_space: u64,
    pub disk_total_usage: u64,
    pub disk: HashMap<String, Vec<u64>>,
}

#[derive(Serialize, Deserialize)]
pub struct SystemNetInfo {
    pub send: String,
    pub receive: String,
}

#[derive(Serialize, Deserialize)]
pub struct SystemNetwork {
    pub net: BTreeMap<String, SystemNetInfo>,
}

#[derive(Serialize, Deserialize)]
pub struct SystemResource {
    pub server_run_time: i64,
    pub cpu: SystemCPU,
    pub ram: SystemRAM,
    pub disk: SystemDisk,
    pub db_postgresql: DbResource,
    pub network: SystemNetwork,
    pub create_at: Option<i64>,
}

pub fn get_unix_epoch_ms() -> i64 {
    //todo 添加一个获取普通utc时间的函数，考虑用结构体还是权举
    // 当获取时间戳失败时会返回默认值-1
    // SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as i64,
        Err(e) => {
            error!(event = "UnixEpochGenerateError", message = e.to_string());
            -1 as i64
        }
    }
}

//用于存储sysinfo 下必要的
#[derive(Clone)]
pub struct Systems {
    pub sys: Arc<Mutex<sysinfo::System>>,
    pub disk: Arc<Mutex<sysinfo::Disks>>,
    pub network: Arc<Mutex<sysinfo::Networks>>,
}

#[derive(Serialize, Deserialize)]
pub struct SystemDetails {
    pub host_name: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: String,
    pub cpu_model: Option<String>,
    pub cpu_vendor: Option<String>,
    pub cpu_frequency_mhz: Option<u64>,
    pub physical_core_count: Option<usize>,
    pub logical_cpu_count: usize,
}

impl Systems {
    pub fn new() -> Self {
        Self {
            sys: Arc::new(Mutex::new(sysinfo::System::new_all())),
            disk: Arc::new(Mutex::new(sysinfo::Disks::new_with_refreshed_list())),
            network: Arc::new(Mutex::new(sysinfo::Networks::new_with_refreshed_list())),
        }
    }
}

impl Default for Systems {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemDetails {
    pub fn new(systems: &Systems) -> Self {
        let sys = systems
            .sys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let first_cpu = sys.cpus().first();

        Self {
            host_name: sysinfo::System::host_name(),
            os_name: sysinfo::System::name(),
            os_version: sysinfo::System::long_os_version(),
            kernel_version: sysinfo::System::kernel_version(),
            architecture: sysinfo::System::cpu_arch(),
            cpu_model: first_cpu
                .map(|cpu| cpu.brand().trim().to_string())
                .filter(|value| !value.is_empty()),
            cpu_vendor: first_cpu
                .map(|cpu| cpu.vendor_id().trim().to_string())
                .filter(|value| !value.is_empty()),
            cpu_frequency_mhz: first_cpu.map(sysinfo::Cpu::frequency),
            physical_core_count: sysinfo::System::physical_core_count(),
            logical_cpu_count: sys.cpus().len(),
        }
    }
}

impl SystemCPU {
    pub fn new(sys: Arc<Mutex<sysinfo::System>>) -> Self {
        let mut cpu_usages = sys.lock().unwrap();
        cpu_usages.refresh_cpu_all();
        // let mut c_hash: HashMap<&str, f32> = HashMap::new();
        // cpu_usages.cpus().iter().map(|cpu| c_hash.insert(cpu.name(), cpu.cpu_usage()));

        let c_hash: HashMap<String, f32> = cpu_usages
            .cpus()
            .iter()
            .map(|cpu| (cpu.name().to_string(), cpu.cpu_usage()))
            .collect();

        Self {
            cpu_usage: cpu_usages.global_cpu_usage(),
            cpu: c_hash,
        }
    }
}

fn usage_percentage(used: u64, total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }

    (used as f64 / total as f64 * 100.0) as f32
}

impl SystemRAM {
    pub fn new(sys: Arc<Mutex<sysinfo::System>>) -> Self {
        let mut sys = sys.lock().unwrap();
        sys.refresh_memory();
        let total_m = sys.total_memory();
        let used_m = sys.used_memory();
        let total_s = sys.total_swap();
        let used_s = sys.used_swap();
        Self {
            ram_usage: usage_percentage(used_m, total_m),
            total_ram: total_m,
            used_ram: used_m,
            total_swap: total_s,
            use_swap: used_s,
            swap_usage: usage_percentage(used_s, total_s),
        }
    }
}

#[cfg(test)]
mod system_ram_tests {
    use super::usage_percentage;

    #[test]
    fn zero_total_has_zero_usage() {
        assert_eq!(usage_percentage(128, 0), 0.0);
    }

    #[test]
    fn usage_preserves_fractional_values() {
        assert_eq!(usage_percentage(1, 4), 25.0);
    }
}

impl SystemDisk {
    pub fn new(disk: Arc<Mutex<sysinfo::Disks>>) -> Self {
        let mut disk = disk.lock().unwrap();
        disk.refresh(true);
        let mut disk_total: u64 = 0;
        let mut disk_total_usage: u64 = 0;
        let mut d_h: HashMap<String, Vec<u64>> = HashMap::new();
        // disk.list().iter().map( |disk|
        //     disk_w(&mut disk_total, &mut disk_total_usage, &mut d_h, disk)
        // );
        // let d_h: HashMap<&str, Vec<u64>> = disk.list().iter().map( |disk|
        //     (disk.name(), ver!<disk.total_space(), disk.available_space()>)

        // )
        for d in disk.list() {
            disk_total += d.total_space();
            disk_total_usage += d.total_space() - d.available_space();
            d_h.insert(
                d.name().to_string_lossy().to_string(),
                vec![d.total_space(), d.available_space()],
            );
        }

        Self {
            disk_total_space: disk_total,
            disk_total_usage: disk_total_usage,
            disk: d_h,
        }
    }
}

impl SystemNetwork {
    pub fn new(net: Arc<Mutex<sysinfo::Networks>>) -> Self {
        let mut net = net.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        net.refresh(true);
        // The dashboard displays counters accumulated since system boot. The
        // received/transmitted methods only contain the latest refresh delta.
        let n_h: BTreeMap<String, SystemNetInfo> = net
            .list()
            .iter()
            .map(|(net_name, net_data)| {
                (
                    net_name.to_string(),
                    SystemNetInfo {
                        send: net_data.total_transmitted().to_string(),
                        receive: net_data.total_received().to_string(),
                    },
                )
            })
            .collect();

        Self { net: n_h }
    }
}

impl DbResource {
    pub async fn new(pool: &deadpool_postgres::Pool, sql_file_path: &str, db_name: &str) -> Self {
        let client = pool.get().await;
        // let mut db_h: HashMap<String, String> = HashMap::new();

        // let default_dbresource = DbResource {
        //     db_library_size: "null".to_string(),
        //     db_table_size: db_h.clone(),
        //     db_conn: "null".to_string()
        // };
        match client {
            Ok(o) => {
                //返回值的单位均为字节

                let db_table_size_sql =
                    get_sql_from_file(&sql_file_path, "get_table_size.sql").await;
                let db_conn_sql = "SELECT COUNT(*) AS db_conn FROM pg_stat_activity;";
                let db_table_size = match db_table_size_sql {
                    Ok(sql) => get_db_table_size_byte(&o, &sql, &[]).await,
                    Err(e) => {
                        error!(
                            event = "DatabaseMetricsSqlLoadError",
                            operation = "load_table_size_query",
                            sql_file = "get_table_size.sql",
                            message = %error_chain_diagnostics(e.as_ref()),
                        );
                        BTreeMap::from([("error".to_owned(), DbTableSizeInfo::default())])
                    }
                };

                Self {
                    db_library_size: get_db_library_size_byte(&o, db_name).await,
                    db_table_size,
                    db_conn: get_db_conn(&o, db_conn_sql, &[]).await,
                }
            }
            Err(e) => {
                error!(
                    event = "DatabaseMetricsPoolError",
                    operation = "acquire_metrics_connection",
                    message = %error_chain_diagnostics(&e),
                );
                //返回默认值
                DbResource::default()
            }
        }
    }
}

impl Default for DbResource {
    fn default() -> Self {
        let tmp = vec![("error".to_string(), DbTableSizeInfo::default())];
        let h: BTreeMap<String, DbTableSizeInfo> = tmp.into_iter().collect();
        Self {
            db_library_size: "none".to_string(),
            db_table_size: h,
            db_conn: "none".to_string(),
        }
    }
}

impl Default for DbTableSizeInfo {
    fn default() -> Self {
        Self {
            total: -1,
            data: -1,
            index: -1,
        }
    }
}

impl SystemResource {
    pub async fn new(sys: Systems, pool: &deadpool_postgres::Pool, db_name: &str) -> Self {
        Self {
            server_run_time: get_server_uptime() as i64,
            cpu: SystemCPU::new(sys.sys.clone()),
            ram: SystemRAM::new(sys.sys.clone()),
            disk: SystemDisk::new(sys.disk.clone()),
            db_postgresql: DbResource::new(pool, "source/database/", db_name).await,
            network: SystemNetwork::new(sys.network.clone()),
            create_at: None,
        }
    }
}

/// 用于存储目标 IP ，适配 IpAddr 和 str
pub enum TargetIP<'a> {
    S(&'a str),
    I(IpNet),
}

pub enum TargetPort<'a> {
    S(&'a str),
    I(u16),
}

/// Parse either a host IP address or an IP network.
///
/// `IpNet` requires an explicit prefix length, while scanner results contain
/// host addresses. Normalize host addresses to their single-host networks so
/// both upload formats share the same validated representation.
fn parse_ip_or_cidr(value: &str) -> Result<IpNet, AddrParseError> {
    let value = value.trim();
    if value.contains('/') {
        value.parse()
    } else {
        let prefix = if value.contains(':') { 128 } else { 32 };
        format!("{value}/{prefix}").parse()
    }
}

#[cfg(test)]
mod parse_ip_or_cidr_tests {
    use super::{
        CreateTask, STask, ScannerObservation, ScannerResultUpload, TargetIP, build_scan_plan,
        parse_ip_or_cidr,
    };

    #[test]
    fn accepts_plain_ipv4_as_single_host_network() {
        let parsed = parse_ip_or_cidr("221.233.151.58").unwrap();

        assert_eq!(parsed.to_string(), "221.233.151.58/32");
    }

    #[test]
    fn accepts_plain_ipv6_as_single_host_network() {
        let parsed = parse_ip_or_cidr("2001:db8::1").unwrap();

        assert_eq!(parsed.to_string(), "2001:db8::1/128");
    }

    #[test]
    fn accepts_ipv4_and_ipv6_cidr() {
        assert_eq!(
            parse_ip_or_cidr("192.0.2.0/24").unwrap().to_string(),
            "192.0.2.0/24"
        );
        assert_eq!(
            parse_ip_or_cidr("2001:db8::/48").unwrap().to_string(),
            "2001:db8::/48"
        );
    }

    #[test]
    fn rejects_invalid_ip() {
        assert!(parse_ip_or_cidr("not-an-ip").is_err());
        assert!(parse_ip_or_cidr("192.0.2.1/99").is_err());
    }

    #[test]
    fn tasks_must_use_one_address_family() {
        let ipv4 =
            STask::new(TargetIP::S("192.0.2.1,198.51.100.0/24"), "test", None, None).unwrap();
        assert_eq!(ipv4.address_family(), Ok("ipv4"));

        let ipv6 = STask::new(TargetIP::S("2001:db8::1"), "test", None, None).unwrap();
        assert_eq!(ipv6.address_family(), Ok("ipv6"));

        let mixed = STask::new(TargetIP::S("192.0.2.1,2001:db8::1"), "test", None, None).unwrap();
        assert!(mixed.address_family().is_err());
    }

    #[test]
    fn scan_profiles_expand_to_allowlisted_plans() {
        let ports = build_scan_plan("port_only").unwrap();
        assert_eq!(ports["version"], 1);
        assert_eq!(ports["stages"].as_array().unwrap().len(), 1);

        let inventory = build_scan_plan("service_inventory").unwrap();
        assert_eq!(inventory["stages"].as_array().unwrap().len(), 2);
        assert!(build_scan_plan("arbitrary_command").is_err());
    }

    #[test]
    fn create_task_may_defer_scan_profile_to_system_settings() {
        let task: CreateTask = serde_json::from_value(serde_json::json!({
            "ip": "192.0.2.1",
            "port": "443",
            "level": 1,
            "remark": null
        }))
        .unwrap();

        assert!(task.scan_profile.is_none());
    }

    #[test]
    fn result_protocol_accepts_legacy_and_typed_payloads() {
        let legacy: ScannerResultUpload = serde_json::from_value(serde_json::json!({
            "scanner_id": "019c0000-0000-7000-8000-000000000001",
            "task_id": "019c0000-0000-7000-8000-000000000002",
            "results": []
        }))
        .unwrap();
        assert_eq!(legacy.protocol_version, 1);

        let typed: ScannerResultUpload = serde_json::from_value(serde_json::json!({
            "protocol_version": 2,
            "scanner_id": "019c0000-0000-7000-8000-000000000001",
            "task_id": "019c0000-0000-7000-8000-000000000002",
            "upload_id": "019c0000-0000-7000-8000-000000000003",
            "batch_index": 0,
            "is_final": true,
            "observations": [{
                "kind": "port",
                "ip": "192.0.2.1",
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "source": "masscan"
            }]
        }))
        .unwrap();
        assert_eq!(typed.protocol_version, 2);
        assert!(matches!(
            typed.observations[0],
            ScannerObservation::Port { .. }
        ));
    }
}

/// 该函数用于解析ip地址，
/// 可以接收传入字符串IP，会自动解析，然后返回一个向量
fn parsing_target(ip: TargetIP) -> Result<Vec<IpNet>, AddrParseError> {
    let mut n_v: Vec<IpNet> = Vec::new();
    match ip {
        TargetIP::S(i_str) => {
            for tmp in i_str.split(",") {
                match parse_ip_or_cidr(tmp) {
                    Ok(o) => n_v.push(o),
                    Err(e) => {
                        error!(event = "PARSING-ERROR", message = e.to_string());
                        return Err(e);
                    }
                }
            }
            return Ok(n_v);
        }
        TargetIP::I(ipadd) => {
            n_v.push(ipadd);
            return Ok(n_v);
        }
    }
}

/// 该函数用于检查传入的 端口 是否合法
/// 返回 布尔 值，如果含有不合法字符就会返回 false
fn check_port(port: &str) -> bool {
    let re = Regex::new(r"^[0-9,\-]+$");
    match re {
        Ok(o) => {
            if o.is_match(port) {
                return true;
            } else {
                return false;
            }
        }
        Err(e) => {
            error!(event = "REGEX-ERROR", message = e.to_string());
            return false;
        }
    }
}

/// 该结构体用于接收用户创建任务时的数据
/// 仅有三个参数
#[derive(Deserialize)]
pub struct CreateTask {
    pub ip: String,
    pub port: String,
    pub level: i8,
    pub remark: Option<String>,
    #[serde(default = "default_dispatch_mode")]
    pub dispatch_mode: String,
    #[serde(default)]
    pub scanner_ids: Vec<Uuid>,
    #[serde(default)]
    pub scan_profile: Option<String>,
}

fn default_dispatch_mode() -> String {
    "automatic".into()
}

pub fn build_scan_plan(profile: &str) -> Result<Value, &'static str> {
    let stages = match profile {
        "legacy" => serde_json::json!([
            {"type": "port_discovery", "required": true},
            {"type": "service_detection", "required": false}
        ]),
        "port_only" => serde_json::json!([
            {"type": "port_discovery", "required": true}
        ]),
        "service_inventory" => serde_json::json!([
            {"type": "port_discovery", "required": true},
            {"type": "service_detection", "required": true}
        ]),
        _ => return Err("unsupported scan profile"),
    };
    Ok(serde_json::json!({
        "version": 1,
        "profile": profile,
        "stages": stages,
    }))
}

/// 该结构体用于表示一个任务，该结构体不适合直接接收用户创建任务时的数据
pub struct STask<'a> {
    pub task_id: Option<uuid::Uuid>,
    pub task_initiator: &'a str,
    pub ip: Vec<IpNet>,
    // u16 刚好 0~65535，如果不提供则默认为全端口，当然可以在配置文件中配置默认端口
    pub port: Option<&'a str>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>,
    pub remark: Option<&'a str>,
}

impl STask<'_> {
    pub fn address_family(&self) -> Result<&'static str, &'static str> {
        let has_ipv4 = self.ip.iter().any(|target| matches!(target, IpNet::V4(_)));
        let has_ipv6 = self.ip.iter().any(|target| matches!(target, IpNet::V6(_)));
        match (has_ipv4, has_ipv6) {
            (true, false) => Ok("ipv4"),
            (false, true) => Ok("ipv6"),
            (true, true) => Err("同一扫描任务不能混合 IPv4 和 IPv6 目标"),
            (false, false) => Err("扫描目标不能为空"),
        }
    }
}

impl<'a> STask<'a> {
    pub fn new(
        ip: TargetIP,
        initiator: &'a str,
        port: Option<&'a str>,
        remark: Option<&'a str>,
    ) -> Result<Self, AddrParseError> {
        let t_ip = parsing_target(ip)?;

        let t_port = match port {
            Some(p) => {
                if check_port(p) {
                    p
                } else {
                    "1-65535"
                }
            }
            None => "1-65535",
        };
        Ok(Self {
            task_id: Some(Uuid::now_v7()),
            task_initiator: initiator,
            ip: t_ip,
            port: Some(t_port),
            start_at: None,
            end_at: None,
            remark: remark,
        })
    }

    /// 用于向数据库中添加一条扫描任务条目
    /// 返回一个 Result，当执行成功时返回 OK
    pub async fn add(
        &self,
        pool: &deadpool_postgres::Pool,
        level: i32,
        user_id: i32,
        dispatch_mode: &str,
        requested_scanners: &[Option<String>],
        scan_profile: &str,
        scan_plan: &Value,
        audit_context: &audit::AuditContext,
        actor: &admin::UserBaseI,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut p = pool.get().await?;
        let client = p.transaction().await?;
        let t_id: String;
        match self.task_id {
            Some(o) => t_id = o.to_string(),
            None => return Err("task_id 为 None".into()),
        };

        // 将 ipnet转换为 String
        let tmp_ip: Vec<String> = self.ip.iter().map(|i| i.to_string()).collect();
        let address_family = self.address_family()?;

        let task_row = client.query_one(
            "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks, dispatch_mode, address_family, scan_profile, scan_plan) \
             VALUES ($1, $2, $3, ARRAY(SELECT inet(unnest($4::text[]))), $5, $6, $7, $8, $9, $10, $11) RETURNING id;",
            &[&user_id, &t_id, &self.task_initiator, &tmp_ip, &self.port, &level, &self.remark, &dispatch_mode, &address_family, &scan_profile, &scan_plan]
        ).await?;
        let task_db_id: i32 = task_row.get("id");
        for requested_scanner in requested_scanners {
            client.execute(
                "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) VALUES ($1, $2, $3);",
                &[&Uuid::now_v7().to_string(), &task_db_id, requested_scanner],
            ).await?;
        }

        let mut audit_event =
            audit::AuditEvent::user("task", "task.create", "success", actor).resource("task", t_id);
        audit_event.response_status = Some(200);
        audit_event.metadata = serde_json::json!({
            "dispatch_mode": dispatch_mode,
            "scanner_count": requested_scanners.len(),
            "target_count": self.ip.len()
            ,"scan_profile": scan_profile
        });
        audit::write(&client, audit_context, &audit_event).await?;

        client.commit().await?;
        return Ok(());
    }
}

///获取数据库表的大小，单位为字节
async fn get_db_table_size_byte(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    // db_h: &mut HashMap<String, DbTableSizeInfo>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> BTreeMap<String, DbTableSizeInfo> {
    let result = pool.query(sql, params).await;
    match result {
        Ok(rows) => {
            rows.iter()
                .map(|row| {
                    (
                        row.get("table_name"),
                        DbTableSizeInfo {
                            total: row.get("total_size"),
                            data: row.get("data_size"),
                            index: row.get("index_size"),
                        },
                    )
                })
                .collect()
            // for row in rows {
            //     let key = row.get("table_name");
            //     let value: i64 = row.get("total_size");
            //     // let value = values.to_s
            //     db_h.insert(key, value.to_string());
            // }
        }
        Err(e) => {
            error!(
                event = "DatabaseMetricsQueryError",
                operation = "query_table_sizes",
                message = %database_error_diagnostics(&e),
            );
            vec![("error".to_string(), DbTableSizeInfo::default())]
                .into_iter()
                .collect()
        }
    }
}

///获取数据库的大小，单位为字节
async fn get_db_library_size_byte(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    db_name: &str,
) -> String {
    let sql = "SELECT pg_database_size($1::text::name) AS db_size;";
    match pool.query_opt(sql, &[&db_name]).await {
        Ok(Some(row)) => {
            let r: i64 = row.get("db_size");
            r.to_string()
        }
        Ok(None) => {
            warn!(
                event = "DatabaseMetricsEmptyResult",
                operation = "query_database_size",
                database = db_name,
                "database size query returned no row"
            );
            "null".to_string()
        }
        Err(error_value) => {
            error!(
                event = "DatabaseMetricsQueryError",
                operation = "query_database_size",
                database = db_name,
                message = %database_error_diagnostics(&error_value),
            );
            "null".to_string()
        }
    }
}

///获取数据库的连接数
async fn get_db_conn(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> String {
    match pool.query_opt(sql, params).await {
        Ok(Some(row)) => {
            let r: i64 = row.get("db_conn");
            r.to_string()
        }
        Ok(None) => {
            warn!(
                event = "DatabaseMetricsEmptyResult",
                operation = "query_connection_count",
                "database connection count query returned no row"
            );
            "null".to_string()
        }
        Err(error_value) => {
            error!(
                event = "DatabaseMetricsQueryError",
                operation = "query_connection_count",
                message = %database_error_diagnostics(&error_value),
            );
            "null".to_string()
        }
    }
}

///获取服务器运行时间
fn get_server_uptime() -> u64 {
    sysinfo::System::uptime()
}

/// 生成 Argon2id 哈希
///
/// 用于添加用户
pub fn generate_hash_password(
    password: &str,
    config: PasswordHashConfig,
) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(config.m * 1024, config.t, config.p, None)?; // 配置文件中默认 64 MiB, 2 次迭代, 2 并行
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// 用于从数据库中获得用户的密码哈希值和在表中的 ID ，返回一个 Result<(i32, String), Error>
pub async fn get_password_and_id_from_database(
    pool: &deadpool_postgres::Pool,
    username: &str,
) -> Result<(i32, String, UserLoginInfo), Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    if let Some(row) = client.query_opt(
        "SELECT id, username, password, role, email, enable_2fa, totp_secret FROM users \
         WHERE limit_login = FALSE AND disabled_at IS NULL AND deleted_at IS NULL AND username = $1",
        &[&username]
    ).await? {
        // TODO 需要改进，避免闭包获得所有权
        let get_twofa_info = |row: Row| -> Option<TotpInfo> {
            if row.get::<_, bool>("enable_2fa") {
                Some(TotpInfo {
                    username: row.get::<_, String>("username"),
                    // email_address: row.get::<_, String>("email"),
                    totp_secret: row.get::<_, String>("totp_secret")
                })
            } else {
                None
            }
        };

        let u_id = row.get::<_, i32>("id");
        let u_pwd = row.get::<_, String>("password");

        let userinfo = UserLoginInfo {
            username: username.to_string(),
            role: row.get::<_, i32>("role"),
            email_address: row.get::<_, Option<String>>("email"),
            twofa: get_twofa_info(row)
        };

        Ok((u_id, u_pwd, userinfo))
    }
    else {
        info!(
                event = "UserPasswordHASHNotFound",
                path = "fn get_password_from_database",
                message = "用户密码哈希值未找到"
            );
        Err("未找到密码".into())
    }
}

/// 校验密码
pub fn verify_password(password: &str, hash: &str) -> bool {
    let start = Instant::now();

    match PasswordHash::new(hash) {
        Ok(parsed_hash) => {
            let argon2 = Argon2::default();
            let result = argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok();
            println!("verify_pwd {:>6} ms", start.elapsed().as_millis());
            result
        }
        Err(e) => {
            error!(
                event = "ParsedHashError",
                path = "",
                message = %e
            );
            println!("verify_pwd_e {:>6}", start.elapsed().as_millis());
            false
        }
    }
}

///自实现MIME系统。接受一个&str类型的文件后缀，返回一个&str。
#[allow(dead_code)]
fn mime_system(file_suffix: &str) -> &str {
    match file_suffix.to_lowercase().as_str() {
        "html" => TEXT_HTML_UTF_8,
        "css" => TEXT_CSS_UTF_8,
        "png" => IMAGE_PNG,
        "js" => APPLICATION_JAVASCRIPT_UTF_8,
        _ => APPLICATION_OCTET_STREAM,
    }
}

///获取文件后缀，可以输入文件名或者是带路径的文件名 e.g example.png 、 directory/example.png
#[allow(dead_code)]
fn get_file_suffix(path_or_file_name: &Path) -> Result<&str, &str> {
    match path_or_file_name.extension().and_then(|s| s.to_str()) {
        Some(ext) => Ok(ext),
        None => {
            warn!("没有扩展名或无法获取扩展名");
            Err("没有扩展名或无法获取扩展名")
        }
    }
}

///# 前端错误页面
///
/// 该函数主要接受错误信息并根据模板返回错误页的HTML
fn front_end_error_page(info: &FrontEndErrorInfo, templates: &TemplatesInit) -> String {
    //在初始化模板时必须用相对路径
    let tera = match Tera::new(&templates.templates_directory) {
        Ok(t) => t,
        Err(_) => {
            error!("tera模板系统初始化错误");
            panic!("tera初始化错误");
        }
    };

    let mut context = Context::new();
    context.insert("status_code", &info.status_code);
    context.insert("error_title", &info.error_title);
    context.insert("error_message", &info.error_message);
    context.insert("request_id", &info.request_id);

    match tera.render(&templates.templates_name, &context) {
        Ok(body) => body,
        Err(e) => {
            error!("Render error: {}", e);
            eprintln!("Render error: {}", e);
            "<h1>系统故障</h1><p>故障组件：模板系统</p>".to_string()
        }
    }
}

//获取系统状态
// async fn get_system_info(sys: System, pool: deadpool_postgres::Pool, get_timer: u16) {
//     let mut client = pool.get().await;
//     match client {
//         Ok(o) => {
//             let
//         },
//         Err(e) => {

//         }
//     };
// }

///系统信息api基准测试
pub async fn benchmark(
    sys: web::Data<Systems>,
    pool: web::Data<&deadpool_postgres::Pool>,
    db_name: String,
) {
    let total_start = Instant::now();
    let pool = pool.get_ref();

    // CPU
    let start = Instant::now();
    let cpu = SystemCPU::new(sys.sys.clone());
    let cpu_elapsed = start.elapsed();

    // RAM
    let start = Instant::now();
    let ram = SystemRAM::new(sys.sys.clone());
    let ram_elapsed = start.elapsed();

    // Disk
    let start = Instant::now();
    let disk = SystemDisk::new(sys.disk.clone());
    let disk_elapsed = start.elapsed();

    // DB
    let start = Instant::now();
    let db = DbResource::new(pool, "source/database/", &db_name).await;
    let db_elapsed = start.elapsed();

    //Network
    let start = Instant::now();
    let net = SystemNetwork::new(sys.network.clone());
    let net_elapsed = start.elapsed();

    let total_elapsed = total_start.elapsed();

    println!("================= Benchmark =================");
    println!("CPU   : {:>6} µs", cpu_elapsed.as_micros());
    println!("RAM   : {:>6} µs", ram_elapsed.as_micros());
    println!("Disk  : {:>6} µs", disk_elapsed.as_micros());
    println!("DB    : {:>6} µs", db_elapsed.as_micros());
    println!("Net   : {:>6} µs", net_elapsed.as_micros());
    println!("---------------------------------------------");
    println!("Total : {:>6} µs", total_elapsed.as_micros());
    println!("=============================================");

    // 防止编译器优化掉
    let _ = (cpu, ram, disk, db, net);
}

///调用者应当按照实际情况处理None值
/// 目前我感觉无需使用泛型 AsRef<Path>
pub fn path_secure_join(root: &str, input: &str) -> Option<PathBuf> {
    let root = Path::new(root);
    let full_path = root.join(input);
    let canonical = full_path.canonicalize().ok()?;

    if canonical.starts_with(root.canonicalize().ok()?) {
        Some(canonical)
    } else {
        None
    }
}

///向数据库插入系统数据
pub async fn insert_system_status(
    pool: &deadpool_postgres::Pool,
    db_name: String,
    sys: Systems,
    elasticsearch: &ElasticsearchService,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (s, elasticsearch_metrics) = tokio::join!(
        SystemResource::new(sys, pool, &db_name),
        elasticsearch.storage_metrics()
    );
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let sql = get_sql_from_file("source/database/", "insert_system_status.sql").await?;
    let statement = transaction.prepare(&sql).await?;
    let server_run_time = s.server_run_time as i64;
    let cpu = serde_json::to_value(s.cpu).unwrap();
    let ram = serde_json::to_value(s.ram).unwrap();
    let disk = serde_json::to_value(s.disk).unwrap();
    let db_postgresql = serde_json::to_value(s.db_postgresql).unwrap();
    let db_elasticsearch = serde_json::to_value(elasticsearch_metrics).unwrap();
    let network = serde_json::to_value(s.network).unwrap();
    let raw = transaction
        .execute(
            &statement,
            &[
                &server_run_time,
                &cpu,
                &ram,
                &disk,
                &db_postgresql,
                &db_elasticsearch,
                &network,
            ],
        )
        .await?;
    if raw == 1 {
        transaction.commit().await?;
        Ok(())
    } else {
        let message = format!("插入表影响行数为 {}", raw);
        transaction.rollback().await?;
        warn!(
            event = "DATABASE-WARNING",
            path = "fn insert_system_status",
            message
        );
        Err(message.into())
    }
}

///通过该函数获取到访问者的ip，如果失败则会返回一个字符串
pub fn get_conn_ip(req: &HttpRequest) -> String {
    match crate::client_ip::request_ip(req) {
        Some(value) => value.to_string(),
        None => {
            warn!(
                event = "GetHTTPClientIPError",
                message = "无法获取到访问者IP"
            );
            "Unknown".to_string()
        }
    }
}

///通过该函数获取收到的http请求头，如果获取失败则会返回一个字符串
pub fn get_user_agent(req: &HttpRequest) -> String {
    // req.headers().get("User-Agent").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string()
    match req.headers().get("User-Agent") {
        Some(o) => match o.to_str() {
            Ok(o) => o.to_string(),
            Err(e) => {
                warn!(event = "GetHTTPHeadersError", message = e.to_string());
                "Unknown".to_string()
            }
        },
        None => {
            error!(event = "GetHTTPHeadersError", message = "无法获取到请求头");
            "Unknown".to_string()
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ApplyTask {
    pub user_id: i32,
    pub task_id: Uuid,
    pub task_target: Vec<String>,
    pub task_port: String,
    pub address_family: String,
    pub scan_plan: Value,
    pub lease_expires_at_ms: i64,
    pub lease_ttl_ms: i64,
}

#[derive(Deserialize)]
pub struct ScannerResultUpload {
    #[serde(default = "default_result_protocol_version")]
    pub protocol_version: u16,
    pub scanner_id: Uuid,
    pub task_id: Uuid,
    pub upload_id: Option<Uuid>,
    pub batch_index: Option<u32>,
    pub is_final: Option<bool>,
    #[serde(default)]
    pub observations: Vec<ScannerObservation>,
    #[serde(default)]
    pub results: Vec<ScannerResultItem>,
}

fn default_result_protocol_version() -> u16 {
    1
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScannerObservation {
    Port {
        ip: String,
        port: u16,
        protocol: String,
        state: String,
        source: String,
        #[serde(default)]
        observed_at: Option<i64>,
    },
    Service {
        ip: String,
        port: u16,
        protocol: String,
        service: Option<String>,
        banner: Option<String>,
        source: String,
        data: Option<Value>,
        #[serde(default)]
        observed_at: Option<i64>,
    },
}

#[derive(Clone, Deserialize)]
pub struct ScannerResultItem {
    pub ip: String,
    pub port: u16,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub other: Option<Value>,
}

#[derive(Clone, Debug)]
struct NormalizedObservation {
    kind: &'static str,
    ip: String,
    port: u16,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    source: String,
    data: Option<Value>,
    observed_at: Option<i64>,
}

#[derive(Debug)]
pub enum SaveScannerResultsError {
    Database(Box<dyn std::error::Error + Send + Sync>),
    Storage(String),
    InvalidIp { ip: String, source: AddrParseError },
    ScannerUnauthorized,
    TaskNotFound,
    TaskNotOwned,
    InvalidUpload(String),
}

#[derive(Debug)]
pub enum ApplyTaskError {
    Database(Box<dyn std::error::Error + Send + Sync>),
    ScannerUnauthorized,
    NoTask,
}

pub async fn validate_scanner_credentials(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    token: &str,
    token_pepper: &str,
) -> Result<(), ApplyTaskError> {
    let token_hash = hash_scanner_token(token, token_pepper).map_err(apply_task_database_error)?;
    let p = pool.get().await.map_err(apply_task_database_error)?;
    validate_scanner_credentials_with_client(&p, scanner_id, &token_hash).await
}

pub(crate) async fn validate_scanner_credentials_with_client<C>(
    client: &C,
    scanner_id: Uuid,
    token_hash: &str,
) -> Result<(), ApplyTaskError>
where
    C: GenericClient + Sync,
{
    let scanner = client.query_opt(
        "SELECT id FROM scanner_info WHERE scanner_id = $1 AND runtime_token_hash = $2 AND is_enable = true;",
        &[&scanner_id.to_string(), &token_hash]
    ).await.map_err(apply_task_database_error)?;

    if scanner.is_some() {
        Ok(())
    } else {
        Err(ApplyTaskError::ScannerUnauthorized)
    }
}

impl fmt::Display for ApplyTaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "{}", e),
            Self::ScannerUnauthorized => write!(f, "扫描器认证失败"),
            Self::NoTask => write!(f, "没有可领取的任务"),
        }
    }
}

impl std::error::Error for ApplyTaskError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(e) => Some(e.as_ref()),
            Self::ScannerUnauthorized | Self::NoTask => None,
        }
    }
}

fn apply_task_database_error<E>(value: E) -> ApplyTaskError
where
    E: std::error::Error + Send + Sync + 'static,
{
    ApplyTaskError::Database(Box::new(value))
}

impl fmt::Display for SaveScannerResultsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "{}", e),
            Self::Storage(message) => write!(f, "扫描事实存储失败：{message}"),
            Self::InvalidIp { ip, source } => write!(f, "无效 IP/CIDR: {} ({})", ip, source),
            Self::ScannerUnauthorized => write!(f, "扫描器认证失败"),
            Self::TaskNotFound => write!(f, "任务不存在"),
            Self::TaskNotOwned => write!(f, "任务不属于当前扫描器或租约已失效"),
            Self::InvalidUpload(message) => write!(f, "无效扫描结果上传: {message}"),
        }
    }
}

impl std::error::Error for SaveScannerResultsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(e) => Some(e.as_ref()),
            Self::Storage(_) => None,
            Self::InvalidIp { source, .. } => Some(source),
            Self::ScannerUnauthorized
            | Self::TaskNotFound
            | Self::TaskNotOwned
            | Self::InvalidUpload(_) => None,
        }
    }
}

fn scanner_result_database_error<E>(value: E) -> SaveScannerResultsError
where
    E: std::error::Error + Send + Sync + 'static,
{
    SaveScannerResultsError::Database(Box::new(value))
}

/// PostgreSQL 的 text/jsonb 类型不接受 NUL 字节，写入会报
/// 22P05 unsupported Unicode escape sequence。zgrab2 抓取的服务数据
/// （banner、响应体等）常含 NUL，写库前必须剔除。
fn sanitize_text(value: &str) -> String {
    if value.contains('\0') {
        value.replace('\0', "")
    } else {
        value.to_owned()
    }
}

fn sanitize_json_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(sanitize_text(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(sanitize_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (sanitize_text(&key), sanitize_json_value(value)))
                .collect(),
        ),
        other => other,
    }
}

fn sanitize_result_item(item: ScannerResultItem) -> ScannerResultItem {
    ScannerResultItem {
        protocol: item.protocol.map(|value| sanitize_text(&value)),
        service: item.service.map(|value| sanitize_text(&value)),
        banner: item.banner.map(|value| sanitize_text(&value)),
        other: item.other.map(sanitize_json_value),
        ..item
    }
}

fn immutable_scan_observation(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        for field in [
            "asn",
            "isp",
            "as_org",
            "country_code",
            "country_name",
            "region_name",
            "city_name",
            "tags",
        ] {
            object.remove(field);
        }
    }
    value
}

fn normalize_upload_observations(
    upload: &ScannerResultUpload,
) -> Result<Vec<NormalizedObservation>, SaveScannerResultsError> {
    let is_v2 = upload.protocol_version == 2;
    let observations: Vec<NormalizedObservation> = if is_v2 {
        upload
            .observations
            .iter()
            .map(|observation| match observation {
                ScannerObservation::Port {
                    ip,
                    port,
                    protocol,
                    state,
                    source,
                    observed_at,
                } => {
                    let state = sanitize_text(state);
                    let source = sanitize_text(source);
                    NormalizedObservation {
                        kind: "port",
                        ip: ip.clone(),
                        port: *port,
                        protocol: Some(sanitize_text(protocol)),
                        service: None,
                        banner: None,
                        source,
                        data: Some(serde_json::json!({"state": state})),
                        observed_at: *observed_at,
                    }
                }
                ScannerObservation::Service {
                    ip,
                    port,
                    protocol,
                    service,
                    banner,
                    source,
                    data,
                    observed_at,
                } => {
                    let source = sanitize_text(source);
                    let data = data.clone().map(sanitize_json_value);
                    NormalizedObservation {
                        kind: "service",
                        ip: ip.clone(),
                        port: *port,
                        protocol: Some(sanitize_text(protocol)),
                        service: service.as_deref().map(sanitize_text),
                        banner: banner.as_deref().map(sanitize_text),
                        source,
                        data,
                        observed_at: *observed_at,
                    }
                }
            })
            .collect()
    } else {
        upload
            .results
            .iter()
            .cloned()
            .map(sanitize_result_item)
            .map(|item| {
                let kind = if item
                    .service
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                    || item
                        .banner
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
                {
                    "service"
                } else {
                    "port"
                };
                let source = item
                    .other
                    .as_ref()
                    .and_then(|value| value.get("source"))
                    .and_then(Value::as_str)
                    .map(sanitize_text)
                    .filter(|value| !value.is_empty() && value.len() <= 64)
                    .unwrap_or_else(|| "legacy".to_owned());
                let data = Some(serde_json::json!({
                    "state": "open",
                    "legacy_other": item.other.clone(),
                }));
                NormalizedObservation {
                    kind,
                    ip: item.ip,
                    port: item.port,
                    protocol: item.protocol.filter(|value| !value.is_empty()),
                    service: item.service,
                    banner: item.banner,
                    source,
                    data,
                    observed_at: None,
                }
            })
            .collect()
    };

    for observation in &observations {
        if observation.port == 0
            || observation
                .protocol
                .as_ref()
                .is_some_and(|value| value.len() > 16)
            || (is_v2
                && observation
                    .protocol
                    .as_ref()
                    .is_none_or(|value| value.is_empty()))
            || observation.source.is_empty()
            || observation.source.len() > 64
            || observation
                .service
                .as_ref()
                .is_some_and(|value| value.len() > 128)
            || observation
                .banner
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
            || (observation.kind == "port"
                && observation
                    .data
                    .as_ref()
                    .and_then(|value| value["state"].as_str())
                    != Some("open"))
            || observation
                .data
                .as_ref()
                .is_some_and(|value| value.to_string().len() > 1_048_576)
        {
            return Err(SaveScannerResultsError::InvalidUpload(
                "observation fields exceed allowed values or sizes".into(),
            ));
        }
    }

    Ok(observations)
}

#[cfg(test)]
mod sanitize_nul_tests {
    use super::{
        ScannerResultItem, ScannerResultUpload, normalize_upload_observations, sanitize_json_value,
        sanitize_result_item, sanitize_text,
    };

    #[test]
    fn strips_nul_from_plain_text() {
        assert_eq!(sanitize_text("a\u{0}b\u{0}c"), "abc");
        assert_eq!(sanitize_text("no nul"), "no nul");
    }

    #[test]
    fn strips_nul_from_nested_json_values() {
        let value = serde_json::json!({
            "module": "http\u{0}",
            "data": {
                "response": {"body": "bin\u{0}ary"},
                "tags": ["a\u{0}", "b"],
            }
        });
        let sanitized = sanitize_json_value(value);
        assert_eq!(sanitized["module"], "http");
        assert_eq!(sanitized["data"]["response"]["body"], "binary");
        assert_eq!(sanitized["data"]["tags"][0], "a");
        assert_eq!(sanitized["data"]["tags"][1], "b");
    }

    #[test]
    fn strips_nul_from_result_item() {
        let item = ScannerResultItem {
            ip: "192.0.2.1".into(),
            port: 80,
            protocol: Some("tcp\u{0}".into()),
            service: Some("http\u{0}".into()),
            banner: Some("banner\u{0}".into()),
            other: Some(serde_json::json!({"data": "x\u{0}y"})),
        };
        let sanitized = sanitize_result_item(item);
        assert_eq!(sanitized.protocol.as_deref(), Some("tcp"));
        assert_eq!(sanitized.service.as_deref(), Some("http"));
        assert_eq!(sanitized.banner.as_deref(), Some("banner"));
        assert_eq!(sanitized.other.unwrap()["data"], "xy");
    }

    #[test]
    fn normalizes_legacy_results_into_observations() {
        let upload: ScannerResultUpload = serde_json::from_value(serde_json::json!({
            "scanner_id": "00000000-0000-0000-0000-000000000001",
            "task_id": "00000000-0000-0000-0000-000000000002",
            "results": [{
                "ip": "192.0.2.1",
                "port": 443,
                "protocol": null,
                "service": "https",
                "banner": null,
                "other": {"source": "legacy-probe", "tls": true}
            }]
        }))
        .unwrap();

        let observations = normalize_upload_observations(&upload).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind, "service");
        assert_eq!(observations[0].protocol, None);
        assert_eq!(observations[0].source, "legacy-probe");
        assert_eq!(observations[0].data.as_ref().unwrap()["state"], "open");
    }

    #[test]
    fn rejects_typed_observations_without_protocol() {
        let upload: ScannerResultUpload = serde_json::from_value(serde_json::json!({
            "protocol_version": 2,
            "scanner_id": "00000000-0000-0000-0000-000000000001",
            "task_id": "00000000-0000-0000-0000-000000000002",
            "upload_id": "00000000-0000-0000-0000-000000000003",
            "batch_index": 0,
            "is_final": true,
            "observations": [{
                "kind": "port",
                "ip": "192.0.2.1",
                "port": 80,
                "protocol": "",
                "state": "open",
                "source": "masscan"
            }]
        }))
        .unwrap();

        assert!(normalize_upload_observations(&upload).is_err());
    }
}

pub async fn save_scanner_results(
    pool: &deadpool_postgres::Pool,
    maxmind: &MaxMindState,
    elasticsearch: &ElasticsearchService,
    upload: &ScannerResultUpload,
    token: &str,
    token_pepper: &str,
) -> Result<usize, SaveScannerResultsError> {
    let is_v2 = upload.protocol_version == 2;
    if upload.protocol_version != 1 && !is_v2 {
        return Err(SaveScannerResultsError::InvalidUpload(format!(
            "unsupported protocol_version {}",
            upload.protocol_version
        )));
    }
    if is_v2
        && (upload.upload_id.is_none()
            || upload.batch_index.is_none()
            || upload.is_final.is_none()
            || !upload.results.is_empty()
            || upload.observations.len() > 500)
    {
        return Err(SaveScannerResultsError::InvalidUpload(
            "version 2 requires upload_id, batch_index and is_final, accepts only observations, and limits each batch to 500 observations".into(),
        ));
    }
    if !is_v2 && !upload.observations.is_empty() {
        return Err(SaveScannerResultsError::InvalidUpload(
            "typed observations require protocol_version 2".into(),
        ));
    }

    let normalized_observations = normalize_upload_observations(upload)?;
    let storage_mode = elasticsearch.scan_storage_mode();

    let mut client = pool.get().await.map_err(scanner_result_database_error)?;
    let transaction = client
        .transaction()
        .await
        .map_err(scanner_result_database_error)?;
    let token_hash =
        hash_scanner_token(token, token_pepper).map_err(scanner_result_database_error)?;
    let scanner_id = upload.scanner_id.to_string();

    let scanner = transaction.query_opt(
        "SELECT id FROM scanner_info WHERE scanner_id = $1 AND runtime_token_hash = $2 AND is_enable = true;",
        &[&scanner_id, &token_hash]
    ).await.map_err(scanner_result_database_error)?;

    if scanner.is_none() {
        return Err(SaveScannerResultsError::ScannerUnauthorized);
    }

    let task_row = transaction
        .query_opt(
            "SELECT t.id AS task_id, t.user_id, e.id AS execution_id, e.execution_id AS public_execution_id, \
             e.execution_status, e.task_start_time, t.task_source, COALESCE(s.name, e.assigned_scanner_id) AS scanner_name \
             FROM scan_task t JOIN scan_task_execution e ON e.task_id = t.id \
             LEFT JOIN scanner_info s ON s.scanner_id = e.assigned_scanner_id \
             WHERE t.task_id = $1 AND e.assigned_scanner_id = $2 \
             AND e.execution_status IN ('running', 'succeeded') LIMIT 1 FOR UPDATE OF e;",
            &[&upload.task_id.to_string(), &scanner_id],
        )
        .await
        .map_err(scanner_result_database_error)?;

    if let Some(row) = task_row.as_ref()
        && row.get::<_, String>("execution_status") == "succeeded"
    {
        let execution_db_id: i32 = row.get("execution_id");
        let context = ScanBatchContext {
            task_id: upload.task_id.to_string(),
            execution_id: row.get("public_execution_id"),
            user_id: row.get("user_id"),
            task_source: row.get("task_source"),
            scanner_id: scanner_id.clone(),
            scanner_name: row.get("scanner_name"),
            upload_id: upload
                .upload_id
                .map(|value| value.to_string())
                .unwrap_or_else(|| row.get("public_execution_id")),
            batch_index: upload
                .batch_index
                .and_then(|value| i32::try_from(value).ok())
                .unwrap_or_default(),
            is_final: true,
        };
        transaction
            .commit()
            .await
            .map_err(scanner_result_database_error)?;
        if storage_mode.writes_elasticsearch() {
            elasticsearch
                .finalize_scan_projection(pool, execution_db_id, &context)
                .await
                .map_err(SaveScannerResultsError::Storage)?;
        }
        return Ok(0);
    }

    let (
        task_db_id,
        user_id,
        execution_db_id,
        public_execution_id,
        task_start_time,
        task_source,
        scanner_name,
    ): (i32, i32, i32, String, Option<i64>, String, Option<String>) = match task_row {
        Some(row) if row.get::<_, String>("execution_status") == "running" => (
            row.get("task_id"),
            row.get("user_id"),
            row.get("execution_id"),
            row.get("public_execution_id"),
            row.get("task_start_time"),
            row.get("task_source"),
            row.get("scanner_name"),
        ),
        Some(_) => return Err(SaveScannerResultsError::TaskNotOwned),
        None => return Err(SaveScannerResultsError::TaskNotFound),
    };

    let (upload_id, batch_index, is_final) = if is_v2 {
        (
            upload.upload_id.expect("validated above").to_string(),
            i32::try_from(upload.batch_index.expect("validated above")).map_err(|_| {
                SaveScannerResultsError::InvalidUpload("batch_index is too large".into())
            })?,
            upload.is_final.expect("validated above"),
        )
    } else {
        (public_execution_id.clone(), 0, true)
    };
    let batch_context = ScanBatchContext {
        task_id: upload.task_id.to_string(),
        execution_id: public_execution_id.clone(),
        user_id,
        task_source: task_source.clone(),
        scanner_id: scanner_id.clone(),
        scanner_name: scanner_name.clone(),
        upload_id: upload_id.clone(),
        batch_index,
        is_final,
    };
    let conflicting_uploads: i64 = transaction
        .query_one(
            "SELECT COUNT(*)::BIGINT AS count FROM scan_result_batch \
             WHERE execution_id = $1 AND upload_id <> $2;",
            &[&execution_db_id, &upload_id],
        )
        .await
        .map_err(scanner_result_database_error)?
        .get("count");
    if conflicting_uploads > 0 {
        return Err(SaveScannerResultsError::InvalidUpload(
            "an execution cannot contain batches from multiple upload_id values".into(),
        ));
    }
    if is_final {
        let sequence = transaction
            .query_one(
                "SELECT COUNT(*) FILTER (WHERE batch_index < $3)::BIGINT AS prior_count, \
                    MIN(batch_index) FILTER (WHERE batch_index < $3) AS first_prior, \
                    MAX(batch_index) FILTER (WHERE batch_index < $3) AS last_prior, \
                    COUNT(*) FILTER (WHERE batch_index > $3)::BIGINT AS later_count, \
                    COUNT(*) FILTER (WHERE is_final)::BIGINT AS final_count, \
                    BOOL_OR(is_final) FILTER (WHERE batch_index = $3) AS current_is_final \
                 FROM scan_result_batch WHERE execution_id = $1 AND upload_id = $2;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let prior_count: i64 = sequence.get("prior_count");
        let first_prior: Option<i32> = sequence.get("first_prior");
        let last_prior: Option<i32> = sequence.get("last_prior");
        let later_count: i64 = sequence.get("later_count");
        let final_count: i64 = sequence.get("final_count");
        let current_is_final: Option<bool> = sequence.get("current_is_final");
        let prior_sequence_valid = if batch_index == 0 {
            prior_count == 0 && first_prior.is_none() && last_prior.is_none()
        } else {
            prior_count == i64::from(batch_index)
                && first_prior == Some(0)
                && last_prior == Some(batch_index - 1)
        };
        let existing_final_valid = match current_is_final {
            Some(true) => final_count == 1,
            Some(false) => false,
            None => final_count == 0,
        };
        if !prior_sequence_valid || later_count != 0 || !existing_final_valid {
            return Err(SaveScannerResultsError::InvalidUpload(
                "final batch requires one contiguous sequence starting at batch_index 0".into(),
            ));
        }
    }
    let observation_count = i32::try_from(normalized_observations.len()).map_err(|_| {
        SaveScannerResultsError::InvalidUpload("too many observations in one upload".into())
    })?;
    let protocol_version = i16::try_from(upload.protocol_version).expect("validated above");
    let mut observation_rows = Vec::with_capacity(normalized_observations.len());
    let mut ip_intel_cache = HashMap::new();
    let fallback_observed_at = task_start_time.unwrap_or_else(get_unix_epoch_ms);
    for observation in &normalized_observations {
        let parsed_ip = parse_ip_or_cidr(&observation.ip).map_err(|source_error| {
            SaveScannerResultsError::InvalidIp {
                ip: observation.ip.clone(),
                source: source_error,
            }
        })?;
        let canonical_ip = parsed_ip.to_string();
        let observation_key = serde_json::to_string(&serde_json::json!([
            observation.kind,
            canonical_ip,
            observation.port,
            observation.protocol,
            observation.service,
            observation.source
        ]))
        .map_err(scanner_result_database_error)?;
        let endpoint_id = openssl::sha::sha256(
            format!(
                "{}\0{}\0{}",
                public_execution_id, canonical_ip, observation.port
            )
            .as_bytes(),
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
        let ip_addr = parsed_ip.addr();
        let intel = ip_intel_cache
            .entry(ip_addr)
            .or_insert_with(|| maxmind.lookup(ip_addr))
            .clone();
        let search_content = search_content::extract_search_content(observation.data.as_ref());
        let observed_at = observation.observed_at.unwrap_or(fallback_observed_at);
        if observed_at <= 0 || observed_at > get_unix_epoch_ms().saturating_add(86_400_000) {
            return Err(SaveScannerResultsError::InvalidUpload(
                "observed_at must be a Unix epoch millisecond value no more than 24 hours in the future".into(),
            ));
        }
        observation_rows.push(serde_json::json!({
            "observation_key": observation_key,
            "endpoint_id": endpoint_id,
            "kind": observation.kind,
            "ip_address": canonical_ip,
            "port": i32::from(observation.port),
            "protocol": observation.protocol,
            "service": observation.service,
            "banner": observation.banner,
            "title": search_content.title,
            "http_body": search_content.http_body,
            "http_body_truncated": search_content.http_body_truncated,
            "tls_subject": search_content.tls_subject,
            "search_content_extracted": true,
            "source": observation.source,
            "data": observation.data,
            "observed_at": observed_at,
            "asn": intel.asn,
            "isp": intel.isp,
            "as_org": intel.as_org,
            "country_code": intel.country_code,
            "country_name": intel.country_name,
            "region_name": intel.region_name,
            "city_name": intel.city_name,
        }));
    }
    if storage_mode.writes_elasticsearch() && !observation_rows.is_empty() {
        let addresses = observation_rows
            .iter()
            .filter_map(|row| {
                row.get("ip_address")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let tag_rows = transaction
            .query(
                "SELECT host(assignment.ip_address) AS ip, JSONB_AGG(JSONB_BUILD_OBJECT( \
                    'id', tag.id, 'name', tag.name, 'kind', tag.kind, 'description', tag.description) \
                    ORDER BY tag.id) AS tags \
                 FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
                 WHERE tag.is_active AND assignment.ip_address IN \
                    (SELECT address::INET FROM UNNEST($1::TEXT[]) address) \
                 GROUP BY assignment.ip_address;",
                &[&addresses],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let tags_by_ip = tag_rows
            .into_iter()
            .map(|row| (row.get::<_, String>("ip"), row.get::<_, Value>("tags")))
            .collect::<HashMap<_, _>>();
        for row in &mut observation_rows {
            let tags = row
                .get("ip_address")
                .and_then(Value::as_str)
                .and_then(|ip| tags_by_ip.get(ip))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            row.as_object_mut()
                .expect("observation row is object")
                .insert("tags".to_owned(), tags);
        }
    }
    let mut storage_references = Vec::new();
    let mut es_execution_summary = None;
    let payload_checksum = if storage_mode.writes_elasticsearch() {
        let expected_checksum = scan_batch_payload_checksum(&batch_context, &observation_rows)
            .map_err(SaveScannerResultsError::Storage)?;
        if let Some(existing) = transaction
            .query_opt(
                "SELECT is_final, observation_count, payload_checksum FROM scan_result_batch \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?
        {
            let existing_checksum: Option<String> = existing.get("payload_checksum");
            if existing.get::<_, bool>("is_final") != is_final
                || existing.get::<_, i32>("observation_count") != observation_count
                || existing_checksum
                    .as_deref()
                    .is_some_and(|checksum| checksum != expected_checksum)
            {
                return Err(SaveScannerResultsError::InvalidUpload(
                    "batch identity was already used with different content".into(),
                ));
            }
        }
        let result = elasticsearch
            .persist_scan_batch(&batch_context, &observation_rows)
            .await
            .map_err(SaveScannerResultsError::Storage)?;
        debug_assert_eq!(result.payload_checksum, expected_checksum);
        storage_references = result.indices;
        es_execution_summary = result.execution_summary;
        result.payload_checksum
    } else {
        openssl::sha::sha256(
            &serde_json::to_vec(&serde_json::json!({
                "execution_id": public_execution_id,
                "upload_id": upload_id,
                "batch_index": batch_index,
                "is_final": is_final,
                "observations": observation_rows.iter().map(immutable_scan_observation).collect::<Vec<_>>(),
            }))
            .map_err(scanner_result_database_error)?,
        )
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
    };
    let storage_backend = match storage_mode {
        config::ScanStorageMode::Postgres => "postgres",
        config::ScanStorageMode::Dual => "dual",
        config::ScanStorageMode::Elasticsearch => "elasticsearch",
    };
    let storage_references =
        Value::Array(storage_references.into_iter().map(Value::String).collect());
    let row = transaction
        .query_opt(
            "INSERT INTO scan_result_batch (execution_id, upload_id, batch_index, is_final, observation_count, \
                protocol_version, payload_checksum, storage_backend, storage_references) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (execution_id, upload_id, batch_index) DO NOTHING RETURNING id;",
            &[
                &execution_db_id,
                &upload_id,
                &batch_index,
                &is_final,
                &observation_count,
                &protocol_version,
                &payload_checksum,
                &storage_backend,
                &storage_references,
            ],
        )
        .await
        .map_err(scanner_result_database_error)?;
    let Some(row) = row else {
        let existing = transaction
            .query_one(
                "SELECT is_final, observation_count, payload_checksum FROM scan_result_batch \
                 WHERE execution_id = $1 AND upload_id = $2 AND batch_index = $3;",
                &[&execution_db_id, &upload_id, &batch_index],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let existing_checksum: Option<String> = existing.get("payload_checksum");
        if existing.get::<_, bool>("is_final") != is_final
            || existing.get::<_, i32>("observation_count") != observation_count
            || existing_checksum
                .as_deref()
                .is_some_and(|checksum| checksum != payload_checksum)
        {
            return Err(SaveScannerResultsError::InvalidUpload(
                "batch identity was already used with different content".into(),
            ));
        }
        transaction
            .commit()
            .await
            .map_err(scanner_result_database_error)?;
        return Ok(0);
    };
    let batch_db_id: i64 = row.get("id");
    let observation_rows = Value::Array(observation_rows);
    // Keep the fact rows and their asset projection in one set-based statement. The
    // projection reads only rows inserted by this batch and deduplicates both IPs and
    // endpoints, so port/service observations do not repeat the same UPSERT work.
    let saved = if storage_mode.writes_postgres() {
        let saved_row = transaction
            .query_one(
            "WITH input AS MATERIALIZED ( \
                SELECT * FROM jsonb_to_recordset($4::jsonb) AS item( \
                    observation_key TEXT, kind TEXT, ip_address INET, port INT, \
                    protocol TEXT, service TEXT, banner TEXT, title TEXT, http_body TEXT, \
                    http_body_truncated BOOLEAN, tls_subject TEXT, source TEXT, data JSONB, \
                    search_content_extracted BOOLEAN, observed_at_ms BIGINT, \
                    asn TEXT, isp TEXT, as_org TEXT, country_code TEXT, \
                    country_name TEXT, region_name TEXT, city_name TEXT) \
             ), inserted_observations AS ( \
                INSERT INTO scan_observation (execution_id, batch_id, observation_key, kind, \
                    ip_address, port, protocol, service, banner, title, http_body, \
                    http_body_truncated, tls_subject, search_content_extracted, source, data, observed_at) \
                SELECT $2, $3, observation_key, kind, ip_address, port, protocol, service, \
                    banner, title, http_body, http_body_truncated, tls_subject, \
                    search_content_extracted, source, data, to_timestamp(observed_at_ms / 1000.0) FROM input \
                ON CONFLICT (execution_id, observation_key) DO NOTHING \
                RETURNING ip_address, port \
             ), inserted_endpoints AS MATERIALIZED ( \
                SELECT DISTINCT ip_address, port FROM inserted_observations \
             ), inserted_ip_addresses AS MATERIALIZED ( \
                SELECT DISTINCT ip_address FROM inserted_endpoints \
             ), upserted_ips AS ( \
                INSERT INTO ips (task_id, execution_id, ip_address, asn, isp, as_org, \
                    country_code, country_name, region_name, city_name) \
                SELECT DISTINCT ON (item.ip_address) $1, $2, item.ip_address, item.asn, \
                    item.isp, item.as_org, item.country_code, item.country_name, \
                    item.region_name, item.city_name \
                FROM input item \
                JOIN inserted_ip_addresses inserted ON inserted.ip_address = item.ip_address \
                ORDER BY item.ip_address \
                ON CONFLICT (execution_id, ip_address) DO UPDATE SET \
                    asn = COALESCE(EXCLUDED.asn, ips.asn), \
                    isp = COALESCE(EXCLUDED.isp, ips.isp), \
                    as_org = COALESCE(EXCLUDED.as_org, ips.as_org), \
                    country_code = COALESCE(EXCLUDED.country_code, ips.country_code), \
                    country_name = COALESCE(EXCLUDED.country_name, ips.country_name), \
                    region_name = COALESCE(EXCLUDED.region_name, ips.region_name), \
                    city_name = COALESCE(EXCLUDED.city_name, ips.city_name), \
                    update_time = (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT \
                RETURNING ip_id, ip_address \
             ), upserted_ports AS ( \
                INSERT INTO ports (ip_id, port) \
                SELECT ip.ip_id, endpoint.port FROM inserted_endpoints endpoint \
                JOIN upserted_ips ip ON ip.ip_address = endpoint.ip_address \
                ON CONFLICT (ip_id, port) DO UPDATE SET \
                    update_time = (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT \
                RETURNING port_id \
             ) \
             SELECT COUNT(*)::BIGINT AS saved FROM inserted_observations;",
            &[
                &task_db_id,
                &execution_db_id,
                &batch_db_id,
                &observation_rows,
            ],
        )
            .await
            .map_err(scanner_result_database_error)?;
        usize::try_from(saved_row.get::<_, i64>("saved")).map_err(scanner_result_database_error)?
    } else {
        normalized_observations.len()
    };

    if !is_v2 || upload.is_final == Some(true) {
        let batch_sequence = transaction
            .query_one(
                "SELECT COUNT(*)::BIGINT AS count, MIN(batch_index) AS first_batch, \
                    MAX(batch_index) AS last_batch, \
                    COUNT(*) FILTER (WHERE is_final)::BIGINT AS final_count \
                 FROM scan_result_batch WHERE execution_id = $1 AND upload_id = $2;",
                &[&execution_db_id, &upload_id],
            )
            .await
            .map_err(scanner_result_database_error)?;
        let count: i64 = batch_sequence.get("count");
        let first_batch: Option<i32> = batch_sequence.get("first_batch");
        let last_batch: Option<i32> = batch_sequence.get("last_batch");
        let final_count: i64 = batch_sequence.get("final_count");
        if first_batch != Some(0)
            || last_batch != Some(batch_index)
            || count != i64::from(batch_index) + 1
            || final_count != 1
        {
            return Err(SaveScannerResultsError::InvalidUpload(
                "final batch requires one contiguous sequence starting at batch_index 0".into(),
            ));
        }
        let execution_summary = if storage_mode.writes_postgres() {
            let row = transaction
                .query_one(
                    "SELECT (SELECT COUNT(*)::BIGINT FROM ips WHERE execution_id = $1) AS ip_count, \
                        (SELECT COUNT(*)::BIGINT FROM ports p JOIN ips i ON i.ip_id = p.ip_id \
                            WHERE i.execution_id = $1) AS port_count, \
                        (SELECT COUNT(*)::BIGINT FROM scan_observation WHERE execution_id = $1) AS observation_count;",
                    &[&execution_db_id],
                )
                .await
                .map_err(scanner_result_database_error)?;
            elasticsearch::ScanExecutionSummary {
                ip_count: row.get("ip_count"),
                port_count: row.get("port_count"),
                observation_count: row.get("observation_count"),
            }
        } else {
            es_execution_summary.ok_or_else(|| {
                SaveScannerResultsError::Storage(
                    "final batch did not produce execution counters".into(),
                )
            })?
        };
        transaction
            .execute(
                "UPDATE scan_task_execution SET execution_status = 'succeeded', task_end_time = $1, \
                 lease_expires_at = NULL, failure_reason = NULL, cancel_requested = false, \
                 result_ip_count = $3, result_port_count = $4, result_observation_count = $5 WHERE id = $2;",
                &[
                    &get_unix_epoch_ms(),
                    &execution_db_id,
                    &execution_summary.ip_count,
                    &execution_summary.port_count,
                    &execution_summary.observation_count,
                ],
            )
            .await
            .map_err(scanner_result_database_error)?;
        if storage_mode.writes_postgres() {
            search_projection::refresh_for_execution(&transaction, execution_db_id)
                .await
                .map_err(scanner_result_database_error)?;
        }
        if storage_mode.writes_elasticsearch() {
            transaction
                .execute(
                    "INSERT INTO scan_projection_outbox (execution_id, attempts, available_at, processed_at, last_error) \
                     VALUES ($1, 0, NOW(), NULL, NULL) ON CONFLICT (execution_id) DO UPDATE SET \
                     attempts = 0, available_at = NOW(), processed_at = NULL, last_error = NULL;",
                    &[&execution_db_id],
                )
                .await
                .map_err(scanner_result_database_error)?;
        }
        refresh_task_aggregate(&transaction, task_db_id)
            .await
            .map_err(scanner_result_database_error)?;
    }

    transaction
        .commit()
        .await
        .map_err(scanner_result_database_error)?;
    if is_final && storage_mode.writes_elasticsearch() {
        elasticsearch
            .finalize_scan_projection(pool, execution_db_id, &batch_context)
            .await
            .map_err(SaveScannerResultsError::Storage)?;
    }
    Ok(saved)
}

pub async fn refresh_task_aggregate(
    transaction: &tokio_postgres::Transaction<'_>,
    task_db_id: i32,
) -> Result<(), tokio_postgres::Error> {
    transaction.execute(
        "WITH aggregate AS (SELECT \
            COUNT(*)::INT AS total, \
            COUNT(*) FILTER (WHERE execution_status = 'pending')::INT AS pending, \
            COUNT(*) FILTER (WHERE execution_status = 'running')::INT AS running, \
            COUNT(*) FILTER (WHERE execution_status = 'succeeded')::INT AS succeeded, \
            COUNT(*) FILTER (WHERE execution_status = 'failed')::INT AS failed, \
            COUNT(*) FILTER (WHERE execution_status = 'cancelled')::INT AS cancelled, \
            MIN(task_start_time) AS started_at, MAX(task_end_time) AS ended_at, \
            SUM(attempt_count)::INT AS attempts, BOOL_OR(cancel_requested) AS cancelling, \
            CASE WHEN COUNT(*) = 1 THEN MAX(assigned_scanner_id) ELSE NULL END AS scanner_id, \
            STRING_AGG(CASE WHEN failure_reason IS NOT NULL THEN \
                COALESCE(assigned_scanner_id, requested_scanner_id, 'unassigned') || ': ' || failure_reason END, E'\\n') AS failures \
          FROM scan_task_execution WHERE task_id = $1 AND execution_status <> 'superseded') \
         UPDATE scan_task t SET \
           task_status = CASE WHEN a.running > 0 THEN 'running' WHEN a.pending > 0 THEN 'pending' \
             WHEN a.succeeded = a.total THEN 'succeeded' WHEN a.failed = a.total THEN 'failed' \
             WHEN a.cancelled = a.total THEN 'cancelled' ELSE 'partial' END, \
           task_start_time = a.started_at, \
           task_end_time = CASE WHEN a.pending = 0 AND a.running = 0 THEN a.ended_at ELSE NULL END, \
           attempt_count = a.attempts, assigned_scanner_id = a.scanner_id, \
           lease_expires_at = NULL, failure_reason = a.failures, cancel_requested = a.cancelling \
         FROM aggregate a WHERE t.id = $1;",
        &[&task_db_id],
    ).await?;
    Ok(())
}

/// 通过该函数实现扫描器申请任务
/// 首先搜索合适的任务，如果没有任务则会创建一个系统任务，该任务也会写入 scan_task 中
pub async fn apply_task(
    pool: &deadpool_postgres::Pool,
    scanner_id: Uuid,
    token: &str,
    token_pepper: &str,
) -> Result<ApplyTask, ApplyTaskError> {
    let mut p = pool.get().await.map_err(apply_task_database_error)?;
    let transaction = p.transaction().await.map_err(apply_task_database_error)?;
    let token_hash = hash_scanner_token(token, token_pepper).map_err(apply_task_database_error)?;
    validate_scanner_credentials_with_client(&transaction, scanner_id, &token_hash).await?;

    let cancelled = transaction
        .query(
            "UPDATE scan_task_execution SET execution_status = 'cancelled', task_end_time = $1, \
             lease_expires_at = NULL, cancel_requested = false \
             WHERE execution_status = 'running' AND cancel_requested = true \
               AND (lease_expires_at IS NULL OR lease_expires_at < $1) RETURNING task_id;",
            &[&get_unix_epoch_ms()],
        )
        .await
        .map_err(apply_task_database_error)?;
    let cancelled_tasks: std::collections::HashSet<i32> =
        cancelled.iter().map(|row| row.get("task_id")).collect();
    for task_id in cancelled_tasks {
        refresh_task_aggregate(&transaction, task_id)
            .await
            .map_err(apply_task_database_error)?;
    }

    let row = transaction
        .query_opt(
            "SELECT t.id AS task_pk, e.id AS execution_pk, t.user_id, t.task_id, t.task_target::text[], t.task_port, t.address_family, t.scan_plan \
         FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
         JOIN scanner_info s ON s.scanner_id = $2 \
         WHERE (e.execution_status = 'pending' OR (e.execution_status = 'running' AND e.cancel_requested = false \
              AND (e.lease_expires_at IS NULL OR e.lease_expires_at < $1))) \
           AND (e.requested_scanner_id IS NULL OR e.requested_scanner_id = $2) \
           AND ((t.address_family = 'ipv4' AND s.supports_ipv4 AND s.ipv4_ready) \
             OR (t.address_family = 'ipv6' AND s.supports_ipv6 AND s.ipv6_ready)) \
           AND (t.scan_profile = 'legacy' OR s.scan_capabilities->'profiles' ? t.scan_profile) \
         ORDER BY t.task_level DESC, t.task_create_time, e.id \
         FOR UPDATE OF e SKIP LOCKED \
         LIMIT 1;",
            &[&get_unix_epoch_ms(), &scanner_id.to_string()],
        )
        .await
        .map_err(apply_task_database_error)?;

    let Some(row) = row else {
        info!(
            event = "NOTFOUND-TASK",
            path = "fn apply_task",
            message = "没有可领取的扫描任务"
        );
        return Err(ApplyTaskError::NoTask);
    };

    let task_pk: i32 = row.get("task_pk");
    let execution_pk: i32 = row.get("execution_pk");
    let lease_expires_at = get_unix_epoch_ms() + 90_000;
    transaction
        .execute(
            "UPDATE scan_task_execution SET task_start_time = COALESCE(task_start_time, $1), task_end_time = NULL, \
             execution_status = 'running', assigned_scanner_id = $2, lease_expires_at = $3, \
             attempt_count = attempt_count + 1, failure_reason = NULL WHERE id = $4;",
            &[
                &get_unix_epoch_ms(),
                &scanner_id.to_string(),
                &lease_expires_at,
                &execution_pk,
            ],
        )
        .await
        .map_err(apply_task_database_error)?;
    refresh_task_aggregate(&transaction, task_pk)
        .await
        .map_err(apply_task_database_error)?;

    let task_id = Uuid::parse_str(row.get::<_, String>("task_id").as_str())
        .map_err(apply_task_database_error)?;
    let apply_task = ApplyTask {
        user_id: row.get("user_id"),
        task_id,
        task_target: row.get("task_target"),
        task_port: row.get("task_port"),
        address_family: row.get("address_family"),
        scan_plan: row.get("scan_plan"),
        lease_expires_at_ms: lease_expires_at,
        lease_ttl_ms: TASK_LEASE_MS,
    };

    transaction
        .commit()
        .await
        .map_err(apply_task_database_error)?;
    info!(
        event = "SEARCH-TASK",
        path = "fn apply_task",
        message = apply_task.task_id.to_string()
    );
    Ok(apply_task)
}

#[derive(Deserialize)]
pub struct ApplyTaskQuery {
    pub scannerid: Uuid,
    pub dryrun: Option<bool>,
}

/// 该函数用于退出登录
///
/// 返回一个 Result<bool> ，返回 true 代表该 token 已被正常销毁，返回 false 代表 token 本身就是无效的。
pub async fn log_out(
    session: &str,
    pool: &deadpool_postgres::Pool,
    reason: &str,
    deleted_by_user_id: Option<i32>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let c = pool.get().await?;
    if let Some(tmp_r) = c
        .query_opt(
            "UPDATE session SET is_enable = FALSE, deleted_at = NOW(), \
             deletion_reason = $2, deleted_by_user_id = $3 \
             WHERE token = $1 AND is_enable = TRUE AND deleted_at IS NULL RETURNING id;",
            &[&session, &reason, &deleted_by_user_id],
        )
        .await?
    {
        info!(
            event = "UserLogout",
            path = "fn log_out",
            message = "用户已退出登录"
        );
        let t_l = tmp_r.len();
        if t_l != 1 {
            error!(
                event = "Error",
                path = "fn log_out",
                message = format!("更新session返回值长度为{}", t_l)
            );
        }
        Ok(true)
    } else {
        info!(
            event = "TokenInvaild",
            path = "fn log_out",
            message = "Token 无效"
        );
        Ok(false)
    }
}

/// 该枚举定义了权限，其中系统权限最高，该级别的用户由初始化数据库时创建，且该权限的用户无法查看其他用户的数据，该权限主要用于系统自动创建的扫描任务
/// Administrator 为管理员权限，该权限可以查看所有的任务
/// 使用枚举时需要传入一个用户id
pub enum Permission {
    Administrator(i32),
    Users(i32),
}

/// 表示单个任务条目
#[derive(Serialize)]
pub struct TaskItem {
    pub task_id: String,
    pub task_target: Vec<IpInet>,
    pub task_initiator: String,
    pub task_port: String,
    pub task_create_time: i64,
    pub task_level: i32,
    pub scanner_id: Option<String>,
    pub task_status: String,
    pub lease_expires_at: Option<i64>,
    pub attempt_count: i32,
    pub failure_reason: Option<String>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>,
    pub remarks: Option<String>,
    pub task_source: String,
    pub address_family: String,
    pub scan_profile: String,
    pub scan_plan: Value,
}

/// 表示 Json 格式的任务列表
#[derive(Serialize)]
pub struct TaskItemJson {
    pub total: i64,
    pub page_size: i64,
    pub next_cursor: Option<i32>,
    pub has_more: bool,
    pub items: Vec<TaskItem>,
}

/// 该结构体表示接收查询任务列表信息
#[derive(Deserialize)]
pub struct ReceiveTaskItemQueryInfo {
    #[serde(alias = "start")]
    pub cursor: Option<i32>,
    #[serde(alias = "count")]
    pub limit: Option<i64>,
    pub include_system: Option<bool>,
    pub task_id: Option<String>,
    pub target: Option<String>,
    pub status: Option<String>,
    pub operator: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub scanner_id: Option<String>,
}

pub struct TaskListFilters {
    pub cursor: Option<i32>,
    pub limit: i64,
    pub include_system: bool,
    pub task_id: Option<String>,
    pub target: Option<String>,
    pub status: Option<String>,
    pub operator: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub scanner_id: Option<String>,
}

pub struct TaskListPage {
    pub items: Vec<TaskItem>,
    pub total: i64,
    pub page_size: i64,
    pub next_cursor: Option<i32>,
    pub has_more: bool,
}

/// 该函数用于获取所有的扫描任务记录，需要鉴权，普通用户只能获取到自己创建的任务，管理员则可以获取所有的
///
/// 接收多个参数，分别为
#[deprecated(note = "use get_filtered_task_page for stable pagination and server-side filters")]
pub async fn get_task_item(
    pool: &deadpool_postgres::Pool,
    s_count: i64,
    start_id: Option<i32>,
    include_system: bool,
    permissions: Permission,
) -> Result<(Vec<TaskItem>, i64, i64, i32), Box<dyn std::error::Error>> {
    let mut c = pool.get().await?;
    let s_count = s_count.clamp(1, 100);
    let transaction = c.transaction().await?;
    let expired = transaction.query(
        "UPDATE scan_task_execution SET execution_status = CASE WHEN cancel_requested THEN 'cancelled' ELSE 'pending' END, \
         assigned_scanner_id = CASE WHEN cancel_requested THEN assigned_scanner_id ELSE NULL END, lease_expires_at = NULL, \
         task_start_time = CASE WHEN cancel_requested THEN task_start_time ELSE NULL END, \
         task_end_time = CASE WHEN cancel_requested THEN (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT ELSE NULL END, \
         cancel_requested = false, failure_reason = CASE WHEN cancel_requested THEN NULL ELSE 'task lease expired' END \
         WHERE execution_status = 'running' AND lease_expires_at IS NOT NULL \
           AND lease_expires_at < (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT RETURNING task_id;", &[]).await?;
    let expired_tasks: std::collections::HashSet<i32> =
        expired.iter().map(|row| row.get("task_id")).collect();
    for task_id in expired_tasks {
        refresh_task_aggregate(&transaction, task_id).await?;
    }
    transaction.commit().await?;

    let row = match permissions {
        Permission::Administrator(_id) => {
            if let Some(st) = start_id {
                c.query(
                    "SELECT *, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE id <= $1 AND ($2::boolean OR task_source <> 'automatic') \
                     ORDER BY id DESC LIMIT $3;",
                    &[&st, &include_system, &s_count],
                )
                .await?
            } else {
                c.query(
                    "SELECT *, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE $1::boolean OR task_source <> 'automatic' ORDER BY id DESC LIMIT $2;",
                    &[&include_system, &s_count],
                )
                .await?
            }
        }
        Permission::Users(u_id) => {
            if let Some(st) = start_id {
                c.query(
                    "SELECT *, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE user_id = $1 AND id <= $2 AND ($3::boolean OR task_source <> 'automatic') \
                     ORDER BY id DESC LIMIT $4;",
                    &[&u_id, &st, &include_system, &s_count]
                ).await?
            } else {
                c.query(
                    "SELECT *, COUNT(*) OVER() AS total_count FROM scan_task \
                     WHERE user_id = $1 AND ($2::boolean OR task_source <> 'automatic') \
                     ORDER BY id DESC LIMIT $3;",
                    &[&u_id, &include_system, &s_count],
                )
                .await?
            }
        }
    };

    let mut task_item_r: Vec<TaskItem> = Vec::new();
    let mut total_count_item: i64 = 0;
    let mut count: i64 = 0;
    let mut start_id: i32 = 0;

    for (index, r) in row.iter().enumerate() {
        if index == 0 {
            start_id = r.get::<_, i32>("id");
        }
        total_count_item = r.get::<_, i64>("total_count");
        let titem = TaskItem {
            task_id: r.get::<_, String>("task_id"),
            task_target: r.get::<_, Vec<IpInet>>("task_target"),
            task_initiator: r.get::<_, String>("task_initiator"),
            task_level: r.get::<_, i32>("task_level"),
            task_port: r.get::<_, String>("task_port"),
            task_create_time: r.get::<_, i64>("task_create_time"),
            scanner_id: r.get::<_, Option<String>>("assigned_scanner_id"),
            task_status: r.get::<_, String>("task_status"),
            lease_expires_at: r.get::<_, Option<i64>>("lease_expires_at"),
            attempt_count: r.get::<_, i32>("attempt_count"),
            failure_reason: r.get::<_, Option<String>>("failure_reason"),
            start_at: r.get::<_, Option<i64>>("task_start_time"),
            end_at: r.get::<_, Option<i64>>("task_end_time"),
            remarks: r.get::<_, Option<String>>("remarks"),
            task_source: r.get::<_, String>("task_source"),
            address_family: r.get::<_, String>("address_family"),
            scan_profile: r.get::<_, String>("scan_profile"),
            scan_plan: r.get::<_, Value>("scan_plan"),
        };
        task_item_r.push(titem);
        count += 1;
    }
    Ok((task_item_r, total_count_item, count, start_id))
}

/// 使用服务端筛选和排他游标分页获取任务，单次最多返回 100 条记录。
pub async fn get_filtered_task_page(
    pool: &deadpool_postgres::Pool,
    filters: &TaskListFilters,
    permissions: Permission,
) -> Result<TaskListPage, Box<dyn std::error::Error>> {
    let mut connection = pool.get().await?;
    let transaction = connection.transaction().await?;
    let expired = transaction
        .query(
            "UPDATE scan_task_execution SET execution_status = CASE WHEN cancel_requested THEN 'cancelled' ELSE 'pending' END, \
             assigned_scanner_id = CASE WHEN cancel_requested THEN assigned_scanner_id ELSE NULL END, lease_expires_at = NULL, \
             task_start_time = CASE WHEN cancel_requested THEN task_start_time ELSE NULL END, \
             task_end_time = CASE WHEN cancel_requested THEN (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT ELSE NULL END, \
             cancel_requested = false, failure_reason = CASE WHEN cancel_requested THEN NULL ELSE 'task lease expired' END \
             WHERE execution_status = 'running' AND lease_expires_at IS NOT NULL \
               AND lease_expires_at < (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT RETURNING task_id;",
            &[],
        )
        .await?;
    let expired_tasks: std::collections::HashSet<i32> =
        expired.iter().map(|row| row.get("task_id")).collect();
    for task_id in expired_tasks {
        refresh_task_aggregate(&transaction, task_id).await?;
    }
    transaction.commit().await?;

    let (role, user_id) = match permissions {
        Permission::Administrator(id) => (1_i32, id),
        Permission::Users(id) => (2_i32, id),
    };
    const FILTER_SQL: &str = "($1 = 1 OR t.user_id = $2) \
        AND ($3::BOOLEAN OR t.task_source <> 'automatic') \
        AND ($4::TEXT IS NULL OR t.task_id ILIKE '%' || $4 || '%') \
        AND ($5::TEXT IS NULL OR EXISTS (\
            SELECT 1 FROM unnest(t.task_target) AS targets(target) \
            WHERE targets.target::TEXT ILIKE '%' || $5 || '%'\
        )) \
        AND ($6::TEXT IS NULL OR t.task_status = $6) \
        AND ($7::TEXT IS NULL OR t.task_initiator ILIKE '%' || $7 || '%') \
        AND ($8::BIGINT IS NULL OR t.task_create_time >= $8) \
        AND ($9::BIGINT IS NULL OR t.task_create_time <= $9) \
        AND ($10::TEXT IS NULL OR COALESCE(t.assigned_scanner_id, '') ILIKE '%' || $10 || '%')";
    let count_sql = format!("SELECT COUNT(*)::BIGINT AS total FROM scan_task t WHERE {FILTER_SQL}");
    let count_params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &role,
        &user_id,
        &filters.include_system,
        &filters.task_id,
        &filters.target,
        &filters.status,
        &filters.operator,
        &filters.start_time,
        &filters.end_time,
        &filters.scanner_id,
    ];
    let total = connection
        .query_one(&count_sql, count_params)
        .await?
        .get("total");

    let page_size = filters.limit.clamp(1, 100);
    let fetch_limit = page_size + 1;
    let page_sql = format!(
        "SELECT t.* FROM scan_task t WHERE {FILTER_SQL} \
         AND ($11::INTEGER IS NULL OR t.id < $11) \
         ORDER BY t.id DESC LIMIT $12"
    );
    let mut rows = connection
        .query(
            &page_sql,
            &[
                &role,
                &user_id,
                &filters.include_system,
                &filters.task_id,
                &filters.target,
                &filters.status,
                &filters.operator,
                &filters.start_time,
                &filters.end_time,
                &filters.scanner_id,
                &filters.cursor,
                &fetch_limit,
            ],
        )
        .await?;
    let has_more = rows.len() > page_size as usize;
    if has_more {
        rows.truncate(page_size as usize);
    }
    let next_cursor = if has_more {
        rows.last().map(|row| row.get::<_, i32>("id"))
    } else {
        None
    };
    let items = rows
        .into_iter()
        .map(|row| TaskItem {
            task_id: row.get("task_id"),
            task_target: row.get("task_target"),
            task_initiator: row.get("task_initiator"),
            task_port: row.get("task_port"),
            task_create_time: row.get("task_create_time"),
            task_level: row.get("task_level"),
            scanner_id: row.get("assigned_scanner_id"),
            task_status: row.get("task_status"),
            lease_expires_at: row.get("lease_expires_at"),
            attempt_count: row.get("attempt_count"),
            failure_reason: row.get("failure_reason"),
            start_at: row.get("task_start_time"),
            end_at: row.get("task_end_time"),
            remarks: row.get("remarks"),
            task_source: row.get("task_source"),
            address_family: row.get("address_family"),
            scan_profile: row.get("scan_profile"),
            scan_plan: row.get("scan_plan"),
        })
        .collect();
    Ok(TaskListPage {
        items,
        total,
        page_size,
        next_cursor,
        has_more,
    })
}

/// 用于接收系统信息查询
#[derive(Deserialize)]
pub struct ReceiveSystemStatusInfo {
    pub count: Option<i64>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct SystemStatusJson {
    pub total_c: i32,
    pub status_item: Vec<SystemResource>,
    pub system_info: SystemDetails,
}

/// 获取系统状态信息
pub async fn get_system_status_info(
    start_at: Option<i64>,
    end_at: Option<i64>,
    count: i64,
    pool: &deadpool_postgres::Pool,
) -> Result<(Vec<SystemResource>, i32), Box<dyn std::error::Error>> {
    let connect = pool.get().await?;

    let row = if start_at.is_some() || end_at.is_some() {
        connect
            .query(
                "SELECT *
                        FROM system_status
                        WHERE create_time BETWEEN
                            COALESCE($1, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT)
                            AND
                            COALESCE($2, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT)
                        ORDER BY id DESC
                        LIMIT $3;",
                &[&start_at, &end_at, &count],
            )
            .await?
    } else {
        connect
            .query(
                "SELECT * FROM system_status ORDER BY id DESC LIMIT $1;",
                &[&count],
            )
            .await?
    };

    let mut vec_status: Vec<SystemResource> = Vec::new();
    let mut tmp_count: i32 = 0;

    for r in row {
        let tmp = SystemResource {
            server_run_time: r.get::<_, i64>("server_run_time"),
            cpu: serde_json::from_value(r.get::<_, Value>("cpu"))?,
            ram: serde_json::from_value(r.get::<_, Value>("ram"))?,
            disk: serde_json::from_value(r.get::<_, Value>("disk"))?,
            db_postgresql: serde_json::from_value(r.get::<_, Value>("db_postgresql"))?,
            network: serde_json::from_value(r.get::<_, Value>("network"))?,
            create_at: Some(r.get::<_, i64>("create_time")),
        };
        tmp_count += 1;
        vec_status.push(tmp);
    }
    Ok((vec_status, tmp_count))
}

/// 加密关键数据
///
/// 该函数接受一个参数 明文。返回三个参数，分别为 nonce、tag、密文
pub fn encrypt_data(
    plaintext: &[u8],
    key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), openssl::error::ErrorStack> {
    // 32 字节密钥，且初始化为 1
    // let mut key = [1u8; 32];
    // rand::rand_bytes(&mut key)?;

    // 12 字节nonce ，初始化为 0
    let mut nonce = [0u8; 12];
    rand::rand_bytes(&mut nonce)?;

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&nonce))?;

    // GCM 不需要 padding
    crypter.pad(false);

    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];

    let count = crypter.update(plaintext, &mut ciphertext)?;

    let rest = crypter.finalize(&mut ciphertext[count..])?;

    ciphertext.truncate(count + rest);

    let mut tag = [0u8; 16];
    crypter.get_tag(&mut tag)?;

    Ok((nonce.to_vec(), tag.to_vec(), ciphertext))
}

/// 解密
///
pub fn decrypt_data(
    // value: &[u8],
    value: &Vec<u8>,
    // ciphertext: &[u8],
    key: &[u8],
    // nonce: &[u8],
    // tag: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let nonce = &value[..12];
    let tag = &value[12..28];
    let ciphertext = &value[28..];

    let cipher = Cipher::aes_256_gcm();

    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce))?;

    crypter.pad(false);

    crypter.set_tag(tag)?;

    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];

    let count = crypter.update(ciphertext, &mut plaintext)?;

    let rest = crypter.finalize(&mut plaintext[count..])?;

    plaintext.truncate(count + rest);

    Ok(plaintext)
}
