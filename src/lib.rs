
pub mod logs;
pub mod config;
pub mod db;
pub mod target_generated;
pub mod login;
pub mod admin;
pub mod handlers;
pub mod rir;                                                  // 该模块用于从五大 RIR 获取 ASN 和组织等信息

// 自己的中间件
pub mod middlewares;


#[cfg(test)]
pub mod test;                                                 // 测试模块

use std::time::{SystemTime, UNIX_EPOCH};
use actix_web::{HttpRequest, web};
use tracing::{error, info, warn};
use std::path::{Path, PathBuf};
use tera::{Tera, Context};
use std::collections::HashMap;
use sysinfo;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use serde_json;
use tokio_postgres::types::ToSql;
use uuid::{Uuid};
use crate::db::{get_sql_from_file};
use regex::Regex;
use std::time::Instant;
use ipnet::{AddrParseError, IpNet};
use argon2::{Argon2, Algorithm, Params, Version, PasswordHasher, PasswordVerifier};
use password_hash::{PasswordHash, SaltString};
use password_hash::rand_core::OsRng;
use cidr::IpInet;
use serde_json::Value;
use crate::config::PasswordHashConfig;

//常量
pub const TEXT_HTML_UTF_8: &str = "text/html; charset=utf-8";
pub const TEXT_CSS_UTF_8: &str = "text/css; charset=utf-8";
pub const APPLICATION_JAVASCRIPT_UTF_8: &str = "application/javascript; charset=utf-8";
pub const IMAGE_PNG: &str = "image/png";
pub const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
pub const APPLICATION_JSON: &str = "application/json";
pub const _SYSTEM_TIME_ZONE: &str = "Asia/Shanghai";

struct FrontEndErrorInfo<'a> {
    status_code: u16,
    error_title: &'a str,
    error_message: &'a str,
}

pub struct _ProxySetting {
    _status: bool,
    _headers: String,
}

pub struct AddUserInfo<'a> {
    pub username: &'a str,
    pub password_hash: &'a str,
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
    pub db_table_size: HashMap<String, DbTableSizeInfo>,
    pub db_conn: String,
}

#[derive(Serialize, Deserialize)]
pub struct DbTableSizeInfo {
    pub total: i64,
    pub data: i64,
    pub index: i64
}

#[derive(Serialize, Deserialize)]
pub struct SystemCPU {
    pub cpu_usage: f32,                 //cpu总体使用率
    pub cpu: HashMap<String, f32>       //单个cpu使用率
}

//系统缓存大小，包括swap
#[derive(Serialize, Deserialize)]
pub struct SystemRAM {
    pub total_ram: u64,
    pub used_ram: u64,
    pub ram_usage: f32,
    pub total_swap: u64,
    pub use_swap: u64,
    pub swap_usage: f32
}

#[derive(Serialize, Deserialize)]
pub struct SystemDisk {
    pub disk_total_space: u64,
    pub disk_total_usage: u64,
    pub disk: HashMap<String, Vec<u64>>
}

#[derive(Serialize, Deserialize)]
pub struct SystemNetInfo {
    pub send: String,
    pub receive: String
}

#[derive(Serialize, Deserialize)]
pub struct SystemNetwork {
    pub net: HashMap<String, SystemNetInfo>
}

#[derive(Serialize, Deserialize)]
pub struct SystemResource {
    pub server_run_time: i64,
    pub cpu: SystemCPU,
    pub ram: SystemRAM,
    pub disk: SystemDisk,
    pub db_postgresql: DbResource,
    pub network: SystemNetwork,
    pub create_at: Option<i64>
}

pub fn get_unix_epoch_ms() -> i64 {
    //todo 添加一个获取普通utc时间的函数，考虑用结构体还是权举
    // 当获取时间戳失败时会返回默认值-1
    // SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as i64,
        Err(e) => {

            error!(
                event = "UnixEpochGenerateError",
                message = e.to_string()
            );
            -1 as i64
        }
    }
}

//用于存储sysinfo 下必要的
#[derive(Clone)]
pub struct Systems {
    pub sys: Arc<Mutex<sysinfo::System>>,
    pub disk: Arc<Mutex<sysinfo::Disks>>,
    pub network: Arc<Mutex<sysinfo::Networks>>
} 

impl Systems {
    pub fn new() -> Self {
        Self { 
            sys: Arc::new(Mutex::new(sysinfo::System::new_all())), 
            disk: Arc::new(Mutex::new(sysinfo::Disks::new_with_refreshed_list())), 
            network:  Arc::new(Mutex::new(sysinfo::Networks::new_with_refreshed_list()))
        }
    }
}

impl Default for Systems {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemCPU {
    pub fn new(sys: Arc<Mutex<sysinfo::System>>) -> Self {
        let mut cpu_usages = sys.lock().unwrap();
        cpu_usages.refresh_cpu_all();
        // let mut c_hash: HashMap<&str, f32> = HashMap::new();
        // cpu_usages.cpus().iter().map(|cpu| c_hash.insert(cpu.name(), cpu.cpu_usage()));

        let c_hash: HashMap<String, f32> = cpu_usages.cpus().iter().map( |cpu|
            (cpu.name().to_string(), cpu.cpu_usage())
        ).collect();
        
        Self { 
            cpu_usage: cpu_usages.global_cpu_usage(),
            cpu: c_hash
         }
    }
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
            ram_usage: (used_m / total_m) as f32 * 100.0,
            total_ram: total_m,
            used_ram: used_m,
            total_swap: total_s,
            use_swap: used_s,
            swap_usage: (used_s / total_s) as f32 * 100.0
        }
    }
}

impl SystemDisk {
    pub fn new(disk: Arc<Mutex<sysinfo::Disks>>) -> Self {
        let disk = disk.lock().unwrap();
        let mut disk_total:u64 = 0; 
        let mut disk_total_usage:u64 = 0;
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
            d_h.insert(d.name().to_string_lossy().to_string(), vec![d.total_space(), d.available_space()]);
        }

        Self { 
            disk_total_space: disk_total,
            disk_total_usage: disk_total_usage,
            disk: d_h
         }
    }
}

impl SystemNetwork {
    pub fn new(net: Arc<Mutex<sysinfo::Networks>>) -> Self {
        let net = net.lock().unwrap();
        // net.refresh(true);
        let n_h: HashMap<String, SystemNetInfo> = net.list().iter().map( |(net_name, net_data)|
            (net_name.to_string(), SystemNetInfo{send: net_data.transmitted().to_string(), receive: net_data.received().to_string()})
        ).collect();

        Self {
            net: n_h
        }

    }
}

impl DbResource {
    pub async fn new(pool: deadpool_postgres::Pool, sql_file_path: &str ) -> Self {
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

                let db_library_size_sql = "SELECT pg_database_size('nmapping') AS db_size;";

                let db_table_size_sql = get_sql_from_file(&sql_file_path, "get_table_size.sql").await;
                let db_conn_sql = "SELECT COUNT(*) AS db_conn FROM pg_stat_activity;";
                //获取数据库大小(Byte)
                let table = vec!["ips", "ports", "scaninfo"];
                
                let sql = match db_table_size_sql {
                    Ok(sql) => sql,
                    Err(e) => {
                        error!(e);
                        error!("获取sql失败");
                        "".to_string()
                    }
                };
                
                
                Self {
                    db_library_size: get_db_library_size_byte(&o, db_library_size_sql, &[]).await,
                    db_table_size: get_db_table_size_byte(&o, &sql, &[&table]).await,
                    db_conn: get_db_conn(&o, db_conn_sql, &[]).await
                }
            },
            Err(e) => {
                let message = format!("无法从连接池中获得连接 {}", e);
                error!(
                    event = "DATABASE-ERROR",
                    path = "DbResource::new",
                    message
                );
                //返回默认值
                DbResource::default()
            }
        }
    }
}

impl Default for DbResource  {
    fn default() -> Self {
        let tmp = vec![("error".to_string(), DbTableSizeInfo::default())];
        let h: HashMap<String, DbTableSizeInfo> = tmp.into_iter().collect();
        Self {
            db_library_size: "none".to_string(),
            db_table_size: h,
            db_conn: "none".to_string()
        }
    }
}

impl Default for DbTableSizeInfo  {
    fn default() -> Self {
        Self {
            total: -1,
            data: -1,
            index: -1
        }
    }
}

impl SystemResource {
    pub async fn new(sys: Systems, pool: deadpool_postgres::Pool, _db_name: String) -> Self {
        Self {
            server_run_time: get_server_uptime() as i64,
            cpu: SystemCPU::new(sys.sys.clone()),
            ram: SystemRAM::new(sys.sys.clone()),
            disk: SystemDisk::new(sys.disk.clone()),
            db_postgresql: DbResource::new(pool, "source/database/").await,
            network: SystemNetwork::new(sys.network.clone()),
            create_at: None
        }
    }
}

/// 用于存储目标 IP ，适配 IpAddr 和 str
pub enum TargetIP<'a> {
    S(&'a str),
    I(IpNet)
}

pub enum TargetPort<'a> {
    S(&'a str),
    I(u16)
}

/// 该函数用于解析ip地址，
/// 可以接收传入字符串IP，会自动解析，然后返回一个向量
fn parsing_target(ip: TargetIP) -> Result<Vec<IpNet>, AddrParseError> {
    let mut n_v:Vec<IpNet> = Vec::new();
    match ip {
        TargetIP::S(i_str) => {
            
            for tmp in i_str.split(",") {
                
                let mut t = tmp.to_string();
                if t.contains("/") {
                    ()
                } 
                else if t.contains(":") {
                    t.push_str("/128");
                }
                else {
                    t.push_str("/32");    
                }
                let t = (&t).parse::<IpNet>();
                match t {
                    Ok(o) => n_v.push(o),
                    Err(e) => {
                        error!(
                            event = "PARSING-ERROR",
                            message = e.to_string()
                        );
                        return Err(e);
                    }
                }
            }
            return Ok(n_v)
        },
        TargetIP::I(ipadd) => {
            n_v.push(ipadd);
            return Ok(n_v)
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
                return true
            }
            else {
                return false
            }
        },
        Err(e) => {
            error!(
                event = "REGEX-ERROR",
                message = e.to_string()
            );
            return false
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
    pub remark: Option<String>
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
    pub remark: Option<&'a str>
}

impl<'a> STask<'a> {
    pub fn new(
        ip: TargetIP,
        initiator: &'a str,
        port: Option<&'a str>,
        remark: Option<&'a str>
    ) -> Result<Self, AddrParseError> {
        let t_ip = parsing_target(ip)?;
        
        let t_port = match port {
            Some(p) => {
                if check_port(p) {
                    p
                }
                else {
                    "1-65535"
                }
            },
            None => "1-65535"
        };
        Ok(Self { 
            task_id: Some(Uuid::now_v7()), 
            task_initiator: initiator, 
            ip: t_ip, 
            port: Some(t_port), 
            start_at: None, 
            end_at: None, 
            remark: remark 
        })
    }

    /// 用于向数据库中添加一条扫描任务条目
    /// 返回一个 Result，当执行成功时返回 OK
    pub async fn add(
        &self,
        pool: web::Data<deadpool_postgres::Pool>,
        level: i32,
        user_id: i32
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut p = pool.get().await?;
        let client = p.transaction().await?;
        let t_id:String;
        match self.task_id {
            Some(o) => t_id = o.to_string(),
            None => return Err("task_id 为 None".into())
        };

        // 将 ipnet转换为 String
        let tmp_ip:Vec<String> = self.ip.iter().map(|i| i.to_string()).collect();

        client.execute(
            "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks) VALUES ($1, $2, $3, ARRAY(SELECT inet(unnest($4::text[]))), $5, $6, $7)", 
            &[&user_id, &t_id, &self.task_initiator, &tmp_ip, &self.port, &level, &self.remark]
        ).await?;

        client.commit().await?;
        return Ok(())
    }
}


///获取数据库表的大小，单位为字节
async fn get_db_table_size_byte(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>, 
    // db_h: &mut HashMap<String, DbTableSizeInfo>,
    sql: &str, 
    params: &[&(dyn ToSql + Sync)]
) -> HashMap<String, DbTableSizeInfo> {
    let result = pool.query(sql, params).await;
    match result {
        Ok(rows) => {
            rows.iter().map( |row|
                (row.get("table_name"), DbTableSizeInfo{ 
                    total: row.get("total_size"), 
                    data: row.get("data_size"), 
                    index: row.get("index_size")
                })

            ).collect()
            // for row in rows {
            //     let key = row.get("table_name");
            //     let value: i64 = row.get("total_size");
            //     // let value = values.to_s
            //     db_h.insert(key, value.to_string());
            // }
        },
        Err(e) => {
            let message = format!("执行sql语句错误 {:?}", e);
            error!(
                event = "DATABASE-ERROR",
                path = "DbResource::new.get_db_table_size_byte",
                message
            );
            vec![("error".to_string(), DbTableSizeInfo::default())].into_iter().collect()
            
        }
    }
}

///获取数据库的大小，单位为字节
async fn get_db_library_size_byte(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)]
) -> String {
    if let Ok(result) = pool.query_opt(sql, params).await {
        if let Some(row) = result {
            let r:i64 = row.get("db_size");
            r.to_string() 
        }
        else {
            let message = format!("没有找到数据库的返回值 {}", sql);
            warn!(
                event = "DATABASE-WARNING",
                path = "DbResource::new.get_db_library_size_byte",
                message
            );
            "null".to_string()
        }
    } 
    else {
        let message = format!("执行sql语句错误 {}", sql);
        error!(
            event = "DATABASE-ERROR",
            path = "DbResource::new.get_db_library_size_byte",
            message
        );
        "null".to_string()
    }
}

///获取数据库的连接数
async fn get_db_conn(
    pool: &deadpool::managed::Object<deadpool_postgres::Manager>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)]
) -> String {
    if let Ok(result) = pool.query_opt(sql, params).await {
        if let Some(row) = result {
            let r:i64 = row.get("db_conn");
            r.to_string()
        }
        else {
            let message = format!("没有找到数据库的返回值 {}", sql);
            warn!(
                event = "DATABASE-WARNING",
                path = "DbResource::new.get_db_conn",
                message
            );
            "null".to_string()
        }
    }
    else {
        let message = format!("执行sql语句错误 {}", sql);
        error!(
            event = "DATABASE-ERROR",
            path = "DbResource::new.get_db_conn",
            message
        );
        "null".to_string()
    }
}

///获取服务器运行时间
fn get_server_uptime() -> u64 {
    sysinfo::System::uptime()
}




/// 生成 Argon2id 哈希
/// 
/// 用于添加用户
pub fn generate_hash_password(password: &str, config: PasswordHashConfig) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(config.m * 1024, config.t, config.p, None)?; // 配置文件中默认 64 MiB, 2 次迭代, 2 并行
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

/// 用于从数据库中获得用户的密码哈希值和在表中的 ID ，返回一个 Result<(i32, String), Error>
pub async fn get_password_and_id_from_database(
    pool: &deadpool_postgres::Pool,
    username: &str
) -> Result<(i32, String), Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    if let Some(row) = client.query_opt("SELECT id, password FROM users WHERE username = $1", &[&username]).await? {
        // let id: i32 = row.get("id");
        // let pwd_hash: String = row.get("password");
        Ok((row.get::<_, i32>("id"), row.get::<_, String>("password")))
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
            let result = argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok();
            println!("verify_pwd {:>6} ms", start.elapsed().as_millis());
            result
        },
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
fn get_file_suffix(path_or_file_name: &Path) -> Result<&str, &str> {
    
    match path_or_file_name.extension().and_then(|s| s.to_str()) {
        Some(ext) => Ok(ext),
        None => {
            warn!("没有扩展名或无法获取扩展名");
            Err("没有扩展名或无法获取扩展名")
        },
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
pub async fn benchmark(sys: web::Data<Systems>, pool: web::Data<deadpool_postgres::Pool>, _db_name: String) {
    let total_start = Instant::now();
    let pool = pool.get_ref().clone();

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
    let db = DbResource::new(pool, "source/database/").await;
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
    }
    else {
        None
    }

}

///向数据库插入系统数据
pub async fn insert_system_status(
    pool: deadpool_postgres::Pool, 
    db_name: String,
    sys: Systems
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = pool.get().await?;
    let s = SystemResource::new(sys, pool, db_name).await;
    let transaction = client.transaction().await?;
    let sql = get_sql_from_file("source/database/", "insert_system_status.sql").await?;
    let statement = transaction.prepare(&sql).await?;
    let server_run_time = s.server_run_time as i64;
    let cpu = serde_json::to_value(s.cpu).unwrap();
    let ram = serde_json::to_value(s.ram).unwrap();
    let disk = serde_json::to_value(s.disk).unwrap();
    let db_postgresql = serde_json::to_value(s.db_postgresql).unwrap();
    let network = serde_json::to_value(s.network).unwrap();
    let raw = transaction.execute(&statement, &[&server_run_time, &cpu, &ram, &disk, &db_postgresql, &network]).await?;
    if raw == 1 {
        transaction.commit().await?;
        Ok(())
    }else {
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
pub fn get_conn_ip(
    req: &HttpRequest
) -> String{
    match req.connection_info().realip_remote_addr() {
        Some(o) => o.to_string(),
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
pub fn get_user_agent(
    req: &HttpRequest
) -> String {
    // req.headers().get("User-Agent").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string()
    match req.headers().get("User-Agent") {
        Some(o) => {
            match o.to_str() {
                Ok(o) => o.to_string(),
                Err(e) => {
                    warn!(
                        event = "GetHTTPHeadersError",
                        message = e.to_string()
                    );
                    "Unknown".to_string()
                }
            }
        },
        None => {
            error!(
                event = "GetHTTPHeadersError",
                message = "无法获取到请求头"
            );
            "Unknown".to_string()
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ApplyTask {
    pub user_id: i32,
    pub task_id: Uuid,
    pub task_target: Vec<String>,
    pub task_port: String
}

/// 通过该函数实现扫描器申请任务
/// 首先搜索合适的任务，如果没有任务则会创建一个系统任务，该任务也会写入 scan_task 中
pub async fn apply_task(
    pool: web::Data<deadpool_postgres::Pool>,
    _scanner_id: web::Query<ApplyTaskQuery>
) -> Result<ApplyTask, Box<dyn std::error::Error>> {
    let p = pool.get().await?;
    let row = p.query_opt(
        "SELECT user_id, task_id, task_target::text[], task_port FROM scan_task WHERE task_start_time IS NULL
                    AND task_end_time IS NULL 
                    ORDER BY task_level DESC, task_create_time LIMIT 1;", 
        &[]
    ).await?;

    if let Some(r_applytask) = row.map(|r| {
        let uid = Uuid::parse_str(r.get("task_id")).unwrap_or_default();

        ApplyTask {
            user_id: r.get("user_id"),
            task_id: uid,
            task_target: r.get("task_target"),
            task_port: r.get("task_port")
        }
    }) {
        info!(event = "SEARCH-TASK", path = "fn apply_task", message = r_applytask.task_id.to_string());
        return Ok(r_applytask)
    }


    info!(event = "NOTFOUND-TASK-1", path = "fn apply_task", message = "数据库表 scan_task 中没有合适的任务");

    // TODO: 到时需要实现 IP 生成，根据上次扫描的 IP 生成此次的 IP 
    let c_task = STask {
        task_id: Some(Uuid::now_v7()),
        task_initiator: "System",
        ip: vec!["47.122.119.248/24".parse::<IpNet>()?],
        port: Some("1-65535"),
        start_at: Some(get_unix_epoch_ms()),
        end_at: None,
        remark: None
    };

    if c_task.task_id.is_none() || c_task.ip.is_empty() || c_task.port.is_none() || c_task.start_at.is_none() {
        Err("c_task 值出现错误".into())
    } 
    else {
        c_task.add(pool, 0, 1).await?;
        info!(event = "CREATE-TASK", path = "fn apply_task", message = "创建系统默认扫描任务");
        let i = ApplyTask {
            user_id: 1,
            task_id: c_task.task_id.unwrap(),
            task_target: c_task.ip.iter().map(|ip| ip.to_string() ).collect(),
            task_port: c_task.port.unwrap().to_string()
        };
        info!(event = "CREATE-TASK", path = "fn apply_task", message = i.task_id.to_string());
        Ok(i)
    }
}

#[derive(Deserialize)]
pub struct ApplyTaskQuery {
    pub scannerid: Uuid
}


/// 该函数用于退出登录
/// 
/// 返回一个 Result<bool> ，返回 true 代表该 token 已被正常销毁，返回 false 代表 token 本身就是无效的。
pub async fn log_out(
    session: &str,
    pool: &deadpool_postgres::Pool
) -> Result<bool, Box<dyn std::error::Error>> {
    let c = pool.get().await?;
    if let Some(tmp_r) = c.query_opt("UPDATE session SET is_enable = false WHERE token = $1;", &[&session]).await? {
        // let tmp_r = c.execute("UPDATE session SET is_enable = false WHERE token = $1;", &[&session]).await?;
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
    }
    else {
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
    Users(i32)
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
    pub scanner_id: Option<Uuid>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>,
    pub remarks: Option<String>
}

/// 表示 Json 格式的任务列表
#[derive(Serialize)]
pub struct TaskItemJson {
    pub total_c: i64,
    pub item_c: i64,
    pub start_id: i32,
    pub task_item: Vec<TaskItem>
}

/// 该结构体表示接收查询任务列表信息
#[derive(Deserialize)]
pub struct ReceiveTaskItemQueryInfo {
    pub start: Option<i32>,
    pub count: Option<i64>,
}

/// 该函数用于获取所有的扫描任务记录，需要鉴权，普通用户只能获取到自己创建的任务，管理员则可以获取所有的
/// 
/// 接收多个参数，分别为 
pub async fn get_task_item(
    pool: &deadpool_postgres::Pool,
    s_count: i64,
    start_id: Option<i32>,
    permissions: Permission
) -> Result<(Vec<TaskItem>, i64, i64, i32), Box<dyn std::error::Error>> {
    let c = pool.get().await?;

    let row = match permissions {
        Permission::Administrator(_id) => {
            if let Some(st) = start_id {
                c.query(
                    "SELECT *, COUNT(*) OVER() AS total_count FROM scan_task WHERE id <= $1 ORDER BY id DESC LIMIT $2;",
                    &[&st, &s_count]
                ).await?
            }
            else {
                c.query(
                    "SELECT *, COUNT(*) OVER() AS total_count FROM scan_task ORDER BY id DESC LIMIT $1;",
                    &[&s_count]
                ).await?
            }
            
        },
        Permission::Users(u_id) => {
            c.query(
                "SELECT *, COUNT(*) OVER() AS total_count FROM scan_task WHERE user_id = $1 ORDER BY id DESC LIMIT $2;", 
                &[&u_id, &s_count]
            ).await?
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
            scanner_id: None,
            start_at: r.get::<_, Option<i64>>("task_start_time"),
            end_at: r.get::<_, Option<i64>>("task_end_time"),
            remarks: r.get::<_, Option<String>>("remarks")  
        };
        task_item_r.push(titem);
        count += 1;
    }
    Ok((task_item_r, total_count_item, count, start_id))
}


/// 用于接收系统信息查询
#[derive(Deserialize)]
pub struct ReceiveSystemStatusInfo {
    pub count: Option<i64>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>
}

#[derive(Serialize, Deserialize)]
pub struct SystemStatusJson {
    pub total_c: i32,
    pub status_item: Vec<SystemResource>
}

/// 获取系统状态信息
pub async fn get_system_status_info(
    start_at: Option<i64>,
    end_at: Option<i64>,
    count: i64,
    pool: &deadpool_postgres::Pool
) -> Result<(Vec<SystemResource>, i32), Box<dyn std::error::Error>> {
    let connect = pool.get().await?;

    let row = if start_at.is_some() || end_at.is_some() {
        connect.query(
            "SELECT * 
                        FROM system_status 
                        WHERE create_time BETWEEN 
                            COALESCE($1, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT)
                            AND 
                            COALESCE($2, (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT)
                        ORDER BY id DESC 
                        LIMIT $3;",
            &[&start_at, &end_at, &count]
        ).await?
    }
    else {
        connect.query(
            "SELECT * FROM system_status ORDER BY id DESC LIMIT $1;",
            &[&count]
        ).await?
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
            create_at: Some(r.get::<_, i64>("create_time"))
        };
        tmp_count += 1;
        vec_status.push(tmp);
    }
    Ok((vec_status, tmp_count))

}