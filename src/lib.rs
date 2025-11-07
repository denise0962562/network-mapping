
pub mod logs;
pub mod config;
pub mod db;
pub mod target_generated;
pub mod login;
pub mod admin;
pub mod handlers;

use std::time::{SystemTime, UNIX_EPOCH};
use actix_web::web;
use tracing::{warn, error};
use std::path::{Path, PathBuf};
use tera::{Tera, Context};
use std::collections::HashMap;
use sysinfo;
use std::sync::{Arc, Mutex};
use serde::Serialize;
use serde_json;
use tokio_postgres::types::ToSql;

use crate::db::{get_sql_from_file, SqlFile};

use std::time::Instant;

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

pub struct AddUserInfo {
    pub username: String,
    pub password_hash: String,
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
#[derive(Serialize)]
pub struct DbResource {
    pub db_library_size: String,
    pub db_table_size: HashMap<String, DbTableSizeInfo>,
    pub db_conn: String,
}

#[derive(Serialize)]
pub struct DbTableSizeInfo {
    pub total: i64,
    pub data: i64,
    pub index: i64
}

#[derive(Serialize)]
pub struct SystemCPU {
    pub cpu_usage: f32,                 //cpu总体使用率
    pub cpu: HashMap<String, f32>       //单个cpu使用率
}

//系统缓存大小，包括swap
#[derive(Serialize)]
pub struct SystemRAM {
    pub total_ram: u64,
    pub used_ram: u64,
    pub ram_usage: f32,
    pub total_swap: u64,
    pub use_swap: u64,
    pub swap_usage: f32
}

#[derive(Serialize)]
pub struct SystemDisk {
    pub disk_total_space: u64,
    pub disk_total_usage: u64,
    pub disk: HashMap<String, Vec<u64>>
}

#[derive(Serialize)]
pub struct SystemNetInfo {
    pub send: String,
    pub receive: String
}

#[derive(Serialize)]
pub struct SystemNetwork {
    pub net: HashMap<String, SystemNetInfo>
}

#[derive(Serialize)]
pub struct SystemResource {
    pub server_run_time: u64,
    pub cpu: SystemCPU,
    pub ram: SystemRAM,
    pub disk: SystemDisk,
    pub db_postgresql: DbResource,
    pub network: SystemNetwork
}

pub fn get_unix_epoch_ms() -> i64 {
    //todo 添加一个获取普通utc时间的函数，考虑用结构体还是权举
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
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

                let db_library_size_sql = "SELECT pg_database_size('nmap') AS db_size;";

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
    pub async fn new(sys: Systems, pool: deadpool_postgres::Pool, db_name: String) -> Self {
        Self {
            server_run_time: get_server_uptime(),
            cpu: SystemCPU::new(sys.sys.clone()),
            ram: SystemRAM::new(sys.sys.clone()),
            disk: SystemDisk::new(sys.disk.clone()),
            db_postgresql: DbResource::new(pool, "source/database/").await,
            network: SystemNetwork::new(sys.network.clone())
        }
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

fn get_server_uptime() -> u64 {
    sysinfo::System::uptime()
}


use argon2::{Argon2, Algorithm, Params, Version, PasswordHasher, PasswordVerifier};
use password_hash::{PasswordHash, SaltString};
use password_hash::rand_core::OsRng;

/// 生成 Argon2id 哈希
/// 
/// 用于添加用户
pub fn generate_hash_password(password: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(64 * 1024, 2, 2, None)?; // 64 MiB, 3 次迭代, 4 并行
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

/// 校验密码
pub fn verify_password(password: &str, hash: &str) -> bool {
    if let Ok(parsed_hash) = PasswordHash::new(hash) {
        let params = Params::new(64 * 1024, 2, 2, None).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok()
    } else {
        false
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
pub async fn benchmark(sys: web::Data<Systems>, pool: web::Data<deadpool_postgres::Pool>, db_name: String) {
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
        println!("插入成功");
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

