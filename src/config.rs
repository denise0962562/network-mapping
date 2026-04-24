///web系统配置文件

use actix_web::web;
use actix_files::Files;
use std::{path::Path, fs};
use serde::{Deserialize};

use crate::{handlers::{self, user}};


#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub log: LogConfig,
    pub templates: TemplatesConfig,
    pub scan_target_generated: ScanTargetConfig,
    pub database: DatabaseConfig,
    pub pwd_hash: PasswordHashConfig
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    pub directory: String,
    pub file_name: String,
    pub file_rolling: u8,
    pub debug_mode: bool,
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
    pub database_type: String,                    //数据库类型
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
        .service(handlers::utils::file_read_test)
        .service(handlers::utils::static_file_system)
        .service(Files::new("/static", "./static").show_files_listing().prefer_utf8(true))
        .service(handlers::utils::get_scan_target)
        .service(handlers::data_saa::get_system_data_handler)
        .service(handlers::utils::benchmark_route)
        .service(handlers::data_saa::render_dashboard_page)
        .service(handlers::task::create_task)
        .service(handlers::task::apply_task_handler)     //更换了 apply_task_handler 和 get_task的注册顺序
        .service(handlers::task::get_all_task_handler)
        .service(handlers::task::get_task)
        .service(handlers::utils::update_rir)
        .service(user::user_logout)
        .default_service(web::to(handlers::utils::not_found));
}