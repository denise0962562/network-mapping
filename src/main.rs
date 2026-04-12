use actix_web::{web, App, HttpServer};
use rust_web_test::smiddleware::{AuthMiddlewareService, AuthMiddleware};
use core::panic;
use std::{io};
use std::io::BufReader;
use std::fs::File;
use rust_web_test::logs::{self, LogRollingMode};
use rust_web_test::{config, db, ReadFile, Systems, TemplatesInit, insert_system_status};
use tracing::{error};
use tokio::time::{Instant, interval_at, Duration};
use chrono::{Utc, Timelike};
use rust_web_test::rir::get_rir_data;


#[actix_web::main]
async fn main() -> io::Result<()> {
    
    let config = config::Config::from_file("config.toml");
    let server = config.server;
    let server_host = server.host;
    let server_port = server.port;
    
    //日志系统配置
    let log =  config.log;
    let log_file_directory = log.directory;
    let log_file_name = log.file_name;
    let log_file_rolling =  match log.file_rolling {
        0 => LogRollingMode::Daily,
        1 => LogRollingMode::Hourly,
        2 => LogRollingMode::Minutely,
        _ => LogRollingMode::Never
    }; 
    let log_debug_mode = log.debug_mode;

    //模板系统配置
    let template = config.templates;
    let template_info = TemplatesInit{
        templates_directory: template.templates_directory,
        templates_name: template.templates_name,
    };

    // let _guard = init_tracing(&log_file_directory, &log_file_name, &log_file_rolling, &log_debug_mode);
    let _guard = logs::init::init(&log_file_directory, &log_file_name, &log_file_rolling, &log_debug_mode);
    println!("日志系统已启动");
    let db_config = config.database;
    let database_c = db_config.clone();
    let database_c2 = db_config.clone();

    // let database = format!("postgresql://{}:{}@{}/{}", db_config.username, db_config.password, db_config.host, db_config.db_name);
    let db_pool = db::create_postgresql_pool(
        db_config.host, 
        db_config.port, 
        db_config.username, 
        db_config.password, 
        db_config.db_name, 
    ).await.expect("创建连接池错误");
    let pool = db_pool.clone();

    match db::init_database_table(&db_pool, &db_config.init_database_file).await {
        Ok(_) => println!("初始化数据库成功"),
        Err(e) => panic!("初始化数据库错误{}", e),
    };

    // 定义密码加密相关配置文件
    let pwd_h = config.pwd_hash;

    // 定义 tls 相关配置
    rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();

    let mut certs_file = BufReader::new(File::open("./ssl/cert.pem").unwrap());
    let mut key_file = BufReader::new(File::open("./ssl/key.pem").unwrap());

    // load TLS certs and key
    // to create a self-signed temporary cert for testing:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'`
    let tls_certs = rustls_pemfile::certs(&mut certs_file)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let tls_key = rustls_pemfile::pkcs8_private_keys(&mut key_file)
        .next()
        .unwrap()
        .unwrap();

    // set up TLS config options
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(tls_certs, rustls::pki_types::PrivateKeyDer::Pkcs8(tls_key))
        .unwrap();


    let sys = Systems::new();  
    let sys_2 = sys.clone();

    println!("服务已启动");
    println!("监听 {}:{}", server_host, server_port);
    println!("监听地址：{}\n端口：{}\n日志使用的目录：{}\n日志文件名：{}\n日志文件滚动周期模式：{}\n日志系统调试模式：{}", &server_host, &server_port, &log_file_directory, &log_file_name, &log.file_rolling, &log_debug_mode);
    println!("模板目录：{}\n模板文件名：{}", template_info.templates_directory, template_info.templates_name);

    // 计算下一个 2 分钟整点
    let now = Utc::now();
    let next_minute = ((now.minute() / 2) + 1) * 2; // 下一个偶数分钟
    let start_time = Utc::now()
        .with_minute(next_minute % 60).unwrap()
        .with_second(0).unwrap()
        .with_nanosecond(0).unwrap();

    let delay = (start_time.timestamp_millis() - now.timestamp_millis()) as u64;

    // 从整点开始，每 2 分钟 tick 一次
    tokio::spawn(async move {
        let mut ticker = interval_at(
            Instant::now() + Duration::from_millis(delay),
            Duration::from_secs(120),
        );

        loop {
            ticker.tick().await;
            match insert_system_status(pool.clone(), database_c.db_name.clone(), sys.clone()).await {
                Ok(_) => (),
                Err(e) => {
                    let message = format!("插入系统状态错误: {}", e);
                    error!(
                        event = "INSERTSystemStatusError",
                        path = "fn insert_system_status",
                        message
                    )
                }
            };
            // TODO: 监控逻辑
        }
    });

    //tag

    // match get_all_filename("/home/wsj/project/RIR-DATA") {
    //     Ok(o) => {
    //         println!("开始处理 RIR 数据");
    //         read_all(&db_pool, o).await
    //     },
    //     Err(e) => {
    //         println!("ERROR: {}", e.to_string());
    //     }
    // }

    // get_rir_data(&db_pool, "/home/wsj/project/RIR-DATA").await;
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .app_data(web::Data::new(template_info.clone()))
            .app_data(web::Data::new(ReadFile{file_name: String::from("index.html"), file_root_directory: String::from("")}))
            .app_data(web::Data::new(sys_2.clone()))
            .app_data(web::Data::new(database_c2.clone()))
            .app_data(web::Data::new(pwd_h.clone()))
            .wrap(AuthMiddleware)
            .configure(config::init_routes)
    })
    .bind_rustls_0_23((server_host, server_port), tls_config)?
    .run()
    .await

}