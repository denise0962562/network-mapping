use actix_web::{web, App, HttpServer};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use rust_web_test::middlewares::smiddleware::AuthMiddleware;
use rust_web_test::middlewares::hmiddleware::SHeaderM;
use rust_web_test::middlewares::csrfmiddleware::CsrfMiddleware;
use core::panic;
use std::{io};
use rust_web_test::logs::{self, LogRollingMode};
use rust_web_test::{config, db, Systems, TemplatesInit, insert_system_status};
use tracing::{error};
use tokio::time::{Instant, interval_at, Duration};
// use lettre::message::{Mailbox, header::ContentType};
use rust_web_test::admin::{check_system_user};

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

    println!("开始检查系统配置");

    check_system_user(&db_pool).await;

    // 定义密码加密相关配置文件
    let pwd_h = config.pwd_hash;

    let mail_c = config.email_config;

    let mut tls = SslAcceptor::mozilla_intermediate(SslMethod::tls_server()).expect("SslAcceptor::mozilla_intermediate(SslMethod::tls_server()) ERROR");
    tls.set_private_key_file("./ssl/key.pem", SslFiletype::PEM).expect("指定私钥文件错误");
    tls.set_certificate_chain_file("./ssl/cert.pem").expect("指定证书文件错误");
    tls.check_private_key().expect("私钥检查错误");
    
    let sys = Systems::new();  
    let sys_2 = sys.clone();

    println!("服务已启动");
    println!("监听 {}:{}", server_host, server_port);
    println!("监听地址：{}\n端口：{}\n日志使用的目录：{}\n日志文件名：{}\n日志文件滚动周期模式：{}\n日志系统调试模式：{}", &server_host, &server_port, &log_file_directory, &log_file_name, &log.file_rolling, &log_debug_mode);
    println!("模板目录：{}\n模板文件名：{}", template_info.templates_directory, template_info.templates_name);
    println!("系统信息采集频率：{}", log.status_duration);

    // 暂时取消等待
    // 计算下一个 2 分钟整点
    // let now = Utc::now();
    // let next_minute = ((now.minute() / 2) + 1) * 2; // 下一个偶数分钟
    // let start_time = Utc::now()
    //     .with_minute(next_minute % 60).unwrap()
    //     .with_second(0).unwrap()
    //     .with_nanosecond(0).unwrap();

    // let delay = (start_time.timestamp_millis() - now.timestamp_millis()) as u64;

    // 从整点开始，每隔一段时间 tick 一次，该时间由配置文件指定
    tokio::spawn(async move {
        let mut ticker = interval_at(
            Instant::now() + Duration::from_millis(0),
            Duration::from_secs(log.status_duration),
        );

        loop {
            ticker.tick().await;
            match insert_system_status(&db_pool, database_c.db_name.clone(), sys.clone()).await {
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

    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(template_info.clone()))
            .app_data(web::Data::new(sys_2.clone()))
            .app_data(web::Data::new(database_c2.clone()))
            .app_data(web::Data::new(pwd_h.clone()))
            .app_data(web::Data::new(mail_c.clone()))
            .wrap(CsrfMiddleware)
            .wrap(SHeaderM)
            .wrap(AuthMiddleware)
            .configure(config::init_routes)
    })
    .bind_openssl((server_host, server_port), tls)?
    .run()
    .await

}