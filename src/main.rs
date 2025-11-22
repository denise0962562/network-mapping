use actix_web::{web, App, HttpServer};
use core::panic;
use std::{io};
use rust_web_test::logs::{self, LogRollingMode};
use rust_web_test::{config, db, ReadFile, Systems, TemplatesInit, insert_system_status};
use tracing::{error};
use tokio::time::{Instant, interval_at, Duration};
use chrono::{Utc, Timelike};

//todo 添加获取用户真实ip即请求数据，然后写进日志中

// #[get("/test")]
// async fn index(data: web::Data<AppState>, req: HttpRequest, conn_info: ConnectionInfo) -> impl Responder {
//     let app_name = &data.app_name;
//     // format!("<html><script>alert(\"Server Name: {app_name}\")</script></html>")
//     // let user_ip = req.headers().get("X-Forwarded-For").and_then(|h| h.to_str().ok())
//     //     .unwrap_or("未知 IP");

//     let ip = &conn_info.realip_remote_addr().unwrap_or("无法获取 IP");
//     logs::write::info_logs(&req, &conn_info, "ReceivedRequests", "ReceivedRequests", false);
//     HttpResponse::Ok()
//         .content_type(TEXT_HTML_UTF_8)
//         .body(format!("<script>alert(\"Server Name: {} Your ip: {}\")</script>", app_name, ip))
// }

//用于存储初始化后的系统信息


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
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .app_data(web::Data::new(template_info.clone()))
            .app_data(web::Data::new(ReadFile{file_name: String::from("index.html"), file_root_directory: String::from("")}))
            .app_data(web::Data::new(sys_2.clone()))
            .app_data(web::Data::new(database_c2.clone()))
            .app_data(web::Data::new(pwd_h.clone()))
            .configure(config::init_routes)
    })
    .bind((server_host, server_port))?
    .run()
    .await

}