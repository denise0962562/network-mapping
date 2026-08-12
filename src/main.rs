use actix_web::{App, HttpMessage, HttpServer, dev::Service, http::header, web};
use clap::Parser;
use core::panic;
use std::io;
use tokio::time::{Duration, Instant, interval_at};
use tracing::{error, info};

use rust_web_test::admin::{check_default_admin_user, check_system_user, reset_admin_password};
use rust_web_test::audit::RequestId;
use rust_web_test::config::{Clis, SelfChecking};
use rust_web_test::logs::{self, LogRollingMode};
use rust_web_test::maxmind::MaxMindState;
use rust_web_test::middlewares::{
    csrfmiddleware::CsrfMiddleware, hmiddleware::SHeaderM, ratelimit::RateLimitMiddleware,
    smiddleware::AuthMiddleware,
};
use rust_web_test::open_source::OpenSourceCatalog;
use rust_web_test::tls::build_acceptor;
use rust_web_test::{Systems, TemplatesInit, config, db, insert_system_status};

#[actix_web::main]
async fn main() -> io::Result<()> {
    let args = Clis::parse();

    let config = config::Config::from_file(&args.config);

    let log_file_rolling = match config.log.file_rolling {
        0 => LogRollingMode::Daily,
        1 => LogRollingMode::Hourly,
        2 => LogRollingMode::Minutely,
        _ => LogRollingMode::Never,
    };
    let log_debug_mode = args.debug_model;
    let _guard = logs::init::init(
        &config.log.directory,
        &config.log.file_name,
        &log_file_rolling,
        &log_debug_mode,
    );
    info!(config_path = %args.config, "配置文件已加载");
    info!("日志系统已启动");
    config.check();

    let ser_con = config.server.clone();
    let server = config.server;
    let server_host = server.host;
    let server_port = server.port;

    //日志系统配置
    let log = config.log;
    let log_file_directory = log.directory;
    let log_file_name = log.file_name;

    //模板系统配置
    let template = config.templates;
    let template_info = TemplatesInit {
        templates_directory: template.templates_directory,
        templates_name: template.templates_name,
    };

    let db_config = config.database;
    let database_c = db_config.clone();
    let database_c2 = db_config.clone();

    let db_pool = db::create_postgresql_pool(
        db_config.host,
        db_config.port,
        db_config.username,
        db_config.password,
        db_config.db_name,
    )
    .await
    .expect("创建连接池错误");
    let pool = db_pool.clone();
    if let Some(username) = args.reset_admin_password.as_deref() {
        match reset_admin_password(username, &db_pool, config.pwd_hash.clone()).await {
            Ok(password) => {
                println!(
                    "\n┌─ 管理员密码已重置 ───────────────────────\n│ 用户名：{username}\n│ 新密码：{password}\n│ 请妥善保存；该密码不会写入日志。\n└──────────────────────────────────────────\n"
                );
                return Ok(());
            }
            Err(error) => {
                eprintln!("重置管理员密码失败：{}", error);
                return Err(io::Error::other("重置管理员密码失败"));
            }
        }
    }

    match db::init_database_table(&db_pool, &db_config.init_database_file).await {
        Ok(_) => info!("数据库结构初始化完成"),
        Err(e) => panic!("初始化数据库错误{}", e),
    };

    info!("正在检查系统账户");

    check_system_user(&db_pool).await;

    // 定义密码加密相关配置文件
    let pwd_h = config.pwd_hash;

    check_default_admin_user(&db_pool, pwd_h.clone()).await;

    let mail_c = config.email_config;

    let tls = build_acceptor(&config.tls)?;

    let sys = Systems::new();
    let sys_2 = sys.clone();
    let maxmind_state = web::Data::new(MaxMindState::from_default_paths());
    let security = web::Data::new(config.security);
    let rate_limiter = RateLimitMiddleware::default();
    let open_source_catalog = web::Data::new(
        OpenSourceCatalog::from_embedded()
            .map_err(|error| io::Error::other(format!("开源项目清单格式错误: {error}")))?,
    );

    info!(
        address = %format!("{}:{}", server_host, server_port),
        log_directory = %log_file_directory,
        log_file = %log_file_name,
        log_rolling_mode = log.file_rolling,
        debug = log_debug_mode,
        template_directory = %template_info.templates_directory,
        template_name = %template_info.templates_name,
        status_interval_seconds = log.status_duration,
        "服务配置就绪"
    );
    info!(address = %format!("https://{}:{}", server_host, server_port), "HTTPS 服务开始监听");

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
            .app_data(web::Data::new(ser_con.clone()))
            .app_data(maxmind_state.clone())
            .app_data(open_source_catalog.clone())
            .app_data(security.clone())
            .wrap(CsrfMiddleware)
            .wrap(SHeaderM)
            .wrap(AuthMiddleware)
            .wrap(rate_limiter.clone())
            .wrap_fn(|req, service| {
                let request_id = req
                    .headers()
                    .get("X-Request-ID")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    .unwrap_or_else(uuid::Uuid::new_v4);
                req.extensions_mut().insert(RequestId(request_id));
                let response_request_id = header::HeaderValue::from_str(&request_id.to_string())
                    .expect("UUID is a valid header value");
                let future = service.call(req);
                async move {
                    let mut response = future.await?;
                    response.headers_mut().insert(
                        header::HeaderName::from_static("x-request-id"),
                        response_request_id,
                    );
                    Ok(response)
                }
            })
            .configure(config::init_routes)
    })
    .bind_openssl((server_host, server_port), tls)?
    .run()
    .await
}
