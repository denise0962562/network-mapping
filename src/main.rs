use actix_web::{App, HttpMessage, HttpServer, dev::Service, http::header, web};
use clap::Parser;
use core::panic;
use std::io;
use tokio::time::{Duration, Instant, interval_at};
use tracing::{Instrument, error, info};

use network_mapping_server::admin::{
    check_default_admin_user, check_system_user, reset_admin_password,
};
use network_mapping_server::audit::RequestId;
use network_mapping_server::backup::BackupManager;
use network_mapping_server::config::{Clis, SelfChecking};
use network_mapping_server::frontend::{self, FrontendAssets};
use network_mapping_server::logs::write::error_chain_diagnostics;
use network_mapping_server::logs::{self, LogRollingMode};
use network_mapping_server::maxmind::MaxMindState;
use network_mapping_server::middlewares::{
    csrfmiddleware::CsrfMiddleware, hmiddleware::SHeaderM, ratelimit::RateLimitMiddleware,
    smiddleware::AuthMiddleware,
};
use network_mapping_server::monitor::{self, HealthEvent};
use network_mapping_server::open_source::OpenSourceCatalog;
use network_mapping_server::request_log;
use network_mapping_server::scanner_latency::{self, ScannerLatencyHistory};
use network_mapping_server::target_generated::{AutomaticTargetService, run_generator};
use network_mapping_server::tls::build_acceptor;
use network_mapping_server::{Systems, TemplatesInit, config, db, insert_system_status};

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
        args.terminal_verbose,
    );
    info!(target: "server::startup", config_path = %args.config, "配置文件已加载");
    info!(
        target: "server::startup",
        terminal_mode = if args.terminal_verbose { "详细" } else { "精简" },
        "日志系统已启动"
    );
    config.check();
    let request_log_config = config.requests.clone();
    let monitor_config = config.monitor.clone();
    let frontend_directory = config.frontend.directory.clone();
    let maxmind_directory = config.maxmind.directory.clone();
    let automatic_target_service = AutomaticTargetService::new(config.automatic_target.clone())
        .map_err(|error| io::Error::other(format!("自动目标生成配置错误：{error}")))?;

    let ser_con = config.server.clone();
    let server = config.server;
    let server_host = server.host;
    let server_port = server.port;
    let server_max_body = server.max_body_size;

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
    let request_log_pool = db_pool.clone();
    let scanner_latency_pool = db_pool.clone();
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
        Ok(_) => info!(target: "server::startup", "数据库结构初始化完成"),
        Err(e) => panic!("初始化数据库错误{}", e),
    };
    if let Ok(client) = db_pool.get().await
        && let Err(error_value) = client
            .execute(
                "UPDATE backup_job SET status = 'failed', finished_at = NOW(), \
                 stderr = CASE WHEN stderr = '' THEN '服务重启，任务执行状态已中断' ELSE stderr END \
                 WHERE status IN ('queued', 'running')",
                &[],
            )
            .await
    {
        error!(event = "BackupJobRecoveryError", message = %error_value);
    }

    let maxmind_state = MaxMindState::from_directory(&maxmind_directory);
    if args.refresh_ip_intel {
        match maxmind_state.refresh_ip_intel(&db_pool).await {
            Ok(report) => {
                println!(
                    "IP 情报刷新完成：扫描 {} 条，更新 {} 条，无匹配 {} 条",
                    report.scanned, report.updated, report.unmatched
                );
                return Ok(());
            }
            Err(error) => {
                error!(event = "RefreshIpIntelError", message = %error);
                return Err(io::Error::other("刷新历史 IP 情报失败"));
            }
        }
    }

    info!(target: "server::startup", "正在检查系统账户");

    check_system_user(&db_pool).await;

    tokio::spawn(run_generator(
        automatic_target_service.clone(),
        db_pool.clone(),
    ));

    // 定义密码加密相关配置文件
    let pwd_h = config.pwd_hash;

    check_default_admin_user(&db_pool, pwd_h.clone()).await;

    let mail_c = config.email_config;

    let monitor_handle = monitor::MonitorHandle::new(
        &monitor_config,
        db_pool.clone(),
        ser_con.encrypt_key.clone(),
    );

    let tls = build_acceptor(&config.tls)?;
    let frontend_assets = FrontendAssets::new(frontend_directory);
    let frontend_directory = frontend_assets.directory().to_path_buf();
    let frontend_assets = web::Data::new(frontend_assets);

    let sys = Systems::new();
    let sys_2 = sys.clone();
    let maxmind_state = web::Data::new(maxmind_state);
    let automatic_target_service = web::Data::new(automatic_target_service);
    let security = web::Data::new(config.security);
    let rate_limiter = RateLimitMiddleware::default();
    let open_source_catalog = web::Data::new(
        OpenSourceCatalog::from_embedded()
            .map_err(|error| io::Error::other(format!("开源项目清单格式错误: {error}")))?,
    );
    let backup_manager = web::Data::new(BackupManager::new(config.backup.clone()));

    info!(target: "server::startup",
        address = %format!("{}:{}", server_host, server_port),
        log_directory = %log_file_directory,
        log_file = %log_file_name,
        log_rolling_mode = log.file_rolling,
        debug = log_debug_mode,
        template_directory = %template_info.templates_directory,
        template_name = %template_info.templates_name,
        frontend_directory = %frontend_directory.display(),
        maxmind_directory = %maxmind_directory.display(),
        automatic_target_enabled = automatic_target_service.enabled(),
        status_interval_seconds = log.status_duration,
        "服务配置就绪"
    );
    info!(target: "server::startup", address = %format!("https://{}:{}", server_host, server_port), "HTTPS 服务开始监听");

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
                    error!(
                        event = "SystemStatusInsertError",
                        operation = "insert_system_status",
                        retry_interval_seconds = log.status_duration,
                        message = %error_chain_diagnostics(e.as_ref()),
                    )
                }
            };
            // TODO: 监控逻辑
        }
    });

    // 请求日志采集：有界 channel + 后台 writer（永不退出）+ 定期清理。
    let request_log_tx = if request_log_config.enabled {
        let (tx, rx) = tokio::sync::mpsc::channel(request_log::CHANNEL_CAPACITY);
        tokio::spawn(request_log::run_writer(request_log_pool.clone(), rx));
        tokio::spawn(request_log::run_retention(
            request_log_pool.clone(),
            request_log_config.retention_days,
        ));
        Some(tx)
    } else {
        None
    };

    let (scanner_latency_history, scanner_latency_rx) = ScannerLatencyHistory::channel();
    tokio::spawn(scanner_latency::run_writer(
        scanner_latency_pool.clone(),
        scanner_latency_rx,
    ));
    tokio::spawn(scanner_latency::run_retention(
        scanner_latency_pool,
        scanner_latency::RETENTION_DAYS,
    ));

    HttpServer::new(move || {
        let request_log_tx = request_log_tx.clone();
        let monitor_handle = monitor_handle.clone();

        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(template_info.clone()))
            .app_data(web::Data::new(sys_2.clone()))
            .app_data(web::Data::new(database_c2.clone()))
            .app_data(web::Data::new(pwd_h.clone()))
            .app_data(web::Data::new(mail_c.clone()))
            .app_data(web::Data::new(ser_con.clone()))
            .app_data(maxmind_state.clone())
            .app_data(automatic_target_service.clone())
            .app_data(open_source_catalog.clone())
            .app_data(backup_manager.clone())
            .app_data(security.clone())
            .app_data(web::Data::new(scanner_latency_history.clone()))
            .app_data(frontend_assets.clone())
            .app_data(web::JsonConfig::default().limit(server_max_body))
            .wrap(CsrfMiddleware)
            .wrap(SHeaderM)
            .wrap(AuthMiddleware)
            .wrap(rate_limiter.clone())
            .wrap_fn(move |req, service| {
                let request_id = req
                    .headers()
                    .get("X-Request-ID")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                    .unwrap_or_else(uuid::Uuid::new_v4);
                req.extensions_mut().insert(RequestId(request_id));
                let response_request_id = header::HeaderValue::from_str(&request_id.to_string())
                    .expect("UUID is a valid header value");

                // 请求日志采集：service.call 前抓取元数据，响应后抓取状态码与耗时。
                // 跳过静态资源与高频心跳，避免污染与放大数据量。
                let path = req.path().to_owned();
                let is_scanner_heartbeat = path == "/api/scanner/heartbeat";
                let latency_probe = (is_scanner_heartbeat
                    && req
                        .headers()
                        .get("NM-Latency-Version")
                        .and_then(|value| value.to_str().ok())
                        == Some("1"))
                .then(|| {
                    req.headers()
                        .get("NM-Latency-Probe")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| uuid::Uuid::parse_str(value).ok())
                })
                .flatten();
                let capture = request_log_tx.is_some()
                    && !network_mapping_server::frontend::is_frontend_resource_path(&path)
                    && !is_scanner_heartbeat;
                let actor = std::sync::Arc::new(std::sync::Mutex::new(None));
                req.extensions_mut()
                    .insert(request_log::RequestActor(actor.clone()));
                let method = req.method().to_string();
                let client_ip = req
                    .connection_info()
                    .realip_remote_addr()
                    .and_then(request_log::parse_ip);
                let user_agent = req
                    .headers()
                    .get(header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.chars().take(512).collect::<String>());
                let started = std::time::Instant::now();

                // 用 request_id 建立 tracing span，使请求处理链路上的所有日志自动携带该 id，
                // 无需在每个日志宏里手动重复写 request_id。
                let span = tracing::info_span!("http_request", request_id = %request_id);
                let future = service.call(req).instrument(span);
                let request_log_tx = request_log_tx.clone();
                let monitor_handle = monitor_handle.clone();
                async move {
                    let mut response = future.await?;
                    response.headers_mut().insert(
                        header::HeaderName::from_static("x-request-id"),
                        response_request_id,
                    );
                    if response.status().is_success()
                        && let Some(probe_id) = latency_probe
                    {
                        let processing_us = started.elapsed().as_micros();
                        let sent_at_ms = network_mapping_server::get_unix_epoch_ms();
                        response.headers_mut().insert(
                            header::HeaderName::from_static("nm-latency-version"),
                            header::HeaderValue::from_static("1"),
                        );
                        response.headers_mut().insert(
                            header::HeaderName::from_static("nm-latency-probe"),
                            header::HeaderValue::from_str(&probe_id.to_string())
                                .expect("UUID is a valid header value"),
                        );
                        response.headers_mut().insert(
                            header::HeaderName::from_static("nm-server-processing-us"),
                            header::HeaderValue::from_str(&processing_us.to_string())
                                .expect("integer is a valid header value"),
                        );
                        response.headers_mut().insert(
                            header::HeaderName::from_static("nm-server-sent-at-ms"),
                            header::HeaderValue::from_str(&sent_at_ms.to_string())
                                .expect("integer is a valid header value"),
                        );
                    }
                    if capture {
                        let status = response.status().as_u16();
                        let (error_level, error_type) = request_log::classify_status(status);
                        let duration_ms = i32::try_from(started.elapsed().as_millis()).ok();
                        let actor = actor
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .take();
                        let (actor_id, actor_name) = match actor {
                            Some((id, name)) => (Some(id), Some(name)),
                            None => (None, None),
                        };

                        // 健康告警：慢请求与 5xx 错误实时判定，仅在命中阈值时才分配/克隆字符串。
                        if let Some(monitor) = &monitor_handle {
                            let slow_duration = duration_ms
                                .map(i64::from)
                                .filter(|value| monitor.is_slow_request(*value));
                            let is_server_error = monitor.server_error_enabled() && status >= 500;
                            if slow_duration.is_some() || is_server_error {
                                let client_ip_str = client_ip.map(|ip| ip.to_string());
                                let actor_name_str = actor_name.clone();
                                if let Some(duration_ms) = slow_duration {
                                    monitor.emit(HealthEvent::slow_request(
                                        &method,
                                        &path,
                                        status,
                                        duration_ms,
                                        request_id,
                                        client_ip_str.clone(),
                                        actor_name_str.clone(),
                                    ));
                                }
                                if is_server_error {
                                    monitor.emit(HealthEvent::server_error(
                                        &method,
                                        &path,
                                        status,
                                        duration_ms.map(i64::from),
                                        request_id,
                                        client_ip_str,
                                        actor_name_str,
                                    ));
                                }
                            }
                        }

                        let entry = request_log::RequestLogEntry {
                            request_id,
                            occurred_at: chrono::Utc::now(),
                            http_method: method,
                            request_path: path,
                            status_code: status as i16,
                            duration_ms,
                            client_ip,
                            user_agent,
                            actor_id,
                            actor_name,
                            error_level: error_level.to_owned(),
                            error_type: error_type.map(str::to_owned),
                        };
                        if let Some(tx) = &request_log_tx {
                            let _ = tx.try_send(entry);
                        }
                    }
                    Ok(response)
                }
            })
            .configure(config::init_routes)
            .configure(frontend::configure)
            .configure(|cfg| frontend::configure_assets(cfg, &frontend_directory))
            .default_service(web::to(network_mapping_server::handlers::utils::not_found))
    })
    .bind_openssl((server_host, server_port), tls)?
    .run()
    .await
}
