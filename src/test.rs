use actix_web::web::Json;
use actix_web::{http::header::ContentType, test, App, web};
use crate::config;
use crate::handlers::user::user_login_h;
use crate::smiddleware::AuthMiddleware;
use crate::{handlers, login::user_login, logs};
use crate::logs::{LogRollingMode};
use crate::db;
use crate::handlers::ReceiveLoginInfo;


#[actix_web::test]
async fn login_test() {

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


    // let _guard = init_tracing(&log_file_directory, &log_file_name, &log_file_rolling, &log_debug_mode);
    let _guard = logs::init::init(&log_file_directory, &log_file_name, &log_file_rolling, &log_debug_mode);
    println!("日志系统已启动");
    let db_config = config.database;

    // let database = format!("postgresql://{}:{}@{}/{}", db_config.username, db_config.password, db_config.host, db_config.db_name);
    let db_pool = db::create_postgresql_pool(
        db_config.host, 
        db_config.port, 
        db_config.username, 
        db_config.password, 
        db_config.db_name, 
    ).await.expect("创建连接池错误");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .wrap(AuthMiddleware)
            .configure(config::init_routes)
    ).await;



    let r = test::TestRequest::post()
        .uri("/api/login")
        .set_json(ReceiveLoginInfo{
            username: "admin".to_string(),
            password: "1".to_string(),
            rememberme: true
        })
        .to_request();

    let ret = test::call_service(&app, r).await;

    assert!(ret.status().is_success());

}
