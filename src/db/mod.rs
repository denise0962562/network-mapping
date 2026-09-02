use crate::config::DatabaseConfig;
use crate::path_secure_join;
use actix_web::web;
use deadpool_postgres::{ManagerConfig, RecyclingMethod};
use std::time::Duration;
use tokio::fs;
use tracing::{debug, error, info};

pub struct SqlFile {
    pub root_path: String,
    pub file_name: String,
}

impl SqlFile {
    pub fn new(root: String, name: String) -> Self {
        Self {
            root_path: root,
            file_name: name,
        }
    }
}

pub async fn create_postgresql_pool(
    config: &DatabaseConfig,
) -> Result<deadpool_postgres::Pool, Box<dyn std::error::Error>> {
    let mut db_poll_cfg = deadpool_postgres::Config::new();
    db_poll_cfg.user = Some(config.username.clone());
    db_poll_cfg.password = Some(config.password.clone());
    db_poll_cfg.dbname = Some(config.db_name.clone());
    db_poll_cfg.host = Some(config.host.clone());
    db_poll_cfg.port = Some(config.port);
    db_poll_cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Verified,
    });
    db_poll_cfg.pool = Some(deadpool_postgres::PoolConfig {
        max_size: config.pool_max_size,
        timeouts: deadpool::managed::Timeouts {
            wait: Some(Duration::from_millis(config.pool_wait_timeout_ms)),
            create: Some(Duration::from_millis(config.pool_create_timeout_ms)),
            recycle: Some(Duration::from_millis(config.pool_recycle_timeout_ms)),
        },
        queue_mode: deadpool::managed::QueueMode::Lifo,
    });
    let pool = db_poll_cfg.create_pool(None, tokio_postgres::NoTls)?;
    info!(
        target: "server::startup",
        pool_max_size = config.pool_max_size,
        pool_wait_timeout_ms = config.pool_wait_timeout_ms,
        pool_create_timeout_ms = config.pool_create_timeout_ms,
        pool_recycle_timeout_ms = config.pool_recycle_timeout_ms,
        "正在检查数据库连接"
    );
    match pool.get().await {
        Ok(_conn) => {
            // _conn 是一个 deadpool::managed::Object，它会在离开作用域时自动返回池中
            info!(target: "server::startup", "数据库连接成功，连接池可用");
        }
        Err(e) => {
            // 如果连接失败，这里会返回错误
            panic!(
                "致命错误：无法从连接池获取连接。请检查数据库配置或服务状态。错误: {}",
                e
            )
        }
    }
    Ok(pool)
}

pub async fn exec_sql(
    pool: web::Data<deadpool_postgres::Pool>,
    sql: &str,
    params: Option<&[&(dyn tokio_postgres::types::ToSql + Sync)]>,
) -> Result<&'static str, Box<dyn std::error::Error>> {
    // 从连接池获取客户端
    let mut client = pool.get().await?; // PoolError 自动转成 Box<dyn Error>

    // 开启事务
    let transaction = client.transaction().await?;

    // 预编译 SQL
    let stmt = transaction.prepare(sql).await?;

    // 执行 SQL
    match params {
        Some(values) => transaction.query(&stmt, values).await?,
        None => transaction.query(&stmt, &[]).await?,
    };

    // 提交事务
    transaction.commit().await?;

    Ok("OK")
}

///初始化数据库表结构
pub async fn init_database_table(
    cpool: &deadpool_postgres::Pool,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sql_from_f = fs::read_to_string(file_path).await;
    match sql_from_f {
        Ok(o) => {
            let mut client = cpool.get().await?;
            let transaction = client.transaction().await?;
            debug!("开始执行数据库初始化事务");
            transaction.batch_execute(&o).await?;
            transaction.commit().await?;
        }
        Err(e) => {
            tracing::error!("{}", e);
            panic!("读取目标文件失败");
        }
    };

    Ok(())
}

//TODO 完成获取数据库数据的函数

//TODO 完成调用该函数，将所有需要sql语句的地方使用该函数
///该函数用于从文件中读取内容并以 String 类型返回。这不是一个安全的函数，因为他需要你自己处理错误，他只会将错误向上传。
pub async fn get_sql_from_file(
    file_path: &str,
    file_name: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let path = path_secure_join(file_path, file_name);
    match path {
        Some(s) => Ok(fs::read_to_string(s).await?),
        None => {
            let message = format!("未能获取到拼接后端路径，用户输入: {}", file_name);
            error!(message);
            Err(message.into())
        }
    }
}
