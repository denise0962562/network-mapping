//! Legacy PostgreSQL preparation, used exclusively by PG -> ES migration.
use crate::cli_progress::{ProgressReporter, ProgressUpdate};
use crate::search_content::extract_search_content;
use deadpool_postgres::Pool;

pub async fn prepare(pool: &Pool, reporter: &dyn ProgressReporter) -> Result<(), String> {
    let client = pool.get().await.map_err(|error| error.to_string())?;
    client
        .batch_execute(include_str!(
            "../source/database/prepare_pg_scan_migration.sql"
        ))
        .await
        .map_err(|error| error.to_string())?;
    drop(client);
    backfill_search_content(pool, reporter)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) async fn backfill_search_content(
    pool: &Pool,
    reporter: &dyn ProgressReporter,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let expected_total = if reporter.is_enabled() {
        reporter.report(ProgressUpdate::phase("正在统计待提取搜索内容的观察记录"));
        let total: i64 = pool
            .get()
            .await?
            .query_one(
                "SELECT COUNT(*)::BIGINT AS total FROM scan_observation \
                 WHERE NOT search_content_extracted;",
                &[],
            )
            .await?
            .get("total");
        Some(u64::try_from(total)?)
    } else {
        None
    };
    let mut completed = 0_u64;
    reporter.report(ProgressUpdate::count(
        "回填搜索内容",
        0,
        expected_total,
        "条",
        "",
    ));
    loop {
        let mut connection = pool.get().await?;
        let transaction = connection.transaction().await?;
        let rows = transaction
            .query(
                "SELECT id, data FROM scan_observation \
                 WHERE NOT search_content_extracted ORDER BY id \
                 FOR UPDATE SKIP LOCKED LIMIT 500;",
                &[],
            )
            .await?;
        if rows.is_empty() {
            transaction.commit().await?;
            break;
        }
        for row in &rows {
            let id: i64 = row.get("id");
            let data: Option<serde_json::Value> = row.get("data");
            let content = extract_search_content(data.as_ref());
            transaction
                .execute(
                    "UPDATE scan_observation SET title = $2, http_body = $3, \
                     http_body_truncated = $4, tls_subject = $5, search_content_extracted = TRUE \
                     WHERE id = $1;",
                    &[
                        &id,
                        &content.title,
                        &content.http_body,
                        &content.http_body_truncated,
                        &content.tls_subject,
                    ],
                )
                .await?;
        }
        completed = completed.saturating_add(rows.len() as u64);
        transaction.commit().await?;
        reporter.report(ProgressUpdate::count(
            "回填搜索内容",
            completed,
            expected_total,
            "条",
            "",
        ));
    }
    Ok(completed)
}

/// A dedicated connection holds a process-lifetime advisory lock. New runtime
/// instances share the lease; an offline migration requires exclusive ownership.
/// Dropping the connection releases it even when initialization or migration fails.
pub async fn acquire_storage_lease(
    config: &crate::config::DatabaseConfig,
    migration: bool,
) -> Result<tokio_postgres::Client, String> {
    let mut connection_config = tokio_postgres::Config::new();
    connection_config
        .host(&config.host)
        .port(config.port)
        .dbname(&config.db_name)
        .user(&config.username)
        .password(&config.password);
    let (client, connection) = connection_config
        .connect(tokio_postgres::NoTls)
        .await
        .map_err(|error| format!("无法获取存储运行锁：{error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::error!(
                event = "StorageLeaseConnectionError",
                operation = "hold_storage_advisory_lock",
                error_kind = "database_connection",
                error_code = "storage_lease_connection_lost",
                error_message = %error,
                retryable = false,
                outcome = "storage_exclusivity_unknown",
                migration,
                "存储运行锁连接中断；迁移前必须确认所有运行实例已停止"
            );
        }
    });
    let statement = if migration {
        "SELECT pg_try_advisory_lock($1)"
    } else {
        "SELECT pg_try_advisory_lock_shared($1)"
    };
    let acquired: bool = client
        .query_one(statement, &[&0x4e4d4553_i64])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    if !acquired {
        return Err("扫描服务与 PG -> ES 迁移不能同时运行，请先停止另一方".into());
    }
    Ok(client)
}
