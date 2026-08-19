//! 慢 SQL 检测：轮询 `pg_stat_statements` 视图，按平均耗时与调用增量识别近期慢查询。
//!
//! 依赖 PostgreSQL 的 `pg_stat_statements` 扩展；未启用或无权读取时轮询失败，
//! 首轮失败记录一次警告后不再重复告警，后续失败仅记录 error 日志。

use std::collections::HashMap;
use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::sync::mpsc;
use tracing::{error, warn};

use super::HealthEvent;
use crate::config::MonitorConfig;
use crate::logs::write::error_chain_diagnostics;

struct SlowQueryRow {
    queryid: Option<i64>,
    query: String,
    calls: i64,
    mean_exec_time_ms: f64,
    max_exec_time_ms: f64,
}

/// 后台轮询任务：首轮仅建立 calls 基线，之后对“仍在执行且平均耗时超阈值”的查询产生告警。
pub async fn run_monitor(pool: Pool, tx: mpsc::Sender<HealthEvent>, config: MonitorConfig) {
    let mut ticker =
        tokio::time::interval(Duration::from_secs(config.slow_sql_check_interval_seconds));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut last_calls: HashMap<i64, i64> = HashMap::new();
    let mut baseline_ready = false;
    let mut warned_unavailable = false;

    loop {
        ticker.tick().await;
        match poll(&pool).await {
            Ok(rows) => {
                if !baseline_ready {
                    for row in rows {
                        if let Some(queryid) = row.queryid {
                            last_calls.insert(queryid, row.calls);
                        }
                    }
                    baseline_ready = true;
                    continue;
                }
                for row in rows {
                    // queryid 可能为 NULL（如 compute_query_id 关闭时的 utility 语句），
                    // 这类语句无法用 queryid 去重，跳过不告警。
                    let Some(queryid) = row.queryid else { continue };
                    let previous = last_calls.get(&queryid).copied().unwrap_or(0);
                    let delta = row.calls - previous;
                    last_calls.insert(queryid, row.calls);
                    if delta > 0 && row.mean_exec_time_ms >= config.slow_sql_threshold_ms as f64 {
                        let event = HealthEvent::slow_sql(
                            queryid,
                            &row.query,
                            row.mean_exec_time_ms,
                            row.max_exec_time_ms,
                            delta,
                        );
                        let _ = tx.try_send(event);
                    }
                }
            }
            Err(error) => {
                if !warned_unavailable {
                    warn!(
                        event = "SlowSqlMonitorUnavailable",
                        message = %error_chain_diagnostics(error.as_ref()),
                        "慢 SQL 检测不可用（pg_stat_statements 未启用或无权限），已跳过"
                    );
                    warned_unavailable = true;
                } else {
                    error!(
                        event = "SlowSqlMonitorError",
                        message = %error_chain_diagnostics(error.as_ref()),
                        "慢 SQL 检测失败"
                    );
                }
            }
        }
    }
}

async fn poll(pool: &Pool) -> Result<Vec<SlowQueryRow>, Box<dyn std::error::Error + Send + Sync>> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT queryid, COALESCE(query, '') AS query, calls, mean_exec_time, max_exec_time \
             FROM pg_stat_statements \
             WHERE calls > 0 \
             ORDER BY mean_exec_time DESC \
             LIMIT 200;",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| SlowQueryRow {
            queryid: row.get("queryid"),
            query: row.get("query"),
            calls: row.get("calls"),
            mean_exec_time_ms: row.get("mean_exec_time"),
            max_exec_time_ms: row.get("max_exec_time"),
        })
        .collect())
}
