//! 慢 SQL 检测：轮询 `pg_stat_statements` 视图，按统计窗口内的平均耗时识别近期慢查询。
//!
//! 依赖 PostgreSQL 的 `pg_stat_statements` 扩展；未启用或无权读取时轮询失败，
//! 首轮失败记录一次警告后不再重复告警，后续失败仅记录 error 日志。

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::sync::mpsc;
use tracing::{error, warn};

use super::{HealthEvent, SlowSqlObservation};
use crate::config::MonitorConfig;
use crate::logs::write::error_chain_diagnostics;

struct SlowQueryRow {
    queryid: Option<i64>,
    query: String,
    stats: StatementStats,
    max_exec_time_ms: f64,
}

#[derive(Clone, Copy, Debug)]
struct StatementStats {
    calls: i64,
    total_exec_time_ms: f64,
    rows: i64,
    shared_blks_hit: i64,
    shared_blks_read: i64,
    temp_blks_read: i64,
    temp_blks_written: i64,
}

#[derive(Debug, PartialEq)]
struct WindowStats {
    calls: i64,
    total_exec_time_ms: f64,
    mean_exec_time_ms: f64,
    rows: i64,
    shared_blks_hit: i64,
    shared_blks_read: i64,
    temp_blks_read: i64,
    temp_blks_written: i64,
}

impl StatementStats {
    fn since(self, previous: Self) -> Option<WindowStats> {
        let calls = self.calls.checked_sub(previous.calls)?;
        let rows = self.rows.checked_sub(previous.rows)?;
        let shared_blks_hit = self.shared_blks_hit.checked_sub(previous.shared_blks_hit)?;
        let shared_blks_read = self
            .shared_blks_read
            .checked_sub(previous.shared_blks_read)?;
        let temp_blks_read = self.temp_blks_read.checked_sub(previous.temp_blks_read)?;
        let temp_blks_written = self
            .temp_blks_written
            .checked_sub(previous.temp_blks_written)?;
        let total_exec_time_ms = self.total_exec_time_ms - previous.total_exec_time_ms;
        if calls <= 0
            || rows < 0
            || shared_blks_hit < 0
            || shared_blks_read < 0
            || temp_blks_read < 0
            || temp_blks_written < 0
            || total_exec_time_ms < 0.0
        {
            return None;
        }
        Some(WindowStats {
            calls,
            total_exec_time_ms,
            mean_exec_time_ms: total_exec_time_ms / calls as f64,
            rows,
            shared_blks_hit,
            shared_blks_read,
            temp_blks_read,
            temp_blks_written,
        })
    }
}

/// 后台轮询任务：首轮仅建立累计统计基线，之后按相邻轮询窗口的增量产生告警。
pub async fn run_monitor(
    pool: Pool,
    tx: mpsc::Sender<HealthEvent>,
    config: Arc<RwLock<MonitorConfig>>,
) {
    let mut baselines: HashMap<i64, StatementStats> = HashMap::new();
    let mut baseline_ready = false;
    let mut warned_unavailable = false;

    loop {
        let settings = config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if !settings.enabled {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        match poll(&pool).await {
            Ok(rows) => {
                if !baseline_ready {
                    for row in rows {
                        if let Some(queryid) = row.queryid {
                            baselines.insert(queryid, row.stats);
                        }
                    }
                    baseline_ready = true;
                    continue;
                }
                for row in rows {
                    // queryid 可能为 NULL（如 compute_query_id 关闭时的 utility 语句），
                    // 这类语句无法用 queryid 去重，跳过不告警。
                    let Some(queryid) = row.queryid else { continue };
                    let Some(previous) = baselines.insert(queryid, row.stats) else {
                        continue;
                    };
                    let Some(window) = row.stats.since(previous) else {
                        continue;
                    };
                    if window.mean_exec_time_ms >= settings.slow_sql_threshold_ms as f64 {
                        let event = HealthEvent::slow_sql(&SlowSqlObservation {
                            queryid,
                            query: &row.query,
                            mean_exec_time_ms: window.mean_exec_time_ms,
                            max_exec_time_ms: row.max_exec_time_ms,
                            calls_delta: window.calls,
                            total_exec_time_ms: window.total_exec_time_ms,
                            rows_delta: window.rows,
                            shared_blks_hit_delta: window.shared_blks_hit,
                            shared_blks_read_delta: window.shared_blks_read,
                            temp_blks_read_delta: window.temp_blks_read,
                            temp_blks_written_delta: window.temp_blks_written,
                        });
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
        tokio::time::sleep(Duration::from_secs(
            settings.slow_sql_check_interval_seconds,
        ))
        .await;
    }
}

async fn poll(pool: &Pool) -> Result<Vec<SlowQueryRow>, Box<dyn std::error::Error + Send + Sync>> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT * FROM ( \
                 SELECT queryid, COALESCE(query, '') AS query, calls, total_exec_time, \
                        max_exec_time, rows, shared_blks_hit, shared_blks_read, \
                        temp_blks_read, temp_blks_written \
                 FROM pg_stat_statements WHERE calls > 0 \
                 ORDER BY total_exec_time DESC LIMIT 500 \
             ) highest_total \
             UNION \
             SELECT * FROM ( \
                 SELECT queryid, COALESCE(query, '') AS query, calls, total_exec_time, \
                        max_exec_time, rows, shared_blks_hit, shared_blks_read, \
                        temp_blks_read, temp_blks_written \
                 FROM pg_stat_statements WHERE calls > 0 \
                 ORDER BY max_exec_time DESC LIMIT 500 \
             ) highest_peak;",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| SlowQueryRow {
            queryid: row.get("queryid"),
            query: row.get("query"),
            stats: StatementStats {
                calls: row.get("calls"),
                total_exec_time_ms: row.get("total_exec_time"),
                rows: row.get("rows"),
                shared_blks_hit: row.get("shared_blks_hit"),
                shared_blks_read: row.get("shared_blks_read"),
                temp_blks_read: row.get("temp_blks_read"),
                temp_blks_written: row.get("temp_blks_written"),
            },
            max_exec_time_ms: row.get("max_exec_time"),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::StatementStats;

    fn stats(calls: i64, total_exec_time_ms: f64) -> StatementStats {
        StatementStats {
            calls,
            total_exec_time_ms,
            rows: calls * 2,
            shared_blks_hit: calls * 3,
            shared_blks_read: calls,
            temp_blks_read: 0,
            temp_blks_written: 0,
        }
    }

    #[test]
    fn window_stats_use_counter_deltas() {
        let window = stats(15, 1_300.0)
            .since(stats(10, 300.0))
            .expect("monotonic counters");
        assert_eq!(window.calls, 5);
        assert_eq!(window.total_exec_time_ms, 1_000.0);
        assert_eq!(window.mean_exec_time_ms, 200.0);
        assert_eq!(window.rows, 10);
        assert_eq!(window.shared_blks_hit, 15);
        assert_eq!(window.shared_blks_read, 5);
    }

    #[test]
    fn counter_reset_reestablishes_baseline_without_alerting() {
        assert!(stats(2, 20.0).since(stats(10, 300.0)).is_none());
    }
}
