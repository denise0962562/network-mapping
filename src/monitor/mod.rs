//! 健康监控与告警：慢请求、5xx 错误、慢 SQL 的检测与邮件通知。
//!
//! 检测分两类来源：
//! - 请求级：`main.rs` 的请求中间件在响应后按状态码与耗时实时判定，投递到有界 channel；
//! - 数据库级：[`slow_sql`] 后台任务轮询 `pg_stat_statements` 视图。
//! 两者统一由 [`run_notifier`] 消费，做冷却去重后复用邮件模板系统发送给管理员。

mod slow_sql;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use deadpool_postgres::Pool;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::config::MonitorConfig;
use crate::logs::write::error_chain_diagnostics;
use crate::mail_template;

pub const CHANNEL_CAPACITY: usize = 1024;

/// 一条健康告警事件。去重 key 相同的事件在冷却窗口内会被合并丢弃。
#[derive(Debug, Clone)]
pub struct HealthEvent {
    pub alert_type: &'static str,
    pub severity: &'static str,
    pub key: String,
    pub summary: String,
    pub details: Vec<(String, String)>,
}

impl HealthEvent {
    pub fn slow_request(
        method: &str,
        path: &str,
        status: u16,
        duration_ms: i64,
        request_id: Uuid,
        client_ip: Option<String>,
        actor_name: Option<String>,
    ) -> Self {
        Self {
            alert_type: "slow_request",
            severity: "warning",
            key: format!("slow_request:{method}:{path}"),
            summary: format!("请求耗时 {duration_ms}ms 超过阈值：{method} {path}"),
            details: request_details(
                method,
                path,
                status,
                Some(duration_ms),
                request_id,
                client_ip,
                actor_name,
            ),
        }
    }

    pub fn server_error(
        method: &str,
        path: &str,
        status: u16,
        duration_ms: Option<i64>,
        request_id: Uuid,
        client_ip: Option<String>,
        actor_name: Option<String>,
    ) -> Self {
        Self {
            alert_type: "server_error",
            severity: "critical",
            key: format!("server_error:{path}:{status}"),
            summary: format!("服务端错误 {status}：{method} {path}"),
            details: request_details(
                method,
                path,
                status,
                duration_ms,
                request_id,
                client_ip,
                actor_name,
            ),
        }
    }

    pub fn slow_sql(
        queryid: i64,
        query: &str,
        mean_exec_time_ms: f64,
        max_exec_time_ms: f64,
        calls_delta: i64,
    ) -> Self {
        let query_text = if query.is_empty() {
            format!("queryid={queryid}")
        } else {
            query.chars().take(2000).collect()
        };
        Self {
            alert_type: "slow_sql",
            severity: "warning",
            key: format!("slow_sql:{queryid}"),
            summary: format!(
                "检测到慢 SQL（平均 {mean_exec_time_ms:.1}ms，峰值 {max_exec_time_ms:.1}ms）"
            ),
            details: vec![
                ("查询".to_owned(), query_text),
                ("平均耗时".to_owned(), format!("{mean_exec_time_ms:.1} ms")),
                ("峰值耗时".to_owned(), format!("{max_exec_time_ms:.1} ms")),
                ("本周期调用次数".to_owned(), calls_delta.to_string()),
            ],
        }
    }
}

fn request_details(
    method: &str,
    path: &str,
    status: u16,
    duration_ms: Option<i64>,
    request_id: Uuid,
    client_ip: Option<String>,
    actor_name: Option<String>,
) -> Vec<(String, String)> {
    vec![
        ("请求方法".to_owned(), method.to_owned()),
        ("请求路径".to_owned(), path.to_owned()),
        ("状态码".to_owned(), status.to_string()),
        (
            "耗时".to_owned(),
            duration_ms
                .map(|value| format!("{value} ms"))
                .unwrap_or_else(|| "未知".to_owned()),
        ),
        ("请求 ID".to_owned(), request_id.to_string()),
        (
            "来源 IP".to_owned(),
            client_ip.unwrap_or_else(|| "未知".to_owned()),
        ),
        (
            "操作者".to_owned(),
            actor_name.unwrap_or_else(|| "匿名/扫描器".to_owned()),
        ),
    ]
}

/// 健康监控句柄：请求中间件通过 [`MonitorHandle::emit`] 投递事件；`None` 表示监控已关闭。
#[derive(Clone)]
pub struct MonitorHandle {
    tx: mpsc::Sender<HealthEvent>,
    slow_request_threshold_ms: i64,
    server_error_enabled: bool,
}

impl MonitorHandle {
    /// 启动后台通知与慢 SQL 轮询任务；`enabled = false` 时返回 `None` 且不启动任何任务。
    pub fn new(config: &MonitorConfig, pool: Pool, encryption_key: String) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(run_notifier(rx, pool.clone(), encryption_key, config.clone()));
        tokio::spawn(slow_sql::run_monitor(pool, tx.clone(), config.clone()));
        info!(target: "server::startup", component = "monitor", "健康监控任务已启动");
        Some(Self {
            tx,
            slow_request_threshold_ms: config.slow_request_threshold_ms,
            server_error_enabled: config.server_error_enabled,
        })
    }

    /// 该耗时是否达到慢请求阈值。
    pub fn is_slow_request(&self, duration_ms: i64) -> bool {
        duration_ms >= self.slow_request_threshold_ms
    }

    /// 是否启用 5xx 服务端错误告警。
    pub fn server_error_enabled(&self) -> bool {
        self.server_error_enabled
    }

    /// 非阻塞投递一条告警事件；channel 满时直接丢弃，绝不阻塞请求路径。
    pub fn emit(&self, event: HealthEvent) {
        let _ = self.tx.try_send(event);
    }
}

/// 将一条已通过冷却去重的告警写入 `health_alert` 历史表；写入失败不影响邮件发送。
async fn record_health_alert(
    pool: &Pool,
    event: &HealthEvent,
) -> Result<(), Box<dyn std::error::Error>> {
    let details = event
        .details
        .iter()
        .map(|(label, value)| serde_json::json!({ "label": label, "value": value }))
        .collect::<Vec<_>>();
    let detail = serde_json::json!({ "details": details });
    let conn = pool.get().await?;
    conn.execute(
        "INSERT INTO health_alert (alert_type, alert_key, severity, summary, detail) \
         VALUES ($1, $2, $3, $4, $5);",
        &[
            &event.alert_type,
            &event.key,
            &event.severity,
            &event.summary,
            &detail,
        ],
    )
    .await?;
    Ok(())
}

/// 消费健康事件：冷却去重后写入历史并调用邮件模板系统向管理员发送告警。
async fn run_notifier(
    mut rx: mpsc::Receiver<HealthEvent>,
    pool: Pool,
    encryption_key: String,
    config: MonitorConfig,
) {
    let cooldown = Duration::from_secs(config.alert_cooldown_seconds);
    let last_alert = Mutex::new(HashMap::<String, Instant>::new());

    while let Some(event) = rx.recv().await {
        {
            let mut last = last_alert
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            if let Some(previous) = last.get(&event.key) {
                if now.duration_since(*previous) < cooldown {
                    debug!(
                        event = "HealthAlertCooldown",
                        alert_type = event.alert_type,
                        key = %event.key,
                        "告警处于冷却期，已合并丢弃"
                    );
                    continue;
                }
            }
            last.insert(event.key.clone(), now);
        }

        if let Err(error) = record_health_alert(&pool, &event).await {
            error!(
                event = "HealthAlertRecordError",
                alert_type = event.alert_type,
                key = %event.key,
                message = %error_chain_diagnostics(error.as_ref()),
                "健康告警历史写入失败"
            );
        }

        if let Err(error) = mail_template::send_health_alert(&pool, &encryption_key, &event).await {
            error!(
                event = "HealthAlertSendError",
                alert_type = event.alert_type,
                key = %event.key,
                message = %error_chain_diagnostics(error.as_ref()),
                "健康告警邮件发送失败"
            );
        }
    }
}
