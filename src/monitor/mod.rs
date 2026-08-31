//! 健康监控与告警：慢请求、5xx、PostgreSQL 慢 SQL 和 Elasticsearch 慢操作。
//!
//! 检测分三类来源：
//! - 请求级：`main.rs` 的请求中间件在响应后按状态码与耗时实时判定，投递到有界 channel；
//! - 数据库级：[`slow_sql`] 后台任务轮询 `pg_stat_statements` 视图。
//! - Elasticsearch：统一请求入口上报端到端耗时、响应状态和分片结果。
//!
//! 三类信号统一由 [`run_notifier`] 消费，做冷却去重后复用邮件模板系统发送给管理员。

mod slow_sql;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use deadpool_postgres::Pool;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::MonitorConfig;
use crate::logs::write::error_chain_diagnostics;
use crate::mail_template;

pub const CHANNEL_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ElasticsearchOperationKind {
    Query,
    Write,
    Maintenance,
}

#[derive(Clone, Debug)]
pub(crate) struct ElasticsearchObservation {
    pub operation: &'static str,
    pub kind: ElasticsearchOperationKind,
    pub duration_ms: i64,
    pub es_took_ms: Option<i64>,
    pub http_status: Option<u16>,
    pub timed_out: bool,
    pub failed_shards: i64,
    pub trace_id: String,
    pub failure_kind: Option<&'static str>,
}

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

    fn elasticsearch(observation: &ElasticsearchObservation, severity: &'static str) -> Self {
        let operation_kind = match observation.kind {
            ElasticsearchOperationKind::Query => "query",
            ElasticsearchOperationKind::Write => "write",
            ElasticsearchOperationKind::Maintenance => "maintenance",
        };
        let failed = observation.failure_kind.is_some()
            || observation.http_status.is_some_and(|status| status >= 400)
            || observation.timed_out
            || observation.failed_shards > 0;
        let alert_type = match (operation_kind, failed) {
            ("query", false) => "slow_elasticsearch_query",
            ("write", false) => "slow_elasticsearch_write",
            ("query", true) => "elasticsearch_query_error",
            ("write", true) => "elasticsearch_write_error",
            (_, _) => "elasticsearch_error",
        };
        let summary = if failed {
            format!(
                "Elasticsearch {} {} 失败或返回异常（{}ms）",
                operation_kind, observation.operation, observation.duration_ms
            )
        } else {
            format!(
                "Elasticsearch {} {} 耗时 {}ms",
                operation_kind, observation.operation, observation.duration_ms
            )
        };
        let mut details = vec![
            ("操作".to_owned(), observation.operation.to_owned()),
            ("类型".to_owned(), operation_kind.to_owned()),
            (
                "服务端总耗时".to_owned(),
                format!("{} ms", observation.duration_ms),
            ),
            (
                "Elasticsearch took".to_owned(),
                observation
                    .es_took_ms
                    .map(|value| format!("{value} ms"))
                    .unwrap_or_else(|| "未知".to_owned()),
            ),
            (
                "应用额外耗时".to_owned(),
                observation
                    .es_took_ms
                    .map(|value| {
                        format!(
                            "{} ms",
                            observation.duration_ms.saturating_sub(value).max(0)
                        )
                    })
                    .unwrap_or_else(|| "未知".to_owned()),
            ),
            (
                "HTTP 状态".to_owned(),
                observation
                    .http_status
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "无响应".to_owned()),
            ),
            ("是否超时".to_owned(), observation.timed_out.to_string()),
            ("失败分片".to_owned(), observation.failed_shards.to_string()),
            ("Trace ID".to_owned(), observation.trace_id.clone()),
        ];
        if let Some(failure_kind) = observation.failure_kind {
            details.push(("失败类型".to_owned(), failure_kind.to_owned()));
        }
        Self {
            alert_type,
            severity,
            key: format!("{alert_type}:{}", observation.operation),
            summary,
            details,
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
    elasticsearch_query_warning_threshold_ms: i64,
    elasticsearch_query_critical_threshold_ms: i64,
    elasticsearch_write_warning_threshold_ms: i64,
    elasticsearch_write_critical_threshold_ms: i64,
    dropped_events: Arc<AtomicU64>,
}

impl MonitorHandle {
    /// 启动后台通知与慢 SQL 轮询任务；`enabled = false` 时返回 `None` 且不启动任何任务。
    pub fn new(config: &MonitorConfig, pool: Pool, encryption_key: String) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(run_notifier(
            rx,
            pool.clone(),
            encryption_key,
            config.clone(),
        ));
        tokio::spawn(slow_sql::run_monitor(pool, tx.clone(), config.clone()));
        info!(target: "server::startup", component = "monitor", "健康监控任务已启动");
        Some(Self {
            tx,
            slow_request_threshold_ms: config.slow_request_threshold_ms,
            server_error_enabled: config.server_error_enabled,
            elasticsearch_query_warning_threshold_ms: config
                .elasticsearch_query_warning_threshold_ms,
            elasticsearch_query_critical_threshold_ms: config
                .elasticsearch_query_critical_threshold_ms,
            elasticsearch_write_warning_threshold_ms: config
                .elasticsearch_write_warning_threshold_ms,
            elasticsearch_write_critical_threshold_ms: config
                .elasticsearch_write_critical_threshold_ms,
            dropped_events: Arc::new(AtomicU64::new(0)),
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
        if self.tx.try_send(event).is_err() {
            let dropped = self.dropped_events.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                warn!(
                    event = "HealthAlertChannelFull",
                    dropped_events = dropped,
                    "健康告警队列已满，事件被丢弃"
                );
            }
        }
    }

    pub(crate) fn observe_elasticsearch(&self, observation: ElasticsearchObservation) {
        if observation.kind == ElasticsearchOperationKind::Maintenance {
            return;
        }
        let (warning_threshold, critical_threshold) = match observation.kind {
            ElasticsearchOperationKind::Query => (
                self.elasticsearch_query_warning_threshold_ms,
                self.elasticsearch_query_critical_threshold_ms,
            ),
            ElasticsearchOperationKind::Write => (
                self.elasticsearch_write_warning_threshold_ms,
                self.elasticsearch_write_critical_threshold_ms,
            ),
            ElasticsearchOperationKind::Maintenance => return,
        };
        let failed = observation.failure_kind.is_some()
            || observation.http_status.is_some_and(|status| status >= 400)
            || observation.timed_out
            || observation.failed_shards > 0;
        if !failed && observation.duration_ms < warning_threshold {
            return;
        }
        let severity = if failed || observation.duration_ms >= critical_threshold {
            "critical"
        } else {
            "warning"
        };
        warn!(
            event = "ElasticsearchSlowOperation",
            operation = observation.operation,
            operation_kind = ?observation.kind,
            duration_ms = observation.duration_ms,
            es_took_ms = observation.es_took_ms,
            http_status = observation.http_status,
            timed_out = observation.timed_out,
            failed_shards = observation.failed_shards,
            trace_id = %observation.trace_id,
            failure_kind = observation.failure_kind,
            "Elasticsearch 操作达到告警条件"
        );
        self.emit(HealthEvent::elasticsearch(&observation, severity));
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
            if let Some(previous) = last.get(&event.key)
                && now.duration_since(*previous) < cooldown
            {
                debug!(
                    event = "HealthAlertCooldown",
                    alert_type = event.alert_type,
                    key = %event.key,
                    "告警处于冷却期，已合并丢弃"
                );
                continue;
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

#[cfg(test)]
mod tests {
    use super::{ElasticsearchObservation, ElasticsearchOperationKind, MonitorHandle};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    fn handle() -> (
        MonitorHandle,
        tokio::sync::mpsc::Receiver<super::HealthEvent>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        (
            MonitorHandle {
                tx,
                slow_request_threshold_ms: 3_000,
                server_error_enabled: true,
                elasticsearch_query_warning_threshold_ms: 1_000,
                elasticsearch_query_critical_threshold_ms: 3_000,
                elasticsearch_write_warning_threshold_ms: 5_000,
                elasticsearch_write_critical_threshold_ms: 15_000,
                dropped_events: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    fn query_observation(duration_ms: i64) -> ElasticsearchObservation {
        ElasticsearchObservation {
            operation: "asset-search",
            kind: ElasticsearchOperationKind::Query,
            duration_ms,
            es_took_ms: Some(duration_ms.saturating_sub(20)),
            http_status: Some(200),
            timed_out: false,
            failed_shards: 0,
            trace_id: "0123456789abcdef0123456789abcdef".to_owned(),
            failure_kind: None,
        }
    }

    #[tokio::test]
    async fn elasticsearch_observer_ignores_fast_queries_and_emits_slow_queries() {
        let (handle, mut rx) = handle();
        handle.observe_elasticsearch(query_observation(999));
        assert!(rx.try_recv().is_err());

        handle.observe_elasticsearch(query_observation(1_000));
        let event = rx.recv().await.unwrap();
        assert_eq!(event.alert_type, "slow_elasticsearch_query");
        assert_eq!(event.severity, "warning");
        assert_eq!(event.key, "slow_elasticsearch_query:asset-search");
    }

    #[tokio::test]
    async fn elasticsearch_failures_are_critical_without_sensitive_details() {
        let (handle, mut rx) = handle();
        let mut observation = query_observation(10);
        observation.http_status = Some(429);
        observation.failure_kind = Some("http");
        handle.observe_elasticsearch(observation);

        let event = rx.recv().await.unwrap();
        assert_eq!(event.alert_type, "elasticsearch_query_error");
        assert_eq!(event.severity, "critical");
        let rendered = format!("{event:?}");
        assert!(!rendered.contains("SELECT "));
        assert!(!rendered.contains("password="));
    }
}
