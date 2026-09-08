//! Offline scan-analysis snapshots.
//!
//! The worker consumes completed executions rather than repeatedly aggregating the entire scan
//! history. `analytics_outbox` is also reconciled from the control plane, so deployments upgraded
//! from older server versions do not lose executions that were completed before this module was
//! installed.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::{DateTime, FixedOffset, NaiveDate, Timelike, Utc};
use deadpool_postgres::Pool;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::time::Duration;
use tracing::{info, warn};

use crate::config::AnalyticsSnapshotConfig;
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::runtime_config::RuntimeConfig;

const WORKER_LOCK_KEY: i64 = 0x4e4d_4153_4e50_0001;
const MAX_EXECUTIONS_PER_TICK: usize = 100;
const WRITE_BATCH_SIZE: usize = 1000;
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Debug)]
struct ExecutionContext {
    database_id: i32,
    execution_id: String,
    owner_id: i32,
    scanner_id: String,
    task_source: String,
    locked_at: DateTime<Utc>,
    expected_observations: i64,
}

#[derive(Default)]
struct ExecutionFacts {
    distribution: BTreeMap<(DateTime<Utc>, String, String), i64>,
    discovery: BTreeSet<(NaiveDate, IpAddr)>,
}

#[derive(Serialize)]
pub(crate) struct SnapshotProgress {
    pub data_as_of: Option<DateTime<Utc>>,
    pub build_started_at: Option<DateTime<Utc>>,
    pub build_completed_at: Option<DateTime<Utc>>,
    pub remaining: i64,
    pub pending: i64,
    pub running: i64,
    pub completed: i64,
    pub retrying: i64,
    pub failed_execution_id: Option<i32>,
    pub last_error: Option<String>,
}

pub(crate) async fn snapshot_progress(
    client: &deadpool_postgres::Client,
) -> Result<SnapshotProgress, tokio_postgres::Error> {
    let row = client.query_one(
        "SELECT \
         (SELECT data_as_of FROM analytics_watermark WHERE watermark_key = 'scan_analysis') AS data_as_of, \
         (SELECT started_at FROM analytics_snapshot_build) AS build_started_at, \
         (SELECT completed_at FROM analytics_snapshot_build) AS build_completed_at, \
         (SELECT COUNT(*) FROM analytics_snapshot_build_execution) AS remaining, \
         COUNT(*) FILTER (WHERE status = 'pending') AS pending, \
         COUNT(*) FILTER (WHERE status = 'running') AS running, \
         COUNT(*) FILTER (WHERE status = 'completed') AS completed, \
         COUNT(*) FILTER (WHERE status <> 'completed' AND last_error IS NOT NULL) AS retrying, \
         (SELECT execution_id FROM analytics_outbox WHERE status <> 'completed' AND last_error IS NOT NULL \
          ORDER BY updated_at DESC LIMIT 1) AS failed_execution_id, \
         (SELECT last_error FROM analytics_outbox WHERE status <> 'completed' AND last_error IS NOT NULL \
          ORDER BY updated_at DESC LIMIT 1) AS last_error \
         FROM analytics_outbox;", &[],
    ).await?;
    Ok(SnapshotProgress {
        data_as_of: row.get("data_as_of"),
        build_started_at: row.get("build_started_at"),
        build_completed_at: row.get("build_completed_at"),
        remaining: row.get("remaining"),
        pending: row.get("pending"),
        running: row.get("running"),
        completed: row.get("completed"),
        retrying: row.get("retrying"),
        failed_execution_id: row.get("failed_execution_id"),
        last_error: row.get("last_error"),
    })
}

/// Starts the worker only in `shadow` or `snapshot` mode. Realtime is deliberately the default
/// for an upgraded installation, preventing a switch to empty statistics before backfill.
pub async fn run_worker(
    config: RuntimeConfig<AnalyticsSnapshotConfig>,
    pool: Pool,
    elasticsearch: ElasticsearchService,
) {
    let mut changes = config.subscribe();
    let mut reconcile_at = tokio::time::Instant::now();
    loop {
        let settings = config.get().await.value;
        if !settings.mode.runs_worker() {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                changed = changes.changed() => if changed.is_err() { return; }
            }
            continue;
        }
        if tokio::time::Instant::now() >= reconcile_at {
            if let Err(error) = reconcile(&pool).await {
                warn!(event = "AnalyticsSnapshotReconcileError", message = %error);
            } else {
                reconcile_at = tokio::time::Instant::now()
                    + Duration::from_secs(settings.interval_minutes * 60);
            }
        }
        let mut exhausted = true;
        for _ in 0..MAX_EXECUTIONS_PER_TICK {
            if !config.get().await.value.mode.runs_worker() {
                break;
            }
            match process_one(&pool, &elasticsearch).await {
                Ok(true) => {}
                Ok(false) => {
                    exhausted = false;
                    break;
                }
                Err(error) => {
                    warn!(event = "AnalyticsSnapshotWorkerError", message = %error);
                    // The failed execution is delayed by fail_execution; continue draining
                    // independent work so one legacy/corrupt execution cannot block upgrades.
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(worker_delay(exhausted)) => {}
            changed = changes.changed() => if changed.is_err() { return; }
        }
    }
}

fn worker_delay(exhausted: bool) -> Duration {
    // Yield between batches; new uploads and delayed retries are polled independently
    // of the much less frequent historical reconciliation.
    Duration::from_secs(if exhausted { 1 } else { 5 })
}

async fn reconcile(pool: &Pool) -> Result<(), String> {
    let mut connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let inserted = transaction
        .execute(
            "INSERT INTO analytics_snapshot_build(singleton) VALUES (TRUE) ON CONFLICT DO NOTHING;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let build = transaction
        .query_one(
            "SELECT completed_at FROM analytics_snapshot_build FOR UPDATE;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .execute(
            "INSERT INTO analytics_outbox (execution_id, status, available_at) \
         SELECT e.id, 'pending', NOW() FROM scan_task_execution e \
         JOIN scan_task t ON t.id = e.task_id \
         WHERE e.execution_status = 'succeeded' AND t.task_kind = 'ip' \
         AND NOT EXISTS (SELECT 1 FROM analytics_outbox o WHERE o.execution_id = e.id) \
         ON CONFLICT (execution_id) DO NOTHING;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    // Membership is immutable until published, even when its last execution was
    // deleted. An empty membership table alone must not admit new arrivals.
    if inserted > 0
        || build
            .get::<_, Option<DateTime<Utc>>>("completed_at")
            .is_some()
    {
        transaction
            .execute(
                "UPDATE analytics_snapshot_build SET started_at = NOW(), completed_at = NULL \
         WHERE singleton;",
                &[],
            )
            .await
            .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
        transaction
            .execute(
                "INSERT INTO analytics_snapshot_build_execution(execution_id) \
         SELECT execution_id FROM analytics_outbox WHERE status <> 'completed' \
         ON CONFLICT DO NOTHING;",
                &[],
            )
            .await
            .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    }
    publish_build(&transaction).await?;
    transaction
        .commit()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))
}

async fn publish_build(transaction: &deadpool_postgres::Transaction<'_>) -> Result<(), String> {
    transaction.execute(
        "WITH finished AS ( \
             UPDATE analytics_snapshot_build SET completed_at = NOW() \
             WHERE completed_at IS NULL \
             AND NOT EXISTS (SELECT 1 FROM analytics_snapshot_build_execution) \
             RETURNING started_at \
         ) INSERT INTO analytics_watermark(watermark_key, data_as_of, updated_at) \
           SELECT 'scan_analysis', started_at, NOW() FROM finished \
           ON CONFLICT (watermark_key) DO UPDATE \
           SET data_as_of = GREATEST(analytics_watermark.data_as_of, EXCLUDED.data_as_of), updated_at = NOW();",
        &[],
    ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    Ok(())
}

/// Rebuilds all completed IP-scan executions. The operation only replaces compact analytics
/// facts; it never alters scan observations or task results. It is intentionally explicit so an
/// upgraded installation can finish historical backfill before selecting `mode = "snapshot"`.
pub async fn rebuild_all(pool: &Pool, elasticsearch: &ElasticsearchService) -> Result<u64, String> {
    reconcile(pool).await?;
    let mut connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .query_one(
            "SELECT singleton FROM analytics_snapshot_build FOR UPDATE;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .execute(
            "INSERT INTO analytics_outbox (execution_id, status, available_at) \
             SELECT e.id, 'pending', NOW() FROM scan_task_execution e \
             JOIN scan_task t ON t.id = e.task_id \
             WHERE e.execution_status = 'succeeded' AND t.task_kind = 'ip' \
             ON CONFLICT (execution_id) DO UPDATE SET status = 'pending', available_at = NOW(), \
                locked_at = NULL, completed_at = NULL, last_error = NULL, updated_at = NOW();",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .batch_execute(
            "DELETE FROM analytics_snapshot_build_execution; \
         UPDATE analytics_snapshot_build SET started_at = NOW(), completed_at = NULL; \
         INSERT INTO analytics_snapshot_build_execution(execution_id) \
         SELECT execution_id FROM analytics_outbox WHERE status <> 'completed';",
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    publish_build(&transaction).await?;
    transaction
        .commit()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    drop(connection);
    let mut processed = 0_u64;
    while process_one(pool, elasticsearch).await? {
        processed += 1;
    }
    let connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let progress = snapshot_progress(&connection)
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    if progress.remaining > 0 {
        return Err(format!(
            "快照重建尚未完成：剩余 {} 个执行，失败待重试 {} 个；请查看统计进度",
            progress.remaining, progress.retrying
        ));
    }
    Ok(processed)
}

async fn process_one(pool: &Pool, elasticsearch: &ElasticsearchService) -> Result<bool, String> {
    let Some(context) = claim_execution(pool).await? else {
        return Ok(false);
    };
    let started = std::time::Instant::now();
    info!(event = "AnalyticsSnapshotExecutionStarted", execution_id = %context.execution_id,
        "开始构建执行统计");
    let result = tokio::time::timeout(EXECUTION_TIMEOUT, async {
        let facts = { facts_from_elasticsearch(elasticsearch, &context).await? };
        info!(event = "AnalyticsSnapshotFactsComputed", execution_id = %context.execution_id,
            elapsed_ms = started.elapsed().as_millis() as u64,
            distribution_rows = facts.distribution.len(), discovery_rows = facts.discovery.len(),
            "执行统计计算完成，开始批量写入");
        replace_execution_facts(pool, &context, facts).await
    })
    .await
    .unwrap_or_else(|_| Err("扫描统计执行超过 30 分钟时间预算".to_owned()));

    match result {
        Ok(()) => {
            info!(
                event = "AnalyticsSnapshotExecutionCompleted",
                execution_id = %context.execution_id,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "扫描分析快照已更新"
            );
            Ok(true)
        }
        Err(error) => {
            warn!(event = "AnalyticsSnapshotExecutionFailed", execution_id = %context.execution_id,
                elapsed_ms = started.elapsed().as_millis() as u64, message = %error,
                "执行统计失败，保留已有统计并安排重试");
            fail_execution(pool, &context, &error).await?;
            Err(error)
        }
    }
}

async fn claim_execution(pool: &Pool) -> Result<Option<ExecutionContext>, String> {
    let mut connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let locked = transaction
        .query_one("SELECT pg_try_advisory_xact_lock($1);", &[&WORKER_LOCK_KEY])
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?
        .get::<_, bool>(0);
    if !locked {
        transaction
            .commit()
            .await
            .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
        return Ok(None);
    }

    let row = transaction
        .query_opt(
            "WITH candidate AS ( \
            SELECT o.execution_id FROM analytics_outbox o \
            WHERE (o.status = 'pending' AND o.available_at <= NOW()) \
               OR (o.status = 'running' AND o.locked_at < NOW() - INTERVAL '60 minutes') \
            ORDER BY EXISTS (SELECT 1 FROM analytics_snapshot_build_execution b WHERE b.execution_id = o.execution_id) DESC, \
                o.available_at, o.execution_id FOR UPDATE SKIP LOCKED LIMIT 1 \
         ), claimed AS ( \
            UPDATE analytics_outbox o SET status = 'running', attempts = attempts + 1, \
                locked_at = clock_timestamp(), updated_at = NOW() \
            FROM candidate WHERE o.execution_id = candidate.execution_id \
            RETURNING o.execution_id, o.locked_at \
         ) \
         SELECT e.id, e.execution_id, t.user_id, \
                COALESCE(e.assigned_scanner_id, e.requested_scanner_id, 'unknown') AS scanner_id, \
                t.task_source, claimed.locked_at, COALESCE(e.result_observation_count, 0) AS expected_observations \
         FROM claimed JOIN scan_task_execution e ON e.id = claimed.execution_id \
         JOIN scan_task t ON t.id = e.task_id;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .commit()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;

    Ok(row.map(|row| ExecutionContext {
        database_id: row.get("id"),
        execution_id: row.get("execution_id"),
        owner_id: row.get("user_id"),
        scanner_id: row.get("scanner_id"),
        task_source: row.get("task_source"),
        locked_at: row.get("locked_at"),
        expected_observations: row.get("expected_observations"),
    }))
}

async fn facts_from_elasticsearch(
    elasticsearch: &ElasticsearchService,
    context: &ExecutionContext,
) -> Result<ExecutionFacts, String> {
    let mut facts = ExecutionFacts::default();
    let mut endpoint_first = BTreeMap::<(String, String, String), DateTime<Utc>>::new();
    let mut ip_first = BTreeMap::<IpAddr, DateTime<Utc>>::new();
    let mut after: Option<Value> = None;
    let mut observed_count = 0_i64;
    loop {
        let mut body = json!({
            "size": 1000,
            "track_total_hits": false,
            "_source": ["kind", "service", "ip_address", "port", "endpoint_id", "observed_at"],
            "query": {"term": {"execution_id": &context.execution_id}},
            "sort": [{"observed_at": {"order": "asc", "format": "epoch_millis"}}, {"observation_key": "asc"}]
        });
        if let Some(after) = after.as_ref() {
            body.as_object_mut()
                .expect("JSON object")
                .insert("search_after".to_owned(), after.clone());
        }
        let response = elasticsearch
            .scan_query(ScanQueryIndex::Observations, &body)
            .await?;
        let hits = response
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| "Elasticsearch 扫描统计响应缺少 hits".to_owned())?;
        for hit in hits {
            observed_count += 1;
            let source = hit
                .pointer("/_source")
                .ok_or_else(|| "Elasticsearch 统计文档缺少 _source".to_owned())?;
            let observed_at = source
                .get("observed_at")
                .and_then(Value::as_i64)
                .ok_or_else(|| "Elasticsearch 统计文档缺少 observed_at".to_owned())?;
            let timestamp = DateTime::<Utc>::from_timestamp_millis(observed_at)
                .ok_or_else(|| "Elasticsearch 统计文档 observed_at 无效".to_owned())?;
            let ip = source
                .get("ip_address")
                .and_then(Value::as_str)
                .ok_or_else(|| "Elasticsearch 统计文档缺少 ip_address".to_owned())?;
            let ip_address = ip.parse::<IpAddr>().map_err(|error| {
                format!("Elasticsearch 统计文档 ip_address 无效（{ip}）：{error}")
            })?;
            let port = source
                .get("port")
                .and_then(Value::as_i64)
                .ok_or_else(|| "Elasticsearch 统计文档缺少 port".to_owned())?;
            let endpoint = source
                .get("endpoint_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{ip}:{port}"));
            update_first(
                &mut endpoint_first,
                ("port".to_owned(), port.to_string(), endpoint.clone()),
                timestamp,
            );
            if source.get("kind").and_then(Value::as_str) == Some("service")
                && let Some(service) = source.get("service").and_then(Value::as_str)
            {
                let label = service.trim().to_lowercase();
                if !label.is_empty() {
                    update_first(
                        &mut endpoint_first,
                        ("service".to_owned(), label, endpoint),
                        timestamp,
                    );
                }
            }
            update_first(&mut ip_first, ip_address, timestamp);
        }
        let next = hits.last().and_then(|hit| hit.get("sort")).cloned();
        if hits.len() == 1000 && (next.is_none() || next == after) {
            return Err("Elasticsearch 统计分页游标缺失或未推进".to_owned());
        }
        after = next;
        if hits.len() < 1000 {
            break;
        }
    }
    if observed_count < context.expected_observations {
        return Err(format!(
            "Elasticsearch 统计数据尚未完整可见：预期至少 {} 条观察，实际读取 {observed_count} 条",
            context.expected_observations
        ));
    }
    for ((dimension, label, _endpoint), first_observed_at) in endpoint_first {
        *facts
            .distribution
            .entry((bucket_start(first_observed_at), dimension, label))
            .or_default() += 1;
    }
    for (ip, first_observed_at) in ip_first {
        facts
            .discovery
            .insert((shanghai_day(first_observed_at), ip));
    }
    Ok(facts)
}

fn update_first<K: Ord>(values: &mut BTreeMap<K, DateTime<Utc>>, key: K, timestamp: DateTime<Utc>) {
    values
        .entry(key)
        .and_modify(|current| *current = (*current).min(timestamp))
        .or_insert(timestamp);
}

async fn replace_execution_facts(
    pool: &Pool,
    context: &ExecutionContext,
    facts: ExecutionFacts,
) -> Result<(), String> {
    let mut connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    // Serialize publication with cohort creation. Fence an expired/replaced claim
    // before touching facts, including when an upload requeues this execution.
    transaction
        .query_one(
            "SELECT singleton FROM analytics_snapshot_build FOR UPDATE;",
            &[],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    if transaction
        .query_opt(
            "SELECT execution_id FROM analytics_outbox \
         WHERE execution_id = $1 AND status = 'running' AND locked_at = $2 FOR UPDATE;",
            &[&context.database_id, &context.locked_at],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?
        .is_none()
    {
        return Err("扫描统计任务已被重新排队，丢弃过期计算结果".to_owned());
    }
    transaction
        .execute(
            "DELETE FROM analytics_distribution_30m WHERE execution_id = $1;",
            &[&context.database_id],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .execute(
            "DELETE FROM analytics_discovery_fact WHERE execution_id = $1;",
            &[&context.database_id],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    let mut distribution = facts.distribution.into_iter();
    loop {
        let batch = distribution
            .by_ref()
            .take(WRITE_BATCH_SIZE)
            .map(|((bucket_start, dimension, label), endpoint_count)| {
                json!({
                    "bucket_start": bucket_start, "dimension": dimension,
                    "label": label, "endpoint_count": endpoint_count
                })
            })
            .collect::<Vec<_>>();
        if batch.is_empty() {
            break;
        }
        transaction.execute(
            "INSERT INTO analytics_distribution_30m \
             (execution_id, owner_id, scanner_id, task_source, bucket_start, dimension, label, endpoint_count) \
             SELECT $1, $2, $3, $4, x.bucket_start, x.dimension, x.label, x.endpoint_count \
             FROM jsonb_to_recordset($5::JSONB) AS x(bucket_start TIMESTAMPTZ, dimension TEXT, label TEXT, endpoint_count BIGINT);",
            &[&context.database_id, &context.owner_id, &context.scanner_id, &context.task_source,
              &postgres_types::Json(json!(batch))],
        ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    }
    let mut discovery = facts.discovery.into_iter();
    loop {
        let batch = discovery
            .by_ref()
            .take(WRITE_BATCH_SIZE)
            .map(
                |(day_start, ip_address)| json!({"day_start": day_start, "ip_address": ip_address}),
            )
            .collect::<Vec<_>>();
        if batch.is_empty() {
            break;
        }
        transaction
            .execute(
                "INSERT INTO analytics_discovery_fact \
             (execution_id, owner_id, scanner_id, task_source, day_start, ip_address) \
             SELECT $1, $2, $3, $4, x.day_start, x.ip_address \
             FROM jsonb_to_recordset($5::JSONB) AS x(day_start DATE, ip_address INET);",
                &[
                    &context.database_id,
                    &context.owner_id,
                    &context.scanner_id,
                    &context.task_source,
                    &postgres_types::Json(json!(batch)),
                ],
            )
            .await
            .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    }
    // Facts and task completion commit together: a failed write cannot strand a
    // running task or publish a watermark for uncommitted facts.
    transaction.execute(
        "UPDATE analytics_outbox SET status = 'completed', completed_at = NOW(), locked_at = NULL, \
         updated_at = NOW(), last_error = NULL WHERE execution_id = $1;",
        &[&context.database_id],
    ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    transaction
        .execute(
            "DELETE FROM analytics_snapshot_build_execution WHERE execution_id = $1;",
            &[&context.database_id],
        )
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    publish_build(&transaction).await?;
    transaction
        .commit()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    Ok(())
}

async fn fail_execution(
    pool: &Pool,
    context: &ExecutionContext,
    message: &str,
) -> Result<(), String> {
    let connection = pool
        .get()
        .await
        .map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    connection.execute(
        "UPDATE analytics_outbox SET status = 'pending', available_at = NOW() + INTERVAL '5 minutes', \
         locked_at = NULL, updated_at = NOW(), last_error = LEFT($2, 2000) \
         WHERE execution_id = $1 AND status = 'running' AND locked_at = $3;",
        &[&context.database_id, &message, &context.locked_at],
    ).await.map_err(|error| crate::logs::write::error_chain_diagnostics(&error))?;
    Ok(())
}

fn bucket_start(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    timestamp
        .with_minute((timestamp.minute() / 30) * 30)
        .expect("valid minute")
        .with_second(0)
        .expect("valid second")
        .with_nanosecond(0)
        .expect("valid nanosecond")
}

fn shanghai_day(timestamp: DateTime<Utc>) -> NaiveDate {
    timestamp
        .with_timezone(&FixedOffset::east_opt(8 * 60 * 60).expect("valid UTC+8 offset"))
        .date_naive()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn aligns_buckets_to_half_hour_boundaries() {
        let timestamp = Utc.with_ymd_and_hms(2026, 9, 1, 10, 47, 12).unwrap();
        assert_eq!(
            bucket_start(timestamp),
            Utc.with_ymd_and_hms(2026, 9, 1, 10, 30, 0).unwrap()
        );
    }

    #[test]
    fn backlog_is_drained_without_waiting_for_reconciliation_interval() {
        assert_eq!(worker_delay(true), Duration::from_secs(1));
        assert_eq!(worker_delay(false), Duration::from_secs(5));
    }

    /// Uses only connection-local temporary tables, never application tables.
    #[tokio::test]
    #[ignore = "requires ANALYTICS_TEST_DATABASE_URL pointing at a disposable PostgreSQL instance"]
    async fn postgres_backfill_publication_retry_and_batch_writes() {
        let config: tokio_postgres::Config = std::env::var("ANALYTICS_TEST_DATABASE_URL")
            .expect("test database URL")
            .parse()
            .unwrap();
        let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
        let pool = Pool::builder(manager).max_size(1).build().unwrap();
        let client = pool.get().await.unwrap();
        client.batch_execute(
            "SET search_path TO pg_temp; \
             CREATE TEMP TABLE scan_task(id INT PRIMARY KEY, user_id INT, task_source TEXT, task_kind TEXT); \
             CREATE TEMP TABLE scan_task_execution(id INT PRIMARY KEY, execution_id TEXT, task_id INT, \
                 execution_status TEXT, assigned_scanner_id TEXT, requested_scanner_id TEXT, result_observation_count BIGINT); \
             INSERT INTO scan_task VALUES (1, 1, 'manual', 'ip'); \
             INSERT INTO scan_task_execution VALUES (1, 'one', 1, 'succeeded', 'scanner', NULL, 0), \
                 (2, 'two', 1, 'succeeded', 'scanner', NULL, 0);"
        ).await.unwrap();
        let schema = include_str!("../source/database/init.sql");
        let start = schema
            .find("CREATE TABLE IF NOT EXISTS analytics_outbox")
            .unwrap();
        let end = schema[start..].find("-- 表 session").unwrap() + start;
        client
            .batch_execute(&schema[start..end].replace(
                "CREATE TABLE IF NOT EXISTS",
                "CREATE TEMP TABLE IF NOT EXISTS",
            ))
            .await
            .unwrap();
        drop(client);

        reconcile(&pool).await.unwrap();
        let client = pool.get().await.unwrap();
        assert_eq!(snapshot_progress(&client).await.unwrap().remaining, 2);
        assert!(
            snapshot_progress(&client)
                .await
                .unwrap()
                .data_as_of
                .is_none()
        );
        // New arrivals must not grow the active backfill cohort.
        client.batch_execute("INSERT INTO scan_task_execution VALUES (3, 'three', 1, 'succeeded', 'scanner', NULL, 0);").await.unwrap();
        drop(client);
        reconcile(&pool).await.unwrap();
        let first = claim_execution(&pool).await.unwrap().unwrap();
        assert_eq!(first.database_id, 1);
        let timestamp = Utc.with_ymd_and_hms(2026, 9, 1, 10, 30, 0).unwrap();
        let mut facts = ExecutionFacts::default();
        for i in 0..1005 {
            facts
                .distribution
                .insert((timestamp, "service".into(), format!("service-{i}")), 1);
            facts.discovery.insert((
                shanghai_day(timestamp),
                IpAddr::V4(std::net::Ipv4Addr::from(i + 1)),
            ));
        }
        facts
            .discovery
            .insert((shanghai_day(timestamp), "2001:db8::1".parse().unwrap()));
        replace_execution_facts(&pool, &first, facts).await.unwrap();
        let client = pool.get().await.unwrap();
        assert_eq!(
            client
                .query_one("SELECT COUNT(*) FROM analytics_distribution_30m", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1005
        );
        assert_eq!(
            client
                .query_one("SELECT COUNT(*) FROM analytics_discovery_fact", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1006
        );
        assert_eq!(snapshot_progress(&client).await.unwrap().remaining, 1);
        drop(client);

        let second = claim_execution(&pool).await.unwrap().unwrap();
        assert_eq!(second.database_id, 2);
        let mut invalid = ExecutionFacts::default();
        invalid
            .distribution
            .insert((timestamp, "service".into(), "invalid".into()), -1);
        let error = replace_execution_facts(&pool, &second, invalid)
            .await
            .unwrap_err();
        assert!(error.contains("23514")); // retain SQLSTATE and the actual constraint error
        fail_execution(&pool, &second, &error).await.unwrap();
        let client = pool.get().await.unwrap();
        let progress = snapshot_progress(&client).await.unwrap();
        assert_eq!(progress.retrying, 1);
        assert_eq!(progress.failed_execution_id, Some(2));
        assert!(progress.data_as_of.is_none());
        assert_eq!(
            client
                .query_one(
                    "SELECT COUNT(*) FROM analytics_distribution_30m WHERE execution_id = 2",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        client
            .execute(
                "UPDATE analytics_outbox SET available_at = NOW() WHERE execution_id = 2",
                &[],
            )
            .await
            .unwrap();
        drop(client);

        let retry = claim_execution(&pool).await.unwrap().unwrap();
        assert_ne!(retry.locked_at, second.locked_at);
        // A timed-out worker cannot overwrite a newer claim or reset its status.
        assert!(
            replace_execution_facts(&pool, &second, ExecutionFacts::default())
                .await
                .is_err()
        );
        fail_execution(&pool, &second, "stale error").await.unwrap();
        replace_execution_facts(&pool, &retry, ExecutionFacts::default())
            .await
            .unwrap();
        let client = pool.get().await.unwrap();
        let progress = snapshot_progress(&client).await.unwrap();
        assert!(progress.data_as_of.is_some());
        assert_eq!(progress.remaining, 0);
        assert_eq!(progress.pending, 1); // execution 3 never blocked publication
        assert_eq!(progress.retrying, 0);
        let published = progress.data_as_of;
        drop(client);
        reconcile(&pool).await.unwrap();
        let client = pool.get().await.unwrap();
        let progress = snapshot_progress(&client).await.unwrap();
        assert_eq!(progress.remaining, 1);
        assert_eq!(progress.data_as_of, published); // keep the published watermark during the next cohort
        // Empty installations must also become ready without processing a job.
        client.batch_execute("TRUNCATE analytics_snapshot_build_execution, analytics_snapshot_build, analytics_watermark, analytics_outbox, analytics_distribution_30m, analytics_discovery_fact, scan_task_execution CASCADE;").await.unwrap();
        drop(client);
        reconcile(&pool).await.unwrap();
        let client = pool.get().await.unwrap();
        assert!(
            snapshot_progress(&client)
                .await
                .unwrap()
                .data_as_of
                .is_some()
        );
        // Failed writes preserve old aggregates; the only fact reader is ES.
        client.batch_execute(
            "INSERT INTO scan_task_execution VALUES (4, 'four', 1, 'succeeded', 'scanner', NULL, 1); \
             INSERT INTO analytics_distribution_30m VALUES (4, '2026-09-01T10:30:00Z', 1, 'scanner', 'manual', 'service', 'old', 1); \
             ALTER TABLE analytics_distribution_30m ADD CONSTRAINT reject_test_write CHECK (label <> 'fail-write');"
        ).await.unwrap();
        drop(client);
        reconcile(&pool).await.unwrap();
        let context = claim_execution(&pool).await.unwrap().unwrap();
        let make_facts = || {
            let mut facts = ExecutionFacts::default();
            facts.distribution.insert(
                (
                    "2026-09-01T10:30:00Z".parse().unwrap(),
                    "service".into(),
                    "fail-write".into(),
                ),
                1,
            );
            facts
        };
        let error = replace_execution_facts(&pool, &context, make_facts())
            .await
            .unwrap_err();
        fail_execution(&pool, &context, &error).await.unwrap();
        let client = pool.get().await.unwrap();
        let progress = snapshot_progress(&client).await.unwrap();
        assert_eq!(progress.running, 0);
        assert_eq!(progress.retrying, 1);
        assert!(progress.last_error.unwrap().contains("reject_test_write"));
        assert!(progress.data_as_of.is_some());
        assert_eq!(
            client
                .query_one(
                    "SELECT label FROM analytics_distribution_30m WHERE execution_id = 4",
                    &[]
                )
                .await
                .unwrap()
                .get::<_, String>(0),
            "old"
        );
        client.batch_execute("ALTER TABLE analytics_distribution_30m DROP CONSTRAINT reject_test_write; UPDATE analytics_outbox SET available_at = NOW() WHERE execution_id = 4;").await.unwrap();
        drop(client);
        let context = claim_execution(&pool).await.unwrap().unwrap();
        replace_execution_facts(&pool, &context, make_facts())
            .await
            .unwrap();
        let client = pool.get().await.unwrap();
        assert_eq!(snapshot_progress(&client).await.unwrap().remaining, 0);
    }
}
