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
use serde_json::{Value, json};
use tokio::time::Duration;
use tracing::{info, warn};

use crate::config::AnalyticsSnapshotConfig;
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::runtime_config::RuntimeConfig;

const WORKER_LOCK_KEY: i64 = 0x4e4d_4153_4e50_0001;
const MAX_EXECUTIONS_PER_TICK: usize = 100;

#[derive(Clone, Debug)]
struct ExecutionContext {
    database_id: i32,
    execution_id: String,
    owner_id: i32,
    scanner_id: String,
    task_source: String,
}

#[derive(Default)]
struct ExecutionFacts {
    distribution: BTreeMap<(DateTime<Utc>, String, String), i64>,
    discovery: BTreeSet<(NaiveDate, IpAddr)>,
}

/// Starts the worker only in `shadow` or `snapshot` mode. Realtime is deliberately the default
/// for an upgraded installation, preventing a switch to empty statistics before backfill.
pub async fn run_worker(
    config: RuntimeConfig<AnalyticsSnapshotConfig>,
    pool: Pool,
    elasticsearch: ElasticsearchService,
) {
    let mut changes = config.subscribe();
    loop {
        let settings = config.get().await.value;
        if !settings.mode.runs_worker() {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                changed = changes.changed() => if changed.is_err() { return; }
            }
            continue;
        }
        for _ in 0..MAX_EXECUTIONS_PER_TICK {
            match process_one(&pool, &elasticsearch).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    warn!(event = "AnalyticsSnapshotWorkerError", message = %error);
                    // The failed execution is delayed by fail_execution; continue draining
                    // independent work so one legacy/corrupt execution cannot block upgrades.
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(settings.interval_minutes * 60)) => {}
            changed = changes.changed() => if changed.is_err() { return; }
        }
    }
}

/// Rebuilds all completed IP-scan executions. The operation only replaces compact analytics
/// facts; it never alters scan observations or task results. It is intentionally explicit so an
/// upgraded installation can finish historical backfill before selecting `mode = "snapshot"`.
pub async fn rebuild_all(pool: &Pool, elasticsearch: &ElasticsearchService) -> Result<u64, String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    connection
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
        .map_err(|error| error.to_string())?;
    connection
        .execute(
            "DELETE FROM analytics_watermark WHERE watermark_key = 'scan_analysis';",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?;

    let mut processed = 0_u64;
    while process_one(pool, elasticsearch).await? {
        processed += 1;
    }
    Ok(processed)
}

async fn process_one(pool: &Pool, elasticsearch: &ElasticsearchService) -> Result<bool, String> {
    let Some(context) = claim_execution(pool).await? else {
        return Ok(false);
    };
    let started_at = Utc::now();
    let facts = if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        facts_from_elasticsearch(elasticsearch, &context).await
    } else {
        facts_from_postgres(pool, &context).await
    };

    match facts {
        Ok(facts) => {
            replace_execution_facts(pool, &context, facts).await?;
            complete_execution(pool, context.database_id, started_at).await?;
            info!(
                event = "AnalyticsSnapshotExecutionCompleted",
                execution_id = %context.execution_id,
                "扫描分析快照已更新"
            );
            Ok(true)
        }
        Err(error) => {
            fail_execution(pool, context.database_id, &error).await?;
            Err(error)
        }
    }
}

async fn claim_execution(pool: &Pool) -> Result<Option<ExecutionContext>, String> {
    let mut connection = pool.get().await.map_err(|error| error.to_string())?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let locked = transaction
        .query_one("SELECT pg_try_advisory_xact_lock($1);", &[&WORKER_LOCK_KEY])
        .await
        .map_err(|error| error.to_string())?
        .get::<_, bool>(0);
    if !locked {
        transaction
            .commit()
            .await
            .map_err(|error| error.to_string())?;
        return Ok(None);
    }

    // This reconciliation is intentional: older server binaries did not create outbox rows.
    transaction
        .execute(
            "INSERT INTO analytics_outbox (execution_id, status, available_at) \
         SELECT e.id, 'pending', NOW() FROM scan_task_execution e \
         JOIN scan_task t ON t.id = e.task_id \
         WHERE e.execution_status = 'succeeded' AND t.task_kind = 'ip' \
         ON CONFLICT (execution_id) DO NOTHING;",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?;

    let row = transaction
        .query_opt(
            "WITH candidate AS ( \
            SELECT o.execution_id FROM analytics_outbox o \
            WHERE (o.status = 'pending' AND o.available_at <= NOW()) \
               OR (o.status = 'running' AND o.locked_at < NOW() - INTERVAL '60 minutes') \
            ORDER BY o.available_at, o.execution_id FOR UPDATE SKIP LOCKED LIMIT 1 \
         ), claimed AS ( \
            UPDATE analytics_outbox o SET status = 'running', attempts = attempts + 1, \
                locked_at = NOW(), updated_at = NOW(), last_error = NULL \
            FROM candidate WHERE o.execution_id = candidate.execution_id \
            RETURNING o.execution_id \
         ) \
         SELECT e.id, e.execution_id, t.user_id, \
                COALESCE(e.assigned_scanner_id, e.requested_scanner_id, 'unknown') AS scanner_id, \
                t.task_source \
         FROM claimed JOIN scan_task_execution e ON e.id = claimed.execution_id \
         JOIN scan_task t ON t.id = e.task_id;",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;

    Ok(row.map(|row| ExecutionContext {
        database_id: row.get("id"),
        execution_id: row.get("execution_id"),
        owner_id: row.get("user_id"),
        scanner_id: row.get("scanner_id"),
        task_source: row.get("task_source"),
    }))
}

async fn facts_from_postgres(
    pool: &Pool,
    context: &ExecutionContext,
) -> Result<ExecutionFacts, String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    let mut facts = ExecutionFacts::default();
    for (dimension, sql) in [
        (
            "service",
            "SELECT bucket_start, label, endpoint_count FROM ( \
            SELECT date_trunc('hour', first_observed_at) + \
                (FLOOR(EXTRACT(MINUTE FROM first_observed_at) / 30) * INTERVAL '30 minutes') AS bucket_start, \
                label, COUNT(*)::BIGINT AS endpoint_count FROM ( \
                    SELECT ip_address, port, LOWER(BTRIM(service)) AS label, MIN(observed_at) AS first_observed_at \
                    FROM scan_observation WHERE execution_id = $1 AND kind = 'service' \
                        AND service IS NOT NULL AND BTRIM(service) <> '' \
                    GROUP BY ip_address, port, LOWER(BTRIM(service)) \
                ) representative GROUP BY bucket_start, label \
            ) grouped ORDER BY bucket_start, label",
        ),
        (
            "port",
            "SELECT bucket_start, label, endpoint_count FROM ( \
            SELECT date_trunc('hour', first_observed_at) + \
                (FLOOR(EXTRACT(MINUTE FROM first_observed_at) / 30) * INTERVAL '30 minutes') AS bucket_start, \
                port::TEXT AS label, COUNT(*)::BIGINT AS endpoint_count FROM ( \
                    SELECT ip_address, port, MIN(observed_at) AS first_observed_at \
                    FROM scan_observation WHERE execution_id = $1 \
                    GROUP BY ip_address, port \
                ) representative GROUP BY bucket_start, port \
            ) grouped ORDER BY bucket_start, label",
        ),
    ] {
        for row in connection
            .query(sql, &[&context.database_id])
            .await
            .map_err(|error| error.to_string())?
        {
            facts.distribution.insert(
                (
                    row.get("bucket_start"),
                    dimension.to_owned(),
                    row.get("label"),
                ),
                row.get("endpoint_count"),
            );
        }
    }
    let rows = connection
        .query(
            "SELECT ((MIN(observed_at) AT TIME ZONE 'Asia/Shanghai')::DATE) AS day_start, \
                ip_address FROM scan_observation \
         WHERE execution_id = $1 GROUP BY ip_address ORDER BY day_start, ip_address;",
            &[&context.database_id],
        )
        .await
        .map_err(|error| error.to_string())?;
    for row in rows {
        facts
            .discovery
            .insert((row.get("day_start"), row.get("ip_address")));
    }
    Ok(facts)
}

async fn facts_from_elasticsearch(
    elasticsearch: &ElasticsearchService,
    context: &ExecutionContext,
) -> Result<ExecutionFacts, String> {
    let mut facts = ExecutionFacts::default();
    let mut endpoint_first = BTreeMap::<(String, String, String), DateTime<Utc>>::new();
    let mut ip_first = BTreeMap::<IpAddr, DateTime<Utc>>::new();
    let mut after: Option<Value> = None;
    loop {
        let mut body = json!({
            "size": 1000,
            "_source": ["kind", "service", "ip_address", "port", "endpoint_id", "observed_at"],
            "query": {"term": {"execution_id": &context.execution_id}},
            "sort": [{"observed_at": {"order": "asc", "format": "epoch_millis"}}, {"observation_key": "asc"}]
        });
        if let Some(after) = after.take() {
            body.as_object_mut()
                .expect("JSON object")
                .insert("search_after".to_owned(), after);
        }
        let response = elasticsearch
            .scan_query(ScanQueryIndex::Observations, &body)
            .await?;
        let hits = response
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| "Elasticsearch 扫描统计响应缺少 hits".to_owned())?;
        for hit in hits {
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
        after = hits.last().and_then(|hit| hit.get("sort")).cloned();
        if hits.len() < 1000 || after.is_none() {
            break;
        }
    }
    let mut endpoints = BTreeMap::<(DateTime<Utc>, String, String), BTreeSet<String>>::new();
    for ((dimension, label, endpoint), first_observed_at) in endpoint_first {
        endpoints
            .entry((bucket_start(first_observed_at), dimension, label))
            .or_default()
            .insert(endpoint);
    }
    for (key, values) in endpoints {
        facts.distribution.insert(key, values.len() as i64);
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
    let mut connection = pool.get().await.map_err(|error| error.to_string())?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "DELETE FROM analytics_distribution_30m WHERE execution_id = $1;",
            &[&context.database_id],
        )
        .await
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "DELETE FROM analytics_discovery_fact WHERE execution_id = $1;",
            &[&context.database_id],
        )
        .await
        .map_err(|error| error.to_string())?;
    for ((bucket_start, dimension, label), endpoint_count) in facts.distribution {
        transaction.execute(
            "INSERT INTO analytics_distribution_30m \
             (execution_id, bucket_start, owner_id, scanner_id, task_source, dimension, label, endpoint_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8);",
            &[&context.database_id, &bucket_start, &context.owner_id, &context.scanner_id,
              &context.task_source, &dimension, &label, &endpoint_count],
        ).await.map_err(|error| error.to_string())?;
    }
    for (day_start, ip_address) in facts.discovery {
        transaction
            .execute(
                "INSERT INTO analytics_discovery_fact \
             (execution_id, day_start, owner_id, scanner_id, task_source, ip_address) \
             VALUES ($1, $2, $3, $4, $5, $6::INET);",
                &[
                    &context.database_id,
                    &day_start,
                    &context.owner_id,
                    &context.scanner_id,
                    &context.task_source,
                    &ip_address,
                ],
            )
            .await
            .map_err(|error| error.to_string())?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())
}

async fn complete_execution(
    pool: &Pool,
    execution_id: i32,
    started_at: DateTime<Utc>,
) -> Result<(), String> {
    let mut connection = pool.get().await.map_err(|error| error.to_string())?;
    let transaction = connection
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    transaction.execute(
        "UPDATE analytics_outbox SET status = 'completed', completed_at = NOW(), locked_at = NULL, \
         updated_at = NOW(), last_error = NULL WHERE execution_id = $1;",
        &[&execution_id],
    ).await.map_err(|error| error.to_string())?;
    let complete = transaction.query_one(
        "SELECT NOT EXISTS (SELECT 1 FROM analytics_outbox WHERE status <> 'completed') AS complete;", &[]
    ).await.map_err(|error| error.to_string())?.get::<_, bool>("complete");
    if complete {
        transaction
            .execute(
                "INSERT INTO analytics_watermark (watermark_key, data_as_of, updated_at) \
             VALUES ('scan_analysis', $1, NOW()) ON CONFLICT (watermark_key) DO UPDATE \
             SET data_as_of = EXCLUDED.data_as_of, updated_at = NOW();",
                &[&started_at],
            )
            .await
            .map_err(|error| error.to_string())?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn fail_execution(pool: &Pool, execution_id: i32, message: &str) -> Result<(), String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    connection.execute(
        "UPDATE analytics_outbox SET status = 'pending', available_at = NOW() + INTERVAL '5 minutes', \
         locked_at = NULL, updated_at = NOW(), last_error = LEFT($2, 2000) WHERE execution_id = $1;",
        &[&execution_id, &message],
    ).await.map_err(|error| error.to_string())?;
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
    use super::bucket_start;
    use chrono::{TimeZone, Utc};

    #[test]
    fn aligns_buckets_to_half_hour_boundaries() {
        let timestamp = Utc.with_ymd_and_hms(2026, 9, 1, 10, 47, 12).unwrap();
        assert_eq!(
            bucket_start(timestamp),
            Utc.with_ymd_and_hms(2026, 9, 1, 10, 30, 0).unwrap()
        );
    }
}
