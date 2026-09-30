use deadpool_postgres::GenericClient;
use serde_json::{Value, json};
use uuid::Uuid;

use super::period::{Period, TIMEZONE, growth};

pub async fn tasks<C: GenericClient + Sync>(client: &C, period: &Period) -> Result<Value, String> {
    let row = client.query_one(
        "SELECT jsonb_build_object('created', COUNT(*) FILTER (WHERE task_create_time >= $1 AND task_create_time < $2), \
         'succeeded', COUNT(*) FILTER (WHERE task_status = 'succeeded' AND task_end_time >= $1 AND task_end_time < $2), \
         'failed', COUNT(*) FILTER (WHERE task_status = 'failed' AND task_end_time >= $1 AND task_end_time < $2), \
         'partial', COUNT(*) FILTER (WHERE task_status = 'partial' AND task_end_time >= $1 AND task_end_time < $2), \
         'cancelled', COUNT(*) FILTER (WHERE task_status = 'cancelled' AND task_end_time >= $1 AND task_end_time < $2)) AS data \
         FROM scan_task WHERE (task_create_time >= $1 AND task_create_time < $2) OR (task_end_time >= $1 AND task_end_time < $2);",
        &[&period.start.timestamp_millis(), &period.end.timestamp_millis()]).await.map_err(|e| e.to_string())?;
    let mut data: Value = row.get("data");
    let succeeded = data["succeeded"].as_i64().unwrap_or(0);
    let denominator =
        succeeded + data["failed"].as_i64().unwrap_or(0) + data["partial"].as_i64().unwrap_or(0);
    data["success_rate"] = if denominator > 0 {
        json!((succeeded as f64 / denominator as f64 * 1000.0).round() / 10.0)
    } else {
        Value::Null
    };
    Ok(data)
}

pub async fn capture<C: GenericClient + Sync>(
    client: &C,
    period: &Period,
) -> Result<Value, String> {
    let current = tasks(client, period).await?;
    let previous = tasks(client, &period.previous()?).await?;
    let start = period.start.timestamp_millis();
    let end = period.end.timestamp_millis();
    let rows = client.query(
        "SELECT COALESCE(s.name, e.assigned_scanner_id, '未分配') AS name, e.assigned_scanner_id AS scanner_id, \
         COUNT(*)::BIGINT AS total, COUNT(*) FILTER (WHERE e.execution_status = 'succeeded')::BIGINT AS succeeded, \
         COUNT(*) FILTER (WHERE e.execution_status = 'failed')::BIGINT AS failed, \
         COUNT(*) FILTER (WHERE e.execution_status = 'cancelled')::BIGINT AS cancelled, \
         COALESCE(AVG(e.task_end_time - e.task_start_time) FILTER (WHERE e.execution_status = 'succeeded' AND e.task_end_time >= e.task_start_time), 0)::FLOAT8 AS avg_duration_ms, \
         COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY (e.task_end_time - e.task_start_time)::FLOAT8) \
            FILTER (WHERE e.execution_status = 'succeeded' AND e.task_end_time >= e.task_start_time), 0)::FLOAT8 AS p50_ms, \
         COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY (e.task_end_time - e.task_start_time)::FLOAT8) \
            FILTER (WHERE e.execution_status = 'succeeded' AND e.task_end_time >= e.task_start_time), 0)::FLOAT8 AS p95_ms \
         FROM scan_task_execution e LEFT JOIN scanner_info s ON s.scanner_id = e.assigned_scanner_id \
         WHERE e.task_end_time >= $1 AND e.task_end_time < $2 \
           AND e.execution_status IN ('succeeded', 'failed', 'cancelled', 'partial') \
         GROUP BY s.name, e.assigned_scanner_id ORDER BY total DESC, name;", &[&start, &end]).await.map_err(|e| e.to_string())?;
    let scanners: Vec<Value> = rows.iter().map(|r| json!({
        "name": r.get::<_, String>("name"), "scanner_id": r.get::<_, Option<String>>("scanner_id"),
        "total": r.get::<_, i64>("total"), "succeeded": r.get::<_, i64>("succeeded"), "failed": r.get::<_, i64>("failed"),
        "cancelled": r.get::<_, i64>("cancelled"), "avg_duration_ms": r.get::<_, f64>("avg_duration_ms"),
        "p50_ms": r.get::<_, f64>("p50_ms"), "p95_ms": r.get::<_, f64>("p95_ms")
    })).collect();
    let rows = client.query(
        "SELECT to_char(d.day, 'YYYY-MM-DD') AS day, \
         COUNT(t.id) FILTER (WHERE t.task_status = 'succeeded')::BIGINT AS succeeded, \
         COUNT(t.id) FILTER (WHERE t.task_status = 'failed')::BIGINT AS failed, \
         COUNT(t.id) FILTER (WHERE t.task_status = 'partial')::BIGINT AS partial, \
         COUNT(t.id) FILTER (WHERE t.task_status = 'cancelled')::BIGINT AS cancelled \
         FROM generate_series(($1::TIMESTAMPTZ AT TIME ZONE 'Asia/Shanghai')::DATE::TIMESTAMP, \
              ($2::TIMESTAMPTZ AT TIME ZONE 'Asia/Shanghai')::DATE::TIMESTAMP - INTERVAL '1 day', INTERVAL '1 day') d(day) \
         LEFT JOIN scan_task t ON t.task_end_time >= $3 AND t.task_end_time < $4 \
              AND (to_timestamp(t.task_end_time / 1000.0) AT TIME ZONE 'Asia/Shanghai')::DATE = d.day::DATE \
         GROUP BY d.day ORDER BY d.day;", &[&period.start, &period.end, &start, &end]).await.map_err(|e| e.to_string())?;
    let trend: Vec<Value> = rows.iter().map(|r| json!({"day": r.get::<_, String>("day"), "succeeded": r.get::<_, i64>("succeeded"),
        "failed": r.get::<_, i64>("failed"), "partial": r.get::<_, i64>("partial"), "cancelled": r.get::<_, i64>("cancelled")})).collect();
    let prior_history: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM scan_task WHERE task_create_time < $1) AS present;",
            &[&period.start.timestamp_millis()],
        )
        .await
        .map_err(|e| e.to_string())?
        .get("present");
    Ok(
        json!({"current": current, "previous": previous, "scanners": scanners, "trend": trend, "previous_has_history": prior_history}),
    )
}

pub async fn quality<C: GenericClient + Sync>(client: &C, id: Uuid) -> Result<Value, String> {
    let rows = client.query(
        "SELECT i.period_slot, COUNT(*)::BIGINT AS expected, \
         COUNT(*) FILTER (WHERE o.status = 'completed' AND COALESCE(e.result_observation_count, (SELECT SUM(b.observation_count) FROM scan_result_batch b WHERE b.execution_id = e.id), 0) = i.expected_observations)::BIGINT AS ready, \
         COUNT(*) FILTER (WHERE e.id IS NULL)::BIGINT AS deleted \
         FROM report_input_execution i LEFT JOIN scan_task_execution e ON e.id = i.execution_id \
         LEFT JOIN analytics_outbox o ON o.execution_id = i.execution_id \
         WHERE i.report_id = $1 GROUP BY i.period_slot;", &[&id]).await.map_err(|e| e.to_string())?;
    let mut result = json!({"current": {"expected": 0, "ready": 0, "deleted": 0}, "previous": {"expected": 0, "ready": 0, "deleted": 0}});
    for r in rows {
        let slot: String = r.get("period_slot");
        result[slot] = json!({"expected": r.get::<_, i64>("expected"), "ready": r.get::<_, i64>("ready"), "deleted": r.get::<_, i64>("deleted")});
    }
    result["complete"] = json!(result["current"]["expected"] == result["current"]["ready"]);
    Ok(result)
}

pub async fn scan_output<C: GenericClient + Sync>(
    client: &C,
    id: Uuid,
    slot: &str,
) -> Result<Value, String> {
    let distinct: i64 = client.query_one(
        "SELECT COUNT(DISTINCT d.ip_address)::BIGINT AS count FROM analytics_discovery_fact d \
         JOIN report_input_execution i ON i.execution_id = d.execution_id WHERE i.report_id = $1 AND i.period_slot = $2;", &[&id, &slot])
        .await.map_err(|e| e.to_string())?.get("count");
    let rows = client.query(
        "SELECT dimension, label, SUM(endpoint_count)::BIGINT AS count \
         FROM analytics_distribution_30m d JOIN report_input_execution i ON i.execution_id = d.execution_id \
         WHERE i.report_id = $1 AND i.period_slot = $2 GROUP BY dimension, label ORDER BY dimension, count DESC, label;", &[&id, &slot])
        .await.map_err(|e| e.to_string())?;
    let mut ports = Vec::new();
    let mut services = Vec::new();
    let mut port_total = 0_i64;
    let mut service_total = 0_i64;
    for row in rows {
        let dim: String = row.get("dimension");
        let count: i64 = row.get("count");
        let list = if dim == "port" {
            port_total += count;
            &mut ports
        } else {
            service_total += count;
            &mut services
        };
        if list.len() < 10 {
            list.push(json!({"name": row.get::<_, String>("label"), "count": count}));
        }
    }
    Ok(
        json!({"unique_ips": distinct, "port_observations": port_total, "service_observations": service_total, "ports": ports, "services": services}),
    )
}

pub async fn build<C: GenericClient + Sync>(
    client: &C,
    id: Uuid,
    period: &Period,
    snapshot: &Value,
    quality: &Value,
) -> Result<Value, String> {
    let current = scan_output(client, id, "current").await?;
    let previous_available = quality["previous"]["expected"] == quality["previous"]["ready"]
        && snapshot["previous_has_history"] == true;
    let previous = if previous_available {
        scan_output(client, id, "previous").await?
    } else {
        Value::Null
    };
    let days = (period.end - period.start).num_days() as f64;
    let previous_days = (period.previous()?.end - period.previous()?.start).num_days() as f64;
    let rate = snapshot["current"]["success_rate"].as_f64();
    let previous_rate = snapshot["previous"]["success_rate"].as_f64();
    let mut recommendations = Vec::new();
    if snapshot["current"]["failed"].as_i64().unwrap_or(0) > 0 {
        recommendations.push("存在失败任务，请检查任务详情中的失败原因并按需重试。".to_owned());
    }
    if snapshot["current"]["partial"].as_i64().unwrap_or(0) > 0 {
        recommendations.push("存在部分完成任务，请确认各扫描器执行结果及扫描阶段状态。".to_owned());
    }
    if let Some(scanner) = snapshot["scanners"].as_array().and_then(|a| {
        a.iter()
            .filter(|v| v["failed"].as_i64().unwrap_or(0) > 0)
            .max_by_key(|v| v["failed"].as_i64().unwrap_or(0))
    }) {
        recommendations.push(format!(
            "扫描器 {} 有 {} 次失败执行，建议检查网络与扫描配置。",
            scanner["name"].as_str().unwrap_or("未分配"),
            scanner["failed"]
        ));
    }
    let comparison = if previous_available {
        json!({
            "unique_ips_growth_percent": growth(current["unique_ips"].as_f64().unwrap_or(0.0), previous["unique_ips"].as_f64().unwrap_or(0.0)),
            "daily_unique_ips_growth_percent": growth(current["unique_ips"].as_f64().unwrap_or(0.0) / days, previous["unique_ips"].as_f64().unwrap_or(0.0) / previous_days),
            "created_growth_percent": growth(snapshot["current"]["created"].as_f64().unwrap_or(0.0), snapshot["previous"]["created"].as_f64().unwrap_or(0.0)),
            "success_rate_change_points": rate.zip(previous_rate).map(|(a,b)| ((a-b)*10.0).round()/10.0)
        })
    } else {
        Value::Null
    };
    Ok(
        json!({"schema_version": 1, "metric_version": 1, "period": {"type": period.kind, "start_at": period.start, "end_at": period.end, "timezone": TIMEZONE},
        "tasks": snapshot["current"], "previous_tasks": if previous_available { snapshot["previous"].clone() } else { Value::Null },
        "scan_output": current, "previous_scan_output": previous, "previous_available": previous_available, "comparison": comparison,
        "trend": snapshot["trend"], "scanners": snapshot["scanners"], "recommendations": recommendations,
        "notes": ["任务按完成时间归属；扫描结果来自本期成功完成的 IP 扫描执行。", "IP 跨执行去重；端口与服务是跨执行累加的观测次数，不是资产存量。", "统计基于生成时保留的历史；不包含 DNS 结果、资产消失判断和漏洞修复状态。", "月报按自然月独立计算；日均去重 IP 为周期去重 IP 数除以周期天数。"]}),
    )
}
