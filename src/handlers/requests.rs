use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Row};
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::client_ip::display_ip;
use crate::handlers::system_resources::{Granularity, MAX_BUCKETS};
use crate::logs::write::{error_logs, error_logs_error};

#[derive(Deserialize)]
pub struct RequestQuery {
    method: Option<String>,
    path: Option<String>,
    status: Option<i16>,
    error_level: Option<String>,
    error_type: Option<String>,
    reason_code: Option<String>,
    request_id: Option<Uuid>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    only_errors: Option<bool>,
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Deserialize)]
pub struct RequestSummaryQuery {
    method: Option<String>,
    path: Option<String>,
    status: Option<i16>,
    error_level: Option<String>,
    error_type: Option<String>,
    reason_code: Option<String>,
    request_id: Option<Uuid>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    only_errors: Option<bool>,
    /// 预设延迟窗口：`1h` / `24h` / `7d`；提供时覆盖任意 start/end 并启用 P95/P99。
    window: Option<String>,
    /// 趋势分桶粒度：`auto` / `1m` / `5m` / `15m` / `30m` / `1h` / `2h` / `6h`。
    granularity: Option<String>,
}

#[derive(Deserialize)]
pub struct RequestPerformanceQuery {
    window: Option<String>,
    granularity: Option<String>,
    method: Option<String>,
    route: Option<String>,
    status_class: Option<String>,
    limit: Option<i64>,
}

struct PerformanceFilters {
    method: Option<String>,
    route: Option<String>,
    status_class: Option<String>,
}

#[derive(Debug)]
struct PerformanceSummary {
    sample_count: i64,
    avg_ms: Option<f64>,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
    max_ms: Option<f64>,
    error_rate: f64,
    slow_rate: f64,
    policy_slow_rate: f64,
    normalized_coverage: f64,
}

#[derive(Debug)]
struct EventPerformance {
    method: String,
    route_pattern: String,
    normalized: bool,
    sample_count: i64,
    avg_ms: Option<f64>,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
    max_ms: Option<f64>,
}

const PERFORMANCE_DURATION_SQL: &str = "COALESCE(duration_us, duration_ms::BIGINT * 1000)";
const SLOW_REQUEST_US: i64 = 1_000_000;

fn is_admin(user: &UserBaseI) -> bool {
    user.role == 1
}

fn pagination(page: Option<i64>, page_size: Option<i64>) -> (i64, i64) {
    (
        page.unwrap_or(1).max(1),
        page_size.unwrap_or(25).clamp(1, 100),
    )
}

fn request_filter<'a>(
    query: &'a dyn RequestFilter,
    start: &'a Option<DateTime<Utc>>,
    end: &'a Option<DateTime<Utc>>,
) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
    let mut conditions = Vec::new();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
    macro_rules! push_filter {
        ($value:expr, $predicate:expr) => {
            if let Some(value) = $value.as_ref() {
                params.push(value);
                conditions.push(format!($predicate, params.len()));
            }
        };
    }
    push_filter!(query.method(), "http_method = ${}");
    push_filter!(query.path(), "request_path ILIKE '%' || ${} || '%'");
    push_filter!(query.status(), "status_code = ${}");
    push_filter!(query.error_level(), "error_level = ${}");
    push_filter!(query.error_type(), "error_type = ${}");
    push_filter!(query.reason_code(), "reason_code = ${}");
    push_filter!(query.request_id(), "request_id = ${}");
    push_filter!(start, "occurred_at >= ${}");
    push_filter!(end, "occurred_at <= ${}");
    if query.only_errors().is_some() {
        conditions.push("error_level <> 'ok'".to_owned());
    }
    let sql = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    (sql, params)
}

fn add_filter_condition(filter_sql: &str, condition: &str) -> String {
    if filter_sql.is_empty() {
        format!(" WHERE {condition}")
    } else {
        format!("{filter_sql} AND {condition}")
    }
}

fn performance_filter<'a>(
    filters: &'a PerformanceFilters,
    start: &'a DateTime<Utc>,
    end: &'a DateTime<Utc>,
) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
    let mut conditions = Vec::new();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
    if let Some(value) = filters.method.as_ref() {
        params.push(value);
        conditions.push(format!("http_method = ${}", params.len()));
    }
    if let Some(value) = filters.route.as_ref() {
        params.push(value);
        conditions.push(format!(
            "COALESCE(route_pattern, '（历史未标准化）') ILIKE '%' || ${} || '%'",
            params.len()
        ));
    }
    if let Some(condition) = match filters.status_class.as_deref() {
        Some("success") => Some("status_code < 400"),
        Some("4xx") => Some("status_code BETWEEN 400 AND 499"),
        Some("5xx") => Some("status_code BETWEEN 500 AND 599"),
        _ => None,
    } {
        conditions.push(condition.to_owned());
    }
    params.push(start);
    conditions.push(format!("occurred_at >= ${}", params.len()));
    params.push(end);
    conditions.push(format!("occurred_at < ${}", params.len()));
    conditions.push("request_path <> '/api/requests/performance'".to_owned());
    conditions.push(format!("{PERFORMANCE_DURATION_SQL} IS NOT NULL"));
    (format!(" WHERE {}", conditions.join(" AND ")), params)
}

/// 两个查询结构体共享过滤字段的读取接口，避免手写两遍参数列表。
trait RequestFilter {
    fn method(&self) -> &Option<String>;
    fn path(&self) -> &Option<String>;
    fn status(&self) -> &Option<i16>;
    fn error_level(&self) -> &Option<String>;
    fn error_type(&self) -> &Option<String>;
    fn reason_code(&self) -> &Option<String>;
    fn request_id(&self) -> &Option<Uuid>;
    fn only_errors(&self) -> &Option<bool>;
}

impl RequestFilter for RequestQuery {
    fn method(&self) -> &Option<String> {
        &self.method
    }
    fn path(&self) -> &Option<String> {
        &self.path
    }
    fn status(&self) -> &Option<i16> {
        &self.status
    }
    fn error_level(&self) -> &Option<String> {
        &self.error_level
    }
    fn error_type(&self) -> &Option<String> {
        &self.error_type
    }
    fn reason_code(&self) -> &Option<String> {
        &self.reason_code
    }
    fn request_id(&self) -> &Option<Uuid> {
        &self.request_id
    }
    fn only_errors(&self) -> &Option<bool> {
        &self.only_errors
    }
}

impl RequestFilter for RequestSummaryQuery {
    fn method(&self) -> &Option<String> {
        &self.method
    }
    fn path(&self) -> &Option<String> {
        &self.path
    }
    fn status(&self) -> &Option<i16> {
        &self.status
    }
    fn error_level(&self) -> &Option<String> {
        &self.error_level
    }
    fn error_type(&self) -> &Option<String> {
        &self.error_type
    }
    fn reason_code(&self) -> &Option<String> {
        &self.reason_code
    }
    fn request_id(&self) -> &Option<Uuid> {
        &self.request_id
    }
    fn only_errors(&self) -> &Option<bool> {
        &self.only_errors
    }
}

fn window_range(window: Option<&str>) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let now = Utc::now();
    match window {
        Some("1h") => Some((now - chrono::Duration::hours(1), now)),
        Some("24h") => Some((now - chrono::Duration::days(1), now)),
        Some("7d") => Some((now - chrono::Duration::days(7), now)),
        _ => None,
    }
}

fn performance_window(window: Option<&str>) -> Result<chrono::Duration, &'static str> {
    match window.unwrap_or("24h") {
        "1h" => Ok(chrono::Duration::hours(1)),
        "24h" => Ok(chrono::Duration::days(1)),
        "7d" => Ok(chrono::Duration::days(7)),
        _ => Err("performance window must be one of: 1h, 24h, 7d"),
    }
}

fn clean_filter(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn metric_delta(current: Option<f64>, baseline: Option<f64>) -> (Option<f64>, Option<f64>) {
    match (current, baseline) {
        (Some(current), Some(baseline)) if baseline > 0.0 => (
            Some(current - baseline),
            Some((current - baseline) / baseline),
        ),
        (Some(current), Some(baseline)) => (Some(current - baseline), None),
        _ => (None, None),
    }
}

fn performance_summary_value(summary: &PerformanceSummary) -> Value {
    json!({
        "sample_count": summary.sample_count,
        "avg_ms": summary.avg_ms,
        "p50_ms": summary.p50_ms,
        "p95_ms": summary.p95_ms,
        "p99_ms": summary.p99_ms,
        "max_ms": summary.max_ms,
        "error_rate": summary.error_rate,
        "slow_rate": summary.slow_rate,
        "policy_slow_rate": summary.policy_slow_rate,
        "normalized_coverage": summary.normalized_coverage,
    })
}

fn performance_summary_from_row(row: Row) -> PerformanceSummary {
    PerformanceSummary {
        sample_count: row.get("sample_count"),
        avg_ms: row.get("avg_ms"),
        p50_ms: row.get("p50_ms"),
        p95_ms: row.get("p95_ms"),
        p99_ms: row.get("p99_ms"),
        max_ms: row.get("max_ms"),
        error_rate: row.get("error_rate"),
        slow_rate: row.get("slow_rate"),
        policy_slow_rate: row.get("policy_slow_rate"),
        normalized_coverage: row.get("normalized_coverage"),
    }
}

async fn query_performance_summary(
    client: &Client,
    filters: &PerformanceFilters,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    policy: &crate::config::MonitorConfig,
) -> Result<PerformanceSummary, tokio_postgres::Error> {
    use crate::monitor::rules::MonitorService;
    let (filter_sql, mut params) = performance_filter(filters, &start, &end);
    let operation_rules = serde_json::to_value(
        policy
            .operation_rules
            .iter()
            .filter(|item| item.service == MonitorService::WebApi)
            .collect::<Vec<_>>(),
    )
    .expect("serializable slow-operation rules");
    let default_rule = policy.default_rule(MonitorService::WebApi);
    let defaults = serde_json::to_value(&default_rule).expect("serializable default rule");
    params.push(&operation_rules);
    let operations_param = params.len();
    params.push(&defaults);
    let defaults_param = params.len();
    let monitor_enabled = policy.enabled;
    params.push(&monitor_enabled);
    let enabled_param = params.len();
    let sql = format!(
        "SELECT COUNT(*)::BIGINT AS sample_count, \
                AVG(({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS avg_ms, \
                percentile_cont(0.50) WITHIN GROUP (ORDER BY ({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS p50_ms, \
                percentile_cont(0.95) WITHIN GROUP (ORDER BY ({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS p95_ms, \
                percentile_cont(0.99) WITHIN GROUP (ORDER BY ({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS p99_ms, \
                MAX({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION / 1000.0 AS max_ms, \
                COALESCE(COUNT(*) FILTER (WHERE status_code >= 400)::DOUBLE PRECISION / NULLIF(COUNT(*), 0), 0) AS error_rate, \
                COALESCE(COUNT(*) FILTER (WHERE {PERFORMANCE_DURATION_SQL} >= {SLOW_REQUEST_US})::DOUBLE PRECISION / NULLIF(COUNT(*), 0), 0) AS slow_rate, \
                COALESCE(COUNT(*) FILTER (WHERE ${enabled_param}::boolean AND COALESCE((policy_rule.rule->>'enabled')::boolean, (${defaults_param}::jsonb->>'enabled')::boolean) \
                    AND {PERFORMANCE_DURATION_SQL} >= COALESCE((policy_rule.rule->>'warning_threshold_ms')::bigint, (${defaults_param}::jsonb->>'warning_threshold_ms')::bigint) * 1000)::DOUBLE PRECISION / NULLIF(COUNT(*), 0), 0) AS policy_slow_rate, \
                COALESCE(COUNT(*) FILTER (WHERE route_pattern IS NOT NULL)::DOUBLE PRECISION / NULLIF(COUNT(*), 0), 0) AS normalized_coverage \
         FROM request_log LEFT JOIN jsonb_to_recordset(${operations_param}::jsonb) AS policy_rule(operation TEXT, rule JSONB) \
         ON policy_rule.operation = http_method || ' ' || route_pattern{filter_sql}"
    );
    client
        .query_one(&sql, &params)
        .await
        .map(performance_summary_from_row)
}

async fn query_performance_trend(
    client: &Client,
    filters: &PerformanceFilters,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    bucket_seconds: i64,
) -> Result<Vec<Value>, tokio_postgres::Error> {
    let (filter_sql, mut params) = performance_filter(filters, &start, &end);
    let bucket_index = params.len() + 1;
    let sql = format!(
        "SELECT to_timestamp((EXTRACT(EPOCH FROM occurred_at)::BIGINT / ${bucket_index}::BIGINT) * ${bucket_index}::BIGINT) AS bucket, \
                COUNT(*)::BIGINT AS sample_count, \
                percentile_cont(0.50) WITHIN GROUP (ORDER BY ({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS p50_ms, \
                percentile_cont(0.95) WITHIN GROUP (ORDER BY ({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS p95_ms, \
                percentile_cont(0.99) WITHIN GROUP (ORDER BY ({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS p99_ms \
         FROM request_log{filter_sql} \
         GROUP BY bucket ORDER BY bucket"
    );
    params.push(&bucket_seconds);
    client.query(&sql, &params).await.map(|rows| {
        rows.iter()
            .map(|row| {
                json!({
                    "bucket": row.get::<_, DateTime<Utc>>("bucket"),
                    "sample_count": row.get::<_, i64>("sample_count"),
                    "p50_ms": row.get::<_, Option<f64>>("p50_ms"),
                    "p95_ms": row.get::<_, Option<f64>>("p95_ms"),
                    "p99_ms": row.get::<_, Option<f64>>("p99_ms"),
                })
            })
            .collect()
    })
}

fn event_performance_from_row(row: &Row) -> EventPerformance {
    EventPerformance {
        method: row.get("http_method"),
        route_pattern: row.get("event_route"),
        normalized: row.get("normalized"),
        sample_count: row.get("sample_count"),
        avg_ms: row.get("avg_ms"),
        p50_ms: row.get("p50_ms"),
        p95_ms: row.get("p95_ms"),
        p99_ms: row.get("p99_ms"),
        max_ms: row.get("max_ms"),
    }
}

async fn query_event_performance(
    client: &Client,
    filters: &PerformanceFilters,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<EventPerformance>, tokio_postgres::Error> {
    let (filter_sql, mut params) = performance_filter(filters, &start, &end);
    let limit_index = params.len() + 1;
    let sql = format!(
        "SELECT http_method, COALESCE(route_pattern, '（历史未标准化）') AS event_route, \
                BOOL_AND(route_pattern IS NOT NULL) AS normalized, \
                COUNT(*)::BIGINT AS sample_count, \
                AVG(({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS avg_ms, \
                percentile_cont(0.50) WITHIN GROUP (ORDER BY ({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS p50_ms, \
                percentile_cont(0.95) WITHIN GROUP (ORDER BY ({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS p95_ms, \
                percentile_cont(0.99) WITHIN GROUP (ORDER BY ({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION) / 1000.0 AS p99_ms, \
                MAX({PERFORMANCE_DURATION_SQL})::DOUBLE PRECISION / 1000.0 AS max_ms \
         FROM request_log{filter_sql} \
         GROUP BY http_method, event_route \
         ORDER BY p95_ms DESC NULLS LAST, sample_count DESC LIMIT ${limit_index}"
    );
    params.push(&limit);
    client
        .query(&sql, &params)
        .await
        .map(|rows| rows.iter().map(event_performance_from_row).collect())
}

fn resolve_granularity(
    granularity: &Option<String>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
) -> Result<Granularity, &'static str> {
    // 无界范围（「全部时间」）按保留期上限 30 天估算跨度，仅用于控制分桶数量。
    let duration = match (start, end) {
        (Some(start), Some(end)) if end > start => end - start,
        _ => chrono::Duration::days(30),
    };
    let resolved = match granularity.as_deref().unwrap_or("auto") {
        "auto" => Granularity::auto_for_request(duration),
        value => Granularity::parse(value)?,
    };
    let seconds = resolved.seconds();
    let bucket_count = (duration.num_seconds().max(1) + seconds - 1) / seconds;
    if bucket_count > MAX_BUCKETS {
        return Err("selected granularity produces more than 1500 data points");
    }
    Ok(resolved)
}

fn row_to_value(row: tokio_postgres::Row) -> Value {
    json!({
        "id": row.get::<_, i64>("id"),
        "request_id": row.get::<_, Uuid>("request_id"),
        "occurred_at": row.get::<_, DateTime<Utc>>("occurred_at"),
        "http_method": row.get::<_, String>("http_method"),
        "request_path": row.get::<_, String>("request_path"),
        "status_code": row.get::<_, i16>("status_code"),
        "duration_ms": row.get::<_, Option<i32>>("duration_ms"),
        "client_ip": display_ip(row.get("client_ip")),
        "user_agent": row.get::<_, Option<String>>("user_agent"),
        "actor_id": row.get::<_, Option<i32>>("actor_id"),
        "actor_name": row.get::<_, Option<String>>("actor_name"),
        "error_level": row.get::<_, String>("error_level"),
        "error_type": row.get::<_, Option<String>>("error_type"),
        "reason_code": row.get::<_, Option<String>>("reason_code"),
    })
}

#[get("/api/requests")]
pub(crate) async fn list_requests(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<RequestQuery>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().json(json!({"success": false, "message": "forbidden"}));
    }

    let (page, page_size) = pagination(query.page, query.page_size);
    let offset = (page - 1) * page_size;
    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs_error(
                &req,
                "RequestsQueryPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let (filter_sql, params) = request_filter(&*query, &query.start, &query.end);
    let count_sql = format!("SELECT COUNT(*) FROM request_log{filter_sql}");
    let total: i64 = match client.query_one(&count_sql, &params).await {
        Ok(row) => row.get(0),
        Err(error_value) => {
            error_logs_error(
                &req,
                "RequestsQueryError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let list_sql = format!(
        "SELECT id, request_id, occurred_at, http_method, request_path, status_code, duration_ms, \
         client_ip, user_agent, actor_id, actor_name, error_level, error_type, reason_code \
         FROM request_log{filter_sql} ORDER BY occurred_at DESC, id DESC \
         LIMIT ${} OFFSET ${}",
        params.len() + 1,
        params.len() + 2,
    );
    let mut list_params = params;
    list_params.push(&page_size);
    list_params.push(&offset);
    let rows = match client.query(&list_sql, &list_params).await {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs_error(
                &req,
                "RequestsQueryError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let items: Vec<Value> = rows.into_iter().map(row_to_value).collect();

    HttpResponse::Ok().json(json!({
        "success": true,
        "items": items,
        "pagination": {"page": page, "page_size": page_size, "total": total}
    }))
}

#[get("/api/requests/summary")]
pub(crate) async fn request_summary(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<RequestSummaryQuery>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().json(json!({"success": false, "message": "forbidden"}));
    }

    // 预设窗口覆盖任意 start/end，统一统计口径；P95/P99 仅在预设窗口下计算。
    let effective_range = window_range(query.window.as_deref());
    let (start, end) = match effective_range {
        Some((start, end)) => (Some(start), Some(end)),
        None => (query.start, query.end),
    };

    // 趋势分桶粒度：auto 按跨度自适应，固定档校验桶数上限。
    let granularity = match resolve_granularity(&query.granularity, start, end) {
        Ok(granularity) => granularity,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let bucket_seconds = granularity.seconds();

    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs_error(
                &req,
                "RequestsSummaryPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let (filter_sql, params) = request_filter(&*query, &start, &end);

    // 计数聚合（任意范围 + 过滤）。
    let counts_sql = format!(
        "SELECT COUNT(*) AS total, \
                COUNT(*) FILTER (WHERE error_level = 'client_error') AS client_errors, \
                COUNT(*) FILTER (WHERE error_level = 'server_error') AS server_errors \
         FROM request_log{filter_sql}"
    );
    let (total, client_errors, server_errors): (i64, i64, i64) =
        match client.query_one(&counts_sql, &params).await {
            Ok(row) => (row.get(0), row.get(1), row.get(2)),
            Err(error_value) => {
                error_logs_error(
                    &req,
                    "RequestsSummaryError",
                    "database_operation",
                    &error_value,
                );
                return HttpResponse::InternalServerError().finish();
            }
        };
    let errors = client_errors + server_errors;
    let error_rate = if total == 0 {
        0.0
    } else {
        errors as f64 / total as f64
    };

    // 错误类型分布。
    let dist_sql = format!(
        "SELECT error_type, COUNT(*) AS count FROM request_log{} \
         GROUP BY error_type ORDER BY count DESC LIMIT 20",
        add_filter_condition(&filter_sql, "error_type IS NOT NULL")
    );
    let error_types: Vec<Value> = match client.query(&dist_sql, &params).await {
        Ok(rows) => rows
            .iter()
            .map(|row| {
                json!({
                    "error_type": row.get::<_, String>("error_type"),
                    "count": row.get::<_, i64>("count"),
                })
            })
            .collect(),
        Err(error_value) => {
            error_logs_error(
                &req,
                "RequestsSummaryError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    // 趋势（epoch 算术分桶），粒度由 granularity 决定。
    // 有界范围用 generate_series 补齐空桶，保证时间轴连续；无界（全部时间）退化为稀疏分桶。
    let (trend_sql, trend_params) = if let (Some(series_start), Some(series_end)) =
        (start.as_ref(), end.as_ref())
    {
        let start_index = params.len() + 1;
        let end_index = params.len() + 2;
        let bucket_index = params.len() + 3;
        let error_filter_sql = add_filter_condition(&filter_sql, "status_code >= 400");
        let sql = format!(
            "WITH bucket_range AS ( \
                 SELECT generate_series( \
                     (EXTRACT(EPOCH FROM ${start_index}::TIMESTAMPTZ)::BIGINT / ${bucket_index}::BIGINT) * ${bucket_index}::BIGINT, \
                     ((EXTRACT(EPOCH FROM ${end_index}::TIMESTAMPTZ)::BIGINT - 1) / ${bucket_index}::BIGINT) * ${bucket_index}::BIGINT, \
                     ${bucket_index}::BIGINT)::BIGINT AS bucket_start \
             ), aggregated AS ( \
                 SELECT (EXTRACT(EPOCH FROM occurred_at)::BIGINT / ${bucket_index}::BIGINT) * ${bucket_index}::BIGINT AS bucket_start, \
                        COUNT(*) AS total, \
                        COUNT(*) FILTER (WHERE error_level = 'client_error') AS client_errors, \
                        COUNT(*) FILTER (WHERE error_level = 'server_error') AS server_errors \
                 FROM request_log{filter_sql} \
                 GROUP BY bucket_start \
             ), status_agg AS ( \
                 SELECT bucket_start, jsonb_object_agg(status_code::TEXT, cnt) AS status_codes \
                 FROM ( \
                     SELECT (EXTRACT(EPOCH FROM occurred_at)::BIGINT / ${bucket_index}::BIGINT) * ${bucket_index}::BIGINT AS bucket_start, \
                            status_code, COUNT(*) AS cnt \
                     FROM request_log{error_filter_sql} \
                     GROUP BY bucket_start, status_code \
                 ) grouped \
                 GROUP BY bucket_start \
             ) \
             SELECT to_timestamp(b.bucket_start) AS bucket, \
                    COALESCE(a.total, 0)::BIGINT AS total, \
                    COALESCE(a.client_errors, 0)::BIGINT AS client_errors, \
                    COALESCE(a.server_errors, 0)::BIGINT AS server_errors, \
                    COALESCE(sa.status_codes, jsonb_build_object()) AS status_codes \
             FROM bucket_range b \
             LEFT JOIN aggregated a USING (bucket_start) \
             LEFT JOIN status_agg sa USING (bucket_start) \
             ORDER BY b.bucket_start"
        );
        let mut trend_params = params.clone();
        trend_params.push(series_start);
        trend_params.push(series_end);
        trend_params.push(&bucket_seconds);
        (sql, trend_params)
    } else {
        let bucket_index = params.len() + 1;
        let error_filter_sql = add_filter_condition(&filter_sql, "status_code >= 400");
        let sql = format!(
            "WITH aggregated AS ( \
                 SELECT (EXTRACT(EPOCH FROM occurred_at)::BIGINT / ${bucket_index}::BIGINT) * ${bucket_index}::BIGINT AS bucket_start, \
                        COUNT(*) AS total, \
                        COUNT(*) FILTER (WHERE error_level = 'client_error') AS client_errors, \
                        COUNT(*) FILTER (WHERE error_level = 'server_error') AS server_errors \
                 FROM request_log{filter_sql} \
                 GROUP BY bucket_start \
             ), status_agg AS ( \
                 SELECT bucket_start, jsonb_object_agg(status_code::TEXT, cnt) AS status_codes \
                 FROM ( \
                     SELECT (EXTRACT(EPOCH FROM occurred_at)::BIGINT / ${bucket_index}::BIGINT) * ${bucket_index}::BIGINT AS bucket_start, \
                            status_code, COUNT(*) AS cnt \
                     FROM request_log{error_filter_sql} \
                     GROUP BY bucket_start, status_code \
                 ) grouped \
                 GROUP BY bucket_start \
             ) \
             SELECT to_timestamp(a.bucket_start) AS bucket, \
                    a.total, a.client_errors, a.server_errors, \
                    COALESCE(sa.status_codes, jsonb_build_object()) AS status_codes \
             FROM aggregated a \
             LEFT JOIN status_agg sa USING (bucket_start) \
             ORDER BY a.bucket_start"
        );
        let mut trend_params = params.clone();
        trend_params.push(&bucket_seconds);
        (sql, trend_params)
    };
    let trend: Vec<Value> = match client.query(&trend_sql, &trend_params).await {
        Ok(rows) => rows
            .iter()
            .map(|row| {
                json!({
                    "bucket": row.get::<_, DateTime<Utc>>("bucket"),
                    "total": row.get::<_, i64>("total"),
                    "client_errors": row.get::<_, i64>("client_errors"),
                    "server_errors": row.get::<_, i64>("server_errors"),
                    "status_codes": row.get::<_, Value>("status_codes"),
                })
            })
            .collect(),
        Err(error_value) => {
            error_logs_error(
                &req,
                "RequestsSummaryError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    // 延迟 P95/P99：仅预设窗口（避免任意范围 × 任意过滤 × 实时分位数的全表扫描）。
    let (p95, p99) = match effective_range {
        Some(_) => {
            let percentile_sql = format!(
                "SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95, \
                        percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms) AS p99 \
                 FROM request_log{}",
                add_filter_condition(&filter_sql, "duration_ms IS NOT NULL")
            );
            match client.query_one(&percentile_sql, &params).await {
                Ok(row) => (row.get::<_, Option<f64>>(0), row.get::<_, Option<f64>>(1)),
                Err(error_value) => {
                    error_logs_error(
                        &req,
                        "RequestsSummaryError",
                        "database_operation",
                        &error_value,
                    );
                    return HttpResponse::InternalServerError().finish();
                }
            }
        }
        None => (None, None),
    };

    HttpResponse::Ok().json(json!({
        "success": true,
        "summary": {
            "total": total,
            "errors": errors,
            "client_errors": client_errors,
            "server_errors": server_errors,
            "error_rate": error_rate,
            "p95_ms": p95,
            "p99_ms": p99,
            "error_types": error_types,
            "trend": trend,
            "granularity": granularity.label(),
        }
    }))
}

#[get("/api/requests/performance")]
pub(crate) async fn request_performance(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<RequestPerformanceQuery>,
    settings: web::Data<crate::runtime_config::RuntimeSettings>,
    user: UserBaseI,
) -> impl Responder {
    if !is_admin(&user) {
        return HttpResponse::Forbidden().json(json!({"success": false, "message": "forbidden"}));
    }

    let duration = match performance_window(query.window.as_deref()) {
        Ok(duration) => duration,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let status_class = clean_filter(query.status_class.as_deref());
    if status_class
        .as_deref()
        .is_some_and(|value| !matches!(value, "success" | "4xx" | "5xx"))
    {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "status_class must be one of: success, 4xx, 5xx"
        }));
    }

    let filters = PerformanceFilters {
        method: clean_filter(query.method.as_deref()).map(|value| value.to_uppercase()),
        route: clean_filter(query.route.as_deref()),
        status_class,
    };
    let end = Utc::now();
    let start = end - duration;
    let baseline_end = start;
    let baseline_start = baseline_end - duration;
    let granularity = match resolve_granularity(&query.granularity, Some(start), Some(end)) {
        Ok(granularity) => granularity,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 100);

    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs(
                &req,
                "RequestPerformancePoolError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let monitor_policy = settings.monitor.get().await;
    // Both periods use the same current policy, so rule changes do not skew comparison.
    // tokio-postgres 会对同时轮询的查询进行流水线处理，降低六组聚合的总等待时间。
    let (current_summary, baseline_summary, trend, baseline_trend, current_events, baseline_events) =
        match tokio::try_join!(
            query_performance_summary(&client, &filters, start, end, &monitor_policy.value),
            query_performance_summary(
                &client,
                &filters,
                baseline_start,
                baseline_end,
                &monitor_policy.value
            ),
            query_performance_trend(&client, &filters, start, end, granularity.seconds()),
            query_performance_trend(
                &client,
                &filters,
                baseline_start,
                baseline_end,
                granularity.seconds(),
            ),
            query_event_performance(&client, &filters, start, end, limit),
            query_event_performance(&client, &filters, baseline_start, baseline_end, 10_000),
        ) {
            Ok(result) => result,
            Err(error_value) => {
                error_logs(
                    &req,
                    "RequestPerformanceQueryError",
                    &error_value.to_string(),
                );
                return HttpResponse::InternalServerError().finish();
            }
        };
    let baseline_by_event: HashMap<(String, String), EventPerformance> = baseline_events
        .into_iter()
        .map(|event| ((event.method.clone(), event.route_pattern.clone()), event))
        .collect();
    let events: Vec<Value> = current_events
        .into_iter()
        .map(|event| {
            let baseline =
                baseline_by_event.get(&(event.method.clone(), event.route_pattern.clone()));
            let baseline_p95 = baseline.and_then(|value| value.p95_ms);
            let (p95_delta_ms, p95_delta_rate) = metric_delta(event.p95_ms, baseline_p95);
            json!({
                "method": event.method,
                "route_pattern": event.route_pattern,
                "normalized": event.normalized,
                "sample_count": event.sample_count,
                "avg_ms": event.avg_ms,
                "p50_ms": event.p50_ms,
                "p95_ms": event.p95_ms,
                "p99_ms": event.p99_ms,
                "max_ms": event.max_ms,
                "baseline_sample_count": baseline.map(|value| value.sample_count).unwrap_or(0),
                "baseline_p95_ms": baseline_p95,
                "p95_delta_ms": p95_delta_ms,
                "p95_delta_rate": p95_delta_rate,
            })
        })
        .collect();
    let (p50_delta_ms, p50_delta_rate) =
        metric_delta(current_summary.p50_ms, baseline_summary.p50_ms);
    let (p95_delta_ms, p95_delta_rate) =
        metric_delta(current_summary.p95_ms, baseline_summary.p95_ms);
    let (p99_delta_ms, p99_delta_rate) =
        metric_delta(current_summary.p99_ms, baseline_summary.p99_ms);

    HttpResponse::Ok().json(json!({
        "success": true,
        "summary": performance_summary_value(&current_summary),
        "baseline": performance_summary_value(&baseline_summary),
        "changes": {
            "p50_delta_ms": p50_delta_ms,
            "p50_delta_rate": p50_delta_rate,
            "p95_delta_ms": p95_delta_ms,
            "p95_delta_rate": p95_delta_rate,
            "p99_delta_ms": p99_delta_ms,
            "p99_delta_rate": p99_delta_rate,
        },
        "trend": trend,
        "baseline_trend": baseline_trend,
        "events": events,
        "meta": {
            "window": query.window.as_deref().unwrap_or("24h"),
            "start": start,
            "end": end,
            "baseline_start": baseline_start,
            "baseline_end": baseline_end,
            "comparison_shift_seconds": duration.num_seconds(),
            "granularity": granularity.label(),
            "slow_threshold_ms": SLOW_REQUEST_US / 1000,
            "policy_revision": monitor_policy.revision,
            "policy_enabled": monitor_policy.value.enabled,
            "policy_basis": "current_policy",
            "event_limit": limit,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        PerformanceFilters, RequestQuery, add_filter_condition, metric_delta, performance_filter,
        performance_window, request_filter, resolve_granularity, window_range,
    };
    use chrono::{Duration, Utc};

    #[tokio::test]
    #[ignore = "requires disposable HEALTH_TEST_DATABASE_URL"]
    async fn health_policy_request_rates_use_current_defaults_and_operation_overrides() {
        use crate::monitor::rules::{MonitorService, OperationRule};
        let (pool, schema) = crate::monitor::policy_tests::isolated_pool().await;
        let client = pool.get().await.unwrap();
        client.batch_execute("INSERT INTO request_log(request_id,http_method,request_path,route_pattern,status_code,duration_us) VALUES
            (gen_random_uuid(),'GET','/api/task/one','/api/task/{task_id}',200,2000000),
            (gen_random_uuid(),'GET','/api/task/two','/api/task/{task_id}',200,5000000),
            (gen_random_uuid(),'GET','/api/task/all','/api/task/all',200,4000000),
            (gen_random_uuid(),'GET','/historical',NULL,200,4000000);").await.unwrap();
        let filters = PerformanceFilters {
            method: None,
            route: None,
            status_class: None,
        };
        let mut config = crate::config::MonitorConfig::default();
        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::seconds(1);
        let summary = super::query_performance_summary(&client, &filters, start, end, &config)
            .await
            .unwrap();
        assert_eq!(summary.sample_count, 4);
        assert_eq!(summary.slow_rate, 1.0);
        assert_eq!(summary.policy_slow_rate, 0.75);
        let mut rule = config.default_rule(MonitorService::WebApi);
        rule.enabled = false;
        config.operation_rules.push(OperationRule {
            service: MonitorService::WebApi,
            operation: "GET /api/task/{task_id}".into(),
            rule,
        });
        let summary = super::query_performance_summary(&client, &filters, start, end, &config)
            .await
            .unwrap();
        assert_eq!(summary.policy_slow_rate, 0.5);
        assert_eq!(summary.slow_rate, 1.0);
        config.enabled = false;
        assert_eq!(
            super::query_performance_summary(&client, &filters, start, end, &config)
                .await
                .unwrap()
                .policy_slow_rate,
            0.0
        );
        drop(client);
        crate::monitor::policy_tests::cleanup(&pool, &schema).await;
    }

    fn request_query() -> RequestQuery {
        RequestQuery {
            method: None,
            path: None,
            status: None,
            error_level: None,
            error_type: None,
            reason_code: None,
            request_id: None,
            start: None,
            end: None,
            only_errors: None,
            page: None,
            page_size: None,
        }
    }

    #[test]
    fn request_filter_omits_absent_predicates() {
        let value = request_query();
        let (sql, params) = request_filter(&value, &value.start, &value.end);
        assert!(sql.is_empty());
        assert!(params.is_empty());
    }

    #[test]
    fn request_filter_numbers_present_parameters() {
        let mut value = request_query();
        value.method = Some("GET".to_owned());
        value.status = Some(500);
        value.reason_code = Some("totp_bind_expired".to_owned());
        value.only_errors = Some(true);
        let (sql, params) = request_filter(&value, &value.start, &value.end);
        assert_eq!(
            sql,
            " WHERE http_method = $1 AND status_code = $2 AND reason_code = $3 AND error_level <> 'ok'"
        );
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn extra_conditions_create_or_extend_where_clause() {
        assert_eq!(
            add_filter_condition("", "status_code >= 400"),
            " WHERE status_code >= 400"
        );
        assert_eq!(
            add_filter_condition(" WHERE http_method = $1", "status_code >= 400"),
            " WHERE http_method = $1 AND status_code >= 400"
        );
    }

    #[test]
    fn performance_filter_keeps_time_bounds_and_omits_absent_options() {
        let filters = PerformanceFilters {
            method: None,
            route: None,
            status_class: None,
        };
        let end = Utc::now();
        let start = end - Duration::hours(1);
        let (sql, params) = performance_filter(&filters, &start, &end);
        assert!(sql.contains("occurred_at >= $1"));
        assert!(sql.contains("occurred_at < $2"));
        assert!(!sql.contains(" IS NULL OR "));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn performance_filter_inlines_validated_status_class() {
        let filters = PerformanceFilters {
            method: Some("GET".to_owned()),
            route: None,
            status_class: Some("5xx".to_owned()),
        };
        let end = Utc::now();
        let start = end - Duration::hours(1);
        let (sql, params) = performance_filter(&filters, &start, &end);
        assert!(sql.contains("http_method = $1"));
        assert!(sql.contains("status_code BETWEEN 500 AND 599"));
        assert!(sql.contains("occurred_at >= $2"));
        assert!(sql.contains("occurred_at < $3"));
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn window_range_only_accepts_presets() {
        assert!(window_range(Some("1h")).is_some());
        assert!(window_range(Some("24h")).is_some());
        assert!(window_range(Some("7d")).is_some());
        assert!(window_range(None).is_none());
        assert!(window_range(Some("30d")).is_none());
    }

    #[test]
    fn window_range_is_approximately_the_preset_span() {
        let (start, end) = window_range(Some("24h")).expect("24h preset");
        let span = (end - start).num_hours();
        assert_eq!(span, 24);
    }

    #[test]
    fn resolve_granularity_auto_adapts_to_span() {
        let now = Utc::now();
        let auto = None;
        assert_eq!(
            resolve_granularity(&auto, Some(now - Duration::hours(1)), Some(now))
                .unwrap()
                .seconds(),
            60
        );
        assert_eq!(
            resolve_granularity(&auto, Some(now - Duration::hours(24)), Some(now))
                .unwrap()
                .seconds(),
            300
        );
        assert_eq!(
            resolve_granularity(&auto, Some(now - Duration::days(7)), Some(now))
                .unwrap()
                .seconds(),
            1800
        );
        assert_eq!(
            resolve_granularity(&auto, None, None).unwrap().seconds(),
            3600
        );
    }

    #[test]
    fn resolve_granularity_rejects_overly_fine_buckets() {
        let now = Utc::now();
        let fine = Some("1m".to_string());
        assert!(resolve_granularity(&fine, Some(now - Duration::days(7)), Some(now)).is_err());
        assert!(resolve_granularity(&fine, Some(now - Duration::hours(24)), Some(now)).is_ok());
    }

    #[test]
    fn resolve_granularity_rejects_unknown_value() {
        let bad = Some("3m".to_string());
        assert!(resolve_granularity(&bad, None, None).is_err());
    }

    #[test]
    fn performance_windows_are_bounded_for_baseline_comparison() {
        assert_eq!(performance_window(Some("1h")).unwrap(), Duration::hours(1));
        assert_eq!(performance_window(Some("24h")).unwrap(), Duration::days(1));
        assert_eq!(performance_window(Some("7d")).unwrap(), Duration::days(7));
        assert!(performance_window(Some("30d")).is_err());
    }

    #[test]
    fn metric_delta_handles_missing_and_zero_baselines() {
        assert_eq!(
            metric_delta(Some(120.0), Some(100.0)),
            (Some(20.0), Some(0.2))
        );
        assert_eq!(metric_delta(Some(5.0), Some(0.0)), (Some(5.0), None));
        assert_eq!(metric_delta(Some(5.0), None), (None, None));
    }
}
