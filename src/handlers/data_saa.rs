use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::config::AnalyticsSnapshotConfig;
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::logs::write::{error_logs, error_logs_error};
use crate::runtime_config::RuntimeConfig;
use crate::system_resource_cache::SystemResourceCache;
use crate::{SystemDetails, SystemStatusJson, Systems};

const ANALYSIS_TIMEZONE: &str = "Asia/Shanghai";
const DEFAULT_RANGE_WEEKS: i64 = 12;
const MAX_RANGE_DAYS: i64 = 366;

#[derive(Deserialize)]
struct AnalysisFilterQuery {
    start_at: Option<DateTime<Utc>>,
    end_at: Option<DateTime<Utc>>,
    scanner_id: Option<Uuid>,
    task_source: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DistributionQuery {
    #[serde(flatten)]
    filters: AnalysisFilterQuery,
    dimension: Option<String>,
    limit: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct HeatmapQuery {
    #[serde(flatten)]
    filters: AnalysisFilterQuery,
}

struct AnalysisFilters {
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    start_ms: i64,
    end_ms: i64,
    scanner_id: Option<String>,
    task_source: Option<String>,
}

fn push_analysis_scope<'a>(
    conditions: &mut Vec<String>,
    params: &mut Vec<&'a (dyn ToSql + Sync)>,
    owner_id: Option<&'a i32>,
    scanner_id: &'a Option<String>,
    task_source: &'a Option<String>,
) {
    if let Some(owner_id) = owner_id {
        params.push(owner_id);
        conditions.push(format!("t.user_id = ${}", params.len()));
    }
    if let Some(scanner_id) = scanner_id.as_ref() {
        params.push(scanner_id);
        conditions.push(format!("e.assigned_scanner_id = ${}", params.len()));
    }
    if let Some(task_source) = task_source.as_ref() {
        params.push(task_source);
        conditions.push(format!("t.task_source = ${}", params.len()));
    }
}

#[derive(Clone, Copy)]
enum DistributionDimension {
    Service,
    Port,
}

impl DistributionDimension {
    fn parse(value: Option<&str>) -> Result<Self, &'static str> {
        match value.unwrap_or("service") {
            "service" => Ok(Self::Service),
            "port" => Ok(Self::Port),
            _ => Err("dimension must be service or port"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Port => "port",
        }
    }
}

#[derive(Serialize)]
struct AnalysisMeta {
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    timezone: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_as_of: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct AnalysisResponse<T> {
    success: bool,
    data: T,
    meta: AnalysisMeta,
}

#[derive(Serialize)]
struct DistributionItem {
    name: String,
    count: i64,
    percentage: f64,
}

#[derive(Serialize)]
struct DistributionData {
    dimension: &'static str,
    items: Vec<DistributionItem>,
    other_count: i64,
    total: i64,
}

#[derive(Serialize)]
struct HeatmapItem {
    date: String,
    count: i64,
}

#[derive(Serialize)]
struct HeatmapData {
    items: Vec<HeatmapItem>,
}

fn normalize_filters(query: &AnalysisFilterQuery) -> Result<AnalysisFilters, &'static str> {
    let end_at = query.end_at.unwrap_or_else(Utc::now);
    let start_at = query
        .start_at
        .unwrap_or_else(|| end_at - Duration::weeks(DEFAULT_RANGE_WEEKS));

    if start_at >= end_at {
        return Err("start_at must be earlier than end_at");
    }
    if end_at - start_at > Duration::days(MAX_RANGE_DAYS) {
        return Err("analysis range cannot exceed 366 days");
    }

    let task_source = query.task_source.as_deref().map(str::trim);
    if task_source.is_some_and(|value| !matches!(value, "manual" | "automatic")) {
        return Err("task_source must be manual or automatic");
    }

    Ok(AnalysisFilters {
        start_at,
        end_at,
        start_ms: start_at.timestamp_millis(),
        end_ms: end_at.timestamp_millis(),
        scanner_id: query.scanner_id.map(|value| value.to_string()),
        task_source: task_source.map(str::to_owned),
    })
}

fn analysis_meta(filters: &AnalysisFilters) -> AnalysisMeta {
    AnalysisMeta {
        start_at: filters.start_at,
        end_at: filters.end_at,
        timezone: ANALYSIS_TIMEZONE,
        data_as_of: None,
    }
}

fn percentage(count: i64, total: i64) -> f64 {
    if total <= 0 {
        return 0.0;
    }
    ((count as f64 / total as f64) * 1000.0).round() / 10.0
}

fn bad_request(message: &'static str) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({"success": false, "message": message}))
}

#[get("/api/data/system-data")]
async fn get_system_data_handler(
    _req: HttpRequest,
    cache: web::Data<SystemResourceCache>,
    systems: web::Data<Systems>,
) -> impl Responder {
    let status_item: Vec<_> = cache.latest().into_iter().collect();

    let t_json = SystemStatusJson {
        total_c: status_item.len() as i32,
        status_item,
        system_info: SystemDetails::new(systems.get_ref()),
    };

    HttpResponse::Ok().json(t_json)
}

#[get("/api/analysis/distribution")]
pub(crate) async fn get_analysis_distribution(
    req: HttpRequest,
    query: web::Query<DistributionQuery>,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    analytics_snapshot: web::Data<RuntimeConfig<AnalyticsSnapshotConfig>>,
    user: UserBaseI,
) -> impl Responder {
    let filters = match normalize_filters(&query.filters) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let dimension = match DistributionDimension::parse(query.dimension.as_deref()) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let limit = query.limit.unwrap_or(5);
    if !matches!(limit, 5 | 7 | 10) {
        return bad_request("limit must be 5, 7 or 10");
    }
    if analytics_snapshot.get().await.value.mode.reads_snapshot() {
        return analysis_distribution_from_snapshot(
            &req,
            pool.get_ref(),
            &filters,
            dimension,
            limit,
            &user,
        )
        .await;
    }
    if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        return analysis_distribution_from_elasticsearch(
            &req,
            elasticsearch.get_ref(),
            &filters,
            dimension,
            limit,
            &user,
        )
        .await;
    }

    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(
                &req,
                "AnalysisDistributionPoolError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let (label_expression, additional_filter) = match dimension {
        DistributionDimension::Service => (
            "LOWER(BTRIM(s.service))",
            "AND s.kind = 'service' AND s.service IS NOT NULL AND BTRIM(s.service) <> ''",
        ),
        DistributionDimension::Port => ("s.port::TEXT", ""),
    };
    let mut conditions = vec![
        "s.observed_at >= $1".to_owned(),
        "s.observed_at < $2".to_owned(),
    ];
    let mut params: Vec<&(dyn ToSql + Sync)> = vec![&filters.start_at, &filters.end_at];
    push_analysis_scope(
        &mut conditions,
        &mut params,
        (user.role != 1).then_some(&user.id),
        &filters.scanner_id,
        &filters.task_source,
    );
    params.push(&limit);
    let sql = format!(
        "WITH grouped AS (\
            SELECT {label_expression} AS label, \
                   COUNT(DISTINCT (s.execution_id, s.ip_address, s.port))::BIGINT AS endpoint_count \
            FROM scan_observation s \
            JOIN scan_task_execution e ON e.id = s.execution_id \
            JOIN scan_task t ON t.id = e.task_id \
            WHERE {} \
              {additional_filter} \
            GROUP BY label\
        ) \
        SELECT label, endpoint_count, (SUM(endpoint_count) OVER ())::BIGINT AS total \
        FROM grouped ORDER BY endpoint_count DESC, label LIMIT ${};",
        conditions.join(" AND "),
        params.len()
    );
    let rows = match client.query(&sql, &params).await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(
                &req,
                "AnalysisDistributionQueryError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items: Vec<DistributionItem> = rows
        .into_iter()
        .map(|row| {
            let count = row.get::<_, i64>("endpoint_count");
            DistributionItem {
                name: row.get("label"),
                count,
                percentage: percentage(count, total),
            }
        })
        .collect();
    let visible_count: i64 = items.iter().map(|item| item.count).sum();

    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: DistributionData {
            dimension: dimension.as_str(),
            items,
            other_count: total.saturating_sub(visible_count),
            total,
        },
        meta: analysis_meta(&filters),
    })
}

#[get("/api/analysis/discovery-heatmap")]
pub(crate) async fn get_analysis_discovery_heatmap(
    req: HttpRequest,
    query: web::Query<HeatmapQuery>,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    analytics_snapshot: web::Data<RuntimeConfig<AnalyticsSnapshotConfig>>,
    user: UserBaseI,
) -> impl Responder {
    let filters = match normalize_filters(&query.filters) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    if analytics_snapshot.get().await.value.mode.reads_snapshot() {
        return analysis_heatmap_from_snapshot(&req, pool.get_ref(), &filters, &user).await;
    }
    if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        return analysis_heatmap_from_elasticsearch(&req, elasticsearch.get_ref(), &filters, &user)
            .await;
    }
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs_error(
                &req,
                "AnalysisHeatmapPoolError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let mut conditions = vec![
        "i.create_time >= $1".to_owned(),
        "i.create_time < $2".to_owned(),
    ];
    let mut params: Vec<&(dyn ToSql + Sync)> = vec![&filters.start_ms, &filters.end_ms];
    push_analysis_scope(
        &mut conditions,
        &mut params,
        (user.role != 1).then_some(&user.id),
        &filters.scanner_id,
        &filters.task_source,
    );
    let sql = format!(
        "SELECT to_char(\
                 (to_timestamp(i.create_time / 1000.0) AT TIME ZONE 'Asia/Shanghai')::DATE,\
                 'YYYY-MM-DD'\
             ) AS day, COUNT(DISTINCT i.ip_address)::BIGINT AS discovered_count \
             FROM ips i \
             JOIN scan_task t ON t.id = i.task_id \
             JOIN scan_task_execution e ON e.id = i.execution_id \
             WHERE {} \
             GROUP BY day ORDER BY day;",
        conditions.join(" AND ")
    );
    let rows = match client.query(&sql, &params).await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs_error(
                &req,
                "AnalysisHeatmapQueryError",
                "database_operation",
                &error_value,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let items = rows
        .into_iter()
        .map(|row| HeatmapItem {
            date: row.get("day"),
            count: row.get("discovered_count"),
        })
        .collect();

    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: HeatmapData { items },
        meta: analysis_meta(&filters),
    })
}

async fn snapshot_data_as_of(
    client: &deadpool_postgres::Client,
) -> Result<Option<DateTime<Utc>>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT data_as_of FROM analytics_watermark WHERE watermark_key = 'scan_analysis';",
            &[],
        )
        .await?;
    Ok(row.map(|row| row.get("data_as_of")))
}

async fn snapshot_not_ready(client: &deadpool_postgres::Client, user: &UserBaseI) -> HttpResponse {
    if user.role == 1 {
        match crate::analytics_snapshot::snapshot_progress(client).await {
            Ok(progress) => return HttpResponse::ServiceUnavailable().json(json!({
                "success": false, "code": "analytics_backfill_pending",
                "message": format!("分析快照历史回填尚未完成：本轮剩余 {} 个执行，队列待处理 {} 个、处理中 {} 个、失败待重试 {} 个。",
                    progress.remaining, progress.pending, progress.running, progress.retrying),
                "progress": progress
            })),
            Err(_) => return HttpResponse::ServiceUnavailable().json(json!({
                "success": false, "code": "analytics_progress_unavailable", "message": "分析快照状态读取失败，请检查数据库及迁移状态"
            })),
        }
    }
    HttpResponse::ServiceUnavailable().json(json!({
        "success": false, "code": "analytics_backfill_pending", "message": "分析快照尚未完成历史回填，请联系管理员查看统计任务进度"
    }))
}

async fn analysis_distribution_from_snapshot(
    req: &HttpRequest,
    pool: &Pool,
    filters: &AnalysisFilters,
    dimension: DistributionDimension,
    limit: i64,
    user: &UserBaseI,
) -> HttpResponse {
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotPoolError",
                "database_operation",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let data_as_of = match snapshot_data_as_of(&client).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return snapshot_not_ready(&client, user).await;
        }
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotWatermarkError",
                "database_operation",
                &error,
            );
            return HttpResponse::ServiceUnavailable()
                .json(json!({"success": false, "code": "analytics_watermark_unavailable", "message": "分析快照水位读取失败，请检查数据库及迁移状态"}));
        }
    };
    let mut conditions = vec![
        "bucket_start >= $1".to_owned(),
        "bucket_start < $2".to_owned(),
        "dimension = $3".to_owned(),
    ];
    let dimension_name = dimension.as_str();
    let mut params: Vec<&(dyn ToSql + Sync)> =
        vec![&filters.start_at, &filters.end_at, &dimension_name];
    if user.role != 1 {
        params.push(&user.id);
        conditions.push(format!("owner_id = ${}", params.len()));
    }
    if let Some(scanner_id) = filters.scanner_id.as_ref() {
        params.push(scanner_id);
        conditions.push(format!("scanner_id = ${}", params.len()));
    }
    if let Some(task_source) = filters.task_source.as_ref() {
        params.push(task_source);
        conditions.push(format!("task_source = ${}", params.len()));
    }
    params.push(&limit);
    let sql = format!(
        "WITH grouped AS ( \
             SELECT label, SUM(endpoint_count)::BIGINT AS endpoint_count \
             FROM analytics_distribution_30m WHERE {} GROUP BY label \
         ) SELECT label, endpoint_count, (SUM(endpoint_count) OVER ())::BIGINT AS total \
           FROM grouped ORDER BY endpoint_count DESC, label LIMIT ${};",
        conditions.join(" AND "),
        params.len()
    );
    let rows = match client.query(&sql, &params).await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotDistributionError",
                "database_operation",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .into_iter()
        .map(|row| {
            let count = row.get("endpoint_count");
            DistributionItem {
                name: row.get("label"),
                count,
                percentage: percentage(count, total),
            }
        })
        .collect::<Vec<_>>();
    let visible_count = items.iter().map(|item| item.count).sum::<i64>();
    let mut meta = analysis_meta(filters);
    meta.data_as_of = Some(data_as_of);
    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: DistributionData {
            dimension: dimension.as_str(),
            items,
            other_count: total.saturating_sub(visible_count),
            total,
        },
        meta,
    })
}

async fn analysis_heatmap_from_snapshot(
    req: &HttpRequest,
    pool: &Pool,
    filters: &AnalysisFilters,
    user: &UserBaseI,
) -> HttpResponse {
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotPoolError",
                "database_operation",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let data_as_of = match snapshot_data_as_of(&client).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return snapshot_not_ready(&client, user).await;
        }
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotWatermarkError",
                "database_operation",
                &error,
            );
            return HttpResponse::ServiceUnavailable()
                .json(json!({"success": false, "code": "analytics_watermark_unavailable", "message": "分析快照水位读取失败，请检查数据库及迁移状态"}));
        }
    };
    let mut conditions = vec![
        "day_start >= (($1 AT TIME ZONE 'Asia/Shanghai')::DATE)".to_owned(),
        "day_start < (($2 AT TIME ZONE 'Asia/Shanghai')::DATE)".to_owned(),
    ];
    let mut params: Vec<&(dyn ToSql + Sync)> = vec![&filters.start_at, &filters.end_at];
    if user.role != 1 {
        params.push(&user.id);
        conditions.push(format!("owner_id = ${}", params.len()));
    }
    if let Some(scanner_id) = filters.scanner_id.as_ref() {
        params.push(scanner_id);
        conditions.push(format!("scanner_id = ${}", params.len()));
    }
    if let Some(task_source) = filters.task_source.as_ref() {
        params.push(task_source);
        conditions.push(format!("task_source = ${}", params.len()));
    }
    let sql = format!(
        "SELECT to_char(day_start, 'YYYY-MM-DD') AS day, COUNT(DISTINCT ip_address)::BIGINT AS discovered_count \
         FROM analytics_discovery_fact WHERE {} GROUP BY day_start ORDER BY day_start;",
        conditions.join(" AND ")
    );
    let rows = match client.query(&sql, &params).await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                req,
                "AnalysisSnapshotHeatmapError",
                "database_operation",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let items = rows
        .into_iter()
        .map(|row| HeatmapItem {
            date: row.get("day"),
            count: row.get("discovered_count"),
        })
        .collect();
    let mut meta = analysis_meta(filters);
    meta.data_as_of = Some(data_as_of);
    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: HeatmapData { items },
        meta,
    })
}

fn analysis_es_filters(filters: &AnalysisFilters, user: &UserBaseI) -> Vec<Value> {
    let mut result = vec![json!({"range": {"observed_at": {
        "gte": filters.start_ms, "lt": filters.end_ms, "format": "epoch_millis"
    }}})];
    if user.role != 1 {
        result.push(json!({"term": {"user_id": user.id}}));
    }
    if let Some(scanner_id) = filters.scanner_id.as_deref() {
        result.push(json!({"term": {"scanner_id": scanner_id}}));
    }
    if let Some(task_source) = filters.task_source.as_deref() {
        result.push(json!({"term": {"task_source": task_source}}));
    }
    result
}

async fn analysis_distribution_from_elasticsearch(
    req: &HttpRequest,
    elasticsearch: &ElasticsearchService,
    filters: &AnalysisFilters,
    dimension: DistributionDimension,
    limit: i64,
    user: &UserBaseI,
) -> HttpResponse {
    let mut query_filters = analysis_es_filters(filters, user);
    let field = match dimension {
        DistributionDimension::Service => {
            query_filters.push(json!({"term": {"kind": "service"}}));
            query_filters.push(json!({"exists": {"field": "service"}}));
            "service"
        }
        DistributionDimension::Port => "port",
    };
    let mut after = None;
    let mut counts = HashMap::<String, i64>::new();
    loop {
        let mut composite = json!({
            "size": 1000,
            "sources": [
                {"label": {"terms": {"field": field}}},
                {"endpoint": {"terms": {"field": "endpoint_id"}}}
            ]
        });
        if let Some(value) = after.take() {
            composite
                .as_object_mut()
                .expect("composite aggregation is an object")
                .insert("after".to_owned(), value);
        }
        let result = match elasticsearch
            .scan_query(
                ScanQueryIndex::Observations,
                &json!({
                    "size": 0,
                    "query": {"bool": {"filter": query_filters}},
                    "aggs": {"groups": {"composite": composite}}
                }),
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                error_logs(req, "AnalysisDistributionElasticsearchError", &error);
                return HttpResponse::ServiceUnavailable()
                    .json(json!({"message": "扫描结果索引暂时不可用"}));
            }
        };
        let buckets = result
            .pointer("/aggregations/groups/buckets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for bucket in &buckets {
            let label = bucket
                .pointer("/key/label")
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                })
                .unwrap_or_default();
            *counts.entry(label).or_default() += 1;
        }
        after = result.pointer("/aggregations/groups/after_key").cloned();
        if buckets.len() < 1000 || after.is_none() {
            break;
        }
    }
    let mut all_items = counts.into_iter().collect::<Vec<_>>();
    all_items.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let total = all_items.iter().map(|item| item.1).sum::<i64>();
    let items = all_items
        .into_iter()
        .take(limit as usize)
        .map(|(name, count)| DistributionItem {
            name,
            count,
            percentage: percentage(count, total),
        })
        .collect::<Vec<_>>();
    let visible_count = items.iter().map(|item| item.count).sum::<i64>();
    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: DistributionData {
            dimension: dimension.as_str(),
            items,
            other_count: total.saturating_sub(visible_count),
            total,
        },
        meta: analysis_meta(filters),
    })
}

async fn analysis_heatmap_from_elasticsearch(
    req: &HttpRequest,
    elasticsearch: &ElasticsearchService,
    filters: &AnalysisFilters,
    user: &UserBaseI,
) -> HttpResponse {
    let mut after = None;
    let mut counts = BTreeMap::<i64, i64>::new();
    loop {
        let mut composite = json!({
            "size": 1000,
            "sources": [
                {"day": {"date_histogram": {"field": "observed_at",
                    "calendar_interval": "1d", "time_zone": "+08:00"}}},
                {"address": {"terms": {"field": "ip_address"}}}
            ]
        });
        if let Some(value) = after.take() {
            composite
                .as_object_mut()
                .expect("composite aggregation is an object")
                .insert("after".to_owned(), value);
        }
        let result = match elasticsearch
            .scan_query(
                ScanQueryIndex::Observations,
                &json!({
                    "size": 0,
                    "query": {"bool": {"filter": analysis_es_filters(filters, user)}},
                    "aggs": {"groups": {"composite": composite}}
                }),
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                error_logs(req, "AnalysisHeatmapElasticsearchError", &error);
                return HttpResponse::ServiceUnavailable()
                    .json(json!({"message": "扫描结果索引暂时不可用"}));
            }
        };
        let buckets = result
            .pointer("/aggregations/groups/buckets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for bucket in &buckets {
            if let Some(day) = bucket.pointer("/key/day").and_then(Value::as_i64) {
                *counts.entry(day).or_default() += 1;
            }
        }
        after = result.pointer("/aggregations/groups/after_key").cloned();
        if buckets.len() < 1000 || after.is_none() {
            break;
        }
    }
    let timezone = chrono::FixedOffset::east_opt(8 * 60 * 60).expect("valid UTC+8 offset");
    let items = counts
        .into_iter()
        .filter_map(|(day, count)| {
            DateTime::<Utc>::from_timestamp_millis(day).map(|time| HeatmapItem {
                date: time.with_timezone(&timezone).format("%Y-%m-%d").to_string(),
                count,
            })
        })
        .collect::<Vec<_>>();
    HttpResponse::Ok().json(AnalysisResponse {
        success: true,
        data: HeatmapData { items },
        meta: analysis_meta(filters),
    })
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};
    use tokio_postgres::types::ToSql;
    use uuid::Uuid;

    use super::{
        AnalysisFilterQuery, DistributionDimension, MAX_RANGE_DAYS, normalize_filters, percentage,
        push_analysis_scope,
    };

    fn query(start_offset_days: i64, task_source: Option<&str>) -> AnalysisFilterQuery {
        let end_at = Utc.with_ymd_and_hms(2026, 8, 16, 12, 0, 0).unwrap();
        AnalysisFilterQuery {
            start_at: Some(end_at - Duration::days(start_offset_days)),
            end_at: Some(end_at),
            scanner_id: Some(Uuid::nil()),
            task_source: task_source.map(str::to_owned),
        }
    }

    #[test]
    fn normalizes_valid_filters() {
        let filters = normalize_filters(&query(84, Some("manual"))).unwrap();
        assert_eq!(filters.task_source.as_deref(), Some("manual"));
        assert_eq!(filters.scanner_id, Some(Uuid::nil().to_string()));
        assert!(filters.start_ms < filters.end_ms);
    }

    #[test]
    fn rejects_invalid_ranges_and_sources() {
        assert!(normalize_filters(&query(MAX_RANGE_DAYS + 1, None)).is_err());
        assert!(normalize_filters(&query(84, Some("system"))).is_err());

        let mut inverted = query(84, None);
        inverted.start_at = inverted.end_at.map(|value| value + Duration::seconds(1));
        assert!(normalize_filters(&inverted).is_err());
    }

    #[test]
    fn validates_distribution_dimension() {
        assert!(matches!(
            DistributionDimension::parse(Some("service")),
            Ok(DistributionDimension::Service)
        ));
        assert!(matches!(
            DistributionDimension::parse(Some("port")),
            Ok(DistributionDimension::Port)
        ));
        assert!(DistributionDimension::parse(Some("product")).is_err());
    }

    #[test]
    fn calculates_percentages_to_one_decimal_place() {
        assert_eq!(percentage(1, 3), 33.3);
        assert_eq!(percentage(0, 0), 0.0);
    }

    #[test]
    fn postgres_scope_omits_absent_optional_conditions() {
        let start = 1_i64;
        let mut conditions = vec!["observed_at >= $1".to_owned()];
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&start];

        push_analysis_scope(&mut conditions, &mut params, None, &None, &None);

        assert_eq!(conditions, ["observed_at >= $1"]);
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn postgres_scope_numbers_present_conditions_only() {
        let start = 1_i64;
        let owner_id = 7;
        let scanner_id = Some("scanner-a".to_owned());
        let task_source = Some("manual".to_owned());
        let mut conditions = vec!["observed_at >= $1".to_owned()];
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&start];

        push_analysis_scope(
            &mut conditions,
            &mut params,
            Some(&owner_id),
            &scanner_id,
            &task_source,
        );

        assert_eq!(params.len(), 4);
        assert_eq!(conditions[1], "t.user_id = $2");
        assert_eq!(conditions[2], "e.assigned_scanner_id = $3");
        assert_eq!(conditions[3], "t.task_source = $4");
        assert!(conditions.iter().all(|condition| !condition.contains("OR")));
    }
}
