use super::{
    ApiError, Principal, Result, auth, business, console,
    query::{self, Search},
};
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use actix_web::{HttpRequest, http::StatusCode};
use chrono::{TimeZone, Utc};
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn catalog() -> Value {
    json!({"types":[{"id":"discovery","groups":["day","week","month","scanner","task_source"],"metrics":["count"]},{"id":"port","groups":["port"],"metrics":["count","percentage"]},{"id":"service","groups":["service"],"metrics":["count","percentage"]},{"id":"tasks","groups":["day","week","month","task_source"],"metrics":["created","completed","succeeded","failed","partial","cancelled","success_rate"]},{"id":"scanners","groups":["scanner","day","week","month"],"metrics":["completed","succeeded","failed","partial","cancelled","success_rate","avg_duration_ms","p50_ms","p95_ms"]}],"max_range_days":366,"max_composite_buckets":50000,"timezone":crate::system_time::timezone().name()})
}
fn range(v: &Value, p: &Principal) -> Result<Search> {
    let now = Utc::now().timestamp_millis();
    let start = query::instant(&v["start_at"])?.unwrap_or(now - 30 * 86400000);
    let end = query::instant(&v["end_at"])?.unwrap_or(now);
    if start >= end || end - start > 366 * 86400000i64 {
        return Err(ApiError::bad("统计范围必须在 366 天以内"));
    }
    if v.get("timezone")
        .and_then(Value::as_str)
        .is_some_and(|s| s != crate::system_time::timezone().name())
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "timezone_changed",
            "统计时区必须与系统业务时区一致",
        ));
    }
    let s = Search {
        start_at: Some(start),
        end_at: Some(end),
        ..Search::default()
    };
    s.validate(p)?;
    Ok(s)
}
pub(crate) async fn dispatch(
    req: &HttpRequest,
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    e: &super::catalog::Endpoint,
    v: &Value,
) -> Result<Value> {
    let _slot = crate::statistics::ClusterSlot::acquire(pool)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "statistics_busy",
                "统计计算繁忙，请稍后重试",
            )
        })?;
    auth::category_quota(
        pool,
        p,
        "statistics.minute",
        p.policy.statistics_per_minute,
        false,
    )
    .await?;
    if e.path == "/analytics/statistics/details" {
        console::allowed_keys(
            v,
            &[
                "data_type",
                "group_by",
                "start_at",
                "end_at",
                "timezone",
                "category",
                "cursor",
                "page_size",
            ],
        )?;
        let mut s = range(v, p)?;
        s.cursor = v
            .get("cursor")
            .filter(|v| !v.is_null())
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|_| ApiError::bad("cursor 无效"))?;
        s.page_size = v["page_size"].as_u64().map(|n| n as usize);
        let kind = v["data_type"].as_str().unwrap_or("discovery");
        if !matches!(
            kind,
            "discovery" | "port" | "service" | "tasks" | "scanners"
        ) {
            return Err(ApiError::bad("data_type 无效"));
        }
        require_metric_field(p, kind)?;
        if matches!(kind, "tasks" | "scanners") {
            if v.get("category").is_some_and(|v| !v.is_null()) {
                return Err(ApiError::bad(
                    "任务和执行明细不接受 category，请使用时间范围和游标",
                ));
            }
            return task_statistics(
                pool,
                p,
                &s,
                kind,
                v["group_by"].as_str().unwrap_or("day"),
                true,
            )
            .await;
        }
        let mut filters = vec![
            json!({"terms":{"kind":if kind=="service"{vec!["service"]}else{vec!["port","service"]}}}),
        ];
        if let Some(category) = v.get("category").and_then(Value::as_str) {
            if kind == "port" {
                filters.push(json!({"term":{"port":category.parse::<u16>().map_err(|_|ApiError::bad("category 端口无效"))?}}));
            } else if kind == "service" {
                filters.push(json!({"term":{"service":category}}));
            }
        }
        return Ok(business::project_facts(
            p,
            query::facts(pool, es, p, &s, filters).await?,
            false,
        ));
    }
    let parameters = if e.path == "/analytics/overview" {
        let q = business::search(req, &json!({}))?;
        json!({"start_at":q.start_at,"end_at":q.end_at})
    } else {
        v.clone()
    };
    console::allowed_keys(
        &parameters,
        &[
            "data_type",
            "group_by",
            "start_at",
            "end_at",
            "timezone",
            "metrics",
            "comparison",
            "dimension",
        ],
    )?;
    let s = range(&parameters, p)?;
    let kind = if e.path == "/analytics/discovery-series" {
        "discovery"
    } else if e.path == "/analytics/distribution" {
        parameters["dimension"].as_str().unwrap_or("port")
    } else {
        parameters["data_type"].as_str().unwrap_or("discovery")
    };
    let group = parameters["group_by"]
        .as_str()
        .unwrap_or(if kind == "port" {
            "port"
        } else if kind == "service" {
            "service"
        } else {
            "day"
        });
    let definitions = catalog();
    let definition = definitions["types"]
        .as_array()
        .and_then(|a| a.iter().find(|d| d["id"] == kind))
        .ok_or_else(|| ApiError::bad("统计类型无效"))?;
    if !definition["groups"]
        .as_array()
        .is_some_and(|a| a.iter().any(|g| g == group))
    {
        return Err(ApiError::bad("统计分组无效"));
    }
    if let Some(metrics) = parameters.get("metrics")
        && !metrics.as_array().is_some_and(|a| {
            !a.is_empty()
                && a.iter().all(|m| {
                    definition["metrics"]
                        .as_array()
                        .is_some_and(|allowed| allowed.contains(m))
                })
        })
    {
        return Err(ApiError::bad("统计指标无效"));
    }
    let value = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        if matches!(kind, "tasks" | "scanners") {
            task_statistics(pool, p, &s, kind, group, false).await
        } else {
            scan_statistics(pool, es, p, &s, kind, group).await
        }
    })
    .await
    .map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "statistics_timeout",
            "统计计算超时",
        )
    })??;
    let mut result = value;
    result["meta"] = json!({"timezone":crate::system_time::timezone().name(),"start_at":s.start_at,"end_at":s.end_at,"policy_revision":p.revision,"scope":"authorized_successful_executions","based_on_retained_history":true,"accuracy":"exact_within_budget","count_semantics":"see OPEN_API.md"});
    if let Some(comparison) = parameters.get("comparison").and_then(Value::as_str) {
        if comparison != "previous" {
            return Err(ApiError::bad("comparison 必须为 previous"));
        }
        let span = s.end_at.unwrap() - s.start_at.unwrap();
        let previous = Search {
            start_at: Some(s.start_at.unwrap() - span),
            end_at: s.start_at,
            ..Search::default()
        };
        result["previous"] = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            if matches!(kind, "tasks" | "scanners") {
                task_statistics(pool, p, &previous, kind, group, false).await
            } else {
                scan_statistics(pool, es, p, &previous, kind, group).await
            }
        })
        .await
        .map_err(|_| ApiError::unavailable())??;
    }
    Ok(result)
}
pub(crate) async fn scan_statistics(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    s: &Search,
    kind: &str,
    group: &str,
) -> Result<Value> {
    scan_statistics_from_inputs(pool, es, p, s, kind, group, None).await
}
pub(crate) async fn scan_statistics_from_inputs(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    s: &Search,
    kind: &str,
    group: &str,
    frozen: Option<&[String]>,
) -> Result<Value> {
    require_metric_field(p, kind)?;
    let mut filters = query::fact_filters(pool, p, s).await?;
    if let Some(ids) = frozen {
        filters.push(json!({"terms":{"execution_id":ids}}));
    }
    filters.push(
        json!({"terms":{"kind":if kind=="service"{vec!["service"]}else{vec!["port","service"]}}}),
    );
    let group_source = match group {
        "day" | "week" | "month" => {
            json!({"date_histogram":{"field":"observed_at","calendar_interval":if group=="day"{"1d"}else if group=="week"{"1w"}else{"1M"},"time_zone":crate::system_time::timezone().name()}})
        }
        "scanner" => json!({"terms":{"field":"scanner_id","missing_bucket":true}}),
        "task_source" => json!({"terms":{"field":"task_source","missing_bucket":true}}),
        "port" => json!({"terms":{"field":"port","missing_bucket":true}}),
        "service" => json!({"terms":{"field":"service","missing_bucket":true}}),
        _ => return Err(ApiError::bad("分组无效")),
    };
    let mut sources = vec![
        json!({"group":group_source}),
        json!({"ip":{"terms":{"field":"ip_address"}}}),
    ];
    if kind != "discovery" {
        sources.push(json!({"execution":{"terms":{"field":"execution_id"}}}));
        sources.push(json!({"port":{"terms":{"field":"port"}}}));
    }
    let mut counts = BTreeMap::<String, u64>::new();
    let mut total_ips = BTreeSet::new();
    let mut after = None;
    let mut seen = 0usize;
    let started = std::time::Instant::now();
    loop {
        if started.elapsed() > std::time::Duration::from_secs(12) {
            return Err(ApiError::unavailable());
        }
        let mut composite = json!({"size":1000,"sources":sources});
        if let Some(a) = after.clone() {
            composite["after"] = a;
        }
        let result=es.scan_query(ScanQueryIndex::Observations,&json!({"size":0,"timeout":"3s","query":{"bool":{"filter":filters}},"aggs":{"groups":{"composite":composite}}})).await.map_err(|_|ApiError::unavailable())?;
        let buckets = result
            .pointer("/aggregations/groups/buckets")
            .and_then(Value::as_array)
            .ok_or_else(ApiError::unavailable)?;
        seen += buckets.len();
        if seen > 50_000 {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "statistics_budget_exceeded",
                "统计超过 50000 个事实分组，请缩小范围",
            ));
        }
        for bucket in buckets {
            let key = bucket.pointer("/key/group").unwrap_or(&Value::Null);
            let label = if matches!(group, "day" | "week" | "month") {
                date_group(key.as_i64().unwrap_or(0), group)
            } else if group == "scanner" {
                format!(
                    "node-{}",
                    &super::model::fingerprint(format!("{}:{key}", p.client_id).as_bytes())[..12]
                )
            } else {
                key.as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| key.to_string())
            };
            *counts.entry(label).or_default() += 1;
            total_ips.insert(
                bucket
                    .pointer("/key/ip")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            );
        }
        let next = result.pointer("/aggregations/groups/after_key").cloned();
        if buckets.len() < 1000 || next.is_none() {
            break;
        }
        if next == after {
            return Err(ApiError::unavailable());
        }
        after = next;
    }
    let total: u64 = counts.values().sum();
    Ok(
        json!({"data_type":kind,"group_by":group,"rows":counts.into_iter().map(|(category,count)|json!({"category":category,"count":count,"percentage":if total>0{Some(count as f64/total as f64*100.0)}else{None}})).collect::<Vec<_>>(),"summary":{"count":if kind=="discovery"{total_ips.len() as u64}else{total},"distinct_ips":total_ips.len()},"notes":["发现按每组独立去重 IP，总体 IP 直接去重，不能累加各组。端口/服务按执行、IP、端点计数。"]}),
    )
}
fn require_metric_field(p: &Principal, kind: &str) -> Result<()> {
    if matches!(kind, "port" | "service") && !p.policy.fields.iter().any(|f| f == kind) {
        return Err(ApiError::forbidden());
    }
    Ok(())
}
#[derive(Default)]
struct TaskMetrics {
    created: u64,
    completed: u64,
    succeeded: u64,
    failed: u64,
    partial: u64,
    cancelled: u64,
    durations: Vec<i64>,
}
impl TaskMetrics {
    fn finish(&mut self, status: &str, duration: Option<i64>) {
        self.completed += 1;
        match status {
            "succeeded" => {
                self.succeeded += 1;
                if let Some(d) = duration.filter(|d| *d >= 0) {
                    self.durations.push(d);
                }
            }
            "failed" => self.failed += 1,
            "partial" => self.partial += 1,
            "cancelled" => self.cancelled += 1,
            _ => {}
        }
    }
    fn value(&mut self) -> Value {
        self.durations.sort_unstable();
        let d = &self.durations;
        let n = self.succeeded + self.failed + self.partial;
        let len = d.len();
        json!({"created":self.created,"completed":self.completed,"succeeded":self.succeeded,"failed":self.failed,"partial":self.partial,"cancelled":self.cancelled,"success_rate":if n>0{Some(self.succeeded as f64/n as f64)}else{None},"avg_duration_ms":if len>0{Some(d.iter().map(|d|*d as f64).sum::<f64>()/len as f64)}else{None},"p50_ms":if len>0{Some(d[(len-1)/2])}else{None},"p95_ms":if len>0{Some(d[((len as f64*0.95).ceil() as usize).saturating_sub(1)])}else{None}})
    }
}
fn date_group(ms: i64, group: &str) -> String {
    use chrono::{Datelike, Duration};
    let Some(t) = Utc.timestamp_millis_opt(ms).single() else {
        return "unknown".into();
    };
    let d = t
        .with_timezone(&crate::system_time::timezone())
        .date_naive();
    if group == "month" {
        format!("{:04}-{:02}", d.year(), d.month())
    } else if group == "week" {
        (d - Duration::days(d.weekday().num_days_from_monday() as i64)).to_string()
    } else {
        d.to_string()
    }
}
async fn task_statistics(
    pool: &Pool,
    p: &Principal,
    s: &Search,
    kind: &str,
    group: &str,
    details: bool,
) -> Result<Value> {
    if details {
        return task_details(pool, p, s, kind, group).await;
    }
    let start = s.start_at.unwrap();
    let end = s.end_at.unwrap();
    let c = pool.get().await?;
    let sql = if kind == "scanners" {
        "SELECT t.*,t.task_target::TEXT[] AS targets,e.execution_status,e.task_start_time AS execution_started,e.task_end_time AS execution_ended,e.assigned_scanner_id,e.execution_id FROM scan_task t JOIN scan_task_execution e ON e.task_id=t.id WHERE t.user_id=$1 AND ($2 OR t.api_client_id=$3) AND e.task_end_time >= $4 AND e.task_end_time<$5 AND e.execution_status IN ('succeeded','failed','partial','cancelled') ORDER BY t.id LIMIT 10001"
    } else {
        "SELECT t.*,t.task_target::TEXT[] AS targets FROM scan_task t WHERE user_id=$1 AND ($2 OR api_client_id=$3) AND ((task_create_time>=$4 AND task_create_time<$5) OR (task_end_time>=$4 AND task_end_time<$5)) ORDER BY t.id LIMIT 10001"
    };
    let rows = c
        .query(
            sql,
            &[
                &p.owner_id,
                &(p.policy.data_mode == "owner"),
                &p.client_pk,
                &start.max(p.policy.from_at.unwrap_or(start)),
                &end.min(p.policy.to_at.unwrap_or(end)),
            ],
        )
        .await?;
    if rows.len() > 10000 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "statistics_budget_exceeded",
            "任务/执行统计超过 10000 项，请缩小范围",
        ));
    }
    let mut metrics = BTreeMap::<String, TaskMetrics>::new();
    let mut total = TaskMetrics::default();
    for row in rows {
        if !super::tasks::visible(&row, p) {
            continue;
        }
        let created: i64 = row.get("task_create_time");
        let ended: Option<i64> = row.get(if kind == "scanners" {
            "execution_ended"
        } else {
            "task_end_time"
        });
        let started: Option<i64> = row.get(if kind == "scanners" {
            "execution_started"
        } else {
            "task_start_time"
        });
        let status: String = row.get(if kind == "scanners" {
            "execution_status"
        } else {
            "task_status"
        });
        let source: String = row.get("task_source");
        let scanner = row
            .try_get::<_, Option<String>>("assigned_scanner_id")
            .ok()
            .flatten()
            .unwrap_or_default();
        let category = |time| {
            if group == "task_source" {
                source.clone()
            } else if group == "scanner" {
                format!(
                    "node-{}",
                    &super::model::fingerprint(format!("{}:{scanner}", p.client_id).as_bytes())
                        [..12]
                )
            } else {
                date_group(time, group)
            }
        };
        if kind == "tasks" && created >= start && created < end {
            metrics.entry(category(created)).or_default().created += 1;
            total.created += 1;
        }
        if let Some(ended) = ended.filter(|t| *t >= start && *t < end)
            && matches!(
                status.as_str(),
                "succeeded" | "failed" | "partial" | "cancelled"
            )
        {
            let duration = started.map(|s| ended - s);
            metrics
                .entry(category(ended))
                .or_default()
                .finish(&status, duration);
            total.finish(&status, duration);
        }
    }
    Ok(
        json!({"data_type":kind,"group_by":group,"rows":metrics.into_iter().map(|(category,mut m)|{let mut value=m.value();value["category"]=json!(category);value}).collect::<Vec<_>>(),"summary":total.value()}),
    )
}
async fn task_details(
    pool: &Pool,
    p: &Principal,
    s: &Search,
    kind: &str,
    group: &str,
) -> Result<Value> {
    let start = s.start_at.unwrap();
    let end = s.end_at.unwrap();
    let size = s.size()?;
    let label = format!("details:{kind}:{group}:{start}:{end}");
    let after = query::db_after(pool, p, s.cursor, &label).await?;
    let sql = if kind == "scanners" {
        "SELECT t.*,t.task_target::TEXT[] AS targets,e.id AS evidence_id,e.execution_id,e.execution_status,e.task_end_time AS ended FROM scan_task t JOIN scan_task_execution e ON e.task_id=t.id WHERE t.user_id=$1 AND ($2 OR t.api_client_id=$3) AND e.task_end_time>=$4 AND e.task_end_time<$5 AND e.id<$6 AND e.execution_status IN ('succeeded','failed','partial','cancelled') ORDER BY e.id DESC LIMIT $7"
    } else {
        "SELECT t.*,t.task_target::TEXT[] AS targets,t.id AS evidence_id FROM scan_task t WHERE t.user_id=$1 AND ($2 OR t.api_client_id=$3) AND ((task_create_time>=$4 AND task_create_time<$5) OR (task_end_time>=$4 AND task_end_time<$5)) AND t.id<$6 ORDER BY t.id DESC LIMIT $7"
    };
    let rows = pool
        .get()
        .await?
        .query(
            sql,
            &[
                &p.owner_id,
                &(p.policy.data_mode == "owner"),
                &p.client_pk,
                &start.max(p.policy.from_at.unwrap_or(start)),
                &end.min(p.policy.to_at.unwrap_or(end)),
                &after,
                &(size as i64 + 1),
            ],
        )
        .await?;
    let next = if rows.len() > size {
        Some(
            query::db_next(
                pool,
                p,
                rows[size - 1].get::<_, i32>("evidence_id") as i64,
                &label,
            )
            .await?,
        )
    } else {
        None
    };
    let items=rows.iter().take(size).filter(|r|super::tasks::visible(r,p)).map(|r|{let mut item=json!({"task_id":r.get::<_,String>("task_id"),"status":r.get::<_,String>("task_status"),"created_at":r.get::<_,i64>("task_create_time"),"ended_at":r.get::<_,Option<i64>>("task_end_time")});if kind=="scanners"{item["execution_id"]=json!(r.get::<_,String>("execution_id"));item["status"]=json!(r.get::<_,String>("execution_status"));item["ended_at"]=json!(r.get::<_,Option<i64>>("ended"));}item}).collect::<Vec<_>>();
    Ok(json!({"items":items,"next_cursor":next}))
}
pub(crate) async fn vulnerability_summary(
    pool: &Pool,
    es: &ElasticsearchService,
    p: &Principal,
    s: &Search,
) -> Result<Value> {
    let _slot = crate::statistics::ClusterSlot::acquire(pool)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "statistics_busy",
                "统计计算繁忙，请稍后重试",
            )
        })?;
    auth::category_quota(
        pool,
        p,
        "statistics.minute",
        p.policy.statistics_per_minute,
        false,
    )
    .await?;
    // Observation `data` is stored with enabled=false in the existing ES mapping.
    // Reduce bounded authorized pages in Rust instead of returning empty ES terms.
    let mut query = s.clone();
    query.page_size = Some(100);
    query.cursor = None;
    let mut severities = BTreeMap::<String, u64>::new();
    let mut templates = BTreeMap::<String, u64>::new();
    let mut count = 0usize;
    let started = std::time::Instant::now();
    loop {
        if started.elapsed() > std::time::Duration::from_secs(12) {
            return Err(ApiError::unavailable());
        }
        let page = query::facts(
            pool,
            es,
            p,
            &query,
            vec![json!({"term":{"kind":"vulnerability"}})],
        )
        .await?;
        for value in page["items"].as_array().into_iter().flatten() {
            let severity = value
                .pointer("/data/severity")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let template = value
                .pointer("/data/template_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if s.severity.as_ref().is_some_and(|v| v != severity)
                || s.template_id.as_ref().is_some_and(|v| v != template)
            {
                continue;
            }
            *severities.entry(severity.to_owned()).or_default() += 1;
            *templates.entry(template.to_owned()).or_default() += 1;
            count += 1;
        }
        if count > 10000 {
            return Err(ApiError::bad("漏洞摘要超过 10000 条预算，请缩小范围"));
        }
        query.cursor = page["next_cursor"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok());
        if query.cursor.is_none() {
            break;
        }
    }
    Ok(
        json!({"severity":severities.into_iter().map(|(key,doc_count)|json!({"key":key,"doc_count":doc_count})).collect::<Vec<_>>(),"templates":templates.into_iter().map(|(key,doc_count)|json!({"key":key,"doc_count":doc_count})).collect::<Vec<_>>(),"count":count,"semantics":"observation_counts; not unique confirmed vulnerabilities"}),
    )
}
