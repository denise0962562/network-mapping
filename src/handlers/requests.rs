use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::admin::UserBaseI;
use crate::logs::write::error_logs;

/// 请求日志查询过滤。`$9` 为「仅看错误」开关：开启时过滤 `error_level <> 'ok'`。
const FILTER_SQL: &str = "
    WHERE ($1::TEXT IS NULL OR http_method = $1)
      AND ($2::TEXT IS NULL OR request_path ILIKE '%' || $2 || '%')
      AND ($3::SMALLINT IS NULL OR status_code = $3)
      AND ($4::TEXT IS NULL OR error_level = $4)
      AND ($5::TEXT IS NULL OR error_type = $5)
      AND ($6::UUID IS NULL OR request_id = $6)
      AND ($7::TIMESTAMPTZ IS NULL OR occurred_at >= $7)
      AND ($8::TIMESTAMPTZ IS NULL OR occurred_at <= $8)
      AND ($9::BOOLEAN IS NULL OR error_level <> 'ok')";

#[derive(Deserialize)]
pub struct RequestQuery {
    method: Option<String>,
    path: Option<String>,
    status: Option<i16>,
    error_level: Option<String>,
    error_type: Option<String>,
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
    request_id: Option<Uuid>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    only_errors: Option<bool>,
    /// 预设延迟窗口：`1h` / `24h` / `7d`；提供时覆盖任意 start/end 并启用 P95/P99。
    window: Option<String>,
}

fn is_admin(user: &UserBaseI) -> bool {
    user.role == 1
}

fn pagination(page: Option<i64>, page_size: Option<i64>) -> (i64, i64) {
    (
        page.unwrap_or(1).max(1),
        page_size.unwrap_or(25).clamp(1, 100),
    )
}

fn filter_params<'a>(
    query: &'a dyn RequestFilter,
    start: &'a Option<DateTime<Utc>>,
    end: &'a Option<DateTime<Utc>>,
) -> Vec<&'a (dyn ToSql + Sync)> {
    vec![
        query.method(),
        query.path(),
        query.status(),
        query.error_level(),
        query.error_type(),
        query.request_id(),
        start,
        end,
        query.only_errors(),
    ]
}

/// 两个查询结构体共享过滤字段的读取接口，避免手写两遍参数列表。
trait RequestFilter {
    fn method(&self) -> &Option<String>;
    fn path(&self) -> &Option<String>;
    fn status(&self) -> &Option<i16>;
    fn error_level(&self) -> &Option<String>;
    fn error_type(&self) -> &Option<String>;
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

fn trend_bucket(start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> &'static str {
    match (start, end) {
        (Some(start), Some(end)) => {
            let span_seconds = (end - start).num_seconds();
            if span_seconds <= 2 * 3600 {
                "minute"
            } else if span_seconds <= 2 * 24 * 3600 {
                "hour"
            } else {
                "day"
            }
        }
        _ => "hour",
    }
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
        "client_ip": row.get::<_, Option<String>>("client_ip"),
        "user_agent": row.get::<_, Option<String>>("user_agent"),
        "actor_id": row.get::<_, Option<i32>>("actor_id"),
        "actor_name": row.get::<_, Option<String>>("actor_name"),
        "error_level": row.get::<_, String>("error_level"),
        "error_type": row.get::<_, Option<String>>("error_type"),
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
            error_logs(&req, "RequestsQueryPoolError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let params = filter_params(&*query, &query.start, &query.end);
    let count_sql = format!("SELECT COUNT(*) FROM request_log {FILTER_SQL}");
    let total: i64 = match client.query_one(&count_sql, &params).await {
        Ok(row) => row.get(0),
        Err(error_value) => {
            error_logs(&req, "RequestsQueryError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let list_sql = format!(
        "SELECT id, request_id, occurred_at, http_method, request_path, status_code, duration_ms, \
         client_ip::TEXT AS client_ip, user_agent, actor_id, actor_name, error_level, error_type \
         FROM request_log {FILTER_SQL} ORDER BY occurred_at DESC, id DESC LIMIT $10 OFFSET $11"
    );
    let mut list_params = params;
    list_params.push(&page_size);
    list_params.push(&offset);
    let rows = match client.query(&list_sql, &list_params).await {
        Ok(rows) => rows,
        Err(error_value) => {
            error_logs(&req, "RequestsQueryError", &error_value.to_string());
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

    let client = match pool.get().await {
        Ok(client) => client,
        Err(error_value) => {
            error_logs(&req, "RequestsSummaryPoolError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let params = filter_params(&*query, &start, &end);

    // 计数聚合（任意范围 + 过滤）。
    let counts_sql = format!(
        "SELECT COUNT(*) AS total, \
                COUNT(*) FILTER (WHERE error_level = 'client_error') AS client_errors, \
                COUNT(*) FILTER (WHERE error_level = 'server_error') AS server_errors \
         FROM request_log {FILTER_SQL}"
    );
    let (total, client_errors, server_errors): (i64, i64, i64) = match client
        .query_one(&counts_sql, &params)
        .await
    {
        Ok(row) => (row.get(0), row.get(1), row.get(2)),
        Err(error_value) => {
            error_logs(&req, "RequestsSummaryError", &error_value.to_string());
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
        "SELECT error_type, COUNT(*) AS count FROM request_log \
         {FILTER_SQL} AND error_type IS NOT NULL GROUP BY error_type ORDER BY count DESC LIMIT 20"
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
            error_logs(&req, "RequestsSummaryError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    // 趋势（date_trunc 分桶），桶粒度随窗口跨度自适应。
    let bucket = trend_bucket(start, end);
    let trend_sql = format!(
        "SELECT date_trunc($10::text, occurred_at) AS bucket, COUNT(*) AS total, \
                COUNT(*) FILTER (WHERE error_level = 'client_error') AS client_errors, \
                COUNT(*) FILTER (WHERE error_level = 'server_error') AS server_errors \
         FROM request_log {FILTER_SQL} GROUP BY bucket ORDER BY bucket"
    );
    let mut trend_params = params.clone();
    trend_params.push(&bucket);
    let trend: Vec<Value> = match client.query(&trend_sql, &trend_params).await {
        Ok(rows) => rows
            .iter()
            .map(|row| {
                json!({
                    "bucket": row.get::<_, DateTime<Utc>>("bucket"),
                    "total": row.get::<_, i64>("total"),
                    "client_errors": row.get::<_, i64>("client_errors"),
                    "server_errors": row.get::<_, i64>("server_errors"),
                })
            })
            .collect(),
        Err(error_value) => {
            error_logs(&req, "RequestsSummaryError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    // 延迟 P95/P99：仅预设窗口（避免任意范围 × 任意过滤 × 实时分位数的全表扫描）。
    let (p95, p99) = match effective_range {
        Some(_) => {
            let percentile_sql = format!(
                "SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95, \
                        percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms) AS p99 \
                 FROM request_log {FILTER_SQL} AND duration_ms IS NOT NULL"
            );
            match client.query_one(&percentile_sql, &params).await {
                Ok(row) => (
                    row.get::<_, Option<f64>>(0),
                    row.get::<_, Option<f64>>(1),
                ),
                Err(error_value) => {
                    error_logs(&req, "RequestsSummaryError", &error_value.to_string());
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
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::{trend_bucket, window_range};
    use chrono::{Duration, Utc};

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
    fn trend_bucket_adapts_to_span() {
        let now = Utc::now();
        assert_eq!(trend_bucket(Some(now - Duration::hours(1)), Some(now)), "minute");
        assert_eq!(trend_bucket(Some(now - Duration::hours(24)), Some(now)), "hour");
        assert_eq!(trend_bucket(Some(now - Duration::days(7)), Some(now)), "day");
        assert_eq!(trend_bucket(None, None), "hour");
    }
}
