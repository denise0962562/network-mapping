use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;
use uuid::Uuid;

use crate::ReceiveSystemStatusInfo;
use crate::admin::UserBaseI;
use crate::logs::write::error_logs;
use crate::{SystemDetails, SystemStatusJson, Systems, get_system_status_info};

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
    query_info: web::Query<ReceiveSystemStatusInfo>,
    pool: web::Data<Pool>,
    systems: web::Data<Systems>,
) -> impl Responder {
    let p = pool.get_ref();

    let (t, c) = match get_system_status_info(
        query_info.start_at,
        query_info.end_at,
        query_info.count.unwrap_or(1),
        p,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            error!(
                event = "GetSystemStatusError",
                path = "fn get_system_data_handler",
                message = %e
            );
            return HttpResponse::InternalServerError().body("500 Internal Server Error");
        }
    };

    let t_json = SystemStatusJson {
        total_c: c,
        status_item: t,
        system_info: SystemDetails::new(systems.get_ref()),
    };

    HttpResponse::Ok().json(t_json)
}

#[get("/api/analysis/distribution")]
pub(crate) async fn get_analysis_distribution(
    req: HttpRequest,
    query: web::Query<DistributionQuery>,
    pool: web::Data<Pool>,
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
    let sql = format!(
        "WITH grouped AS (\
            SELECT {label_expression} AS label, \
                   COUNT(DISTINCT (s.execution_id, s.ip_address, s.port))::BIGINT AS endpoint_count \
            FROM scan_observation s \
            JOIN scan_task_execution e ON e.id = s.execution_id \
            JOIN scan_task t ON t.id = e.task_id \
            WHERE s.observed_at >= $1 AND s.observed_at < $2 \
              AND ($3 = 1 OR t.user_id = $4) \
              AND ($5::TEXT IS NULL OR e.assigned_scanner_id = $5) \
              AND ($6::TEXT IS NULL OR t.task_source = $6) \
              {additional_filter} \
            GROUP BY label\
        ) \
        SELECT label, endpoint_count, (SUM(endpoint_count) OVER ())::BIGINT AS total \
        FROM grouped ORDER BY endpoint_count DESC, label LIMIT $7;"
    );
    let rows = match client
        .query(
            &sql,
            &[
                &filters.start_at,
                &filters.end_at,
                &user.role,
                &user.id,
                &filters.scanner_id,
                &filters.task_source,
                &limit,
            ],
        )
        .await
    {
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
    user: UserBaseI,
) -> impl Responder {
    let filters = match normalize_filters(&query.filters) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(&req, "AnalysisHeatmapPoolError", &error_value.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let rows = match client
        .query(
            "SELECT to_char(\
                 (to_timestamp(i.create_time / 1000.0) AT TIME ZONE 'Asia/Shanghai')::DATE,\
                 'YYYY-MM-DD'\
             ) AS day, COUNT(DISTINCT i.ip_address)::BIGINT AS discovered_count \
             FROM ips i \
             JOIN scan_task t ON t.id = i.task_id \
             JOIN scan_task_execution e ON e.id = i.execution_id \
             WHERE i.create_time >= $1 AND i.create_time < $2 \
               AND ($3 = 1 OR t.user_id = $4) \
               AND ($5::TEXT IS NULL OR e.assigned_scanner_id = $5) \
               AND ($6::TEXT IS NULL OR t.task_source = $6) \
             GROUP BY day ORDER BY day;",
            &[
                &filters.start_ms,
                &filters.end_ms,
                &user.role,
                &user.id,
                &filters.scanner_id,
                &filters.task_source,
            ],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(&req, "AnalysisHeatmapQueryError", &error_value.to_string());
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

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        AnalysisFilterQuery, DistributionDimension, MAX_RANGE_DAYS, normalize_filters, percentage,
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
}
