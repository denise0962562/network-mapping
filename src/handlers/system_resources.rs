use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::admin::UserBaseI;
use crate::logs::write::error_logs;

const DEFAULT_RANGE_DAYS: i64 = 7;
const MAX_RANGE_DAYS: i64 = 30;
const MAX_BUCKETS: i64 = 1_500;
const RESOURCE_TIMEZONE: &str = "Asia/Shanghai";
const RESOURCE_HISTORY_SQL: &str = r#"
WITH bucket_range AS (
    SELECT generate_series(
        ($1::BIGINT / $3::BIGINT) * $3::BIGINT,
        (($2::BIGINT - 1) / $3::BIGINT) * $3::BIGINT,
        $3
    )::BIGINT AS bucket_start
), normalized AS (
    SELECT create_time,
        CASE WHEN jsonb_typeof(cpu->'cpu_usage') = 'number'
             THEN (cpu->>'cpu_usage')::DOUBLE PRECISION END AS cpu_usage,
        CASE WHEN jsonb_typeof(ram->'ram_usage') = 'number'
             THEN (ram->>'ram_usage')::DOUBLE PRECISION
             WHEN jsonb_typeof(ram->'used_ram') = 'number'
              AND jsonb_typeof(ram->'total_ram') = 'number'
              AND (ram->>'total_ram')::DOUBLE PRECISION > 0
             THEN (ram->>'used_ram')::DOUBLE PRECISION
                  / (ram->>'total_ram')::DOUBLE PRECISION * 100 END AS ram_usage,
        CASE WHEN jsonb_typeof(disk->'disk_total_usage') = 'number'
              AND jsonb_typeof(disk->'disk_total_space') = 'number'
              AND (disk->>'disk_total_space')::DOUBLE PRECISION > 0
             THEN (disk->>'disk_total_usage')::DOUBLE PRECISION
                  / (disk->>'disk_total_space')::DOUBLE PRECISION * 100 END AS disk_usage
    FROM system_status
    WHERE create_time >= $1 AND create_time < $2
), aggregated AS (
    SELECT (create_time / $3::BIGINT) * $3::BIGINT AS bucket_start,
        COUNT(*)::BIGINT AS sample_count,
        AVG(cpu_usage) FILTER (WHERE cpu_usage BETWEEN 0 AND 100) AS cpu_avg,
        MAX(cpu_usage) FILTER (WHERE cpu_usage BETWEEN 0 AND 100) AS cpu_max,
        AVG(ram_usage) FILTER (WHERE ram_usage BETWEEN 0 AND 100) AS ram_avg,
        MAX(ram_usage) FILTER (WHERE ram_usage BETWEEN 0 AND 100) AS ram_max,
        AVG(disk_usage) FILTER (WHERE disk_usage BETWEEN 0 AND 100) AS disk_avg,
        MAX(disk_usage) FILTER (WHERE disk_usage BETWEEN 0 AND 100) AS disk_max
    FROM normalized
    GROUP BY bucket_start
)
SELECT b.bucket_start,
       COALESCE(a.sample_count, 0)::BIGINT AS sample_count,
       a.cpu_avg,
       a.cpu_max,
       a.ram_avg,
       a.ram_max,
       a.disk_avg,
       a.disk_max
FROM bucket_range b
LEFT JOIN aggregated a USING (bucket_start)
ORDER BY b.bucket_start;
"#;

#[derive(Deserialize)]
pub(crate) struct ResourceHistoryQuery {
    start_at: Option<DateTime<Utc>>,
    end_at: Option<DateTime<Utc>>,
    granularity: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Granularity {
    OneMinute,
    FiveMinutes,
    FifteenMinutes,
    ThirtyMinutes,
    OneHour,
    TwoHours,
}

impl Granularity {
    fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "1m" => Ok(Self::OneMinute),
            "5m" => Ok(Self::FiveMinutes),
            "15m" => Ok(Self::FifteenMinutes),
            "30m" => Ok(Self::ThirtyMinutes),
            "1h" => Ok(Self::OneHour),
            "2h" => Ok(Self::TwoHours),
            _ => Err("granularity must be auto, 1m, 5m, 15m, 30m, 1h or 2h"),
        }
    }

    fn auto_for(duration: Duration) -> Self {
        if duration <= Duration::hours(6) {
            Self::OneMinute
        } else if duration <= Duration::hours(24) {
            Self::FiveMinutes
        } else if duration <= Duration::days(7) {
            Self::ThirtyMinutes
        } else {
            Self::TwoHours
        }
    }

    fn seconds(self) -> i64 {
        match self {
            Self::OneMinute => 60,
            Self::FiveMinutes => 300,
            Self::FifteenMinutes => 900,
            Self::ThirtyMinutes => 1_800,
            Self::OneHour => 3_600,
            Self::TwoHours => 7_200,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::OneMinute => "1m",
            Self::FiveMinutes => "5m",
            Self::FifteenMinutes => "15m",
            Self::ThirtyMinutes => "30m",
            Self::OneHour => "1h",
            Self::TwoHours => "2h",
        }
    }
}

struct NormalizedHistoryQuery {
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    granularity: Granularity,
}

#[derive(Serialize)]
struct ResourceHistoryPoint {
    timestamp_ms: i64,
    sample_count: i64,
    cpu_avg: Option<f64>,
    cpu_max: Option<f64>,
    ram_avg: Option<f64>,
    ram_max: Option<f64>,
    disk_avg: Option<f64>,
    disk_max: Option<f64>,
}

#[derive(Serialize)]
struct ResourceHistoryData {
    points: Vec<ResourceHistoryPoint>,
}

#[derive(Serialize)]
struct ResourceHistoryMeta {
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    granularity: &'static str,
    granularity_seconds: i64,
    timezone: &'static str,
    point_count: usize,
}

#[derive(Serialize)]
struct ResourceHistoryResponse {
    success: bool,
    data: ResourceHistoryData,
    meta: ResourceHistoryMeta,
}

fn normalize_query(query: &ResourceHistoryQuery) -> Result<NormalizedHistoryQuery, &'static str> {
    let end_at = query.end_at.unwrap_or_else(Utc::now);
    let start_at = query
        .start_at
        .unwrap_or_else(|| end_at - Duration::days(DEFAULT_RANGE_DAYS));
    if start_at >= end_at {
        return Err("start_at must be earlier than end_at");
    }

    let duration = end_at - start_at;
    if duration > Duration::days(MAX_RANGE_DAYS) {
        return Err("resource history range cannot exceed 30 days");
    }

    let granularity = match query.granularity.as_deref().unwrap_or("auto") {
        "auto" => Granularity::auto_for(duration),
        value => Granularity::parse(value)?,
    };
    let duration_seconds = duration.num_seconds();
    let bucket_count = (duration_seconds + granularity.seconds() - 1) / granularity.seconds();
    if bucket_count > MAX_BUCKETS {
        return Err("selected granularity produces more than 1500 data points");
    }

    Ok(NormalizedHistoryQuery {
        start_at,
        end_at,
        granularity,
    })
}

fn rounded(value: Option<f64>) -> Option<f64> {
    value.map(|number| (number * 100.0).round() / 100.0)
}

fn bad_request(message: &'static str) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({"success": false, "message": message}))
}

fn database_error_diagnostics(error: &tokio_postgres::Error) -> String {
    let Some(database_error) = error.as_db_error() else {
        return format!("{error:?}");
    };

    format!(
        "sqlstate={} message={} detail={} hint={} table={} column={} constraint={}",
        database_error.code().code(),
        database_error.message(),
        database_error.detail().unwrap_or("-"),
        database_error.hint().unwrap_or("-"),
        database_error.table().unwrap_or("-"),
        database_error.column().unwrap_or("-"),
        database_error.constraint().unwrap_or("-"),
    )
}

#[get("/api/data/system-resource-history")]
pub(crate) async fn get_system_resource_history(
    req: HttpRequest,
    query: web::Query<ResourceHistoryQuery>,
    pool: web::Data<Pool>,
    _user: UserBaseI,
) -> impl Responder {
    let normalized = match normalize_query(&query) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let client = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(
                &req,
                "SystemResourceHistoryPoolError",
                &error_value.to_string(),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let start_seconds = normalized.start_at.timestamp();
    let end_seconds = normalized.end_at.timestamp();
    let bucket_seconds = normalized.granularity.seconds();
    let rows = match client
        .query(
            RESOURCE_HISTORY_SQL,
            &[&start_seconds, &end_seconds, &bucket_seconds],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            error_logs(
                &req,
                "SystemResourceHistoryQueryError",
                &database_error_diagnostics(&error_value),
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let points: Vec<ResourceHistoryPoint> = rows
        .into_iter()
        .map(|row| ResourceHistoryPoint {
            timestamp_ms: row.get::<_, i64>("bucket_start") * 1_000,
            sample_count: row.get("sample_count"),
            cpu_avg: rounded(row.get("cpu_avg")),
            cpu_max: rounded(row.get("cpu_max")),
            ram_avg: rounded(row.get("ram_avg")),
            ram_max: rounded(row.get("ram_max")),
            disk_avg: rounded(row.get("disk_avg")),
            disk_max: rounded(row.get("disk_max")),
        })
        .collect();
    let point_count = points.len();

    HttpResponse::Ok().json(ResourceHistoryResponse {
        success: true,
        data: ResourceHistoryData { points },
        meta: ResourceHistoryMeta {
            start_at: normalized.start_at,
            end_at: normalized.end_at,
            granularity: normalized.granularity.label(),
            granularity_seconds: bucket_seconds,
            timezone: RESOURCE_TIMEZONE,
            point_count,
        },
    })
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};

    use super::{
        Granularity, RESOURCE_HISTORY_SQL, ResourceHistoryQuery, normalize_query, rounded,
    };

    fn query(duration: Duration, granularity: &str) -> ResourceHistoryQuery {
        let end_at = Utc.with_ymd_and_hms(2026, 8, 16, 12, 0, 0).unwrap();
        ResourceHistoryQuery {
            start_at: Some(end_at - duration),
            end_at: Some(end_at),
            granularity: Some(granularity.to_owned()),
        }
    }

    #[test]
    fn automatic_granularity_matches_supported_ranges() {
        assert_eq!(
            normalize_query(&query(Duration::hours(6), "auto"))
                .unwrap()
                .granularity,
            Granularity::OneMinute
        );
        assert_eq!(
            normalize_query(&query(Duration::hours(24), "auto"))
                .unwrap()
                .granularity,
            Granularity::FiveMinutes
        );
        assert_eq!(
            normalize_query(&query(Duration::days(7), "auto"))
                .unwrap()
                .granularity,
            Granularity::ThirtyMinutes
        );
        assert_eq!(
            normalize_query(&query(Duration::days(30), "auto"))
                .unwrap()
                .granularity,
            Granularity::TwoHours
        );
    }

    #[test]
    fn rejects_oversized_ranges_and_point_counts() {
        assert!(normalize_query(&query(Duration::days(31), "auto")).is_err());
        assert!(normalize_query(&query(Duration::days(7), "1m")).is_err());
    }

    #[test]
    fn rejects_invalid_boundaries_and_granularity() {
        assert!(normalize_query(&query(Duration::hours(1), "10m")).is_err());
        let mut inverted = query(Duration::hours(1), "auto");
        inverted.start_at = inverted.end_at;
        assert!(normalize_query(&inverted).is_err());
    }

    #[test]
    fn rounds_optional_metrics() {
        assert_eq!(rounded(Some(12.345)), Some(12.35));
        assert_eq!(rounded(None), None);
    }

    #[test]
    fn history_query_keeps_sql_clause_boundaries() {
        assert!(RESOURCE_HISTORY_SQL.contains("FROM system_status"));
        assert!(RESOURCE_HISTORY_SQL.contains("FROM normalized"));
        assert!(RESOURCE_HISTORY_SQL.contains("FROM bucket_range"));
        assert!(!RESOURCE_HISTORY_SQL.contains("usageFROM"));
        assert!(!RESOURCE_HISTORY_SQL.contains("maxFROM"));
    }
}
