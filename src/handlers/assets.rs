use std::net::IpAddr;
use std::str::FromStr;

use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use chrono::{Duration, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::admin::UserBaseI;
use crate::logs::write::error_logs;

const DEFAULT_STALE_AFTER_DAYS: i64 = 30;
const DEFAULT_HISTORY_LIMIT: i64 = 50;
const MAX_HISTORY_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub(crate) struct AssetPortsQuery {
    ip: String,
    stale_after_days: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct AssetPortHistoryQuery {
    ip: String,
    port: u16,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Serialize)]
struct AssetPortCurrent {
    port: i32,
    protocol: Option<String>,
    state: String,
    service: Option<String>,
    banner: Option<String>,
    source: String,
    service_source: Option<String>,
    first_seen_at: i64,
    last_seen_at: i64,
    service_observed_at: Option<i64>,
    service_stale: bool,
    execution_id: String,
    task_id: String,
}

#[derive(Serialize)]
struct AssetObservationHistoryItem {
    id: i64,
    kind: String,
    state: String,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    source: String,
    data: Option<Value>,
    observed_at: i64,
    execution_id: String,
    task_id: String,
    scanner_name: Option<String>,
    upload_id: String,
    batch_index: i32,
}

fn normalize_ip(value: &str) -> Result<String, &'static str> {
    IpAddr::from_str(value.trim())
        .map(|address| address.to_string())
        .map_err(|_| "IP 地址格式无效")
}

fn normalize_stale_after_days(value: Option<i64>) -> Result<i64, &'static str> {
    let value = value.unwrap_or(DEFAULT_STALE_AFTER_DAYS);
    if !(1..=3650).contains(&value) {
        return Err("stale_after_days 必须在 1 到 3650 之间");
    }
    Ok(value)
}

fn normalize_history_pagination(
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<(i64, i64), &'static str> {
    let limit = limit.unwrap_or(DEFAULT_HISTORY_LIMIT);
    let offset = offset.unwrap_or(0);
    if !(1..=MAX_HISTORY_LIMIT).contains(&limit) {
        return Err("limit 必须在 1 到 100 之间");
    }
    if !(0..=10_000).contains(&offset) {
        return Err("offset 超出允许范围");
    }
    Ok((limit, offset))
}

fn bad_request(message: &'static str) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({"message": message}))
}

#[get("/api/assets/ports")]
pub(crate) async fn get_asset_ports(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<AssetPortsQuery>,
    user: UserBaseI,
) -> impl Responder {
    let ip = match normalize_ip(&query.ip) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let stale_after_days = match normalize_stale_after_days(query.stale_after_days) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let stale_before = Utc::now() - Duration::days(stale_after_days);
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "AssetPortsPoolError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let rows = match connection
        .query(
            "WITH eligible AS (\
                SELECT o.*, e.execution_id AS public_execution_id, t.task_id AS public_task_id \
                FROM scan_observation o \
                JOIN scan_task_execution e ON e.id = o.execution_id \
                JOIN scan_task t ON t.id = e.task_id \
                WHERE o.ip_address = $1::TEXT::INET \
                  AND e.execution_status = 'succeeded' \
                  AND ($2 = 1 OR t.user_id = $3)\
             ), endpoint AS (\
                SELECT port, MIN(observed_at) AS first_seen_at, MAX(observed_at) AS last_seen_at \
                FROM eligible GROUP BY port\
             ) \
             SELECT endpoint.port, latest.protocol, \
                    CASE WHEN endpoint.last_seen_at < $4 THEN 'stale' ELSE 'open' END AS state, \
                    service.service, service.banner, latest.source, service.source AS service_source, \
                    FLOOR(EXTRACT(EPOCH FROM endpoint.first_seen_at) * 1000)::BIGINT AS first_seen_at, \
                    FLOOR(EXTRACT(EPOCH FROM endpoint.last_seen_at) * 1000)::BIGINT AS last_seen_at, \
                    FLOOR(EXTRACT(EPOCH FROM service.observed_at) * 1000)::BIGINT AS service_observed_at, \
                    COALESCE(service.observed_at < endpoint.last_seen_at, false) AS service_stale, \
                    latest.public_execution_id AS execution_id, latest.public_task_id AS task_id \
             FROM endpoint \
             JOIN LATERAL (\
                SELECT protocol, source, observed_at, id, public_execution_id, public_task_id \
                FROM eligible WHERE eligible.port = endpoint.port \
                ORDER BY observed_at DESC, id DESC LIMIT 1\
             ) latest ON true \
             LEFT JOIN LATERAL (\
                SELECT service, banner, source, observed_at, id \
                FROM eligible WHERE eligible.port = endpoint.port AND kind = 'service' \
                ORDER BY observed_at DESC, id DESC LIMIT 1\
             ) service ON true \
             ORDER BY endpoint.port;",
            &[&ip, &user.role, &user.id, &stale_before],
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "AssetPortsQueryError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    if rows.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "message": "没有可访问的资产观察记录"
        }));
    }

    let items: Vec<AssetPortCurrent> = rows
        .into_iter()
        .map(|row| AssetPortCurrent {
            port: row.get("port"),
            protocol: row.get("protocol"),
            state: row.get("state"),
            service: row.get("service"),
            banner: row.get("banner"),
            source: row.get("source"),
            service_source: row.get("service_source"),
            first_seen_at: row.get("first_seen_at"),
            last_seen_at: row.get("last_seen_at"),
            service_observed_at: row.get("service_observed_at"),
            service_stale: row.get("service_stale"),
            execution_id: row.get("execution_id"),
            task_id: row.get("task_id"),
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "ip": ip,
            "stale_after_days": stale_after_days,
            "items": items,
        }
    }))
}

#[get("/api/assets/port-history")]
pub(crate) async fn get_asset_port_history(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<AssetPortHistoryQuery>,
    user: UserBaseI,
) -> impl Responder {
    let ip = match normalize_ip(&query.ip) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    if query.port == 0 {
        return bad_request("端口必须在 1 到 65535 之间");
    }
    let (limit, offset) = match normalize_history_pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let port = i32::from(query.port);
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "AssetPortHistoryPoolError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let rows = match connection
        .query(
            "SELECT o.id, o.kind, COALESCE(o.data->>'state', 'open') AS state, \
                    o.protocol, o.service, o.banner, o.source, o.data, \
                    FLOOR(EXTRACT(EPOCH FROM o.observed_at) * 1000)::BIGINT AS observed_at, \
                    e.execution_id, t.task_id, \
                    COALESCE(scanner.name, e.assigned_scanner_id, e.requested_scanner_id) AS scanner_name, \
                    b.upload_id, b.batch_index, COUNT(*) OVER()::BIGINT AS total \
             FROM scan_observation o \
             JOIN scan_result_batch b ON b.id = o.batch_id \
             JOIN scan_task_execution e ON e.id = o.execution_id \
             JOIN scan_task t ON t.id = e.task_id \
             LEFT JOIN scanner_info scanner \
                ON scanner.scanner_id = COALESCE(e.assigned_scanner_id, e.requested_scanner_id) \
             WHERE o.ip_address = $1::TEXT::INET AND o.port = $2 \
               AND e.execution_status <> 'superseded' \
               AND ($3 = 1 OR t.user_id = $4) \
             ORDER BY o.observed_at DESC, o.id DESC LIMIT $5 OFFSET $6;",
            &[&ip, &port, &user.role, &user.id, &limit, &offset],
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "AssetPortHistoryQueryError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let total = rows.first().map(|row| row.get("total")).unwrap_or(0_i64);
    let items: Vec<AssetObservationHistoryItem> = rows
        .into_iter()
        .map(|row| AssetObservationHistoryItem {
            id: row.get("id"),
            kind: row.get("kind"),
            state: row.get("state"),
            protocol: row.get("protocol"),
            service: row.get("service"),
            banner: row.get("banner"),
            source: row.get("source"),
            data: row.get("data"),
            observed_at: row.get("observed_at"),
            execution_id: row.get("execution_id"),
            task_id: row.get("task_id"),
            scanner_name: row.get("scanner_name"),
            upload_id: row.get("upload_id"),
            batch_index: row.get("batch_index"),
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "ip": ip,
            "port": port,
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::{normalize_history_pagination, normalize_ip, normalize_stale_after_days};

    #[test]
    fn normalizes_asset_ip_addresses() {
        assert_eq!(normalize_ip(" 192.0.2.1 "), Ok("192.0.2.1".to_owned()));
        assert_eq!(normalize_ip("2001:0db8::1"), Ok("2001:db8::1".to_owned()));
        assert!(normalize_ip("192.0.2.0/24").is_err());
    }

    #[test]
    fn validates_asset_query_ranges() {
        assert_eq!(normalize_stale_after_days(None), Ok(30));
        assert!(normalize_stale_after_days(Some(0)).is_err());
        assert_eq!(normalize_history_pagination(None, None), Ok((50, 0)));
        assert!(normalize_history_pagination(Some(101), None).is_err());
    }
}
