use std::net::IpAddr;
use std::str::FromStr;

use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::admin::UserBaseI;
use crate::handlers::tags::{AssetTag, tags_from_json};
use crate::logs::write::error_logs;

const DEFAULT_PORT_LIMIT: i64 = 20;
const MAX_PORT_LIMIT: i64 = 100;
const DEFAULT_HISTORY_LIMIT: i64 = 50;
const MAX_HISTORY_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub(crate) struct AssetQuery {
    ip: String,
}

#[derive(Deserialize)]
pub(crate) struct AssetPortsQuery {
    ip: String,
    limit: Option<i64>,
    offset: Option<i64>,
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
struct AssetSummary {
    ip: String,
    asn: Option<String>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    port_count: i64,
    service_count: i64,
    scanner_count: i64,
    observation_count: i64,
    first_seen_at: Option<i64>,
    last_seen_at: Option<i64>,
    tags: Vec<AssetTag>,
    can_manage_tags: bool,
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

fn normalize_port_pagination(
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<(i64, i64), &'static str> {
    let limit = limit.unwrap_or(DEFAULT_PORT_LIMIT);
    let offset = offset.unwrap_or(0);
    if !(1..=MAX_PORT_LIMIT).contains(&limit) {
        return Err("limit 必须在 1 到 100 之间");
    }
    if !(0..=10_000).contains(&offset) {
        return Err("offset 超出允许范围");
    }
    Ok((limit, offset))
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

#[get("/api/assets/summary")]
pub(crate) async fn get_asset_summary(
    req: HttpRequest,
    pool: web::Data<Pool>,
    query: web::Query<AssetQuery>,
    user: UserBaseI,
) -> impl Responder {
    let ip = match normalize_ip(&query.ip) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "AssetSummaryPoolError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let row = match connection
        .query_one(
            "WITH eligible AS (\
                SELECT o.port, o.service, o.observed_at, \
                       COALESCE(scanner.name, e.assigned_scanner_id, e.requested_scanner_id) AS scanner_name \
                FROM scan_observation o \
                JOIN scan_task_execution e ON e.id = o.execution_id \
                JOIN scan_task t ON t.id = e.task_id \
                LEFT JOIN scanner_info scanner \
                    ON scanner.scanner_id = COALESCE(e.assigned_scanner_id, e.requested_scanner_id) \
                WHERE o.ip_address = $1::TEXT::INET \
                  AND e.execution_status = 'succeeded' \
                  AND ($2 = 1 OR t.user_id = $3)\
             ), endpoints AS (\
                SELECT port, MIN(observed_at) AS first_seen_at, MAX(observed_at) AS last_seen_at \
                FROM eligible WHERE port > 0 GROUP BY port\
             ), stats AS (\
                SELECT COUNT(*)::BIGINT AS port_count, \
                       FLOOR(EXTRACT(EPOCH FROM MIN(first_seen_at)) * 1000)::BIGINT AS first_seen_at, \
                       FLOOR(EXTRACT(EPOCH FROM MAX(last_seen_at)) * 1000)::BIGINT AS last_seen_at \
                FROM endpoints\
             ), latest_intel AS (\
                SELECT i.asn, i.isp, i.as_org, i.country_code, i.country_name, \
                       i.region_name, i.city_name \
                FROM ips i \
                JOIN scan_task_execution e ON e.id = i.execution_id \
                JOIN scan_task t ON t.id = e.task_id \
                WHERE i.ip_address = $1::TEXT::INET \
                  AND e.execution_status = 'succeeded' \
                  AND ($2 = 1 OR t.user_id = $3) \
                ORDER BY i.update_time DESC, i.ip_id DESC LIMIT 1\
             ), asset_tags AS (\
                SELECT COALESCE(JSONB_AGG(JSONB_BUILD_OBJECT(\
                    'id', tag.id, 'name', tag.name, 'kind', tag.kind, 'description', tag.description\
                    ) ORDER BY CASE tag.kind WHEN 'malicious' THEN 1 WHEN 'benign' THEN 2 ELSE 3 END, LOWER(tag.name), tag.id), '[]'::JSONB) AS tags \
                FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
                WHERE assignment.ip_address = $1::TEXT::INET AND tag.is_active\
             ) \
             SELECT stats.*, \
                    (SELECT COUNT(DISTINCT service)::BIGINT FROM eligible \
                     WHERE NULLIF(BTRIM(service), '') IS NOT NULL) AS service_count, \
                    (SELECT COUNT(DISTINCT scanner_name)::BIGINT FROM eligible \
                     WHERE scanner_name IS NOT NULL) AS scanner_count, \
                    (SELECT COUNT(*)::BIGINT FROM eligible) AS observation_count, \
                    latest_intel.asn, latest_intel.isp, latest_intel.as_org, \
                    latest_intel.country_code, latest_intel.country_name, \
                    latest_intel.region_name, latest_intel.city_name, \
                    asset_tags.tags \
             FROM stats LEFT JOIN latest_intel ON true CROSS JOIN asset_tags;",
            &[&ip, &user.role, &user.id],
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            error_logs(&req, "AssetSummaryQueryError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let observation_count = row.get("observation_count");
    if observation_count == 0_i64 {
        return HttpResponse::NotFound().json(serde_json::json!({
            "message": "没有可访问的资产观察记录"
        }));
    }

    let summary = AssetSummary {
        ip,
        asn: row.get("asn"),
        isp: row.get("isp"),
        as_org: row.get("as_org"),
        country_code: row.get("country_code"),
        country_name: row.get("country_name"),
        region_name: row.get("region_name"),
        city_name: row.get("city_name"),
        port_count: row.get("port_count"),
        service_count: row.get("service_count"),
        scanner_count: row.get("scanner_count"),
        observation_count,
        first_seen_at: row.get("first_seen_at"),
        last_seen_at: row.get("last_seen_at"),
        tags: tags_from_json(row.get("tags")),
        can_manage_tags: user.role == 1,
    };

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "summary": summary,
        }
    }))
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
    let (limit, offset) = match normalize_port_pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
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
                FROM eligible WHERE port > 0 GROUP BY port\
             ) \
             SELECT endpoint.port, latest.protocol, \
                    service.service, service.banner, latest.source, service.source AS service_source, \
                    FLOOR(EXTRACT(EPOCH FROM endpoint.first_seen_at) * 1000)::BIGINT AS first_seen_at, \
                    FLOOR(EXTRACT(EPOCH FROM endpoint.last_seen_at) * 1000)::BIGINT AS last_seen_at, \
                    FLOOR(EXTRACT(EPOCH FROM service.observed_at) * 1000)::BIGINT AS service_observed_at, \
                    COALESCE(service.observed_at < endpoint.last_seen_at, false) AS service_stale, \
                    latest.public_execution_id AS execution_id, latest.public_task_id AS task_id, \
                    COUNT(*) OVER()::BIGINT AS total \
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
             ORDER BY endpoint.port LIMIT $4 OFFSET $5;",
            &[&ip, &user.role, &user.id, &limit, &offset],
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

    let total = rows.first().map(|row| row.get("total")).unwrap_or(0_i64);
    let items: Vec<AssetPortCurrent> = rows
        .into_iter()
        .map(|row| AssetPortCurrent {
            port: row.get("port"),
            protocol: row.get("protocol"),
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
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
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
    use super::{normalize_history_pagination, normalize_ip, normalize_port_pagination};

    #[test]
    fn normalizes_asset_ip_addresses() {
        assert_eq!(normalize_ip(" 192.0.2.1 "), Ok("192.0.2.1".to_owned()));
        assert_eq!(normalize_ip("2001:0db8::1"), Ok("2001:db8::1".to_owned()));
        assert!(normalize_ip("192.0.2.0/24").is_err());
    }

    #[test]
    fn validates_asset_query_ranges() {
        assert_eq!(normalize_port_pagination(None, None), Ok((20, 0)));
        assert!(normalize_port_pagination(Some(101), None).is_err());
        assert_eq!(normalize_history_pagination(None, None), Ok((50, 0)));
        assert!(normalize_history_pagination(Some(101), None).is_err());
    }
}
