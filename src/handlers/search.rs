use actix_web::{HttpResponse, Responder, get, web};
use deadpool_postgres::Pool;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use tracing::error;

use crate::admin::UserBaseI;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;
const MAX_OFFSET: i64 = 10_000;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Deserialize)]
pub struct PortSearchQuery {
    pub port: String,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Serialize)]
struct SearchResponse {
    query_type: &'static str,
    query: String,
    items: Vec<SearchItem>,
    total: i64,
    limit: i64,
    offset: i64,
}

#[derive(Serialize)]
struct SearchItem {
    ip_address: String,
    port: Option<i32>,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    scanner_name: Option<String>,
    scan_time: Option<i64>,
    asn: Option<String>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    city_name: Option<String>,
}

fn pagination(limit: Option<i64>, offset: Option<i64>) -> Result<(i64, i64), &'static str> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    let offset = offset.unwrap_or(0);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err("limit 必须在 1 到 100 之间");
    }
    if !(0..=MAX_OFFSET).contains(&offset) {
        return Err("offset 超出允许范围");
    }
    Ok((limit, offset))
}

fn validate_ip(value: &str) -> Result<(), &'static str> {
    IpAddr::from_str(value)
        .map(|_| ())
        .map_err(|_| "IP 地址格式无效")
}

fn normalize_cidr(value: &str) -> Result<String, &'static str> {
    let Some((ip, prefix)) = value.split_once('/') else {
        return Err("CIDR 必须包含前缀长度");
    };
    let ip = IpAddr::from_str(ip).map_err(|_| "CIDR 中的 IP 地址格式无效")?;
    let prefix = prefix.parse::<u8>().map_err(|_| "CIDR 前缀长度格式无效")?;
    if prefix > if ip.is_ipv4() { 32 } else { 128 } {
        return Err("CIDR 前缀长度超出范围");
    }
    Ok(IpNet::new(ip, prefix)
        .map_err(|_| "CIDR 前缀长度超出范围")?
        .trunc()
        .to_string())
}

fn validate_keyword(value: &str, name: &str) -> Result<(), String> {
    let length = value.chars().count();
    if !(2..=128).contains(&length) {
        return Err(format!("{} 的长度必须在 2 到 128 个字符之间", name));
    }
    Ok(())
}

fn bad_request(message: impl Into<String>) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({ "message": message.into() }))
}

async fn search_assets(
    pool: &Pool,
    user: &UserBaseI,
    query_type: &'static str,
    query: String,
    value: &str,
    where_clause: &str,
    pagination: (i64, i64),
) -> Result<SearchResponse, Box<dyn std::error::Error>> {
    let (limit, offset) = pagination;
    let client = pool.get().await?;
    let statement = format!(
        "SELECT latest.*, COUNT(*) OVER() AS total FROM (\
         SELECT DISTINCT ON (s.ip_address, s.port) host(s.ip_address) AS ip_address, \
         s.port, s.protocol, s.service, s.banner, \
         COALESCE(scanner.name, e.assigned_scanner_id, e.requested_scanner_id) AS scanner_name, \
         FLOOR(EXTRACT(EPOCH FROM s.observed_at) * 1000)::BIGINT AS scan_time, \
         i.asn, i.isp, i.as_org, i.country_code, i.country_name, i.city_name \
         FROM scan_observation s \
         JOIN scan_task_execution e ON e.id = s.execution_id \
         JOIN scan_task t ON t.id = e.task_id \
         LEFT JOIN scanner_info scanner ON scanner.scanner_id = COALESCE(e.assigned_scanner_id, e.requested_scanner_id) \
         LEFT JOIN ips i ON i.execution_id = s.execution_id AND i.ip_address = s.ip_address \
         WHERE {where_clause} AND e.execution_status <> 'superseded' AND ($2 = 1 OR t.user_id = $3) \
         ORDER BY s.ip_address, s.port, s.observed_at DESC, s.id DESC\
         ) latest ORDER BY latest.ip_address, latest.port LIMIT $4 OFFSET $5"
    );
    let rows = client
        .query(&statement, &[&value, &user.role, &user.id, &limit, &offset])
        .await?;
    let total = rows.first().map(|row| row.get("total")).unwrap_or(0);
    let items = rows
        .into_iter()
        .map(|row| SearchItem {
            ip_address: row.get("ip_address"),
            port: row.get("port"),
            protocol: row.get("protocol"),
            service: row.get("service"),
            banner: row.get("banner"),
            scanner_name: row.get("scanner_name"),
            scan_time: row.get("scan_time"),
            asn: row.get("asn"),
            isp: row.get("isp"),
            as_org: row.get("as_org"),
            country_code: row.get("country_code"),
            country_name: row.get("country_name"),
            city_name: row.get("city_name"),
        })
        .collect();
    Ok(SearchResponse {
        query_type,
        query,
        items,
        total,
        limit,
        offset,
    })
}

async fn respond_search(
    pool: &Pool,
    user: &UserBaseI,
    query_type: &'static str,
    query: String,
    value: &str,
    where_clause: &str,
    pagination: (i64, i64),
) -> HttpResponse {
    match search_assets(
        pool,
        user,
        query_type,
        query,
        value,
        where_clause,
        pagination,
    )
    .await
    {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(err) => {
            error!(event = "SearchDatabaseError", query_type, message = %err, error = ?err);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "搜索服务暂时不可用" }))
        }
    }
}

#[get("/api/search/ip")]
pub async fn search_ip(
    pool: web::Data<Pool>,
    query: web::Query<SearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let q = query.q.trim();
    if let Err(message) = validate_ip(q) {
        return bad_request(message);
    }
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    respond_search(
        pool.get_ref(),
        &user,
        "ip",
        q.to_string(),
        q,
        "s.ip_address = $1::TEXT::INET",
        (limit, offset),
    )
    .await
}

#[get("/api/search/network")]
pub async fn search_network(
    pool: web::Data<Pool>,
    query: web::Query<SearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let q = query.q.trim();
    let normalized_cidr = match normalize_cidr(q) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    respond_search(
        pool.get_ref(),
        &user,
        "network",
        q.to_string(),
        &normalized_cidr,
        "s.ip_address <<= $1::TEXT::INET",
        (limit, offset),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::normalize_cidr;

    #[test]
    fn normalizes_ipv4_cidr_with_host_bits() {
        assert_eq!(
            normalize_cidr("192.168.1.123/24"),
            Ok("192.168.1.0/24".to_owned())
        );
    }

    #[test]
    fn normalizes_ipv6_cidr_with_host_bits() {
        assert_eq!(
            normalize_cidr("2001:db8::1234/64"),
            Ok("2001:db8::/64".to_owned())
        );
    }

    #[test]
    fn rejects_out_of_range_prefixes() {
        assert_eq!(normalize_cidr("192.0.2.1/33"), Err("CIDR 前缀长度超出范围"));
        assert_eq!(
            normalize_cidr("2001:db8::1/129"),
            Err("CIDR 前缀长度超出范围")
        );
    }
}

#[get("/api/search/port")]
pub async fn search_port(
    pool: web::Data<Pool>,
    query: web::Query<PortSearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let port = match query.port.trim().parse::<u16>() {
        Ok(value @ 1..=65535) => value,
        _ => return bad_request("端口必须在 1 到 65535 之间"),
    };
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let port = port.to_string();
    respond_search(
        pool.get_ref(),
        &user,
        "port",
        port.clone(),
        &port,
        "s.port = $1::TEXT::INTEGER",
        (limit, offset),
    )
    .await
}

#[get("/api/search/service")]
pub async fn search_service(
    pool: web::Data<Pool>,
    query: web::Query<SearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let q = query.q.trim();
    if let Err(message) = validate_keyword(q, "服务名") {
        return bad_request(message);
    }
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    respond_search(
        pool.get_ref(),
        &user,
        "service",
        q.to_string(),
        q,
        "s.service ILIKE '%' || $1 || '%'",
        (limit, offset),
    )
    .await
}

#[get("/api/search/banner")]
pub async fn search_banner(
    pool: web::Data<Pool>,
    query: web::Query<SearchQuery>,
    user: UserBaseI,
) -> impl Responder {
    let q = query.q.trim();
    if let Err(message) = validate_keyword(q, "Banner 关键字") {
        return bad_request(message);
    }
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    respond_search(
        pool.get_ref(),
        &user,
        "banner",
        q.to_string(),
        q,
        "s.banner ILIKE '%' || $1 || '%'",
        (limit, offset),
    )
    .await
}
