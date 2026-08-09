use actix_web::{HttpResponse, Responder, get, web};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use tracing::error;

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

fn validate_cidr(value: &str) -> Result<(), &'static str> {
    let Some((ip, prefix)) = value.split_once('/') else {
        return Err("CIDR 必须包含前缀长度");
    };
    let ip = IpAddr::from_str(ip).map_err(|_| "CIDR 中的 IP 地址格式无效")?;
    let prefix = prefix.parse::<u8>().map_err(|_| "CIDR 前缀长度格式无效")?;
    if prefix > if ip.is_ipv4() { 32 } else { 128 } {
        return Err("CIDR 前缀长度超出范围");
    }
    Ok(())
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
    query_type: &'static str,
    query: String,
    value: &str,
    where_clause: &str,
    limit: i64,
    offset: i64,
) -> Result<SearchResponse, Box<dyn std::error::Error>> {
    let client = pool.get().await?;
    let statement = format!(
        "SELECT latest.*, COUNT(*) OVER() AS total FROM (\
         SELECT DISTINCT ON (i.ip_address, p.port) i.ip_address::TEXT AS ip_address, \
         p.port, s.protocol, s.service, s.banner, s.scanner_name, s.scan_time, i.asn, i.isp \
         FROM ips i LEFT JOIN ports p ON p.ip_id = i.ip_id \
         LEFT JOIN scaninfo s ON s.port_id = p.port_id WHERE {where_clause} \
         ORDER BY i.ip_address, p.port NULLS LAST, s.scan_time DESC NULLS LAST\
         ) latest ORDER BY latest.ip_address, latest.port NULLS LAST LIMIT $2 OFFSET $3"
    );
    let rows = client.query(&statement, &[&value, &limit, &offset]).await?;
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
    query_type: &'static str,
    query: String,
    value: &str,
    where_clause: &str,
    limit: i64,
    offset: i64,
) -> HttpResponse {
    match search_assets(pool, query_type, query, value, where_clause, limit, offset).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(err) => {
            error!(event = "SearchDatabaseError", query_type, message = %err);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "搜索服务暂时不可用" }))
        }
    }
}

#[get("/api/search/ip")]
pub async fn search_ip(pool: web::Data<Pool>, query: web::Query<SearchQuery>) -> impl Responder {
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
        "ip",
        q.to_string(),
        q,
        "i.ip_address = $1::TEXT::INET",
        limit,
        offset,
    )
    .await
}

#[get("/api/search/network")]
pub async fn search_network(
    pool: web::Data<Pool>,
    query: web::Query<SearchQuery>,
) -> impl Responder {
    let q = query.q.trim();
    if let Err(message) = validate_cidr(q) {
        return bad_request(message);
    }
    let (limit, offset) = match pagination(query.limit, query.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    respond_search(
        pool.get_ref(),
        "network",
        q.to_string(),
        q,
        "i.ip_address <<= $1::TEXT::CIDR",
        limit,
        offset,
    )
    .await
}

#[get("/api/search/port")]
pub async fn search_port(
    pool: web::Data<Pool>,
    query: web::Query<PortSearchQuery>,
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
        "port",
        port.clone(),
        &port,
        "p.port = $1::TEXT::INTEGER",
        limit,
        offset,
    )
    .await
}

#[get("/api/search/service")]
pub async fn search_service(
    pool: web::Data<Pool>,
    query: web::Query<SearchQuery>,
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
        "service",
        q.to_string(),
        q,
        "s.service ILIKE '%' || $1 || '%'",
        limit,
        offset,
    )
    .await
}

#[get("/api/search/banner")]
pub async fn search_banner(
    pool: web::Data<Pool>,
    query: web::Query<SearchQuery>,
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
        "banner",
        q.to_string(),
        q,
        "s.banner ILIKE '%' || $1 || '%'",
        limit,
        offset,
    )
    .await
}
