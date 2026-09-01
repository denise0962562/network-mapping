use actix_web::{HttpResponse, Responder, get, post, web};
use deadpool_postgres::Pool;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use tokio_postgres::types::ToSql;
use tracing::error;

use crate::admin::UserBaseI;
use crate::elasticsearch::ElasticsearchService;
use crate::handlers::search_dsl::{
    ElasticsearchCompilation, parse_and_compile, parse_and_compile_elasticsearch,
};
use crate::handlers::tags::{AssetTag, tags_from_json};

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

#[derive(Deserialize)]
pub struct AdvancedSearchRequest {
    pub query: String,
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
    title: Option<String>,
    tls_subject: Option<String>,
    scanner_name: Option<String>,
    scan_time: Option<i64>,
    asn: Option<String>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    tags: Vec<AssetTag>,
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

#[get("/api/search/elasticsearch/status")]
pub async fn elasticsearch_status(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"message": "仅管理员可以查看搜索索引状态"}));
    }
    match elasticsearch.status(pool.get_ref()).await {
        Ok(status) => HttpResponse::Ok().json(status),
        Err(error_value) => {
            error!(event = "ElasticsearchStatusError", message = %error_value);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"message": "无法读取搜索索引状态"}))
        }
    }
}

#[post("/api/search/v2")]
pub async fn search_v2(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    payload: web::Json<AdvancedSearchRequest>,
    user: UserBaseI,
) -> impl Responder {
    let query = payload.query.trim();
    let (limit, offset) = match pagination(payload.limit, payload.offset) {
        Ok(value) => value,
        Err(message) => return bad_request(message),
    };
    let compiled = match parse_and_compile(query) {
        Ok(value) => value,
        Err(error_value) => {
            let utf16_offset = |byte_offset: usize| {
                query
                    .get(..byte_offset)
                    .map(|value| value.encode_utf16().count())
                    .unwrap_or_else(|| query.encode_utf16().count())
            };
            return HttpResponse::UnprocessableEntity().json(serde_json::json!({
                "code": "SEARCH_SYNTAX_ERROR",
                "message": error_value.message,
                "span": {
                    "start": utf16_offset(error_value.start),
                    "end": utf16_offset(error_value.end),
                },
            }));
        }
    };

    let elasticsearch_compilation = parse_and_compile_elasticsearch(query)
        .expect("PostgreSQL and Elasticsearch parsers share the validated syntax tree");
    if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        return match elasticsearch_compilation {
            ElasticsearchCompilation::Supported(filter) => respond_search_elasticsearch(
                elasticsearch.get_ref(), &user, "advanced", query.to_owned(), filter, (limit, offset),
            ).await,
            ElasticsearchCompilation::RequiresPostgres => HttpResponse::UnprocessableEntity().json(
                serde_json::json!({"code": "SEARCH_ES_UNSUPPORTED", "message": "该查询暂不支持 Elasticsearch 读路径"}),
            ),
        };
    }

    if let ElasticsearchCompilation::Supported(filter) = elasticsearch_compilation {
        if elasticsearch.can_read() {
            match elasticsearch
                .search(user.role, user.id, filter, limit, offset)
                .await
            {
                Ok(page) => {
                    let items = page
                        .items
                        .into_iter()
                        .map(|item| SearchItem {
                            ip_address: item.ip_address,
                            port: Some(item.port),
                            protocol: item.protocol,
                            service: item.service,
                            banner: item.banner,
                            title: item.title,
                            tls_subject: item.tls_subject,
                            scanner_name: item.scanner_name,
                            scan_time: Some(item.scan_time),
                            asn: item.asn,
                            isp: item.isp,
                            as_org: item.as_org,
                            country_code: item.country_code,
                            country_name: item.country_name,
                            region_name: item.region_name,
                            city_name: item.city_name,
                            tags: item.tags,
                        })
                        .collect();
                    return HttpResponse::Ok().json(SearchResponse {
                        query_type: "advanced",
                        query: query.to_owned(),
                        items,
                        total: page.total,
                        limit,
                        offset,
                    });
                }
                Err(err) if elasticsearch.fallback_to_postgres() => {
                    error!(event = "ElasticsearchSearchFallback", message = %err, error = ?err);
                }
                Err(err) => {
                    error!(event = "ElasticsearchSearchError", message = %err, error = ?err);
                    return HttpResponse::ServiceUnavailable()
                        .json(serde_json::json!({"message": "搜索索引暂时不可用"}));
                }
            }
        } else if !elasticsearch.fallback_to_postgres() {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"message": "搜索索引暂时不可用"}));
        }
    }

    let limit_parameter = compiled.parameters.len() + 3;
    let offset_parameter = compiled.parameters.len() + 4;
    let statement = format!(
        "WITH search_rows AS (\
            SELECT current.ip_address, current.port, current.protocol, current.service, \
                   current.banner, current.title, current.http_body, current.tls_subject, \
                   current.source, current.scanner_name, current.first_seen_at, current.last_seen_at, \
                   current.asn, current.isp, current.as_org, current.country_code, \
                   current.country_name, current.region_name, current.city_name \
            FROM asset_endpoint_current current \
            WHERE (($1 = 1 AND current.scope_type = 'global' AND current.scope_id = 0) \
                OR ($1 <> 1 AND current.scope_type = 'user' AND current.scope_id = $2))\
         ), filtered AS (\
            SELECT result.*, COUNT(*) OVER()::BIGINT AS total \
            FROM search_rows result WHERE {} \
            ORDER BY result.last_seen_at DESC, result.ip_address, result.port \
            LIMIT ${} OFFSET ${}\
         ) \
         SELECT host(filtered.ip_address) AS ip_address, filtered.port, filtered.protocol, \
                filtered.service, filtered.banner, filtered.title, filtered.tls_subject, filtered.scanner_name, \
                FLOOR(EXTRACT(EPOCH FROM filtered.last_seen_at) * 1000)::BIGINT AS scan_time, \
                filtered.asn, filtered.isp, filtered.as_org, filtered.country_code, \
                filtered.country_name, filtered.region_name, filtered.city_name, filtered.total, \
                COALESCE(tag_data.tags, '[]'::JSONB) AS tags \
         FROM filtered \
         LEFT JOIN LATERAL (\
            SELECT JSONB_AGG(JSONB_BUILD_OBJECT(\
                'id', tag.id, 'name', tag.name, 'kind', tag.kind, 'description', tag.description, \
                'category_id', category.id, 'category_name', category.name\
            ) ORDER BY category.sort_order, LOWER(category.name), CASE tag.kind WHEN 'malicious' THEN 1 WHEN 'benign' THEN 2 ELSE 3 END, LOWER(tag.name), tag.id) AS tags \
            FROM asset_ip_tag assignment \
            JOIN asset_tag tag ON tag.id = assignment.tag_id \
            JOIN asset_tag_category category ON category.id = tag.category_id \
            WHERE assignment.ip_address = filtered.ip_address AND tag.is_active AND category.is_active\
         ) tag_data ON true \
         ORDER BY filtered.last_seen_at DESC, filtered.ip_address, filtered.port",
        compiled.sql, limit_parameter, offset_parameter
    );

    let client = match pool.get().await {
        Ok(value) => value,
        Err(err) => {
            error!(event = "AdvancedSearchPoolError", message = %err, error = ?err);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "搜索服务暂时不可用" }));
        }
    };
    let mut parameters: Vec<&(dyn ToSql + Sync)> =
        Vec::with_capacity(compiled.parameters.len() + 4);
    parameters.push(&user.role);
    parameters.push(&user.id);
    parameters.extend(
        compiled
            .parameters
            .iter()
            .map(|value| value as &(dyn ToSql + Sync)),
    );
    parameters.push(&limit);
    parameters.push(&offset);
    let rows = match client.query(&statement, &parameters).await {
        Ok(value) => value,
        Err(err) => {
            error!(event = "AdvancedSearchDatabaseError", message = %err, error = ?err);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "搜索服务暂时不可用" }));
        }
    };
    let total = rows.first().map(|row| row.get("total")).unwrap_or(0);
    let items = rows
        .into_iter()
        .map(|row| SearchItem {
            ip_address: row.get("ip_address"),
            port: row.get("port"),
            protocol: row.get("protocol"),
            service: row.get("service"),
            banner: row.get("banner"),
            title: row.get("title"),
            tls_subject: row.get("tls_subject"),
            scanner_name: row.get("scanner_name"),
            scan_time: row.get("scan_time"),
            asn: row.get("asn"),
            isp: row.get("isp"),
            as_org: row.get("as_org"),
            country_code: row.get("country_code"),
            country_name: row.get("country_name"),
            region_name: row.get("region_name"),
            city_name: row.get("city_name"),
            tags: tags_from_json(row.get("tags")),
        })
        .collect();

    HttpResponse::Ok().json(SearchResponse {
        query_type: "advanced",
        query: query.to_owned(),
        items,
        total,
        limit,
        offset,
    })
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
         SELECT host(s.ip_address) AS ip_address, s.port, s.protocol, s.service, s.banner, \
         s.title, s.tls_subject, s.scanner_name, \
         FLOOR(EXTRACT(EPOCH FROM s.last_seen_at) * 1000)::BIGINT AS scan_time, \
         s.asn, s.isp, s.as_org, s.country_code, s.country_name, s.region_name, s.city_name, \
         COALESCE(tag_data.tags, '[]'::JSONB) AS tags \
         FROM asset_endpoint_current s \
         LEFT JOIN LATERAL (SELECT JSONB_AGG(JSONB_BUILD_OBJECT(\
             'id', tag.id, 'name', tag.name, 'kind', tag.kind, 'description', tag.description, \
             'category_id', category.id, 'category_name', category.name\
             ) ORDER BY category.sort_order, LOWER(category.name), CASE tag.kind WHEN 'malicious' THEN 1 WHEN 'benign' THEN 2 ELSE 3 END, LOWER(tag.name), tag.id) AS tags \
             FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
             JOIN asset_tag_category category ON category.id = tag.category_id \
             WHERE assignment.ip_address = s.ip_address AND tag.is_active AND category.is_active) tag_data ON true \
         WHERE {where_clause} AND (($2 = 1 AND s.scope_type = 'global' AND s.scope_id = 0) \
             OR ($2 <> 1 AND s.scope_type = 'user' AND s.scope_id = $3)) \
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
            title: row.get("title"),
            tls_subject: row.get("tls_subject"),
            scanner_name: row.get("scanner_name"),
            scan_time: row.get("scan_time"),
            asn: row.get("asn"),
            isp: row.get("isp"),
            as_org: row.get("as_org"),
            country_code: row.get("country_code"),
            country_name: row.get("country_name"),
            region_name: row.get("region_name"),
            city_name: row.get("city_name"),
            tags: tags_from_json(row.get("tags")),
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

async fn respond_search_elasticsearch(
    elasticsearch: &ElasticsearchService,
    user: &UserBaseI,
    query_type: &'static str,
    query: String,
    filter: serde_json::Value,
    pagination: (i64, i64),
) -> HttpResponse {
    let (limit, offset) = pagination;
    match elasticsearch
        .search(user.role, user.id, filter, limit, offset)
        .await
    {
        Ok(page) => HttpResponse::Ok().json(SearchResponse {
            query_type,
            query,
            items: page
                .items
                .into_iter()
                .map(|item| SearchItem {
                    ip_address: item.ip_address,
                    port: Some(item.port),
                    protocol: item.protocol,
                    service: item.service,
                    banner: item.banner,
                    title: item.title,
                    tls_subject: item.tls_subject,
                    scanner_name: item.scanner_name,
                    scan_time: Some(item.scan_time),
                    asn: item.asn,
                    isp: item.isp,
                    as_org: item.as_org,
                    country_code: item.country_code,
                    country_name: item.country_name,
                    region_name: item.region_name,
                    city_name: item.city_name,
                    tags: item.tags,
                })
                .collect(),
            total: page.total,
            limit,
            offset,
        }),
        Err(error_value) => {
            error!(event = "SearchElasticsearchError", query_type, message = %error_value);
            HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"message": "搜索索引暂时不可用"}))
        }
    }
}

#[get("/api/search/ip")]
pub async fn search_ip(
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
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
    if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        return respond_search_elasticsearch(
            elasticsearch.get_ref(),
            &user,
            "ip",
            q.to_owned(),
            serde_json::json!({"term": {"ip": q}}),
            (limit, offset),
        )
        .await;
    }
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
    elasticsearch: web::Data<ElasticsearchService>,
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
    if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        return respond_search_elasticsearch(
            elasticsearch.get_ref(),
            &user,
            "network",
            q.to_owned(),
            serde_json::json!({"term": {"ip": normalized_cidr}}),
            (limit, offset),
        )
        .await;
    }
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
    elasticsearch: web::Data<ElasticsearchService>,
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
    if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        return respond_search_elasticsearch(
            elasticsearch.get_ref(),
            &user,
            "port",
            port.to_string(),
            serde_json::json!({"term": {"port": port}}),
            (limit, offset),
        )
        .await;
    }
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
    elasticsearch: web::Data<ElasticsearchService>,
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
    if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        let escaped = q
            .replace('\\', "\\\\")
            .replace('*', "\\*")
            .replace('?', "\\?");
        return respond_search_elasticsearch(
            elasticsearch.get_ref(), &user, "service", q.to_owned(),
            serde_json::json!({"wildcard": {"service": {"value": format!("*{escaped}*"), "case_insensitive": true}}}),
            (limit, offset),
        ).await;
    }
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
    elasticsearch: web::Data<ElasticsearchService>,
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
    if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        let escaped = q
            .replace('\\', "\\\\")
            .replace('*', "\\*")
            .replace('?', "\\?");
        return respond_search_elasticsearch(
            elasticsearch.get_ref(), &user, "banner", q.to_owned(),
            serde_json::json!({"wildcard": {"banner": {"value": format!("*{escaped}*"), "case_insensitive": true}}}),
            (limit, offset),
        ).await;
    }
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
