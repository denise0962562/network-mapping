use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::config::ElasticsearchConfig;
use crate::handlers::tags::{AssetTag, tags_from_json};

const INDEX_SCHEMA_VERSION: &str = "1";
const OUTBOX_LOCK_TIMEOUT_MINUTES: i64 = 5;

#[derive(Clone)]
pub struct ElasticsearchService {
    inner: Arc<ElasticsearchInner>,
}

struct ElasticsearchInner {
    config: ElasticsearchConfig,
    client: reqwest::Client,
    runtime: RwLock<ElasticsearchRuntime>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ElasticsearchRuntime {
    pub connected: bool,
    pub read_ready: bool,
    pub server_version: Option<String>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ElasticsearchStatus {
    pub enabled: bool,
    pub read_enabled: bool,
    pub fallback_to_postgres: bool,
    pub url: String,
    pub index: String,
    pub expected_version: String,
    #[serde(flatten)]
    pub runtime: ElasticsearchRuntime,
    pub pending_events: i64,
    pub oldest_pending_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
struct SearchDocument {
    scope_type: String,
    scope_id: i32,
    endpoint_key: String,
    ip: String,
    port: i32,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    title: Option<String>,
    http_body: Option<String>,
    http_body_truncated: bool,
    tls_subject: Option<String>,
    source: String,
    scanner_name: Option<String>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    asn: Option<String>,
    asn_number: Option<i64>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    tags: Vec<AssetTag>,
    tag_names: Vec<String>,
    tag_ids: Vec<i64>,
    tag_kinds: Vec<String>,
    latest_endpoint_observation_id: i64,
    latest_service_observation_id: Option<i64>,
    projection_version: i64,
}

#[derive(Debug, Deserialize)]
struct SearchSource {
    ip: String,
    port: i32,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    title: Option<String>,
    tls_subject: Option<String>,
    scanner_name: Option<String>,
    last_seen: DateTime<Utc>,
    asn: Option<String>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    #[serde(default)]
    tags: Vec<AssetTag>,
}

#[derive(Debug)]
pub(crate) struct ElasticsearchSearchItem {
    pub(crate) ip_address: String,
    pub(crate) port: i32,
    pub(crate) protocol: Option<String>,
    pub(crate) service: Option<String>,
    pub(crate) banner: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) tls_subject: Option<String>,
    pub(crate) scanner_name: Option<String>,
    pub(crate) scan_time: i64,
    pub(crate) asn: Option<String>,
    pub(crate) isp: Option<String>,
    pub(crate) as_org: Option<String>,
    pub(crate) country_code: Option<String>,
    pub(crate) country_name: Option<String>,
    pub(crate) region_name: Option<String>,
    pub(crate) city_name: Option<String>,
    pub(crate) tags: Vec<AssetTag>,
}

#[derive(Debug)]
pub(crate) struct ElasticsearchSearchPage {
    pub(crate) items: Vec<ElasticsearchSearchItem>,
    pub(crate) total: i64,
}

#[derive(Debug)]
struct OutboxEvent {
    id: i64,
    event_kind: String,
    aggregate_key: String,
    attempts: i32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum IndexState {
    Existing,
    Created,
}

impl ElasticsearchService {
    pub fn new(config: ElasticsearchConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut builder =
            reqwest::Client::builder().timeout(Duration::from_secs(config.request_timeout_seconds));
        if config.enabled
            && let Some(path) = config.ca_certificate_file.as_deref()
        {
            let pem = std::fs::read(path)?;
            let certificate = reqwest::Certificate::from_pem(&pem)?;
            builder = builder.add_root_certificate(certificate);
        }
        Ok(Self {
            inner: Arc::new(ElasticsearchInner {
                config,
                client: builder.build()?,
                runtime: RwLock::new(ElasticsearchRuntime::default()),
            }),
        })
    }

    pub fn enabled(&self) -> bool {
        self.inner.config.enabled
    }

    pub fn can_read(&self) -> bool {
        self.inner.config.enabled
            && self.inner.config.read_enabled
            && self
                .inner
                .runtime
                .read()
                .expect("elasticsearch runtime lock poisoned")
                .read_ready
    }

    pub fn fallback_to_postgres(&self) -> bool {
        self.inner.config.fallback_to_postgres
    }

    pub fn runtime(&self) -> ElasticsearchRuntime {
        self.inner
            .runtime
            .read()
            .expect("elasticsearch runtime lock poisoned")
            .clone()
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.inner.config.url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let request = self.inner.client.request(method, self.endpoint(path));
        if let Some(api_key) = self.inner.config.api_key.as_deref() {
            request.header(reqwest::header::AUTHORIZATION, format!("ApiKey {api_key}"))
        } else if let (Some(username), Some(password)) = (
            self.inner.config.username.as_deref(),
            self.inner.config.password.as_deref(),
        ) {
            request.basic_auth(username, Some(password))
        } else {
            request
        }
    }

    async fn initialize(&self, pool: &Pool) -> Result<IndexState, String> {
        if !self.enabled() {
            return Ok(IndexState::Existing);
        }
        let response = self
            .request(Method::GET, "/")
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let root = response_json(response).await?;
        let version = root
            .pointer("/version/number")
            .and_then(Value::as_str)
            .ok_or_else(|| "Elasticsearch 根响应缺少 version.number".to_owned())?;
        if version != self.inner.config.expected_version {
            return Err(format!(
                "Elasticsearch 版本不匹配：期望 {}，实际 {version}",
                self.inner.config.expected_version
            ));
        }
        let state = self.ensure_index().await?;
        if state == IndexState::Created {
            let mut connection = pool.get().await.map_err(|error| error.to_string())?;
            let transaction = connection
                .transaction()
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "DELETE FROM search_projection_state WHERE state_key = 'elasticsearch_full_sync_index';",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "DELETE FROM search_index_outbox WHERE event_kind = 'full' AND processed_at IS NULL;",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO search_index_outbox (event_kind, aggregate_key, payload) \
                     VALUES ('full', 'all', '{}');",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .commit()
                .await
                .map_err(|error| error.to_string())?;
        }
        let connection = pool.get().await.map_err(|error| error.to_string())?;
        let synced: bool = connection
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM search_projection_state \
                 WHERE state_key = 'elasticsearch_full_sync_index' AND state_value = $1) AS synced;",
                &[&self.inner.config.index],
            )
            .await
            .map_err(|error| error.to_string())?
            .get("synced");
        self.update_runtime(|runtime| {
            runtime.connected = true;
            runtime.read_ready = synced;
            runtime.server_version = Some(version.to_owned());
            runtime.last_success_at = Some(Utc::now());
            runtime.last_error = None;
        });
        Ok(state)
    }

    async fn ensure_index(&self) -> Result<IndexState, String> {
        let response = self
            .request(Method::HEAD, &self.inner.config.index)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if response.status().is_success() {
            return Ok(IndexState::Existing);
        }
        if response.status() != StatusCode::NOT_FOUND {
            return Err(response_error(response).await);
        }
        self.create_index().await?;
        Ok(IndexState::Created)
    }

    async fn create_index(&self) -> Result<(), String> {
        let response = self
            .request(Method::PUT, &self.inner.config.index)
            .json(&index_definition())
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(response_error(response).await)
    }

    async fn reset_index(&self) -> Result<(), String> {
        self.update_runtime(|runtime| runtime.read_ready = false);
        let response = self
            .request(Method::DELETE, &self.inner.config.index)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
            return Err(response_error(response).await);
        }
        self.create_index().await
    }

    async fn bulk_index(&self, documents: &[SearchDocument]) -> Result<(), String> {
        if documents.is_empty() {
            return Ok(());
        }
        let mut body = String::new();
        for document in documents {
            let document_id = format!(
                "{}:{}|{}|{}",
                document.scope_type, document.scope_id, document.ip, document.port
            );
            let action = json!({
                "index": {
                    "_index": self.inner.config.index,
                    "_id": document_id,
                    "version": document.projection_version,
                    "version_type": "external_gte"
                }
            });
            body.push_str(&serde_json::to_string(&action).map_err(|error| error.to_string())?);
            body.push('\n');
            body.push_str(&serde_json::to_string(document).map_err(|error| error.to_string())?);
            body.push('\n');
        }
        let response = self
            .request(Method::POST, "/_bulk")
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .body(body)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let result = response_json(response).await?;
        if result.get("errors").and_then(Value::as_bool) != Some(true) {
            self.mark_success();
            return Ok(());
        }
        let failures = result
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("index"))
            .filter(|item| {
                item.get("status")
                    .and_then(Value::as_u64)
                    .is_some_and(|status| status >= 300 && status != 409)
            })
            .take(3)
            .map(Value::to_string)
            .collect::<Vec<_>>();
        if failures.is_empty() {
            self.mark_success();
            Ok(())
        } else {
            Err(format!(
                "Elasticsearch Bulk 部分失败：{}",
                failures.join("; ")
            ))
        }
    }

    pub(crate) async fn search(
        &self,
        role: i32,
        user_id: i32,
        filter: Value,
        limit: i64,
        offset: i64,
    ) -> Result<ElasticsearchSearchPage, String> {
        if !self.can_read() {
            return Err("Elasticsearch 搜索读路径尚未就绪".to_owned());
        }
        let (scope_type, scope_id) = if role == 1 {
            ("global", 0)
        } else {
            ("user", user_id)
        };
        let body = json!({
            "from": offset,
            "size": limit,
            "track_total_hits": true,
            "_source": {"excludes": ["http_body"]},
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"scope_type": scope_type}},
                        {"term": {"scope_id": scope_id}},
                        filter
                    ]
                }
            },
            "sort": [
                {"last_seen": {"order": "desc"}},
                {"ip": {"order": "asc"}},
                {"port": {"order": "asc"}}
            ]
        });
        let response = match self
            .request(
                Method::POST,
                &format!("{}/_search", self.inner.config.index),
            )
            .json(&body)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let message = error.to_string();
                self.mark_error(&message);
                return Err(message);
            }
        };
        let result = match response_json(response).await {
            Ok(result) => result,
            Err(message) => {
                self.mark_error(&message);
                return Err(message);
            }
        };
        let total = result
            .pointer("/hits/total/value")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let hits = result
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| "Elasticsearch 搜索响应缺少 hits.hits".to_owned())?;
        let mut items = Vec::with_capacity(hits.len());
        for hit in hits {
            let source: SearchSource = serde_json::from_value(
                hit.get("_source")
                    .cloned()
                    .ok_or_else(|| "Elasticsearch hit 缺少 _source".to_owned())?,
            )
            .map_err(|error| format!("Elasticsearch hit 解析失败：{error}"))?;
            items.push(ElasticsearchSearchItem {
                ip_address: source.ip,
                port: source.port,
                protocol: source.protocol,
                service: source.service,
                banner: source.banner,
                title: source.title,
                tls_subject: source.tls_subject,
                scanner_name: source.scanner_name,
                scan_time: source.last_seen.timestamp_millis(),
                asn: source.asn,
                isp: source.isp,
                as_org: source.as_org,
                country_code: source.country_code,
                country_name: source.country_name,
                region_name: source.region_name,
                city_name: source.city_name,
                tags: source.tags,
            });
        }
        self.mark_success();
        Ok(ElasticsearchSearchPage { items, total })
    }

    fn update_runtime(&self, update: impl FnOnce(&mut ElasticsearchRuntime)) {
        let mut runtime = self
            .inner
            .runtime
            .write()
            .expect("elasticsearch runtime lock poisoned");
        update(&mut runtime);
    }

    fn mark_success(&self) {
        self.update_runtime(|runtime| {
            runtime.connected = true;
            runtime.last_success_at = Some(Utc::now());
            runtime.last_error = None;
        });
    }

    fn mark_error(&self, message: &str) {
        self.update_runtime(|runtime| {
            runtime.connected = false;
            runtime.read_ready = false;
            runtime.last_error = Some(message.chars().take(2_000).collect());
        });
    }

    pub(crate) async fn status(&self, pool: &Pool) -> Result<ElasticsearchStatus, String> {
        let connection = pool.get().await.map_err(|error| error.to_string())?;
        let row = connection
            .query_one(
                "SELECT COUNT(*)::BIGINT AS pending, MIN(created_at) AS oldest \
                 FROM search_index_outbox WHERE processed_at IS NULL;",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(ElasticsearchStatus {
            enabled: self.inner.config.enabled,
            read_enabled: self.inner.config.read_enabled,
            fallback_to_postgres: self.inner.config.fallback_to_postgres,
            url: self.inner.config.url.clone(),
            index: self.inner.config.index.clone(),
            expected_version: self.inner.config.expected_version.clone(),
            runtime: self.runtime(),
            pending_events: row.get("pending"),
            oldest_pending_at: row.get("oldest"),
        })
    }

    pub async fn full_sync(&self, pool: &Pool) -> Result<u64, String> {
        if !self.enabled() {
            return Err("Elasticsearch 未启用".to_owned());
        }
        self.initialize(pool).await?;
        clear_full_sync_marker(pool).await?;
        self.reset_index().await?;
        let mut cursor = 0_i64;
        let mut indexed = 0_u64;
        loop {
            let documents = load_documents(
                pool,
                "full",
                "all",
                cursor,
                i64::try_from(self.inner.config.bulk_batch_size)
                    .map_err(|error| error.to_string())?,
            )
            .await?;
            if documents.is_empty() {
                break;
            }
            cursor = documents
                .last()
                .map(|document| document.projection_version)
                .unwrap_or(cursor);
            indexed = indexed.saturating_add(documents.len() as u64);
            self.bulk_index(&documents).await?;
        }
        let connection = pool.get().await.map_err(|error| error.to_string())?;
        connection
            .execute(
                "INSERT INTO search_projection_state (state_key, state_value, updated_at) \
                 VALUES ('elasticsearch_full_sync_index', $1, NOW()) \
                 ON CONFLICT (state_key) DO UPDATE SET state_value = EXCLUDED.state_value, updated_at = NOW();",
                &[&self.inner.config.index],
            )
            .await
            .map_err(|error| error.to_string())?;
        connection
            .execute(
                "UPDATE search_index_outbox SET processed_at = NOW(), locked_at = NULL, last_error = NULL \
                 WHERE event_kind = 'full' AND processed_at IS NULL;",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        self.update_runtime(|runtime| runtime.read_ready = true);
        Ok(indexed)
    }
}

pub async fn run_worker(service: ElasticsearchService, pool: Pool) {
    if !service.enabled() {
        return;
    }
    let mut ticker = interval(Duration::from_millis(service.inner.config.poll_interval_ms));
    loop {
        ticker.tick().await;
        if !service.runtime().connected
            && let Err(message) = service.initialize(&pool).await
        {
            service.mark_error(&message);
            warn!(event = "ElasticsearchInitializeError", message = %message);
            continue;
        }
        let event = match claim_event(&pool).await {
            Ok(value) => value,
            Err(message) => {
                service.mark_error(&message);
                error!(event = "ElasticsearchOutboxClaimError", message = %message);
                continue;
            }
        };
        let Some(event) = event else {
            continue;
        };
        match process_event(&service, &pool, &event).await {
            Ok(()) => {
                if let Err(message) = complete_event(&pool, event.id).await {
                    error!(event = "ElasticsearchOutboxCompleteError", outbox_id = event.id, message = %message);
                }
            }
            Err(message) => {
                service.mark_error(&message);
                warn!(event = "ElasticsearchOutboxProcessError", outbox_id = event.id, event_kind = %event.event_kind, message = %message);
                if let Err(mark_error) = retry_event(&pool, &event, &message).await {
                    error!(event = "ElasticsearchOutboxRetryError", outbox_id = event.id, message = %mark_error);
                }
            }
        }
    }
}

async fn claim_event(pool: &Pool) -> Result<Option<OutboxEvent>, String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    let row = connection
        .query_opt(
            "UPDATE search_index_outbox SET locked_at = NOW(), attempts = attempts + 1 \
             WHERE id = (SELECT id FROM search_index_outbox \
                 WHERE processed_at IS NULL AND available_at <= NOW() \
                   AND (locked_at IS NULL OR locked_at < NOW() - ($1 * INTERVAL '1 minute')) \
                 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) \
             RETURNING id, event_kind, aggregate_key, attempts;",
            &[&OUTBOX_LOCK_TIMEOUT_MINUTES],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(row.map(|row| OutboxEvent {
        id: row.get("id"),
        event_kind: row.get("event_kind"),
        aggregate_key: row.get("aggregate_key"),
        attempts: row.get("attempts"),
    }))
}

async fn process_event(
    service: &ElasticsearchService,
    pool: &Pool,
    event: &OutboxEvent,
) -> Result<(), String> {
    if event.event_kind == "full" {
        clear_full_sync_marker(pool).await?;
        service.reset_index().await?;
    }
    let mut cursor = 0_i64;
    loop {
        let documents = load_documents(
            pool,
            &event.event_kind,
            &event.aggregate_key,
            cursor,
            i64::try_from(service.inner.config.bulk_batch_size)
                .map_err(|error| error.to_string())?,
        )
        .await?;
        if documents.is_empty() {
            break;
        }
        cursor = documents
            .last()
            .map(|document| document.projection_version)
            .unwrap_or(cursor);
        service.bulk_index(&documents).await?;
    }
    if event.event_kind == "full" {
        let connection = pool.get().await.map_err(|error| error.to_string())?;
        connection
            .execute(
                "INSERT INTO search_projection_state (state_key, state_value, updated_at) \
                 VALUES ('elasticsearch_full_sync_index', $1, NOW()) \
                 ON CONFLICT (state_key) DO UPDATE SET state_value = EXCLUDED.state_value, updated_at = NOW();",
                &[&service.inner.config.index],
            )
            .await
            .map_err(|error| error.to_string())?;
        service.update_runtime(|runtime| runtime.read_ready = true);
        info!(event = "ElasticsearchFullSyncCompleted", index = %service.inner.config.index);
    }
    Ok(())
}

async fn clear_full_sync_marker(pool: &Pool) -> Result<(), String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    connection
        .execute(
            "DELETE FROM search_projection_state WHERE state_key = 'elasticsearch_full_sync_index';",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn load_documents(
    pool: &Pool,
    event_kind: &str,
    aggregate_key: &str,
    cursor: i64,
    limit: i64,
) -> Result<Vec<SearchDocument>, String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    let (filter, value): (&str, Option<&str>) = match event_kind {
        "full" => ("TRUE", None),
        "ip" => ("current.ip_address = $3::TEXT::INET", Some(aggregate_key)),
        "execution" => (
            "EXISTS (SELECT 1 FROM scan_observation affected \
             WHERE affected.execution_id = $3::TEXT::INT \
               AND affected.ip_address = current.ip_address \
               AND affected.port = current.port)",
            Some(aggregate_key),
        ),
        _ => return Err(format!("不支持的搜索 Outbox 事件：{event_kind}")),
    };
    let sql = format!(
        "SELECT current.scope_type, current.scope_id, host(current.ip_address) AS ip_address, \
                current.port, current.protocol, current.service, current.banner, current.title, \
                current.http_body, current.http_body_truncated, current.tls_subject, current.source, \
                current.scanner_name, current.first_seen_at, current.last_seen_at, current.asn, \
                current.isp, current.as_org, current.country_code, current.country_name, \
                current.region_name, current.city_name, current.latest_endpoint_observation_id, \
                current.latest_service_observation_id, current.projection_version, \
                COALESCE(tag_data.tags, '[]'::JSONB) AS tags \
         FROM asset_endpoint_current current \
         LEFT JOIN LATERAL (SELECT JSONB_AGG(JSONB_BUILD_OBJECT(\
             'id', tag.id, 'name', tag.name, 'kind', tag.kind, 'description', tag.description\
             ) ORDER BY CASE tag.kind WHEN 'malicious' THEN 1 WHEN 'benign' THEN 2 ELSE 3 END, LOWER(tag.name), tag.id) AS tags \
             FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
             WHERE assignment.ip_address = current.ip_address AND tag.is_active) tag_data ON true \
         WHERE current.projection_version > $1 AND {filter} \
         ORDER BY current.projection_version LIMIT $2"
    );
    let rows = if let Some(value) = value {
        connection.query(&sql, &[&cursor, &limit, &value]).await
    } else {
        connection.query(&sql, &[&cursor, &limit]).await
    }
    .map_err(|error| error.to_string())?;
    Ok(rows.into_iter().map(document_from_row).collect())
}

fn document_from_row(row: tokio_postgres::Row) -> SearchDocument {
    let ip: String = row.get("ip_address");
    let port: i32 = row.get("port");
    let asn: Option<String> = row
        .get::<_, Option<String>>("asn")
        .map(|value| canonical_asn(&value).to_owned());
    let tags = tags_from_json(row.get("tags"));
    SearchDocument {
        scope_type: row.get("scope_type"),
        scope_id: row.get("scope_id"),
        endpoint_key: format!("{ip}:{port}"),
        ip,
        port,
        protocol: row.get("protocol"),
        service: row.get("service"),
        banner: row.get("banner"),
        title: row.get("title"),
        http_body: row.get("http_body"),
        http_body_truncated: row.get("http_body_truncated"),
        tls_subject: row.get("tls_subject"),
        source: row.get("source"),
        scanner_name: row.get("scanner_name"),
        first_seen: row.get("first_seen_at"),
        last_seen: row.get("last_seen_at"),
        asn_number: asn.as_deref().and_then(parse_asn),
        asn,
        isp: row.get("isp"),
        as_org: row.get("as_org"),
        country_code: row.get("country_code"),
        country_name: row.get("country_name"),
        region_name: row.get("region_name"),
        city_name: row.get("city_name"),
        tag_names: tags.iter().map(|tag| tag.name.clone()).collect(),
        tag_ids: tags.iter().map(|tag| tag.id).collect(),
        tag_kinds: tags.iter().map(|tag| tag.kind.clone()).collect(),
        tags,
        latest_endpoint_observation_id: row.get("latest_endpoint_observation_id"),
        latest_service_observation_id: row.get("latest_service_observation_id"),
        projection_version: row.get("projection_version"),
    }
}

fn parse_asn(value: &str) -> Option<i64> {
    canonical_asn(value).parse().ok()
}

fn canonical_asn(value: &str) -> &str {
    value
        .strip_prefix("AS")
        .or_else(|| value.strip_prefix("as"))
        .unwrap_or(value)
}

async fn complete_event(pool: &Pool, id: i64) -> Result<(), String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    connection
        .execute(
            "UPDATE search_index_outbox SET processed_at = NOW(), locked_at = NULL, last_error = NULL \
             WHERE id = $1;",
            &[&id],
        )
        .await
        .map_err(|error| error.to_string())?;
    connection
        .execute(
            "DELETE FROM search_index_outbox WHERE processed_at < NOW() - INTERVAL '7 days';",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn retry_event(pool: &Pool, event: &OutboxEvent, message: &str) -> Result<(), String> {
    let delay_seconds = i64::from(2_i32.saturating_pow(event.attempts.clamp(1, 8) as u32));
    let last_error: String = message.chars().take(2_000).collect();
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    connection
        .execute(
            "UPDATE search_index_outbox SET locked_at = NULL, last_error = $2, \
             available_at = NOW() + ($3 * INTERVAL '1 second') WHERE id = $1;",
            &[&event.id, &last_error, &delay_seconds],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn response_json(response: reqwest::Response) -> Result<Value, String> {
    if !response.status().is_success() {
        return Err(response_error(response).await);
    }
    response.json().await.map_err(|error| error.to_string())
}

async fn response_error(response: reqwest::Response) -> String {
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|error| error.to_string());
    format!(
        "Elasticsearch HTTP {status}: {}",
        body.chars().take(2_000).collect::<String>()
    )
}

fn index_definition() -> Value {
    json!({
        "settings": {
            "index": {"auto_expand_replicas": "0-1"},
            "analysis": {
                "normalizer": {
                    "lowercase_normalizer": {"type": "custom", "filter": ["lowercase"]}
                }
            }
        },
        "mappings": {
            "dynamic": "strict",
            "_meta": {
                "application": "network-mapping",
                "schema_version": INDEX_SCHEMA_VERSION,
                "elasticsearch_version": "9.5.2"
            },
            "properties": {
                "scope_type": {"type": "keyword"},
                "scope_id": {"type": "integer"},
                "endpoint_key": {"type": "keyword"},
                "ip": {"type": "ip"},
                "port": {"type": "integer"},
                "protocol": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "service": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "banner": {"type": "wildcard", "copy_to": "banner_text"},
                "banner_text": {"type": "text"},
                "title": {
                    "type": "text",
                    "copy_to": "title_contains",
                    "fields": {"raw": {"type": "keyword", "normalizer": "lowercase_normalizer", "ignore_above": 512}}
                },
                "title_contains": {"type": "wildcard"},
                "http_body": {"type": "match_only_text", "copy_to": "http_body_contains"},
                "http_body_contains": {"type": "wildcard"},
                "http_body_truncated": {"type": "boolean"},
                "tls_subject": {"type": "wildcard", "copy_to": "tls_subject_text"},
                "tls_subject_text": {"type": "text"},
                "source": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "scanner_name": {"type": "wildcard"},
                "first_seen": {"type": "date"},
                "last_seen": {"type": "date"},
                "asn": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "asn_number": {"type": "long"},
                "isp": {"type": "wildcard"},
                "as_org": {"type": "wildcard"},
                "country_code": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "country_name": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "region_name": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "city_name": {"type": "wildcard"},
                "tags": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "long"},
                        "name": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                        "kind": {"type": "keyword"},
                        "description": {"type": "text", "index": false}
                    }
                },
                "tag_names": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                "tag_ids": {"type": "long"},
                "tag_kinds": {"type": "keyword"},
                "latest_endpoint_observation_id": {"type": "long", "index": false},
                "latest_service_observation_id": {"type": "long", "index": false},
                "projection_version": {"type": "long"}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{index_definition, parse_asn};

    #[test]
    fn index_mapping_targets_elasticsearch_9_5_2_and_expected_field_types() {
        let mapping = index_definition();
        assert_eq!(
            mapping.pointer("/mappings/_meta/elasticsearch_version"),
            Some(&serde_json::json!("9.5.2"))
        );
        assert_eq!(
            mapping.pointer("/mappings/properties/ip/type"),
            Some(&serde_json::json!("ip"))
        );
        assert_eq!(
            mapping.pointer("/mappings/properties/banner/type"),
            Some(&serde_json::json!("wildcard"))
        );
        assert_eq!(
            mapping.pointer("/mappings/properties/http_body/type"),
            Some(&serde_json::json!("match_only_text"))
        );
    }

    #[test]
    fn parses_asn_with_or_without_prefix() {
        assert_eq!(parse_asn("AS4134"), Some(4134));
        assert_eq!(parse_asn("4134"), Some(4134));
        assert_eq!(parse_asn("unknown"), None);
    }
}
