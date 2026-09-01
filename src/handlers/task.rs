use crate::admin::{UserBaseI, get_default_scan_profile_from_database};
use crate::audit::{self, AuditContext};
use crate::client_ip::{normalize_ip, request_ip};
use crate::config::SecurityConfig;
use crate::elasticsearch::{ElasticsearchService, ScanQueryIndex};
use crate::logs::write::{error_logs, error_logs_error, info_logs};
use crate::maxmind::MaxMindState;
use crate::scanner_latency::{ScannerLatencyHistory, ScannerLatencyHistoryEntry};
use crate::system_maintenance::{
    MaintenanceSnapshot, SystemMaintenanceState, maintenance_response,
};
use crate::{
    ApplyTaskError, ApplyTaskQuery, CreateTask, ReceiveTaskItemQueryInfo, STask, TargetIP,
    TaskItemJson, TaskListFilters, apply_task, build_scan_plan, get_filtered_task_page,
    validate_scanner_credentials,
};
use crate::{Permission, TEXT_HTML_UTF_8};
use crate::{SaveScannerResultsError, ScannerResultUpload, save_scanner_results};
use actix_web::{HttpRequest, HttpResponse, Responder, get, http::header, post, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use tracing::error;
use uuid::Uuid;

#[derive(Serialize)]
struct ScannerHeartbeatLease {
    task_id: Uuid,
    status: &'static str,
    expires_at_ms: Option<i64>,
    ttl_ms: i64,
    maintenance_hold: bool,
}

#[derive(Deserialize)]
struct CreateDnsTask {
    domains: Vec<String>,
    #[serde(default)]
    dns_resolvers: Vec<CreateDnsResolver>,
    level: i8,
    remark: Option<String>,
    #[serde(default = "default_dns_scan_profile")]
    scan_profile: String,
    port: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CreateDnsResolver {
    id: String,
    label: String,
    ip: String,
    port: u16,
    transport: String,
}

impl CreateDnsResolver {
    fn normalize(mut self) -> Result<Self, &'static str> {
        self.id = self.id.trim().to_ascii_lowercase();
        self.label = self.label.trim().to_owned();
        self.ip = self
            .ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "DNS server IP is invalid")?
            .to_string();
        self.transport = self.transport.trim().to_ascii_lowercase();
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err("DNS server ID must contain 1 to 64 letters, numbers, - or _");
        }
        if self.label.is_empty() || self.label.len() > 128 {
            return Err("DNS server name must contain 1 to 128 characters");
        }
        if self.port == 0 {
            return Err("DNS server port must be between 1 and 65535");
        }
        if !matches!(self.transport.as_str(), "udp" | "tcp") {
            return Err("DNS server transport must be udp or tcp");
        }
        Ok(self)
    }
}

fn default_dns_scan_profile() -> String {
    "dns_records".into()
}

#[derive(Serialize)]
struct ScannerHeartbeatCommand {
    #[serde(rename = "type")]
    command_type: &'static str,
    task_id: Uuid,
}

#[derive(Serialize)]
struct ScannerHeartbeatResponse {
    success: bool,
    lease: Option<ScannerHeartbeatLease>,
    command: Option<ScannerHeartbeatCommand>,
    maintenance: Option<MaintenanceSnapshot>,
}

#[derive(Deserialize)]
pub struct ScannerSystemInfo {
    os_name: String,
    os_version: String,
    cpu_model: String,
    cpu_cores: u32,
    ram_total_mb: u64,
    uptime_seconds: u64,
}

#[derive(Deserialize)]
pub struct ScannerHeartbeat {
    scanner_id: Uuid,
    state: String,
    active_task_id: Option<Uuid>,
    scanner_version: String,
    system: ScannerSystemInfo,
    #[serde(default)]
    network_capabilities: ScannerNetworkCapabilities,
    #[serde(default)]
    scan_capabilities: ScannerScanCapabilities,
    #[serde(default)]
    latency_report: Option<ScannerLatencyReport>,
}

const LATENCY_PROTOCOL_VERSION: u16 = 1;
const MAX_LATENCY_US: i64 = 120_000_000;

#[derive(Deserialize)]
pub struct ScannerLatencyReport {
    version: u16,
    probe_id: Uuid,
    rtt_us: i64,
    server_processing_us: i64,
    network_rtt_us: i64,
    server_sent_at_ms: i64,
}

#[derive(Clone, Debug)]
struct ValidatedScannerLatency {
    probe_id: Uuid,
    measured_at: DateTime<Utc>,
    rtt_us: i64,
    server_processing_us: i64,
    network_rtt_us: i64,
}

fn validate_latency_report(
    report: &ScannerLatencyReport,
) -> Result<ValidatedScannerLatency, &'static str> {
    if report.version != LATENCY_PROTOCOL_VERSION {
        return Err("unsupported latency protocol version");
    }
    if !(0..=MAX_LATENCY_US).contains(&report.rtt_us)
        || !(0..=MAX_LATENCY_US).contains(&report.server_processing_us)
        || !(0..=MAX_LATENCY_US).contains(&report.network_rtt_us)
    {
        return Err("latency value is out of range");
    }
    if report.server_processing_us > report.rtt_us {
        return Err("server processing time exceeds total RTT");
    }
    let network_rtt_us = report.rtt_us.saturating_sub(report.server_processing_us);
    let now = Utc::now();
    let measured_at = DateTime::from_timestamp_millis(report.server_sent_at_ms)
        .filter(|value| (*value - now).num_seconds().abs() <= 24 * 60 * 60)
        .unwrap_or(now);

    Ok(ValidatedScannerLatency {
        probe_id: report.probe_id,
        measured_at,
        rtt_us: report.rtt_us,
        server_processing_us: report.server_processing_us,
        network_rtt_us,
    })
}

#[derive(Deserialize, Serialize)]
pub struct ScannerScanCapabilities {
    plan_versions: Vec<u16>,
    profiles: Vec<String>,
    stages: Vec<String>,
    #[serde(default)]
    explicit_dns_resolvers: bool,
}

impl Default for ScannerScanCapabilities {
    fn default() -> Self {
        Self {
            plan_versions: Vec::new(),
            profiles: vec!["legacy".into()],
            stages: vec!["port_discovery".into()],
            explicit_dns_resolvers: false,
        }
    }
}

impl ScannerScanCapabilities {
    fn validate(&self) -> Result<(), &'static str> {
        if self.plan_versions.len() > 8 || self.profiles.len() > 8 || self.stages.len() > 16 {
            return Err("too many scan capabilities");
        }
        if self.profiles.iter().any(|value| {
            !matches!(
                value.as_str(),
                "legacy"
                    | "port_only"
                    | "service_inventory"
                    | "dns_records"
                    | "dns_ports"
                    | "dns_full"
            )
        }) || self.stages.iter().any(|value| {
            !matches!(
                value.as_str(),
                "port_discovery" | "service_detection" | "dns_lookup"
            )
        }) {
            return Err("unsupported scan capability");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct ScannerNetworkCapabilities {
    ipv4: ScannerNetworkFamily,
    ipv6: ScannerNetworkFamily,
}

impl Default for ScannerNetworkCapabilities {
    fn default() -> Self {
        Self {
            ipv4: ScannerNetworkFamily {
                supported: true,
                ready: true,
                public_ip: None,
                reason: Some("legacy_scanner".to_owned()),
            },
            ipv6: ScannerNetworkFamily::default(),
        }
    }
}

#[derive(Default, Deserialize)]
pub struct ScannerNetworkFamily {
    supported: bool,
    ready: bool,
    public_ip: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
pub struct ScannerTaskFailure {
    scanner_id: Uuid,
    task_id: Uuid,
    error: String,
    #[serde(default = "default_retryable")]
    retryable: bool,
}

#[derive(Deserialize)]
pub struct ScannerTaskCancelled {
    scanner_id: Uuid,
    task_id: Uuid,
}

fn default_retryable() -> bool {
    true
}

fn validate_public_ip(value: Option<&str>, expect_ipv6: bool) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let address = normalize_ip(
        value
            .parse::<IpAddr>()
            .map_err(|_| "network capability contains an invalid public IP".to_owned())?,
    );
    if address.is_ipv6() != expect_ipv6 {
        return Err("network capability public IP has the wrong address family".to_owned());
    }
    Ok(Some(address.to_string()))
}

fn bearer_token(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

async fn maintenance_gate_for_runtime_scanner(
    pool: &Pool,
    security: &SecurityConfig,
    scanner_id: Uuid,
    token: &str,
    snapshot: MaintenanceSnapshot,
    should_block: bool,
) -> Option<HttpResponse> {
    if !should_block {
        return None;
    }
    match validate_scanner_credentials(pool, scanner_id, token, &security.scanner_token_pepper)
        .await
    {
        Ok(()) => Some(maintenance_response(&snapshot)),
        Err(ApplyTaskError::ScannerUnauthorized) => {
            Some(HttpResponse::Unauthorized().body("unauthorized"))
        }
        Err(_) => Some(HttpResponse::InternalServerError().finish()),
    }
}

#[derive(Deserialize)]
pub struct ScannerPublicIpQuery {
    scannerid: Uuid,
}

#[derive(Serialize)]
struct ScannerPublicIpResponse {
    ip: String,
}

/// Returns the source address observed by the server to an authenticated scanner.
#[get("/api/scanner/network/public-ip")]
pub(crate) async fn scanner_public_ip_handler(
    req: HttpRequest,
    query: web::Query<ScannerPublicIpQuery>,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    if let Err(error) = validate_scanner_credentials(
        pool.get_ref(),
        query.scannerid,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        return match error {
            ApplyTaskError::ScannerUnauthorized => {
                HttpResponse::Unauthorized().body("unauthorized")
            }
            error => {
                error_logs_error(
                    &req,
                    "ScannerPublicIpCredentialCheckError",
                    "validate_scanner_credentials",
                    &error,
                );
                HttpResponse::InternalServerError().finish()
            }
        };
    }

    let snapshot = maintenance.snapshot().await;
    if snapshot.blocks_all_scanner_requests() {
        return maintenance_response(&snapshot);
    }

    let Some(address) = request_ip(&req) else {
        error!(
            event = "ScannerPublicIpUnavailable",
            scanner_id = %query.scannerid,
            "authenticated scanner request had no peer address"
        );
        return HttpResponse::ServiceUnavailable().body("client address unavailable");
    };
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(ScannerPublicIpResponse {
            ip: address.to_string(),
        })
}

#[derive(Deserialize)]
pub struct TaskDetailQuery {
    page: Option<i64>,
    page_size: Option<i64>,
    execution_id: Option<Uuid>,
}

#[derive(Serialize)]
struct TaskResultPort {
    port: i32,
    protocol: Option<String>,
    service: Option<String>,
    banner: Option<String>,
    other: Option<Value>,
    scan_time: Option<i64>,
}

#[derive(Serialize)]
struct TaskResultIp {
    ip: String,
    asn: Option<String>,
    isp: Option<String>,
    as_org: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    ports: Vec<TaskResultPort>,
}

fn task_result_pagination(page: Option<i64>, page_size: Option<i64>) -> (i64, i64, i64) {
    let page = page.unwrap_or(1).max(1);
    let page_size = page_size.unwrap_or(20).clamp(1, 100);
    (page, page_size, (page - 1) * page_size)
}

async fn load_execution_results_from_elasticsearch(
    elasticsearch: &ElasticsearchService,
    execution_id: &str,
    offset: i64,
    page_size: i64,
) -> Result<Vec<TaskResultIp>, String> {
    let mut search_after: Option<Value> = None;
    let mut skipped_ips = 0_i64;
    let mut results: Vec<TaskResultIp> = Vec::new();
    let mut current_ip: Option<String> = None;
    let mut collect_current = false;
    loop {
        let mut body = json!({
            "size": 1000,
            "query": {"term": {"execution_id": execution_id}},
            "sort": [{"ip": "asc"}, {"port": "asc"}]
        });
        if let Some(value) = search_after.clone() {
            body.as_object_mut()
                .expect("query body is object")
                .insert("search_after".to_owned(), value);
        }
        let response = elasticsearch
            .scan_query(ScanQueryIndex::ExecutionEndpoints, &body)
            .await?;
        let hits = response
            .pointer("/hits/hits")
            .and_then(Value::as_array)
            .ok_or_else(|| "Elasticsearch execution query response is missing hits".to_owned())?;
        if hits.is_empty() {
            break;
        }
        for hit in hits {
            let source = hit
                .get("_source")
                .ok_or_else(|| "Elasticsearch execution hit is missing _source".to_owned())?;
            let ip = source
                .get("ip")
                .and_then(Value::as_str)
                .ok_or_else(|| "Elasticsearch execution hit is missing ip".to_owned())?;
            let is_new_ip = current_ip.as_deref() != Some(ip);
            if is_new_ip {
                current_ip = Some(ip.to_owned());
                if skipped_ips < offset {
                    skipped_ips += 1;
                    collect_current = false;
                    continue;
                }
                if results.len() >= page_size as usize {
                    return Ok(results);
                }
                collect_current = true;
                let text =
                    |field: &str| source.get(field).and_then(Value::as_str).map(str::to_owned);
                results.push(TaskResultIp {
                    ip: ip.to_owned(),
                    asn: text("asn"),
                    isp: text("isp"),
                    as_org: text("as_org"),
                    country_code: text("country_code"),
                    country_name: text("country_name"),
                    region_name: text("region_name"),
                    city_name: text("city_name"),
                    ports: Vec::new(),
                });
            } else if !collect_current {
                continue;
            }
            if let Some(asset) = results.last_mut().filter(|asset| asset.ip == ip) {
                let kind = source.get("kind").and_then(Value::as_str).unwrap_or("port");
                let other = if kind == "service" {
                    json!({
                        "observation_kind": kind,
                        "source": source.get("source"),
                        "data": source.get("data")
                    })
                } else {
                    json!({
                        "observation_kind": kind,
                        "state": source.pointer("/data/state").and_then(Value::as_str).unwrap_or("open"),
                        "source": source.get("source")
                    })
                };
                asset.ports.push(TaskResultPort {
                    port: source.get("port").and_then(Value::as_i64).unwrap_or(0) as i32,
                    protocol: source
                        .get("protocol")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    service: source
                        .get("service")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    banner: source
                        .get("banner")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    other: Some(other),
                    scan_time: source.get("observed_at_ms").and_then(Value::as_i64),
                });
            }
        }
        search_after = hits.last().and_then(|hit| hit.get("sort")).cloned();
        if hits.len() < 1000 || search_after.is_none() {
            break;
        }
    }
    Ok(results)
}

#[post("/api/scanner/heartbeat")]
pub(crate) async fn scanner_heartbeat_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    latency_history: web::Data<ScannerLatencyHistory>,
    maintenance: web::Data<SystemMaintenanceState>,
    heartbeat: web::Json<ScannerHeartbeat>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    let maintenance_snapshot = maintenance.snapshot().await;
    let should_block = maintenance_snapshot.blocks_new_work() && heartbeat.active_task_id.is_none();
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        pool.get_ref(),
        security.get_ref(),
        heartbeat.scanner_id,
        token,
        maintenance_snapshot.clone(),
        should_block,
    )
    .await
    {
        return response;
    }
    if !matches!(heartbeat.state.as_str(), "idle" | "scanning" | "stopping") {
        return HttpResponse::BadRequest().body("invalid scanner state");
    }
    if let Err(message) = heartbeat.scan_capabilities.validate() {
        return HttpResponse::BadRequest().body(message);
    }
    let token_hash = match crate::hash_scanner_token(token, &security.scanner_token_pepper) {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerHeartbeatCredentialHashError",
                "hash_scanner_token",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let ip_address = request_ip(&req).map(|address| address.to_string());
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerHeartbeatPoolError",
                "acquire_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(transaction) => transaction,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerHeartbeatTransactionError",
                "begin_transaction",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let scanner_id = heartbeat.scanner_id.to_string();
    let system_version = format!(
        "{} {}",
        heartbeat.system.os_name, heartbeat.system.os_version
    );
    let cpu_cores = i32::try_from(heartbeat.system.cpu_cores).unwrap_or(i32::MAX);
    let ram_mb = i32::try_from(heartbeat.system.ram_total_mb).unwrap_or(i32::MAX);
    let uptime = i32::try_from(heartbeat.system.uptime_seconds).unwrap_or(i32::MAX);
    let public_ipv4 = match validate_public_ip(
        heartbeat.network_capabilities.ipv4.public_ip.as_deref(),
        false,
    ) {
        Ok(value) => value,
        Err(message) => return HttpResponse::BadRequest().body(message),
    };
    let public_ipv6 = match validate_public_ip(
        heartbeat.network_capabilities.ipv6.public_ip.as_deref(),
        true,
    ) {
        Ok(value) => value,
        Err(message) => return HttpResponse::BadRequest().body(message),
    };
    let network_status_reason = serde_json::json!({
        "ipv4": heartbeat.network_capabilities.ipv4.reason,
        "ipv6": heartbeat.network_capabilities.ipv6.reason,
    });
    let scan_capabilities = match serde_json::to_value(&heartbeat.scan_capabilities) {
        Ok(value) => value,
        Err(_) => return HttpResponse::BadRequest().body("invalid scan capabilities"),
    };
    let latency =
        heartbeat.latency_report.as_ref().and_then(|report| {
            match validate_latency_report(report) {
                Ok(latency) => Some(latency),
                Err(reason) => {
                    tracing::warn!(
                        scanner_id = %heartbeat.scanner_id,
                        reason,
                        "ignored invalid scanner latency report"
                    );
                    None
                }
            }
        });
    let latency_rtt_us = latency.as_ref().map(|value| value.rtt_us);
    let latency_network_rtt_us = latency.as_ref().map(|value| value.network_rtt_us);
    let latency_server_processing_us = latency.as_ref().map(|value| value.server_processing_us);
    let latency_measured_at = latency.as_ref().map(|value| value.measured_at);
    let latency_probe_id = latency.as_ref().map(|value| value.probe_id);
    let update = transaction
        .query_opt(
            "UPDATE scanner_info SET system_version = $1, scanner_version = $2, cpu_model = $3, \
             cpus = $4, ram = $5, uptime = $6, runtime_state = $7, last_seen_at = NOW(), \
             update_time = NOW(), is_run = ($7 <> 'stopping'), \
             ip_address = COALESCE($8::text::inet, ip_address), supports_ipv4 = $9, \
             supports_ipv6 = $10, ipv4_ready = $11, ipv6_ready = $12, \
             public_ipv4 = $13::text::inet, public_ipv6 = $14::text::inet, \
             network_status_reason = $15, network_capabilities_updated_at = NOW(), \
             scan_capabilities = $16, scan_capabilities_updated_at = NOW(), \
             latency_rtt_us = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $17::BIGINT ELSE latency_rtt_us END, \
             latency_network_rtt_us = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $18::BIGINT ELSE latency_network_rtt_us END, \
             latency_server_processing_us = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $19::BIGINT ELSE latency_server_processing_us END, \
             latency_probe_id = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $21::UUID ELSE latency_probe_id END, \
             latency_measured_at = CASE WHEN $20::TIMESTAMPTZ IS NOT NULL \
                 AND (latency_measured_at IS NULL OR $20 >= latency_measured_at) \
                 THEN $20::TIMESTAMPTZ ELSE latency_measured_at END \
             WHERE scanner_id = $22 AND runtime_token_hash = $23 AND is_enable = TRUE \
             RETURNING id;",
            &[
                &system_version,
                &heartbeat.scanner_version,
                &heartbeat.system.cpu_model,
                &cpu_cores,
                &ram_mb,
                &uptime,
                &heartbeat.state,
                &ip_address,
                &heartbeat.network_capabilities.ipv4.supported,
                &heartbeat.network_capabilities.ipv6.supported,
                &heartbeat.network_capabilities.ipv4.ready,
                &heartbeat.network_capabilities.ipv6.ready,
                &public_ipv4.as_deref(),
                &public_ipv6.as_deref(),
                &network_status_reason,
                &scan_capabilities,
                &latency_rtt_us,
                &latency_network_rtt_us,
                &latency_server_processing_us,
                &latency_measured_at,
                &latency_probe_id,
                &scanner_id,
                &token_hash,
            ],
        )
        .await;
    match update {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::Unauthorized().body("unauthorized"),
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerHeartbeatUpdateError",
                "update_scanner_state",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    let mut lease = None;
    let mut cancel_task_id = None;
    if let Some(task_id) = heartbeat.active_task_id {
        let lease_expires_at = crate::get_unix_epoch_ms() + crate::TASK_LEASE_MS;
        let renewed = match transaction
            .query_opt(
                "UPDATE scan_task_execution e SET lease_expires_at = CASE \
                 WHEN e.maintenance_hold THEN NULL ELSE $1::bigint END FROM scan_task t \
                 WHERE e.task_id = t.id AND t.task_id = $2 AND e.assigned_scanner_id = $3 \
                 AND e.execution_status = 'running' RETURNING e.maintenance_hold, e.lease_expires_at;",
                &[&lease_expires_at, &task_id.to_string(), &scanner_id],
            )
            .await
        {
            Err(error) => {
                error_logs_error(&req, "ScannerLeaseRenewError", "renew_task_lease", &error);
                return HttpResponse::InternalServerError().finish();
            }
            Ok(row) => row,
        };
        if let Some(renewed) = renewed {
            let maintenance_hold: bool = renewed.get("maintenance_hold");
            lease = Some(ScannerHeartbeatLease {
                task_id,
                status: "renewed",
                expires_at_ms: renewed.get("lease_expires_at"),
                ttl_ms: if maintenance_hold {
                    crate::system_maintenance::RESULT_UPLOAD_GRACE_TTL_MS
                } else {
                    crate::TASK_LEASE_MS
                },
                maintenance_hold,
            });
            match transaction
                .query_opt(
                    "SELECT t.task_id FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
                     WHERE t.task_id = $1 AND e.assigned_scanner_id = $2 \
                     AND e.execution_status = 'running' AND e.cancel_requested = true LIMIT 1;",
                    &[&task_id.to_string(), &scanner_id],
                )
                .await
            {
                Ok(Some(_)) => cancel_task_id = Some(task_id),
                Ok(None) => {}
                Err(error) => {
                    error_logs_error(
                        &req,
                        "ScannerCancelCommandError",
                        "read_cancel_command",
                        &error,
                    );
                    return HttpResponse::InternalServerError().finish();
                }
            }
        } else {
            lease = Some(ScannerHeartbeatLease {
                task_id,
                status: "lost",
                expires_at_ms: None,
                ttl_ms: crate::TASK_LEASE_MS,
                maintenance_hold: false,
            });
        }
    }
    if let Err(error) = transaction.commit().await {
        error_logs_error(
            &req,
            "ScannerHeartbeatCommitError",
            "commit_heartbeat",
            &error,
        );
        return HttpResponse::InternalServerError().finish();
    }
    if let Some(latency) = latency {
        latency_history.record(ScannerLatencyHistoryEntry {
            scanner_id,
            probe_id: latency.probe_id,
            measured_at: latency.measured_at,
            rtt_us: latency.rtt_us,
            server_processing_us: latency.server_processing_us,
            network_rtt_us: latency.network_rtt_us,
        });
    }
    HttpResponse::Ok().json(ScannerHeartbeatResponse {
        success: true,
        lease,
        command: cancel_task_id.map(|task_id| ScannerHeartbeatCommand {
            command_type: "cancel_task",
            task_id,
        }),
        maintenance: maintenance_snapshot.enabled.then_some(maintenance_snapshot),
    })
}

#[post("/api/scanner/task/fail")]
pub(crate) async fn scanner_task_failure_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    failure: web::Json<ScannerTaskFailure>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    let maintenance_snapshot = maintenance.snapshot().await;
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        pool.get_ref(),
        security.get_ref(),
        failure.scanner_id,
        token,
        maintenance_snapshot.clone(),
        maintenance_snapshot.blocks_all_scanner_requests(),
    )
    .await
    {
        return response;
    }
    let token_hash = match crate::hash_scanner_token(token, &security.scanner_token_pepper) {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskFailureCredentialHashError",
                "hash_scanner_token",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskFailurePoolError",
                "acquire_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let scanner_id = failure.scanner_id.to_string();
    let task_id = failure.task_id.to_string();
    let reason: String = failure.error.chars().take(1000).collect();
    let force_terminal = !failure.retryable;
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskFailureTransactionError",
                "begin_transaction",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    match crate::validate_scanner_credentials_with_client(
        &transaction,
        failure.scanner_id,
        &token_hash,
    )
    .await
    {
        Ok(()) => {}
        Err(ApplyTaskError::ScannerUnauthorized) => {
            return HttpResponse::Unauthorized().body("unauthorized");
        }
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskFailureCredentialCheckError",
                "validate_scanner_credentials",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    let changed = transaction
        .query(
            "UPDATE scan_task_execution SET execution_status = CASE WHEN $1::boolean OR attempt_count >= 3 THEN 'failed' ELSE 'pending' END, \
             task_end_time = CASE WHEN $1::boolean OR attempt_count >= 3 THEN $2::bigint ELSE NULL::bigint END, task_start_time = NULL, \
             assigned_scanner_id = CASE WHEN $1::boolean OR attempt_count >= 3 THEN assigned_scanner_id ELSE NULL END, \
             lease_expires_at = NULL, maintenance_hold = FALSE, maintenance_hold_until = NULL, \
             failure_reason = $3, cancel_requested = false \
             WHERE task_id = (SELECT id FROM scan_task WHERE task_id = $4) AND assigned_scanner_id = $5 \
             AND execution_status = 'running' RETURNING execution_status, task_id;",
            &[
                &force_terminal,
                &crate::get_unix_epoch_ms(),
                &reason,
                &task_id,
                &scanner_id,
            ],
        )
        .await;
    match changed {
        Ok(rows) if !rows.is_empty() => {
            let task_db_id: i32 = rows[0].get("task_id");
            let retryable = rows
                .iter()
                .any(|row| row.get::<_, String>("execution_status") == "pending");
            let status = if retryable { "pending" } else { "failed" };
            if rows.len() > 1 {
                error_logs(
                    &req,
                    "ScannerTaskDuplicateExecutions",
                    &format!(
                        "task_id={task_id} scanner_id={scanner_id} updated_executions={}",
                        rows.len()
                    ),
                );
            }
            if let Err(error) = crate::refresh_task_aggregate(&transaction, task_db_id).await {
                error_logs_error(
                    &req,
                    "ScannerTaskFailureAggregateError",
                    "refresh_task_aggregate",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
            if let Err(error) = transaction.commit().await {
                error_logs_error(
                    &req,
                    "ScannerTaskFailureCommitError",
                    "commit_task_failure",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "retryable": retryable,
                "status": status,
            }))
        }
        Ok(_) => HttpResponse::Conflict().body("task is not owned by scanner"),
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskFailureUpdateError",
                "record_task_failure",
                &error,
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[post("/api/scanner/task/cancelled")]
pub(crate) async fn scanner_task_cancelled_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    cancelled: web::Json<ScannerTaskCancelled>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };
    let maintenance_snapshot = maintenance.snapshot().await;
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        pool.get_ref(),
        security.get_ref(),
        cancelled.scanner_id,
        token,
        maintenance_snapshot.clone(),
        maintenance_snapshot.blocks_all_scanner_requests(),
    )
    .await
    {
        return response;
    }
    let token_hash = match crate::hash_scanner_token(token, &security.scanner_token_pepper) {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskCancelledCredentialHashError",
                "hash_scanner_token",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskCancelledPoolError",
                "acquire_connection",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskCancelledTransactionError",
                "begin_transaction",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    match crate::validate_scanner_credentials_with_client(
        &transaction,
        cancelled.scanner_id,
        &token_hash,
    )
    .await
    {
        Ok(()) => {}
        Err(ApplyTaskError::ScannerUnauthorized) => {
            return HttpResponse::Unauthorized().body("unauthorized");
        }
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskCancelledCredentialCheckError",
                "validate_scanner_credentials",
                &error,
            );
            return HttpResponse::InternalServerError().finish();
        }
    }
    let changed = transaction
        .query(
            "UPDATE scan_task_execution e SET execution_status = 'cancelled', task_end_time = $1, \
             lease_expires_at = NULL, maintenance_hold = FALSE, maintenance_hold_until = NULL, \
             cancel_requested = false, failure_reason = NULL FROM scan_task t \
             WHERE e.task_id = t.id AND t.task_id = $2 AND e.assigned_scanner_id = $3 \
             AND e.execution_status = 'running' AND e.cancel_requested = true RETURNING e.task_id;",
            &[
                &crate::get_unix_epoch_ms(),
                &cancelled.task_id.to_string(),
                &cancelled.scanner_id.to_string(),
            ],
        )
        .await;
    match changed {
        Ok(rows) if !rows.is_empty() => {
            if let Err(error) =
                crate::refresh_task_aggregate(&transaction, rows[0].get("task_id")).await
            {
                error_logs_error(
                    &req,
                    "ScannerTaskCancelledAggregateError",
                    "refresh_task_aggregate",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
            if let Err(error) = transaction.commit().await {
                error_logs_error(
                    &req,
                    "ScannerTaskCancelledCommitError",
                    "commit_task_cancellation",
                    &error,
                );
                return HttpResponse::InternalServerError().finish();
            }
            HttpResponse::Ok().json(serde_json::json!({"success": true}))
        }
        Ok(_) => HttpResponse::Conflict().body("task cancellation was not requested"),
        Err(error) => {
            error_logs_error(
                &req,
                "ScannerTaskCancelledUpdateError",
                "mark_task_cancelled",
                &error,
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[get("/api/task/{task_id}")]
async fn get_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    task_id: web::Path<Uuid>,
    query: web::Query<TaskDetailQuery>,
    user: UserBaseI,
) -> impl Responder {
    let connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error) => {
            error_logs(&req, "GetTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task_id = task_id.into_inner().to_string();
    let task = match connection
        .query_opt(
            "SELECT t.id, t.task_id, CASE WHEN t.task_kind = 'dns' THEN t.dns_targets ELSE t.task_target::text[] END AS display_targets, \
             t.task_kind, t.task_port, t.task_initiator, \
             t.task_level, t.task_create_time, t.task_start_time, t.task_end_time, \
             t.task_status, t.lease_expires_at, t.attempt_count, t.failure_reason, t.cancel_requested, \
             t.retry_of_task_id, t.remarks, t.dispatch_mode, t.task_source, \
             t.generation_strategy, t.generation_metadata, t.address_family, t.scan_profile, t.scan_plan, t.dns_resolvers \
             FROM scan_task t \
             WHERE t.task_id = $1 AND ($2 = 1 OR t.user_id = $3) LIMIT 1;",
            &[&task_id, &user.role, &user.id],
        )
        .await
    {
        Ok(Some(task)) => task,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "success": false,
                "message": "task not found",
            }));
        }
        Err(error) => {
            error_logs(&req, "GetTaskDatabaseError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };

    let task_pk: i32 = task.get("id");
    let execution_rows = match connection.query(
        "SELECT e.id, e.execution_id, e.requested_scanner_id, e.assigned_scanner_id, \
         COALESCE(s.name, e.assigned_scanner_id, e.requested_scanner_id) AS scanner_name, s.location, \
         e.execution_status, e.attempt_count, e.task_start_time, e.task_end_time, e.lease_expires_at, \
         e.failure_reason, e.cancel_requested, COALESCE(e.result_ip_count, 0)::BIGINT AS ip_count, \
         COALESCE(e.result_port_count, 0)::BIGINT AS port_count, COALESCE(e.result_observation_count, 0)::BIGINT AS result_count \
         FROM scan_task_execution e \
         LEFT JOIN scanner_info s ON s.scanner_id = COALESCE(e.assigned_scanner_id, e.requested_scanner_id) \
         WHERE e.task_id = $1 AND e.execution_status <> 'superseded' \
         ORDER BY e.id;", &[&task_pk]).await {
        Ok(rows) => rows,
        Err(error) => { error_logs(&req, "GetTaskExecutionsError", &error.to_string()); return HttpResponse::InternalServerError().finish(); }
    };
    let selected_execution = query
        .execution_id
        .and_then(|id| {
            execution_rows
                .iter()
                .find(|row| row.get::<_, String>("execution_id") == id.to_string())
        })
        .or_else(|| execution_rows.first());
    let Some(selected_execution) = selected_execution else {
        error_logs(
            &req,
            "GetTaskExecutionsError",
            "task has no execution records",
        );
        return HttpResponse::InternalServerError().finish();
    };
    let selected_execution_pk: i32 = selected_execution.get("id");
    let executions: Vec<Value> = execution_rows.iter().map(|row| serde_json::json!({
        "execution_id": row.get::<_, String>("execution_id"),
        "requested_scanner_id": row.get::<_, Option<String>>("requested_scanner_id"),
        "scanner_id": row.get::<_, Option<String>>("assigned_scanner_id"),
        "scanner_name": row.get::<_, Option<String>>("scanner_name"),
        "scanner_location": row.get::<_, Option<String>>("location"),
        "status": row.get::<_, String>("execution_status"),
        "attempt_count": row.get::<_, i32>("attempt_count"),
        "task_start_time": row.get::<_, Option<i64>>("task_start_time"),
        "task_end_time": row.get::<_, Option<i64>>("task_end_time"),
        "lease_expires_at": row.get::<_, Option<i64>>("lease_expires_at"),
        "failure_reason": row.get::<_, Option<String>>("failure_reason"),
        "cancel_requested": row.get::<_, bool>("cancel_requested"),
        "summary": {"ip_count": row.get::<_, i64>("ip_count"), "port_count": row.get::<_, i64>("port_count"), "result_count": row.get::<_, i64>("result_count")}
    })).collect();
    let (page, page_size, offset) = task_result_pagination(query.page, query.page_size);
    let ip_count = selected_execution.get::<_, i64>("ip_count");
    let port_count = selected_execution.get::<_, i64>("port_count");
    let result_count = selected_execution.get::<_, i64>("result_count");
    let results = if elasticsearch.scan_storage_mode().reads_elasticsearch() {
        match load_execution_results_from_elasticsearch(
            elasticsearch.get_ref(),
            selected_execution.get::<_, String>("execution_id").as_str(),
            offset,
            page_size,
        )
        .await
        {
            Ok(results) => results,
            Err(error) => {
                error_logs(&req, "GetTaskResultsElasticsearchError", &error);
                return HttpResponse::ServiceUnavailable()
                    .json(json!({"message": "扫描结果索引暂时不可用"}));
            }
        }
    } else {
        let ip_rows = match connection
            .query(
                "SELECT ip_id, ip_address::text AS ip, asn, isp, as_org, \
                 country_code, country_name, region_name, city_name FROM ips \
                 WHERE execution_id = $1 ORDER BY ip_address LIMIT $2 OFFSET $3;",
                &[&selected_execution_pk, &page_size, &offset],
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                error_logs(&req, "GetTaskResultsError", &error.to_string());
                return HttpResponse::InternalServerError().finish();
            }
        };
        let ip_ids: Vec<i32> = ip_rows.iter().map(|row| row.get("ip_id")).collect();
        let mut ports_by_ip: HashMap<i32, Vec<TaskResultPort>> = HashMap::new();
        if !ip_ids.is_empty() {
            let port_rows = match connection
                .query(
                    "SELECT p.ip_id, p.port, latest.protocol, latest.service, latest.banner, \
                     CASE WHEN latest.kind IS NULL THEN NULL \
                     WHEN latest.kind = 'port' THEN jsonb_strip_nulls(jsonb_build_object( \
                        'observation_kind', latest.kind, 'state', latest.data->>'state', 'source', latest.source)) \
                     ELSE jsonb_strip_nulls(jsonb_build_object('observation_kind', latest.kind, \
                        'source', latest.source, 'data', latest.data)) END AS other, \
                     latest.scan_time FROM ports p JOIN ips i ON i.ip_id = p.ip_id \
                     LEFT JOIN LATERAL ( \
                        SELECT o.kind, o.protocol, o.service, o.banner, o.source, o.data, \
                            FLOOR(EXTRACT(EPOCH FROM o.observed_at) * 1000)::BIGINT AS scan_time \
                        FROM scan_observation o \
                        WHERE o.execution_id = i.execution_id \
                            AND o.ip_address = i.ip_address AND o.port = p.port \
                        ORDER BY (o.kind = 'service') DESC, \
                            (o.service IS NOT NULL OR o.banner IS NOT NULL) DESC, \
                            o.observed_at DESC, o.id DESC LIMIT 1 \
                     ) latest ON true \
                     WHERE p.ip_id = ANY($1) ORDER BY p.ip_id, p.port;",
                    &[&ip_ids],
                )
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    error_logs(&req, "GetTaskPortsError", &error.to_string());
                    return HttpResponse::InternalServerError().finish();
                }
            };
            for row in port_rows {
                ports_by_ip
                    .entry(row.get("ip_id"))
                    .or_default()
                    .push(TaskResultPort {
                        port: row.get("port"),
                        protocol: row.get("protocol"),
                        service: row.get("service"),
                        banner: row.get("banner"),
                        other: row.get("other"),
                        scan_time: row.get("scan_time"),
                    });
            }
        }
        ip_rows
            .into_iter()
            .map(|row| {
                let ip_id: i32 = row.get("ip_id");
                TaskResultIp {
                    ip: row.get("ip"),
                    asn: row.get("asn"),
                    isp: row.get("isp"),
                    as_org: row.get("as_org"),
                    country_code: row.get("country_code"),
                    country_name: row.get("country_name"),
                    region_name: row.get("region_name"),
                    city_name: row.get("city_name"),
                    ports: ports_by_ip.remove(&ip_id).unwrap_or_default(),
                }
            })
            .collect()
    };
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "task_id": task.get::<_, String>("task_id"),
            "task_target": task.get::<_, Vec<String>>("display_targets"),
            "task_kind": task.get::<_, String>("task_kind"),
            "task_port": task.get::<_, String>("task_port"),
            "task_initiator": task.get::<_, String>("task_initiator"),
            "task_level": task.get::<_, i32>("task_level"),
            "task_create_time": task.get::<_, i64>("task_create_time"),
            "task_start_time": selected_execution.get::<_, Option<i64>>("task_start_time"),
            "task_end_time": selected_execution.get::<_, Option<i64>>("task_end_time"),
            "task_status": task.get::<_, String>("task_status"),
            "dispatch_mode": task.get::<_, String>("dispatch_mode"),
            "task_source": task.get::<_, String>("task_source"),
            "generation_strategy": task.get::<_, Option<String>>("generation_strategy"),
            "generation_metadata": task.get::<_, Option<Value>>("generation_metadata"),
            "address_family": task.get::<_, String>("address_family"),
            "scan_profile": task.get::<_, String>("scan_profile"),
            "scan_plan": task.get::<_, Value>("scan_plan"),
            "dns_resolvers": task.get::<_, Value>("dns_resolvers"),
            "selected_execution_id": selected_execution.get::<_, String>("execution_id"),
            "executions": executions,
            "scanner_id": selected_execution.get::<_, Option<String>>("assigned_scanner_id"),
            "scanner_name": selected_execution.get::<_, Option<String>>("scanner_name"),
            "lease_expires_at": selected_execution.get::<_, Option<i64>>("lease_expires_at"),
            "attempt_count": selected_execution.get::<_, i32>("attempt_count"),
            "failure_reason": selected_execution.get::<_, Option<String>>("failure_reason"),
            "cancel_requested": selected_execution.get::<_, bool>("cancel_requested"),
            "retry_of_task_id": task.get::<_, Option<String>>("retry_of_task_id"),
            "remarks": task.get::<_, Option<String>>("remarks"),
            "summary": {
                "ip_count": ip_count,
                "port_count": port_count,
                "result_count": result_count,
            },
            "results": results,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": ip_count,
                "total_pages": if ip_count == 0 { 1 } else { (ip_count + page_size - 1) / page_size },
            }
        }
    }))
}

#[derive(Clone, Debug, Serialize)]
struct DnsComparisonResolverResult {
    id: String,
    label: String,
    ip: Option<String>,
    port: Option<u16>,
    transport: Option<String>,
    response_code: String,
    latency_ms: Option<u32>,
    answers: Vec<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct DnsComparisonRecord {
    name: String,
    record_type: String,
    resolvers: Vec<DnsComparisonResolverResult>,
    common_answers: Vec<Value>,
    differences: Vec<Value>,
    response_code_difference: bool,
}

fn build_dns_comparison(payload: &Value) -> Vec<DnsComparisonRecord> {
    let mut latest =
        BTreeMap::<(String, String, String), (String, DnsComparisonResolverResult)>::new();
    for hit in payload
        .pointer("/hits/hits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let source = hit.get("_source").unwrap_or(hit);
        let Some(name) = source.pointer("/dns/question/name").and_then(Value::as_str) else {
            continue;
        };
        let Some(record_type) = source.pointer("/dns/question/type").and_then(Value::as_str) else {
            continue;
        };
        let resolver_id = source
            .pointer("/resolver/id")
            .and_then(Value::as_str)
            .or_else(|| source.pointer("/dns_view/id").and_then(Value::as_str))
            .unwrap_or("system");
        let observed_at = source
            .get("@timestamp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let answers = source
            .pointer("/dns/answers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let item = DnsComparisonResolverResult {
            id: resolver_id.to_owned(),
            label: source
                .pointer("/resolver/label")
                .and_then(Value::as_str)
                .unwrap_or(resolver_id)
                .to_owned(),
            ip: source
                .pointer("/resolver/ip")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            port: source
                .pointer("/resolver/port")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok()),
            transport: source
                .pointer("/resolver/transport")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            response_code: source
                .pointer("/dns/response_code")
                .and_then(Value::as_str)
                .unwrap_or("SERVFAIL")
                .to_owned(),
            latency_ms: source
                .get("latency_ms")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            answers,
        };
        let key = (
            name.to_owned(),
            record_type.to_owned(),
            resolver_id.to_owned(),
        );
        if latest
            .get(&key)
            .is_none_or(|(current, _)| observed_at > *current)
        {
            latest.insert(key, (observed_at, item));
        }
    }
    let mut groups = BTreeMap::<(String, String), Vec<DnsComparisonResolverResult>>::new();
    for ((name, record_type, _), (_, resolver)) in latest {
        groups
            .entry((name, record_type))
            .or_default()
            .push(resolver);
    }
    groups.into_iter().map(|((name, record_type), mut resolvers)| {
        resolvers.sort_by(|left, right| left.id.cmp(&right.id));
        let resolver_count = resolvers.len();
        let response_code_difference = resolvers
            .iter()
            .map(|resolver| resolver.response_code.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            > 1;
        let mut occurrences = BTreeMap::<String, (Value, BTreeSet<String>)>::new();
        for resolver in &resolvers {
            for answer in &resolver.answers {
                let identity = format!("{}\u{0}{}", answer.get("type").and_then(Value::as_str).unwrap_or(""), answer.get("value").and_then(Value::as_str).unwrap_or(""));
                let entry = occurrences.entry(identity).or_insert_with(|| (answer.clone(), BTreeSet::new()));
                entry.1.insert(resolver.id.clone());
            }
        }
        let common_answers = occurrences.values()
            .filter(|(_, resolver_ids)| resolver_count > 0 && resolver_ids.len() == resolver_count)
            .map(|(answer, _)| answer.clone()).collect();
        let differences = occurrences.into_values()
            .filter(|(_, resolver_ids)| resolver_ids.len() != resolver_count)
            .map(|(answer, resolver_ids)| json!({"answer": answer, "resolver_ids": resolver_ids.into_iter().collect::<Vec<_>>() }))
            .collect();
        DnsComparisonRecord {
            name,
            record_type,
            resolvers,
            common_answers,
            differences,
            response_code_difference,
        }
    }).collect()
}

#[get("/api/task/{task_id}/dns-comparison")]
async fn get_dns_comparison(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    task_id: web::Path<Uuid>,
    user: UserBaseI,
) -> impl Responder {
    let task_id = task_id.into_inner().to_string();
    let connection = match pool.get().await {
        Ok(connection) => connection,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    let task_kind = match connection.query_opt(
        "SELECT task_kind FROM scan_task WHERE task_id = $1 AND ($2 = 1 OR user_id = $3) LIMIT 1;",
        &[&task_id, &user.role, &user.id],
    ).await {
        Ok(Some(task)) => task.get::<_, String>("task_kind"),
        Ok(None) => return HttpResponse::NotFound().json(json!({"success": false, "message": "task not found"})),
        Err(error) => { error_logs(&req, "GetDnsComparisonDatabaseError", &error.to_string()); return HttpResponse::InternalServerError().finish(); }
    };
    if task_kind != "dns" {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "task is not a DNS task"}));
    }
    match elasticsearch.dns_task_observations(&task_id).await {
        Ok(payload) => {
            let records = build_dns_comparison(&payload);
            HttpResponse::Ok().json(json!({"success": true, "data": {"records": records}}))
        }
        Err(error) => {
            error_logs(&req, "GetDnsComparisonElasticsearchError", &error);
            HttpResponse::ServiceUnavailable().json(
                json!({"success": false, "message": "DNS comparison is temporarily unavailable"}),
            )
        }
    }
}

#[post("/api/task/create")]
async fn create_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    create_data: web::Json<CreateTask>,
    user_base_i: UserBaseI,
) -> impl Responder {
    match create_data.level {
        0..5 => (),
        _ => {
            info_logs(
                &req,
                "InvalidParams",
                format!("任务优先级level不符合要求{}", create_data.level).as_str(),
            );
            return HttpResponse::BadRequest().body("400 Bad Request");
        }
    }

    let database_conn = pool.get_ref();
    let user_id = user_base_i.id;
    let user_name = user_base_i.username.clone();

    let task_info = match STask::new(
        TargetIP::S(&create_data.ip),
        &user_name,
        Some(&create_data.port),
        create_data.remark.as_deref(),
    ) {
        Ok(task) => task,
        Err(error_value) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "message": error_value.to_string()
            }));
        }
    };
    let address_family = match task_info.address_family() {
        Ok(family) => family,
        Err(message) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"success": false, "message": message}));
        }
    };
    let scan_profile = match create_data
        .scan_profile
        .as_deref()
        .map(str::trim)
        .filter(|profile| !profile.is_empty())
    {
        Some(profile) => profile.to_lowercase(),
        None => match get_default_scan_profile_from_database(database_conn).await {
            Ok(profile) => profile,
            Err(error_value) => {
                error_logs(
                    &req,
                    "ReadDefaultScanProfileError",
                    &error_value.to_string(),
                );
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "success": false,
                    "message": "默认扫描模式暂时无法读取"
                }));
            }
        },
    };
    let scan_plan = match build_scan_plan(&scan_profile) {
        Ok(plan) => plan,
        Err(message) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"success": false, "message": message}));
        }
    };
    let capability_filter = if address_family == "ipv6" {
        "supports_ipv6 AND ipv6_ready"
    } else {
        "supports_ipv4 AND ipv4_ready"
    };

    let dispatch_mode = create_data.dispatch_mode.trim().to_lowercase();
    let requested_scanners: Vec<Option<String>> = match dispatch_mode.as_str() {
        "automatic" if create_data.scanner_ids.is_empty() => vec![None],
        "selected" if !create_data.scanner_ids.is_empty() => {
            let ids: HashSet<String> = create_data.scanner_ids.iter().map(Uuid::to_string).collect();
            let connection = match database_conn.get().await {
                Ok(value) => value,
                Err(_) => return HttpResponse::InternalServerError().finish(),
            };
            let values: Vec<String> = ids.into_iter().collect();
            let query = format!(
                "SELECT scanner_id FROM scanner_info WHERE scanner_id = ANY($1::text[]) \
                 AND is_enable = true AND deleted_at IS NULL AND {capability_filter} \
                 AND ($2 = 'legacy' OR scan_capabilities->'profiles' ? $2);"
            );
            let rows = match connection.query(&query, &[&values, &scan_profile]).await {
                Ok(rows) => rows,
                Err(error) => { error_logs(&req, "ResolveTaskScannersError", &error.to_string()); return HttpResponse::InternalServerError().finish(); }
            };
            if rows.len() != values.len() {
                return HttpResponse::BadRequest().json(serde_json::json!({"success": false, "message": format!("selected scanner is unavailable or does not support {address_family}/{scan_profile}")}));
            }
            rows.into_iter().map(|row| Some(row.get("scanner_id"))).collect()
        }
        "all" if create_data.scanner_ids.is_empty() => {
            let connection = match database_conn.get().await {
                Ok(value) => value,
                Err(_) => return HttpResponse::InternalServerError().finish(),
            };
            let query = format!(
                "SELECT scanner_id FROM scanner_info WHERE is_enable = true AND deleted_at IS NULL \
                 AND {capability_filter} \
                 AND ($1 = 'legacy' OR scan_capabilities->'profiles' ? $1) ORDER BY scanner_id;"
            );
            let rows = match connection.query(&query, &[&scan_profile]).await {
                Ok(rows) => rows,
                Err(error) => { error_logs(&req, "ResolveTaskScannersError", &error.to_string()); return HttpResponse::InternalServerError().finish(); }
            };
            if rows.is_empty() {
                return HttpResponse::Conflict().json(serde_json::json!({"success": false, "message": format!("no scanner supporting {address_family}/{scan_profile} is currently available")}));
            }
            rows.into_iter().map(|row| Some(row.get("scanner_id"))).collect()
        }
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"success": false, "message": "invalid dispatch mode or scanner selection"})),
    };

    match task_info
        .add(
            database_conn,
            create_data.level as i32,
            user_id,
            &dispatch_mode,
            &requested_scanners,
            &scan_profile,
            &scan_plan,
            &AuditContext::from_request(&req),
            &user_base_i,
        )
        .await
    {
        Ok(()) => HttpResponse::Ok()
            .content_type(TEXT_HTML_UTF_8)
            .body("创建成功"),
        Err(e) => {
            error_logs(&req, "AddTaskError", e.to_string().as_str());
            HttpResponse::InternalServerError().body("500")
        }
    }
}

/// Creates the initial DNS-only task type. DNS tasks intentionally use an
/// explicit domain list and automatic dispatch only; they do not inherit the
/// IP/CIDR target generator or automatically expand into port scans.
#[post("/api/task/create-dns")]
async fn create_dns_task(
    req: HttpRequest,
    pool: web::Data<Pool>,
    input: web::Json<CreateDnsTask>,
    user: UserBaseI,
) -> impl Responder {
    if !(0..=4).contains(&input.level) {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "invalid task level"}));
    }
    if input.domains.is_empty() || input.domains.len() > 500 {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "domains must contain 1 to 500 entries"}));
    }
    if input.dns_resolvers.len() > 8 {
        return HttpResponse::BadRequest().json(
            json!({"success": false, "message": "dns_resolvers must contain at most 8 entries"}),
        );
    }
    let mut dns_resolvers = match input
        .dns_resolvers
        .iter()
        .cloned()
        .map(CreateDnsResolver::normalize)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(resolvers) => resolvers,
        Err(error) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": error}));
        }
    };
    dns_resolvers.sort_by(|left, right| left.id.cmp(&right.id));
    if dns_resolvers
        .windows(2)
        .any(|pair| pair[0].id == pair[1].id)
    {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "dns_resolvers contains duplicate IDs"}));
    }
    if !matches!(
        input.scan_profile.as_str(),
        "dns_records" | "dns_ports" | "dns_full"
    ) {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "invalid DNS scan profile"}));
    }
    let task_port = if input.scan_profile == "dns_records" {
        "53".to_owned()
    } else {
        let port = input.port.as_deref().unwrap_or("1-65535");
        if !crate::check_port(port) {
            return HttpResponse::BadRequest()
                .json(json!({"success": false, "message": "invalid port range"}));
        }
        port.to_owned()
    };
    let mut domains = match input
        .domains
        .iter()
        .map(|domain| crate::dns::canonical_domain(domain))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(domains) => domains,
        Err(error) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": error}));
        }
    };
    domains.sort();
    domains.dedup();
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };
    match connection
        .query(
            "SELECT 1 FROM scanner_info WHERE is_enable = true AND deleted_at IS NULL \
             AND supports_ipv4 AND ipv4_ready AND scan_capabilities->'profiles' ? $1 \
             AND ($2 = FALSE OR COALESCE((scan_capabilities->>'explicit_dns_resolvers')::BOOLEAN, FALSE)) \
             LIMIT 1;",
            &[&input.scan_profile, &!dns_resolvers.is_empty()],
        )
        .await
    {
        Ok(rows) if !rows.is_empty() => (),
        Ok(_) => return HttpResponse::Conflict().json(
            json!({"success": false, "message": "no DNS-capable scanner is currently available"}),
        ),
        Err(error) => {
            error_logs(&req, "ResolveDnsTaskScannersError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task_id = Uuid::now_v7().to_string();
    let transaction = match connection.build_transaction().start().await {
        Ok(transaction) => transaction,
        Err(error) => {
            error_logs(&req, "CreateDnsTaskTransactionError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task = match transaction
        .query_one(
            "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, task_level, remarks, \
             dispatch_mode, address_family, scan_profile, scan_plan, task_kind, dns_targets, dns_resolvers) \
             VALUES ($1, $2, $3, ARRAY[]::INET[], $4, $5, $6, 'automatic', 'ipv4', $7, \
             $8, 'dns', $9, $10) RETURNING id;",
            &[
                &user.id,
                &task_id,
                &user.username,
                &task_port,
                &(i32::from(input.level)),
                &input.remark,
                &input.scan_profile,
                &build_scan_plan(&input.scan_profile).expect("DNS scan profile was validated"),
                &domains,
                &serde_json::to_value(&dns_resolvers).expect("DNS resolver input is serializable"),
            ],
        )
        .await
    {
        Ok(task) => task,
        Err(error) => {
            error_logs(&req, "CreateDnsTaskError", &error.to_string());
            return HttpResponse::InternalServerError().finish();
        }
    };
    let task_db_id: i32 = task.get("id");
    if let Err(error) = transaction
        .execute(
            "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) VALUES ($1, $2, NULL);",
            &[&Uuid::now_v7().to_string(), &task_db_id],
        )
        .await
    {
        error_logs(&req, "CreateDnsTaskExecutionError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    let mut audit_event = audit::AuditEvent::user("task", "task.create_dns", "success", &user)
        .resource("task", task_id.clone());
    audit_event.response_status = Some(200);
    audit_event.metadata = json!({"target_count": domains.len(), "scan_profile": input.scan_profile, "dns_resolver_count": dns_resolvers.len()});
    if let Err(error) = audit::write(
        &transaction,
        &AuditContext::from_request(&req),
        &audit_event,
    )
    .await
    {
        error_logs(&req, "CreateDnsTaskAuditError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    if let Err(error) = transaction.commit().await {
        error_logs(&req, "CreateDnsTaskCommitError", &error.to_string());
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(json!({"success": true, "task_id": task_id, "domains": domains, "dns_resolvers": dns_resolvers}))
}

/// 用于扫描器申请一个扫描目标
#[get("/api/task/apply")]
async fn apply_task_handler(
    req: HttpRequest,
    scanner_id: web::Query<ApplyTaskQuery>,
    pool: web::Data<Pool>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
) -> impl Responder {
    let database_conn = pool.get_ref();
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(token) = token else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };

    let maintenance_snapshot = maintenance.snapshot().await;
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        database_conn,
        security.get_ref(),
        scanner_id.scannerid,
        token,
        maintenance_snapshot.clone(),
        maintenance_snapshot.blocks_new_work(),
    )
    .await
    {
        return response;
    }

    if scanner_id.dryrun.unwrap_or(false) {
        return match validate_scanner_credentials(
            database_conn,
            scanner_id.scannerid,
            token,
            &security.scanner_token_pepper,
        )
        .await
        {
            Ok(()) => HttpResponse::Ok().finish(),
            Err(ApplyTaskError::ScannerUnauthorized) => {
                HttpResponse::Unauthorized().body("unauthorized")
            }
            Err(ApplyTaskError::NoTask) => HttpResponse::NoContent().finish(),
            Err(ApplyTaskError::Database(e)) => {
                error_logs_error(
                    &req,
                    "ScannerCredentialCheckError",
                    "validate_scanner_credentials",
                    e.as_ref(),
                );
                HttpResponse::InternalServerError().finish()
            }
        };
    }

    match apply_task(
        database_conn,
        scanner_id.scannerid,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(a_t) => HttpResponse::Ok().json(a_t),
        Err(ApplyTaskError::ScannerUnauthorized) => {
            HttpResponse::Unauthorized().body("unauthorized")
        }
        Err(ApplyTaskError::NoTask) => HttpResponse::NoContent().finish(),
        Err(ApplyTaskError::Database(e)) => {
            error_logs_error(
                &req,
                "ApplyTaskDatabaseError",
                "claim_scan_task",
                e.as_ref(),
            );
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// 用于扫描器上传扫描结果。
#[post("/api/scanner/result")]
async fn upload_scanner_result_handler(
    req: HttpRequest,
    pool: web::Data<Pool>,
    maxmind: web::Data<MaxMindState>,
    elasticsearch: web::Data<crate::elasticsearch::ElasticsearchService>,
    security: web::Data<SecurityConfig>,
    maintenance: web::Data<SystemMaintenanceState>,
    upload_data: web::Json<ScannerResultUpload>,
) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(token) = token else {
        return HttpResponse::Unauthorized().body("missing scanner token");
    };

    let maintenance_snapshot = maintenance.snapshot().await;
    if let Some(response) = maintenance_gate_for_runtime_scanner(
        pool.get_ref(),
        security.get_ref(),
        upload_data.scanner_id,
        token,
        maintenance_snapshot.clone(),
        maintenance_snapshot.blocks_all_scanner_requests(),
    )
    .await
    {
        return response;
    }

    match save_scanner_results(
        pool.get_ref(),
        maxmind.get_ref(),
        elasticsearch.get_ref(),
        &upload_data,
        token,
        &security.scanner_token_pepper,
    )
    .await
    {
        Ok(saved) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "saved": saved,
        })),
        Err(e) => {
            error_logs_error(&req, "SaveScannerResultError", "persist_scan_results", &e);
            match e {
                SaveScannerResultsError::InvalidIp { .. } => {
                    HttpResponse::BadRequest().body("invalid ip")
                }
                SaveScannerResultsError::InvalidUpload(message) => {
                    HttpResponse::BadRequest().body(message)
                }
                SaveScannerResultsError::ScannerUnauthorized => {
                    HttpResponse::Unauthorized().body("unauthorized")
                }
                SaveScannerResultsError::TaskNotFound => {
                    HttpResponse::NotFound().body("task not found")
                }
                SaveScannerResultsError::TaskNotOwned => {
                    HttpResponse::Conflict().body("task is not owned by scanner")
                }
                SaveScannerResultsError::Database(_) => {
                    HttpResponse::InternalServerError().body("500")
                }
                SaveScannerResultsError::Storage(_) => {
                    HttpResponse::ServiceUnavailable().body("scan storage unavailable")
                }
            }
        }
    }
}

/// 获取所有任务接口
///
/// 分为管理员权限和普通用户权限
fn normalize_task_list_text(
    value: &Option<String>,
    max_length: usize,
    field_name: &str,
) -> Result<Option<String>, String> {
    let Some(value) = value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if value.chars().count() > max_length {
        return Err(format!("{field_name}长度不能超过 {max_length} 个字符"));
    }
    Ok(Some(value.to_owned()))
}

fn normalize_task_list_query(query: &ReceiveTaskItemQueryInfo) -> Result<TaskListFilters, String> {
    let limit = query.limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err("limit 必须在 1 到 100 之间".to_owned());
    }
    if query.cursor.is_some_and(|cursor| cursor <= 0) {
        return Err("cursor 必须是正整数".to_owned());
    }
    if query.start_time.is_some_and(|value| value < 0)
        || query.end_time.is_some_and(|value| value < 0)
    {
        return Err("时间范围不能为负数".to_owned());
    }
    if matches!((query.start_time, query.end_time), (Some(start), Some(end)) if start > end) {
        return Err("开始时间不能晚于结束时间".to_owned());
    }
    let status = normalize_task_list_text(&query.status, 32, "状态")?;
    if status.as_deref().is_some_and(|value| {
        !matches!(
            value,
            "pending" | "running" | "succeeded" | "failed" | "cancelled" | "partial"
        )
    }) {
        return Err("任务状态无效".to_owned());
    }
    Ok(TaskListFilters {
        cursor: query.cursor,
        limit,
        include_system: query.include_system.unwrap_or(false),
        task_id: normalize_task_list_text(&query.task_id, 36, "任务 ID")?,
        target: normalize_task_list_text(&query.target, 128, "目标")?,
        status,
        operator: normalize_task_list_text(&query.operator, 64, "操作者")?,
        start_time: query.start_time,
        end_time: query.end_time,
        scanner_id: normalize_task_list_text(&query.scanner_id, 36, "扫描器 ID")?,
    })
}

#[get("/api/task/all")]
async fn get_all_task_handler(
    _req: HttpRequest,
    query_info: web::Query<ReceiveTaskItemQueryInfo>,
    pool: web::Data<Pool>,
    user_base_i: UserBaseI,
) -> impl Responder {
    let p = pool.get_ref();
    let filters = match normalize_task_list_query(&query_info) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(serde_json::json!({"message": message}));
        }
    };

    let user_id = user_base_i.id;
    let user_role = user_base_i.role;

    let permi = match user_role {
        1 => Permission::Administrator(user_id),
        2 => Permission::Users(user_id),
        _ => {
            error!(
                event = "UserRoleValueInvalid",
                path = "fn get_all_task_handler",
                message = format!("用户角色值为：{}", user_role)
            );
            return HttpResponse::InternalServerError().finish();
        }
    };

    let page = match get_filtered_task_page(p, &filters, permi).await {
        Ok(o) => o,
        Err(e) => {
            error!(
                event = "GetTaskError",
                path = "fn get_all_task_handler",
                message = %e
            );
            return HttpResponse::InternalServerError().body("500");
        }
    };

    let tmp_json = TaskItemJson {
        total: page.total,
        page_size: page.page_size,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
        items: page.items,
    };

    HttpResponse::Ok().json(tmp_json)
}

#[cfg(test)]
mod tests {
    use super::{
        ScannerHeartbeatLease, ScannerHeartbeatResponse, ScannerLatencyReport,
        ScannerScanCapabilities, build_dns_comparison, normalize_task_list_query,
        task_result_pagination, validate_latency_report, validate_public_ip,
    };
    use crate::ReceiveTaskItemQueryInfo;
    use actix_web::web;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn latency_reports_are_bounded_and_recomputed() {
        let report = ScannerLatencyReport {
            version: 1,
            probe_id: Uuid::now_v7(),
            rtt_us: 42_000,
            server_processing_us: 7_000,
            network_rtt_us: 1,
            server_sent_at_ms: Utc::now().timestamp_millis(),
        };
        let validated = validate_latency_report(&report).expect("valid latency report");
        assert_eq!(validated.network_rtt_us, 35_000);

        let invalid = ScannerLatencyReport {
            server_processing_us: 50_000,
            ..report
        };
        assert!(validate_latency_report(&invalid).is_err());
    }

    #[test]
    fn task_list_query_excludes_system_tasks_by_default() {
        let default_query =
            web::Query::<ReceiveTaskItemQueryInfo>::from_query("").expect("empty query is valid");
        assert!(!default_query.include_system.unwrap_or(false));
        let normalized = normalize_task_list_query(&default_query).expect("normalize defaults");
        assert_eq!(normalized.limit, 20);
        assert!(!normalized.include_system);

        let include_query =
            web::Query::<ReceiveTaskItemQueryInfo>::from_query("include_system=true&count=10")
                .expect("include_system query is valid");
        assert_eq!(include_query.include_system, Some(true));
        assert_eq!(include_query.limit, Some(10));
    }

    #[test]
    fn task_list_query_validates_filters_and_pagination() {
        let valid = web::Query::<ReceiveTaskItemQueryInfo>::from_query(
            "limit=20&status=running&operator=admin&start_time=10&end_time=20",
        )
        .expect("valid task query");
        let normalized = normalize_task_list_query(&valid).expect("normalize task query");
        assert_eq!(normalized.limit, 20);
        assert_eq!(normalized.status.as_deref(), Some("running"));
        assert_eq!(normalized.operator.as_deref(), Some("admin"));

        let invalid_status = web::Query::<ReceiveTaskItemQueryInfo>::from_query("status=unknown")
            .expect("deserialize invalid status");
        assert!(normalize_task_list_query(&invalid_status).is_err());

        let invalid_range =
            web::Query::<ReceiveTaskItemQueryInfo>::from_query("start_time=20&end_time=10")
                .expect("deserialize invalid range");
        assert!(normalize_task_list_query(&invalid_range).is_err());

        let invalid_cursor = web::Query::<ReceiveTaskItemQueryInfo>::from_query("cursor=0")
            .expect("deserialize invalid cursor");
        assert!(normalize_task_list_query(&invalid_cursor).is_err());
    }

    #[test]
    fn task_result_pagination_uses_safe_bounds() {
        assert_eq!(task_result_pagination(None, None), (1, 20, 0));
        assert_eq!(task_result_pagination(Some(-5), Some(0)), (1, 1, 0));
        assert_eq!(task_result_pagination(Some(3), Some(500)), (3, 100, 200));
    }

    #[test]
    fn public_probe_addresses_must_match_the_reported_family() {
        assert_eq!(
            validate_public_ip(Some("203.0.113.10"), false).unwrap(),
            Some("203.0.113.10".to_owned())
        );
        assert_eq!(
            validate_public_ip(Some("::ffff:64.81.116.137"), false).unwrap(),
            Some("64.81.116.137".to_owned())
        );
        assert!(validate_public_ip(Some("2001:db8::1"), false).is_err());
        assert!(validate_public_ip(Some("::ffff:64.81.116.137"), true).is_err());
        assert!(validate_public_ip(Some("not-an-ip"), true).is_err());
    }

    #[test]
    fn scan_capabilities_are_allowlisted() {
        let valid = ScannerScanCapabilities {
            plan_versions: vec![1],
            profiles: vec!["legacy".into(), "port_only".into()],
            stages: vec!["port_discovery".into()],
            explicit_dns_resolvers: false,
        };
        assert!(valid.validate().is_ok());

        let invalid = ScannerScanCapabilities {
            plan_versions: vec![1],
            profiles: vec!["run_arbitrary_command".into()],
            stages: vec!["port_discovery".into()],
            explicit_dns_resolvers: false,
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn dns_comparison_groups_answers_by_resolver_and_question() {
        let comparison = build_dns_comparison(&json!({
            "hits": {"hits": [
                {"_source": {
                    "@timestamp": "2026-01-01T00:00:00Z", "dns_view": {"id": "dns-a"},
                    "resolver": {"id": "dns-a", "label": "DNS A", "ip": "192.0.2.53", "port": 53, "transport": "udp"},
                    "dns": {"question": {"name": "example.com", "type": "A"}, "response_code": "NOERROR", "answers": [{"type": "A", "value": "192.0.2.10", "ttl": 60}]}
                }},
                {"_source": {
                    "@timestamp": "2026-01-01T00:00:01Z", "dns_view": {"id": "dns-b"},
                    "resolver": {"id": "dns-b", "label": "DNS B", "ip": "192.0.2.54", "port": 53, "transport": "udp"},
                    "dns": {"question": {"name": "example.com", "type": "A"}, "response_code": "NOERROR", "answers": [{"type": "A", "value": "192.0.2.10", "ttl": 55}, {"type": "A", "value": "192.0.2.11", "ttl": 60}]}
                }}
            ]}
        }));
        assert_eq!(comparison.len(), 1);
        assert_eq!(comparison[0].resolvers.len(), 2);
        assert_eq!(comparison[0].common_answers.len(), 1);
        assert_eq!(comparison[0].differences.len(), 1);
    }

    #[test]
    fn heartbeat_reports_lost_task_lease_explicitly() {
        let task_id = uuid::Uuid::now_v7();
        let body = serde_json::to_value(ScannerHeartbeatResponse {
            success: true,
            lease: Some(ScannerHeartbeatLease {
                task_id,
                status: "lost",
                expires_at_ms: None,
                ttl_ms: crate::TASK_LEASE_MS,
                maintenance_hold: false,
            }),
            command: None,
            maintenance: None,
        })
        .unwrap();

        assert_eq!(body["lease"]["task_id"], task_id.to_string());
        assert_eq!(body["lease"]["status"], "lost");
        assert!(body["lease"]["expires_at_ms"].is_null());
        assert_eq!(body["lease"]["ttl_ms"], crate::TASK_LEASE_MS);
        assert_eq!(body["lease"]["maintenance_hold"], false);
    }
}
