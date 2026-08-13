use std::net::Ipv4Addr;

use actix_web::{HttpResponse, Responder, get, web};
use deadpool_postgres::Pool;
use ipnet::Ipv4Net;
use serde::Serialize;
use serde_json::{Value, json};
use tracing::{error, info};
use uuid::Uuid;

use crate::audit::{AuditContext, AuditEvent, write as write_audit};
use crate::config::AutomaticTargetConfig;

const STRATEGY: &str = "sequential_subnet";
const SYSTEM_REQUEST_PATH: &str = "system://automatic-target-generator";

#[derive(Clone, Debug)]
pub struct AutomaticTargetService {
    policy: AutomaticTargetConfig,
    pools: Vec<Ipv4Net>,
    total_subnets: u64,
    policy_hash: String,
}

#[derive(Debug, Default, Serialize)]
pub struct RefillReport {
    pub pending_before: i64,
    pub pending_after: i64,
    pub generated: usize,
    pub skipped_recent: usize,
    pub scanner_available: bool,
}

#[derive(Debug, Serialize)]
struct GeneratedTarget {
    cidr: String,
    generation_key: String,
    pool: String,
    position: u64,
}

#[derive(Debug, Serialize)]
pub struct AutomaticTargetStatus {
    enabled: bool,
    strategy: String,
    authorized_cidrs: Vec<String>,
    ipv4_task_prefix: u8,
    common_ports: String,
    pending_low_watermark: u32,
    pending_high_watermark: u32,
    repeat_after_seconds: u64,
    pending_tasks: i64,
    running_tasks: i64,
    cursor_position: u64,
    total_subnets: u64,
    last_generated_at: Option<String>,
    last_error: Option<String>,
}

impl AutomaticTargetService {
    pub fn new(policy: AutomaticTargetConfig) -> Result<Self, Box<dyn std::error::Error>> {
        policy.validate()?;
        let pools: Vec<Ipv4Net> = policy
            .authorized_cidrs
            .iter()
            .map(|value| value.parse::<Ipv4Net>())
            .collect::<Result<_, _>>()?;
        let total_subnets = pools
            .iter()
            .map(|network| subnet_count(*network, policy.ipv4_task_prefix))
            .sum();
        let policy_hash = policy_hash(&policy);
        Ok(Self {
            policy,
            pools,
            total_subnets,
            policy_hash,
        })
    }

    pub fn enabled(&self) -> bool {
        self.policy.enabled
    }

    pub fn interval_seconds(&self) -> u64 {
        self.policy.interval_seconds
    }

    pub async fn refill(
        &self,
        pool: &Pool,
    ) -> Result<RefillReport, Box<dyn std::error::Error + Send + Sync>> {
        let mut client = pool.get().await?;
        let transaction = client.transaction().await?;
        transaction
            .execute(
                "INSERT INTO automatic_target_state (strategy, policy_hash) VALUES ($1, $2) \
                 ON CONFLICT (strategy) DO NOTHING;",
                &[&STRATEGY, &self.policy_hash],
            )
            .await?;
        let state = transaction
            .query_one(
                "SELECT cursor, policy_hash FROM automatic_target_state \
                 WHERE strategy = $1 FOR UPDATE;",
                &[&STRATEGY],
            )
            .await?;
        let stored_policy_hash: String = state.get("policy_hash");
        let cursor: Value = state.get("cursor");
        let mut position = if stored_policy_hash == self.policy_hash {
            cursor
                .get("position")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        } else {
            0
        };

        let scanner_available: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM scanner_info \
                 WHERE is_enable = true AND deleted_at IS NULL) AS available;",
                &[],
            )
            .await?
            .get("available");
        let pending_before: i64 = transaction
            .query_one(
                "SELECT COUNT(*)::BIGINT AS count FROM scan_task_execution e \
                 JOIN scan_task t ON t.id = e.task_id \
                 WHERE t.task_source = 'automatic' AND e.execution_status = 'pending';",
                &[],
            )
            .await?
            .get("count");
        let mut report = RefillReport {
            pending_before,
            pending_after: pending_before,
            scanner_available,
            ..RefillReport::default()
        };

        if !self.policy.enabled
            || !scanner_available
            || pending_before >= i64::from(self.policy.pending_low_watermark)
        {
            transaction.commit().await?;
            return Ok(report);
        }

        let to_generate = i64::from(self.policy.pending_high_watermark) - pending_before;
        let mut attempts = 0_u64;
        let max_attempts = self.total_subnets.max(1);
        while report.generated < to_generate as usize && attempts < max_attempts {
            let target = self.target_at(position);
            position = (position + 1) % self.total_subnets;
            attempts += 1;
            let recent_exists: bool = transaction
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM scan_task \
                     WHERE generation_key = $1 AND task_source = 'automatic' \
                       AND task_create_time >= (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT - $2::BIGINT) AS recent;",
                    &[
                        &target.generation_key,
                        &((self.policy.repeat_after_seconds as i64) * 1000),
                    ],
                )
                .await?
                .get("recent");
            if recent_exists {
                report.skipped_recent += 1;
                continue;
            }

            self.insert_task(&transaction, &target, pending_before)
                .await?;
            report.generated += 1;
        }
        report.pending_after = pending_before + report.generated as i64;
        transaction
            .execute(
                "UPDATE automatic_target_state SET cursor = $2, policy_hash = $3, \
                 last_generated_at = CASE WHEN $4::BIGINT > 0 THEN NOW() ELSE last_generated_at END, \
                 last_error = NULL, updated_at = NOW() WHERE strategy = $1;",
                &[
                    &STRATEGY,
                    &json!({"position": position}),
                    &self.policy_hash,
                    &(report.generated as i64),
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(report)
    }

    async fn insert_task(
        &self,
        transaction: &deadpool_postgres::Transaction<'_>,
        target: &GeneratedTarget,
        queue_depth_before: i64,
    ) -> Result<(), tokio_postgres::Error> {
        let system_user_id: i32 = transaction
            .query_one("SELECT id FROM users WHERE role = 0 LIMIT 1;", &[])
            .await?
            .get("id");
        let task_id = Uuid::now_v7().to_string();
        let metadata = json!({
            "strategy": STRATEGY,
            "pool": target.pool,
            "position": target.position,
            "policy_hash": self.policy_hash,
            "queue_depth_before": queue_depth_before,
        });
        let task_pk: i32 = transaction
            .query_one(
                "INSERT INTO scan_task (user_id, task_id, task_initiator, task_target, task_port, \
                 task_level, remarks, dispatch_mode, task_source, generation_strategy, generation_key, generation_metadata) \
                 VALUES ($1, $2, 'system', ARRAY[$3::text::inet], $4, $5, \
                 '系统自动生成扫描任务', 'automatic', 'automatic', $6, $7, $8) RETURNING id;",
                &[
                    &system_user_id,
                    &task_id,
                    &target.cidr,
                    &self.policy.common_ports,
                    &self.policy.priority,
                    &STRATEGY,
                    &target.generation_key,
                    &metadata,
                ],
            )
            .await?
            .get("id");
        transaction
            .execute(
                "INSERT INTO scan_task_execution (execution_id, task_id, requested_scanner_id) \
                 VALUES ($1, $2, NULL);",
                &[&Uuid::now_v7().to_string(), &task_pk],
            )
            .await?;

        let mut event = AuditEvent::anonymous("task", "task.auto_generate", "success")
            .resource("task", task_id);
        event.actor_type = "system".to_owned();
        event.actor_id = Some(system_user_id.to_string());
        event.actor_name = Some("system".to_owned());
        event.severity = "info".to_owned();
        event.response_status = Some(200);
        event.metadata = json!({
            "strategy": STRATEGY,
            "target": target.cidr,
            "ports": self.policy.common_ports,
            "policy_hash": self.policy_hash,
            "queue_depth_before": queue_depth_before,
        });
        write_audit(transaction, &system_audit_context(), &event).await
    }

    fn target_at(&self, position: u64) -> GeneratedTarget {
        let mut remaining = position % self.total_subnets;
        for pool in &self.pools {
            let count = subnet_count(*pool, self.policy.ipv4_task_prefix);
            if remaining < count {
                let subnet_size = 1_u64 << (32 - self.policy.ipv4_task_prefix);
                let base = u32::from(pool.network()) as u64 + remaining * subnet_size;
                let subnet =
                    Ipv4Net::new(Ipv4Addr::from(base as u32), self.policy.ipv4_task_prefix)
                        .expect("validated IPv4 prefix");
                let cidr = subnet.to_string();
                return GeneratedTarget {
                    generation_key: format!("{STRATEGY}:{cidr}"),
                    cidr,
                    pool: pool.to_string(),
                    position,
                };
            }
            remaining -= count;
        }
        unreachable!("position is normalized to configured subnet count")
    }

    async fn status(
        &self,
        pool: &Pool,
    ) -> Result<AutomaticTargetStatus, Box<dyn std::error::Error + Send + Sync>> {
        let client = pool.get().await?;
        let counts = client
            .query_one(
                "SELECT COUNT(*) FILTER (WHERE e.execution_status = 'pending')::BIGINT AS pending, \
                 COUNT(*) FILTER (WHERE e.execution_status = 'running')::BIGINT AS running \
                 FROM scan_task_execution e JOIN scan_task t ON t.id = e.task_id \
                 WHERE t.task_source = 'automatic';",
                &[],
            )
            .await?;
        let state = client
            .query_opt(
                "SELECT cursor, last_generated_at::TEXT, last_error FROM automatic_target_state WHERE strategy = $1;",
                &[&STRATEGY],
            )
            .await?;
        let cursor_position = state
            .as_ref()
            .and_then(|row| {
                row.get::<_, Value>("cursor")
                    .get("position")
                    .and_then(Value::as_u64)
            })
            .unwrap_or_default();
        Ok(AutomaticTargetStatus {
            enabled: self.policy.enabled,
            strategy: self.policy.strategy.clone(),
            authorized_cidrs: self.policy.authorized_cidrs.clone(),
            ipv4_task_prefix: self.policy.ipv4_task_prefix,
            common_ports: self.policy.common_ports.clone(),
            pending_low_watermark: self.policy.pending_low_watermark,
            pending_high_watermark: self.policy.pending_high_watermark,
            repeat_after_seconds: self.policy.repeat_after_seconds,
            pending_tasks: counts.get("pending"),
            running_tasks: counts.get("running"),
            cursor_position,
            total_subnets: self.total_subnets,
            last_generated_at: state.as_ref().and_then(|row| row.get("last_generated_at")),
            last_error: state.as_ref().and_then(|row| row.get("last_error")),
        })
    }

    async fn record_error(&self, pool: &Pool, message: &str) {
        let Ok(client) = pool.get().await else {
            return;
        };
        let message: String = message.chars().take(1000).collect();
        let _ = client
            .execute(
                "INSERT INTO automatic_target_state (strategy, policy_hash, last_error) \
                 VALUES ($1, $2, $3) ON CONFLICT (strategy) DO UPDATE SET \
                 last_error = EXCLUDED.last_error, updated_at = NOW();",
                &[&STRATEGY, &self.policy_hash, &message],
            )
            .await;
    }
}

pub async fn run_generator(service: AutomaticTargetService, pool: Pool) {
    if !service.enabled() {
        info!(target: "server::startup", "自动目标生成未启用");
        return;
    }
    let mut ticker =
        tokio::time::interval(std::time::Duration::from_secs(service.interval_seconds()));
    loop {
        ticker.tick().await;
        match service.refill(&pool).await {
            Ok(report) if report.generated > 0 => info!(
                target: "server::automatic_target",
                generated = report.generated,
                pending = report.pending_after,
                "自动目标队列已补充"
            ),
            Ok(report) if !report.scanner_available => info!(
                target: "server::automatic_target",
                "没有已启用的扫描器，暂停生成自动任务"
            ),
            Ok(_) => {}
            Err(error_value) => {
                service.record_error(&pool, &error_value.to_string()).await;
                error!(
                    target: "server::automatic_target",
                    event = "AutomaticTargetRefillError",
                    message = %error_value
                );
            }
        }
    }
}

#[get("/api/automatic-target/status")]
pub async fn automatic_target_status(
    pool: web::Data<Pool>,
    service: web::Data<AutomaticTargetService>,
    user: crate::admin::UserBaseI,
) -> impl Responder {
    if user.role != 1 {
        return HttpResponse::Forbidden().finish();
    }
    match service.status(pool.get_ref()).await {
        Ok(status) => HttpResponse::Ok().json(json!({"success": true, "data": status})),
        Err(error_value) => {
            error!(event = "AutomaticTargetStatusError", message = %error_value);
            HttpResponse::InternalServerError().finish()
        }
    }
}

fn subnet_count(network: Ipv4Net, task_prefix: u8) -> u64 {
    1_u64 << (task_prefix - network.prefix_len())
}

fn policy_hash(policy: &AutomaticTargetConfig) -> String {
    let serialized = serde_json::to_vec(&json!({
        "strategy": policy.strategy,
        "authorized_cidrs": policy.authorized_cidrs,
        "ipv4_task_prefix": policy.ipv4_task_prefix,
        "common_ports": policy.common_ports,
    }))
    .expect("automatic target policy is serializable");
    let digest = openssl::sha::sha256(&serialized);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn system_audit_context() -> AuditContext {
    AuditContext {
        request_id: Uuid::new_v4(),
        source_ip: None,
        user_agent: None,
        http_method: "SYSTEM".to_owned(),
        request_path: SYSTEM_REQUEST_PATH.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::AutomaticTargetService;
    use crate::config::AutomaticTargetConfig;

    fn service() -> AutomaticTargetService {
        AutomaticTargetService::new(AutomaticTargetConfig {
            enabled: true,
            authorized_cidrs: vec!["10.0.0.0/23".to_owned(), "192.168.1.0/24".to_owned()],
            ..AutomaticTargetConfig::default()
        })
        .unwrap()
    }

    #[test]
    fn sequential_strategy_walks_authorized_subnets_and_wraps() {
        let service = service();
        assert_eq!(service.total_subnets, 3);
        assert_eq!(service.target_at(0).cidr, "10.0.0.0/24");
        assert_eq!(service.target_at(1).cidr, "10.0.1.0/24");
        assert_eq!(service.target_at(2).cidr, "192.168.1.0/24");
        assert_eq!(service.target_at(3).cidr, "10.0.0.0/24");
    }

    #[test]
    fn generation_key_is_stable_for_a_subnet() {
        let service = service();
        assert_eq!(
            service.target_at(0).generation_key,
            "sequential_subnet:10.0.0.0/24"
        );
    }
}
