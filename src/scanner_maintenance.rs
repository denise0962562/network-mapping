use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use actix_web::{HttpResponse, http::header, web};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use serde::Serialize;
use serde_json::json;
use tokio::sync::RwLock;
use tokio_postgres::Row;
use tracing::{error, info};
use uuid::Uuid;

pub const DEFAULT_RETRY_AFTER_SECONDS: i32 = 600;
const DRAIN_EMPTY_CHECKS_REQUIRED: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenancePhase {
    Off,
    Draining,
    Active,
}

impl MaintenancePhase {
    fn from_database(value: &str) -> Self {
        match value {
            "draining" => Self::Draining,
            "active" => Self::Active,
            _ => Self::Off,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MaintenanceSnapshot {
    pub enabled: bool,
    pub phase: MaintenancePhase,
    pub maintenance_id: Option<Uuid>,
    pub message: String,
    pub expected_end_at: Option<DateTime<Utc>>,
    pub retry_after_seconds: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub revision: i64,
}

impl MaintenanceSnapshot {
    pub(crate) fn from_row(row: &Row) -> Self {
        Self {
            enabled: row.get("enabled"),
            phase: MaintenancePhase::from_database(row.get("phase")),
            maintenance_id: row.get("maintenance_id"),
            message: row.get("message"),
            expected_end_at: row.get("expected_end_at"),
            retry_after_seconds: row.get("retry_after_seconds"),
            started_at: row.get("started_at"),
            updated_at: row.get("updated_at"),
            revision: row.get("revision"),
        }
    }

    pub fn blocks_new_work(&self) -> bool {
        self.enabled
    }

    pub fn blocks_all_scanner_requests(&self) -> bool {
        self.enabled && self.phase == MaintenancePhase::Active
    }
}

pub struct ScannerMaintenanceState {
    snapshot: RwLock<MaintenanceSnapshot>,
    consecutive_empty_checks: AtomicU8,
}

impl ScannerMaintenanceState {
    pub async fn from_database(
        pool: &Pool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = pool.get().await?;
        let row = client
            .query_one(
                "SELECT enabled, phase, maintenance_id, message, expected_end_at, \
                 retry_after_seconds, started_at, updated_at, revision \
                 FROM scanner_maintenance_state WHERE singleton = TRUE;",
                &[],
            )
            .await?;
        Ok(Self {
            snapshot: RwLock::new(MaintenanceSnapshot::from_row(&row)),
            consecutive_empty_checks: AtomicU8::new(0),
        })
    }

    pub async fn snapshot(&self) -> MaintenanceSnapshot {
        self.snapshot.read().await.clone()
    }

    pub async fn replace(&self, snapshot: MaintenanceSnapshot) {
        let mut current = self.snapshot.write().await;
        if snapshot.revision >= current.revision {
            self.consecutive_empty_checks.store(0, Ordering::Relaxed);
            *current = snapshot;
        }
    }

    async fn reconcile(&self, pool: &Pool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let snapshot = self.snapshot().await;
        if !snapshot.enabled || snapshot.phase != MaintenancePhase::Draining {
            self.consecutive_empty_checks.store(0, Ordering::Relaxed);
            return Ok(());
        }

        let reclaimed = reclaim_expired_tasks(pool).await?;
        if reclaimed > 0 {
            info!(
                reclaimed,
                "expired scanner task leases reclaimed while draining"
            );
        }
        let running_tasks = active_task_count(pool).await?;
        if running_tasks > 0 {
            self.consecutive_empty_checks.store(0, Ordering::Relaxed);
            return Ok(());
        }
        let checks = self
            .consecutive_empty_checks
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if checks < DRAIN_EMPTY_CHECKS_REQUIRED {
            return Ok(());
        }

        let client = pool.get().await?;
        let row = client
            .query_opt(
                "UPDATE scanner_maintenance_state SET phase = 'active', updated_at = NOW(), \
                 revision = revision + 1 WHERE singleton = TRUE AND enabled = TRUE \
                 AND phase = 'draining' RETURNING enabled, phase, maintenance_id, message, \
                 expected_end_at, retry_after_seconds, started_at, updated_at, revision;",
                &[],
            )
            .await?;
        if let Some(row) = row {
            let next = MaintenanceSnapshot::from_row(&row);
            info!(
                maintenance_id = ?next.maintenance_id,
                revision = next.revision,
                "scanner maintenance drain completed"
            );
            self.replace(next).await;
        }
        Ok(())
    }
}

async fn reclaim_expired_tasks(
    pool: &Pool,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut client = pool.get().await?;
    let transaction = client.transaction().await?;
    let rows = transaction
        .query(
            "UPDATE scan_task_execution SET execution_status = CASE WHEN cancel_requested \
             THEN 'cancelled' ELSE 'pending' END, assigned_scanner_id = CASE WHEN cancel_requested \
             THEN assigned_scanner_id ELSE NULL END, lease_expires_at = NULL, task_start_time = \
             CASE WHEN cancel_requested THEN task_start_time ELSE NULL END, task_end_time = CASE \
             WHEN cancel_requested THEN (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT \
             ELSE NULL END, cancel_requested = false, failure_reason = CASE WHEN cancel_requested \
             THEN NULL ELSE 'task lease expired during maintenance drain' END WHERE \
             execution_status = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at < \
             (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT RETURNING task_id;",
            &[],
        )
        .await?;
    let task_ids: std::collections::HashSet<i32> =
        rows.iter().map(|row| row.get("task_id")).collect();
    for task_id in &task_ids {
        crate::refresh_task_aggregate(&transaction, *task_id).await?;
    }
    transaction.commit().await?;
    Ok(task_ids.len())
}

pub async fn active_task_count(
    pool: &Pool,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COUNT(*)::BIGINT AS count FROM scan_task_execution \
             WHERE execution_status = 'running';",
            &[],
        )
        .await?;
    Ok(row.get("count"))
}

pub async fn run_reconciler(state: web::Data<ScannerMaintenanceState>, pool: Pool) {
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    loop {
        ticker.tick().await;
        if let Err(error_value) = state.reconcile(&pool).await {
            error!(
                event = "ScannerMaintenanceReconcileError",
                message = %error_value,
            );
        }
    }
}

pub fn maintenance_response(snapshot: &MaintenanceSnapshot) -> HttpResponse {
    HttpResponse::ServiceUnavailable()
        .insert_header((
            header::RETRY_AFTER,
            snapshot.retry_after_seconds.to_string(),
        ))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header(("NM-Maintenance-Version", "1"))
        .json(json!({
            "success": false,
            "code": "scanner_maintenance",
            "maintenance": {
                "id": snapshot.maintenance_id,
                "phase": snapshot.phase,
                "message": snapshot.message,
                "started_at": snapshot.started_at,
                "expected_end_at": snapshot.expected_end_at,
                "server_time": Utc::now(),
                "retry_after_seconds": snapshot.retry_after_seconds,
                "manual_exit_required": true,
                "revision": snapshot.revision,
            }
        }))
}

#[cfg(test)]
mod tests {
    use super::{MaintenancePhase, MaintenanceSnapshot, maintenance_response};
    use actix_web::body::to_bytes;
    use chrono::Utc;

    #[actix_web::test]
    async fn maintenance_response_has_retry_contract() {
        let snapshot = MaintenanceSnapshot {
            enabled: true,
            phase: MaintenancePhase::Active,
            maintenance_id: None,
            message: "database upgrade".to_owned(),
            expected_end_at: None,
            retry_after_seconds: 600,
            started_at: Some(Utc::now()),
            updated_at: Utc::now(),
            revision: 1,
        };
        let response = maintenance_response(&snapshot);
        assert_eq!(
            response.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(response.headers().get("retry-after").unwrap(), "600");
        assert_eq!(
            response.headers().get("nm-maintenance-version").unwrap(),
            "1"
        );
        let body = to_bytes(response.into_body()).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "scanner_maintenance");
        assert_eq!(value["maintenance"]["phase"], "active");
    }
}
