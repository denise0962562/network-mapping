use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, warn};
use uuid::Uuid;

use crate::logs::write::error_diagnostics;

pub const CHANNEL_CAPACITY: usize = 4096;
pub const RETENTION_DAYS: i32 = 30;
const BATCH_SIZE: usize = 250;
const FLUSH_INTERVAL_MS: u64 = 500;
const PURGE_BATCH_SIZE: i64 = 5000;

#[derive(Clone, Debug)]
pub struct ScannerLatencyHistory {
    sender: mpsc::Sender<ScannerLatencyHistoryEntry>,
}

#[derive(Clone, Debug)]
pub struct ScannerLatencyHistoryEntry {
    pub scanner_id: String,
    pub probe_id: Uuid,
    pub measured_at: DateTime<Utc>,
    pub rtt_us: i64,
    pub server_processing_us: i64,
    pub network_rtt_us: i64,
}

impl ScannerLatencyHistory {
    pub fn channel() -> (Self, mpsc::Receiver<ScannerLatencyHistoryEntry>) {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        (Self { sender }, receiver)
    }

    pub fn record(&self, entry: ScannerLatencyHistoryEntry) {
        if let Err(error) = self.sender.try_send(entry) {
            warn!(
                event = "ScannerLatencyHistoryDropped",
                reason = %error,
                "scanner latency history queue is full or unavailable"
            );
        }
    }
}

pub async fn run_writer(pool: Pool, mut receiver: mpsc::Receiver<ScannerLatencyHistoryEntry>) {
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut last_persisted = HashMap::<String, DateTime<Utc>>::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(FLUSH_INTERVAL_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                flush_batch(&pool, &mut batch).await;
            }
            entry = receiver.recv() => {
                match entry {
                    Some(entry) => {
                        if last_persisted.get(&entry.scanner_id).is_some_and(|previous| {
                            entry.measured_at.signed_duration_since(*previous)
                                < chrono::Duration::minutes(1)
                        }) {
                            continue;
                        }
                        last_persisted.insert(entry.scanner_id.clone(), entry.measured_at);
                        batch.push(entry);
                        if batch.len() >= BATCH_SIZE {
                            flush_batch(&pool, &mut batch).await;
                        }
                    }
                    None => {
                        flush_batch(&pool, &mut batch).await;
                        return;
                    }
                }
            }
        }
    }
}

async fn flush_batch(pool: &Pool, batch: &mut Vec<ScannerLatencyHistoryEntry>) {
    if batch.is_empty() {
        return;
    }
    let entries = std::mem::take(batch);
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(error_value) => {
            log_history_write_error("acquire_connection", &entries, &error_value);
            return;
        }
    };
    let transaction = match connection.transaction().await {
        Ok(transaction) => transaction,
        Err(error_value) => {
            log_history_write_error("begin_transaction", &entries, &error_value);
            return;
        }
    };

    for entry in &entries {
        if let Err(error_value) = transaction
            .execute(
                "INSERT INTO scanner_latency_sample (scanner_id, probe_id, measured_at, \
                 rtt_us, server_processing_us, network_rtt_us) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (scanner_id, probe_id) DO NOTHING;",
                &[
                    &entry.scanner_id,
                    &entry.probe_id,
                    &entry.measured_at,
                    &entry.rtt_us,
                    &entry.server_processing_us,
                    &entry.network_rtt_us,
                ],
            )
            .await
        {
            log_history_write_error("insert_latency_batch", &entries, &error_value);
            return;
        }
    }
    if let Err(error_value) = transaction.commit().await {
        log_history_write_error("commit_latency_batch", &entries, &error_value);
    }
}

fn log_history_write_error(
    operation: &'static str,
    entries: &[ScannerLatencyHistoryEntry],
    error_value: &(dyn std::error::Error + 'static),
) {
    let diagnostics = error_diagnostics(error_value);
    error!(
        event = "ScannerLatencyHistoryWriteError",
        operation,
        error_kind = "database",
        error_code = %format!("scanner_latency_{operation}_failed"),
        error_message = %diagnostics.error_message,
        error_chain = %diagnostics.error_chain,
        root_cause = %diagnostics.root_cause,
        error_truncated = diagnostics.error_truncated,
        retryable = false,
        outcome = "latency_samples_dropped",
        batch_size = entries.len(),
        dropped_this_batch = entries.len(),
        first_probe_at = ?entries.first().map(|entry| entry.measured_at),
        last_probe_at = ?entries.last().map(|entry| entry.measured_at),
        "failed to persist scanner latency history batch"
    );
}

pub async fn run_retention(pool: Pool, retention_days: i32) {
    let mut ticker = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let cutoff = Utc::now() - chrono::Duration::days(i64::from(retention_days));
        loop {
            let connection = match pool.get().await {
                Ok(connection) => connection,
                Err(error_value) => {
                    let diagnostics = error_diagnostics(&error_value);
                    error!(
                        event = "ScannerLatencyRetentionError",
                        operation = "acquire_retention_connection",
                        error_kind = "database",
                        error_code = "scanner_latency_retention_pool_failed",
                        error_message = %diagnostics.error_message,
                        error_chain = %diagnostics.error_chain,
                        root_cause = %diagnostics.root_cause,
                        error_truncated = diagnostics.error_truncated,
                        retryable = true,
                        outcome = "retention_deferred",
                        retention_days,
                        cutoff = %cutoff,
                        retry_after_ms = 86_400_000_u64,
                    );
                    break;
                }
            };
            match connection
                .execute(
                    "DELETE FROM scanner_latency_sample WHERE id IN (\
                     SELECT id FROM scanner_latency_sample WHERE measured_at < $1 \
                     ORDER BY measured_at ASC LIMIT $2);",
                    &[&cutoff, &PURGE_BATCH_SIZE],
                )
                .await
            {
                Ok(affected) if affected == PURGE_BATCH_SIZE as u64 => {}
                Ok(_) => break,
                Err(error_value) => {
                    let diagnostics = error_diagnostics(&error_value);
                    error!(
                        event = "ScannerLatencyRetentionError",
                        operation = "delete_expired_latency_samples",
                        error_kind = "database",
                        error_code = "scanner_latency_retention_delete_failed",
                        error_message = %diagnostics.error_message,
                        error_chain = %diagnostics.error_chain,
                        root_cause = %diagnostics.root_cause,
                        error_truncated = diagnostics.error_truncated,
                        retryable = true,
                        outcome = "retention_deferred",
                        retention_days,
                        cutoff = %cutoff,
                        purge_batch_size = PURGE_BATCH_SIZE,
                        retry_after_ms = 86_400_000_u64,
                    );
                    break;
                }
            }
        }
    }
}
