-- Run this file outside an explicit transaction on an existing installation.
-- The server's init.sql runner wraps the whole file in a transaction, so the
-- concurrent index statements below deliberately live in this operator migration.

ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS write_token UUID;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS write_lease_expires_at TIMESTAMPTZ;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS write_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS write_started_at TIMESTAMPTZ;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS last_write_error TEXT;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_task_claim_priority
    ON scan_task (task_level DESC, task_create_time, id)
    WHERE task_status IN ('pending', 'running');
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_task_execution_selected_pending
    ON scan_task_execution (requested_scanner_id, task_id, id)
    WHERE execution_status = 'pending' AND requested_scanner_id IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_task_execution_public_pending
    ON scan_task_execution (task_id, id)
    WHERE execution_status = 'pending' AND requested_scanner_id IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_task_execution_expired_running
    ON scan_task_execution (task_id, lease_expires_at, id)
    WHERE execution_status = 'running' AND maintenance_hold = FALSE AND cancel_requested = FALSE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_task_execution_cancel_reaper
    ON scan_task_execution (lease_expires_at, id)
    WHERE execution_status = 'running' AND cancel_requested = TRUE;
