-- Persistent recovery count; safe to reapply on existing databases.
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS recovery_failure_count INTEGER NOT NULL DEFAULT 0 CHECK (recovery_failure_count >= 0);
