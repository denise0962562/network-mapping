-- Additive migration; safe for existing scanners and repeated initialization.
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS diagnostics_capabilities JSONB NOT NULL DEFAULT '{}';
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS accepting_tasks BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS diagnostic_health TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS diagnostic_dropped_events BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS scanner_diagnostic_job (
    job_id UUID PRIMARY KEY,
    scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id),
    kind TEXT NOT NULL CHECK (kind IN ('list_logs', 'collect_logs')),
    source_file_ids JSONB NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','accepted','uploading','ready','failed','expired','cancelled')),
    requested_by INTEGER,
    automatic BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 minutes',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    error_code TEXT,
    sources JSONB NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS scanner_diagnostic_job_pending ON scanner_diagnostic_job(scanner_id, created_at)
    WHERE status IN ('queued','accepted','uploading');

CREATE TABLE IF NOT EXISTS scanner_log_source (
    scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id),
    source_file_id TEXT NOT NULL,
    document JSONB NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scanner_id, source_file_id)
);

CREATE TABLE IF NOT EXISTS scanner_log_file (
    file_id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES scanner_diagnostic_job(job_id) ON DELETE CASCADE,
    scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id),
    snapshot JSONB NOT NULL,
    ready BOOLEAN NOT NULL DEFAULT FALSE,
    parse_status TEXT NOT NULL DEFAULT 'pending' CHECK (parse_status IN ('pending','ready','failed')),
    parse_summary JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(job_id, file_id)
);
ALTER TABLE scanner_log_file ADD COLUMN IF NOT EXISTS parse_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scanner_log_file ADD COLUMN IF NOT EXISTS parse_retry_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS scanner_log_file_scanner ON scanner_log_file(scanner_id, created_at DESC);
CREATE TABLE IF NOT EXISTS scanner_log_upload_part (
    file_id UUID NOT NULL REFERENCES scanner_log_file(file_id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index >= 0),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    sha256 TEXT NOT NULL,
    PRIMARY KEY(file_id, part_index)
);

CREATE TABLE IF NOT EXISTS scanner_error_event (
    scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id),
    event_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    level TEXT NOT NULL,
    error_code TEXT NOT NULL,
    category TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    document JSONB NOT NULL,
    PRIMARY KEY(scanner_id, event_id)
);
CREATE INDEX IF NOT EXISTS scanner_error_event_time ON scanner_error_event(scanner_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS scanner_error_event_code ON scanner_error_event(scanner_id, error_code, occurred_at DESC);
CREATE TABLE IF NOT EXISTS scanner_error_evidence (
    scanner_id VARCHAR(36) NOT NULL,
    event_id TEXT NOT NULL,
    file_id UUID NOT NULL REFERENCES scanner_log_file(file_id) ON DELETE CASCADE,
    line_number BIGINT NOT NULL,
    byte_offset BIGINT NOT NULL,
    PRIMARY KEY(scanner_id, event_id, file_id, byte_offset),
    FOREIGN KEY(scanner_id, event_id) REFERENCES scanner_error_event(scanner_id, event_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS scanner_incident (
    scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id),
    fingerprint TEXT NOT NULL,
    error_code TEXT NOT NULL,
    operation TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    occurrences BIGINT NOT NULL DEFAULT 1,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by INTEGER,
    recovered_at TIMESTAMPTZ,
    PRIMARY KEY(scanner_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS scanner_diagnostic_recovery (
    scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id),
    operation TEXT NOT NULL,
    recovered_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(scanner_id, operation)
);
