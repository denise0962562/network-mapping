-- Lightweight instance metadata; aggregation queries reuse existing indexes.
CREATE TABLE IF NOT EXISTS statistics_instance (
    instance_id TEXT PRIMARY KEY,
    status JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
