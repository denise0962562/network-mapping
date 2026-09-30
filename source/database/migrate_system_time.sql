-- Preserve absolute observation instants and immutable report calendar rules.
ALTER TABLE analytics_discovery_fact ADD COLUMN IF NOT EXISTS first_observed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_analytics_discovery_instant ON analytics_discovery_fact(first_observed_at, owner_id, scanner_id, task_source);
ALTER TABLE report_run ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai';
ALTER TABLE report_run ADD COLUMN IF NOT EXISTS settings_revision BIGINT NOT NULL DEFAULT 0;

ALTER TABLE report_run DROP CONSTRAINT IF EXISTS report_run_period_type_period_start_period_end_revision_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_report_run_calendar_revision ON report_run(period_type, period_start, period_end, timezone, revision);
INSERT INTO runtime_configuration(namespace, document) VALUES ('general', '{"timezone":"Asia/Shanghai","hourCycle":"24","dateFormat":"YYYY-MM-DD"}'::JSONB) ON CONFLICT(namespace) DO NOTHING;
