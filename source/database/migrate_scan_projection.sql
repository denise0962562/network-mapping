-- Additive migration. Stop all old projection workers before switching protocols.
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS claim_token UUID;
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS cursor JSONB;
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS phase TEXT NOT NULL DEFAULT 'promoting'
    CHECK (phase IN ('promoting', 'refreshing'));
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS processed_endpoints BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
