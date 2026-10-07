CREATE TABLE IF NOT EXISTS report_mail_asset (
    report_id UUID PRIMARY KEY REFERENCES report_run(id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT 'trend' CHECK (kind = 'trend'),
    renderer_version INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'image/png' CHECK (content_type = 'image/png'),
    width INTEGER NOT NULL CHECK (width = 1280),
    height INTEGER NOT NULL CHECK (height = 600),
    png_bytes BYTEA NOT NULL CHECK (octet_length(png_bytes) BETWEEN 8 AND 1048576),
    sha256 TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    lifetime_days INTEGER NOT NULL CHECK (lifetime_days BETWEEN 1 AND 3650),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
