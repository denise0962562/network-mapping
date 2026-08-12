-- 可重复执行的旧审计数据迁移。上线前先备份数据库，并在低流量时段执行。
INSERT INTO audit_event (
    event_id, occurred_at, category, action, outcome, severity, actor_type,
    actor_id, source_ip, response_status, reason_code, metadata
)
SELECT
    md5('login_logs:' || id::TEXT)::UUID,
    TO_TIMESTAMP(event_at),
    'authentication',
    'auth.login',
    CASE WHEN is_successful THEN 'success' ELSE 'failure' END,
    CASE WHEN is_successful THEN 'info' ELSE 'warning' END,
    CASE WHEN event_usage_id IS NULL OR event_usage_id < 0 THEN 'anonymous' ELSE 'user' END,
    CASE WHEN event_usage_id IS NULL OR event_usage_id < 0 THEN NULL ELSE event_usage_id::TEXT END,
    event_ip,
    CASE WHEN is_successful THEN 200 ELSE 401 END,
    CASE WHEN is_successful THEN NULL ELSE 'legacy_login_failure' END,
    jsonb_build_object('legacy_source', 'login_logs', 'legacy_id', id)
FROM login_logs
ON CONFLICT (event_id) DO NOTHING;

INSERT INTO audit_event (
    event_id, occurred_at, category, action, outcome, severity, actor_type,
    actor_id, resource_type, resource_id, changes, metadata
)
SELECT
    md5('operation_audit:' || id::TEXT)::UUID,
    created_at,
    CASE WHEN resource_type = 'scanner' THEN 'scanner' ELSE 'task' END,
    action,
    'success',
    'info',
    CASE WHEN actor_user_id IS NULL THEN 'system' ELSE 'user' END,
    actor_user_id::TEXT,
    resource_type,
    resource_id,
    detail,
    jsonb_build_object('legacy_source', 'operation_audit', 'legacy_id', id)
FROM operation_audit
ON CONFLICT (event_id) DO NOTHING;
