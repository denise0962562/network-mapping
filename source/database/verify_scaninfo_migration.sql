-- scaninfo 下线前只读核验脚本。
-- 仅在遗留表仍存在时执行；本脚本不会修改、清空或删除任何数据。
-- missing_backfill_rows 与 mismatched_backfill_rows 均为 0 才表示历史回填通过。
WITH typed_executions AS (
    SELECT DISTINCT execution_id
    FROM scan_observation
    WHERE observation_key NOT LIKE 'legacy:%'
),
legacy_rows AS (
    SELECT
        e.id AS execution_id,
        si.scan_info_id,
        i.ip_address,
        p.port,
        si.protocol,
        si.service,
        si.banner,
        COALESCE(NULLIF(si.other->>'source', ''), 'legacy') AS source,
        CASE
            WHEN si.other->>'observation_kind' IN ('port', 'service')
                THEN si.other->>'observation_kind'
            WHEN NULLIF(BTRIM(si.service), '') IS NOT NULL
                OR NULLIF(BTRIM(si.banner), '') IS NOT NULL
                THEN 'service'
            ELSE 'port'
        END AS kind
    FROM scaninfo si
    JOIN ports p ON p.port_id = si.port_id
    JOIN ips i ON i.ip_id = p.ip_id
    JOIN scan_task_execution e ON e.id = i.execution_id
    LEFT JOIN typed_executions typed ON typed.execution_id = e.id
    WHERE typed.execution_id IS NULL
),
comparison AS (
    SELECT
        legacy.*,
        observation.id AS observation_id,
        observation.kind IS DISTINCT FROM legacy.kind
            OR observation.ip_address IS DISTINCT FROM legacy.ip_address
            OR observation.port IS DISTINCT FROM legacy.port
            OR observation.protocol IS DISTINCT FROM legacy.protocol
            OR observation.service IS DISTINCT FROM legacy.service
            OR observation.banner IS DISTINCT FROM legacy.banner
            OR observation.source IS DISTINCT FROM legacy.source AS is_mismatched
    FROM legacy_rows legacy
    LEFT JOIN scan_observation observation
        ON observation.execution_id = legacy.execution_id
        AND observation.observation_key = 'legacy:' || legacy.scan_info_id
)
SELECT
    COUNT(*) AS eligible_scaninfo_rows,
    COUNT(observation_id) AS backfilled_observation_rows,
    COUNT(*) FILTER (WHERE observation_id IS NULL) AS missing_backfill_rows,
    COUNT(*) FILTER (
        WHERE observation_id IS NOT NULL AND is_mismatched
    ) AS mismatched_backfill_rows
FROM comparison;
