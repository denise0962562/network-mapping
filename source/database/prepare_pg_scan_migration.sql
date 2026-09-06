-- Only the explicit PG -> ES migration command executes this legacy compatibility SQL.
-- 表 ips 用于存储ip数据，并配置了级联更新
CREATE TABLE IF NOT EXISTS ips ( 
	task_id INT NOT NULL, 
	execution_id INT NOT NULL,
	ip_id SERIAL PRIMARY KEY, 
	ip_address INET NOT NULL,
	asn TEXT DEFAULT NULL,
	isp TEXT DEFAULT NULL,
	as_org TEXT DEFAULT NULL,
	country_code VARCHAR(2) DEFAULT NULL,
	country_name TEXT DEFAULT NULL,
	region_name TEXT DEFAULT NULL,
	city_name TEXT DEFAULT NULL,
	latitude DOUBLE PRECISION DEFAULT NULL,
	longitude DOUBLE PRECISION DEFAULT NULL,
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
	update_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
	CONSTRAINT fk_task
        FOREIGN KEY (task_id)
        REFERENCES scan_task(id)
	        ON UPDATE CASCADE,
	CONSTRAINT fk_execution
		FOREIGN KEY (execution_id)
		REFERENCES scan_task_execution(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE
);

-- 兼容已有数据库；CREATE TABLE IF NOT EXISTS 不会为现有表补充列。
ALTER TABLE ips ADD COLUMN IF NOT EXISTS as_org TEXT DEFAULT NULL;
ALTER TABLE ips ADD COLUMN IF NOT EXISTS country_code VARCHAR(2) DEFAULT NULL;
ALTER TABLE ips ADD COLUMN IF NOT EXISTS country_name TEXT DEFAULT NULL;
ALTER TABLE ips ADD COLUMN IF NOT EXISTS region_name TEXT DEFAULT NULL;
ALTER TABLE ips ADD COLUMN IF NOT EXISTS city_name TEXT DEFAULT NULL;
ALTER TABLE ips ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION DEFAULT NULL;
ALTER TABLE ips ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION DEFAULT NULL;


-- 表 ports 用于存储扫描出的端口，其中ip_id通过外键关联到表ips，并配置了级联更新删除
CREATE TABLE IF NOT EXISTS ports ( 
	ip_id INT NOT NULL, 
	port_id SERIAL PRIMARY KEY, 
	port INT NOT NULL CHECK (port >=0 AND port <= 65535), 
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
	update_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT, 
	UNIQUE( ip_id, port), 
	CONSTRAINT fk_ip 
		FOREIGN KEY (ip_id) 
		REFERENCES ips(ip_id) 
		ON DELETE CASCADE 
		ON UPDATE CASCADE 
); 

-- scaninfo 是旧版本遗留表。初始化流程不会创建、清空或删除该表；
-- 若升级时该表仍存在，下方迁移块只读取它并幂等回填 observation。


CREATE TABLE IF NOT EXISTS scan_observation (
	id BIGSERIAL PRIMARY KEY,
	execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	batch_id BIGINT NOT NULL REFERENCES scan_result_batch(id) ON DELETE CASCADE,
	observation_key TEXT NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('port', 'service', 'vulnerability')),
	ip_address INET NOT NULL,
	port INT NOT NULL CHECK (port >= 0 AND port <= 65535),
	protocol TEXT NOT NULL,
	service TEXT,
	banner TEXT,
	title TEXT,
	http_body TEXT,
	http_body_truncated BOOLEAN NOT NULL DEFAULT FALSE,
	tls_subject TEXT,
	search_content_extracted BOOLEAN NOT NULL DEFAULT FALSE,
	source TEXT NOT NULL,
	data JSONB,
	observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	UNIQUE(execution_id, observation_key)
);

ALTER TABLE scan_observation DROP CONSTRAINT IF EXISTS scan_observation_kind_check;
ALTER TABLE scan_observation ADD CONSTRAINT scan_observation_kind_check
	CHECK (kind IN ('port', 'service', 'vulnerability'));

-- 旧版结果允许协议为空；类型化上传仍由应用层要求协议非空。
ALTER TABLE scan_observation ALTER COLUMN protocol DROP NOT NULL;
ALTER TABLE scan_observation ADD COLUMN IF NOT EXISTS title TEXT;
ALTER TABLE scan_observation ADD COLUMN IF NOT EXISTS http_body TEXT;
ALTER TABLE scan_observation ADD COLUMN IF NOT EXISTS http_body_truncated BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE scan_observation ADD COLUMN IF NOT EXISTS tls_subject TEXT;
ALTER TABLE scan_observation ADD COLUMN IF NOT EXISTS search_content_extracted BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_scan_observation_execution_kind
	ON scan_observation(execution_id, kind);
CREATE INDEX IF NOT EXISTS idx_scan_observation_endpoint_latest
	ON scan_observation(execution_id, ip_address, port, kind, observed_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_observation_observed_at
	ON scan_observation(observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_observation_service
	ON scan_observation(service)
	WHERE kind = 'service' AND service IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scan_observation_asset_endpoint_latest
	ON scan_observation(ip_address, port, observed_at DESC, id DESC)
	WHERE port > 0;
CREATE INDEX IF NOT EXISTS idx_scan_observation_port_latest
	ON scan_observation(port, observed_at DESC, id DESC)
	WHERE port > 0;
CREATE INDEX IF NOT EXISTS idx_scan_observation_service_lower
	ON scan_observation(LOWER(service))
	WHERE kind = 'service' AND service IS NOT NULL;


-- 将尚未进入 typed observation 模型的 v1 scaninfo 历史记录回填到合成批次。
-- 使用动态 SQL，确保 scaninfo 已由用户手动删除或新安装不存在时仍可正常初始化。
-- 限定为完全没有 observation 的 execution，避免把旧双写时期的兼容镜像重复导入。
DO $scaninfo_migration$
BEGIN
	IF to_regclass('scaninfo') IS NOT NULL THEN
		EXECUTE $sql$
			INSERT INTO scan_result_batch (
				execution_id, upload_id, batch_index, is_final, observation_count, protocol_version, storage_backend
			)
			SELECT e.id, e.execution_id, 0, true, COUNT(si.scan_info_id)::INT, 1, 'postgres'
			FROM scan_task_execution e
			JOIN ips i ON i.execution_id = e.id
			JOIN ports p ON p.ip_id = i.ip_id
			JOIN scaninfo si ON si.port_id = p.port_id
			WHERE NOT EXISTS (
				SELECT 1 FROM scan_observation existing WHERE existing.execution_id = e.id
			)
			GROUP BY e.id, e.execution_id
			ON CONFLICT (execution_id, upload_id, batch_index) DO NOTHING
		$sql$;

		EXECUTE $sql$
			INSERT INTO scan_observation (
				execution_id, batch_id, observation_key, kind, ip_address, port,
				protocol, service, banner, source, data, observed_at
			)
			SELECT
				e.id,
				b.id,
				'legacy:' || si.scan_info_id,
				CASE
					WHEN si.other->>'observation_kind' IN ('port', 'service')
						THEN si.other->>'observation_kind'
					WHEN NULLIF(BTRIM(si.service), '') IS NOT NULL OR NULLIF(BTRIM(si.banner), '') IS NOT NULL
						THEN 'service'
					ELSE 'port'
				END,
				i.ip_address,
				p.port,
				si.protocol,
				si.service,
				si.banner,
				COALESCE(NULLIF(si.other->>'source', ''), 'legacy'),
				CASE
					WHEN COALESCE(si.other->>'observation_kind', '') = 'service'
						OR NULLIF(BTRIM(si.service), '') IS NOT NULL
						OR NULLIF(BTRIM(si.banner), '') IS NOT NULL
						THEN COALESCE(si.other->'data', si.other)
					ELSE jsonb_strip_nulls(jsonb_build_object(
						'state', COALESCE(NULLIF(si.other->>'state', ''), 'open'),
						'legacy_other', si.other
					))
				END,
				COALESCE(to_timestamp(si.scan_time / 1000.0), NOW())
			FROM scaninfo si
			JOIN ports p ON p.port_id = si.port_id
			JOIN ips i ON i.ip_id = p.ip_id
			JOIN scan_task_execution e ON e.id = i.execution_id
			JOIN scan_result_batch b
				ON b.execution_id = e.id
				AND b.upload_id = e.execution_id
				AND b.batch_index = 0
				AND b.protocol_version = 1
			WHERE NOT EXISTS (
				SELECT 1
				FROM scan_observation existing
				WHERE existing.execution_id = e.id
					AND existing.observation_key = 'legacy:' || si.scan_info_id
			)
			ON CONFLICT (execution_id, observation_key) DO NOTHING
		$sql$;
	END IF;
END
$scaninfo_migration$;

-- 统一定义一次执行内端口的展示结果：服务识别优先，其次取最近观察。

-- One-time compatibility backfill. These are execution-level control-plane counters;
-- scan facts remain in scan_observation for PostgreSQL/dual mode or Elasticsearch after cutover.
UPDATE scan_task_execution execution SET
	result_ip_count = (SELECT COUNT(*) FROM ips WHERE execution_id = execution.id),
	result_port_count = (SELECT COUNT(*) FROM ports p JOIN ips i ON i.ip_id = p.ip_id WHERE i.execution_id = execution.id),
	result_observation_count = (SELECT COUNT(*) FROM scan_observation WHERE execution_id = execution.id)
WHERE execution.result_ip_count IS NULL
	OR execution.result_port_count IS NULL
	OR execution.result_observation_count IS NULL;
