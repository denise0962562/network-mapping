

-- 表 users 用于存储平台用户信息
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(200) NOT NULL UNIQUE,
    password TEXT NOT NULL,
	role INT,                                                                             -- 用户的权限级别，INT4 值，从 0-2 分别为系统、管理员、普通用户
	email TEXT,
    create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,    -- 用户的创建时间
	limit_login boolean DEFAULT false,                                                    -- 表示用户是否是被限制登录，既可以表示系统用户永远无法登录以及该账号是否因为密码错误而临时禁止登录
	limit_at BIGINT,                                                                      -- 限制登录操作产生的时间
	limit_time INT,                                                                       -- 限制登录时间，单位为 秒 
	enable_2fa boolean DEFAULT false,                                                     -- 表示用户是否启用了 2FA
	totp_secret TEXT,                                                                     -- TOTP 密钥
	last_login_at BIGINT,                                                                 -- 表示该用户最后一次登录的时间
	last_login_ip INET,                                                                   -- 最后一次登录的 IP 地址
	login_error_count INT,                                                                -- 登录错误的次数
	last_error_at BIGINT,                                                                 -- 最后一次登录出错的时间，以该时间为起点，判断是否将登录错误次数清零
	disabled_at TIMESTAMPTZ,                                                              -- 管理员主动禁用时间，与密码错误锁定分离
	deleted_at TIMESTAMPTZ,                                                               -- 软删除时间，保留任务与审计历史
	update_at TIMESTAMPTZ
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS update_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_users_management_status
ON users (role, disabled_at, deleted_at) WHERE role IN (1, 2);

-- 表 scan_task 用于存储扫描任务信息，配置了级联更新和删除
CREATE TABLE IF NOT EXISTS scan_task( 
	id SERIAL PRIMARY KEY,
	user_id INT NOT NULL,
	task_id VARCHAR(36) NOT NULL,                                                             -- 任务的 ID ，应该为 UUIDV7
	task_initiator VARCHAR(10) NOT NULL, 
	task_target INET[] NOT NULL,                                                              -- 扫描的目标 IP/CIDR 数组
	task_port TEXT DEFAULT '1-65535',                                                         -- 扫描目标的 PORT
	task_create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,   -- 表示扫描任务的创建时间
	task_level INT NOT NULL CHECK ( task_level >= 0 AND task_level <=4 ) DEFAULT 1,           -- 表示任务的优先级
	task_start_time BIGINT DEFAULT NULL,                                                      -- 扫描开始时间
	task_end_time BIGINT DEFAULT NULL,                                                        -- 扫描结束时间
	task_status TEXT NOT NULL DEFAULT 'pending',                                              -- pending/running/succeeded/failed
	assigned_scanner_id VARCHAR(36),                                                          -- 当前领取任务的扫描器 UUID
	lease_expires_at BIGINT,                                                                  -- 任务租约到期时间（毫秒时间戳）
	attempt_count INT NOT NULL DEFAULT 0,                                                     -- 任务领取次数
	failure_reason TEXT,                                                                      -- 最近一次扫描失败原因
	cancel_requested BOOLEAN NOT NULL DEFAULT false,                                          -- 控制端请求扫描器终止当前任务
	retry_of_task_id VARCHAR(36),                                                             -- 重试任务所引用的原任务
	dispatch_mode TEXT NOT NULL DEFAULT 'automatic',                                          -- automatic/selected/all
	task_source TEXT NOT NULL DEFAULT 'manual',                                               -- manual/automatic
	generation_strategy TEXT,
	generation_key TEXT,
	generation_metadata JSONB,
	address_family TEXT NOT NULL DEFAULT 'ipv4' CHECK (address_family IN ('ipv4', 'ipv6')),
	scan_profile TEXT NOT NULL DEFAULT 'legacy',
	scan_plan JSONB NOT NULL DEFAULT '{"version":1,"profile":"legacy","stages":[{"type":"port_discovery","required":true},{"type":"service_detection","required":false}]}'::jsonb,
	remarks TEXT DEFAULT NULL ,                                                               -- 扫描任务的备注
	CONSTRAINT fk_user
		FOREIGN KEY (user_id)
		REFERENCES users(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE,
	CONSTRAINT uk_task_id UNIQUE (task_id)
);

-- 兼容已有数据库中的任务表。
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS task_source TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS generation_strategy TEXT;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS generation_key TEXT;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS generation_metadata JSONB;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS address_family TEXT NOT NULL DEFAULT 'ipv4';
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS scan_profile TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS scan_plan JSONB NOT NULL
    DEFAULT '{"version":1,"profile":"legacy","stages":[{"type":"port_discovery","required":true},{"type":"service_detection","required":false}]}'::jsonb;
UPDATE scan_task SET address_family = 'ipv6'
WHERE cardinality(task_target) > 0
  AND NOT EXISTS (SELECT 1 FROM unnest(task_target) AS target WHERE family(target) <> 6);
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'scan_task_address_family_check'
    ) THEN
        ALTER TABLE scan_task ADD CONSTRAINT scan_task_address_family_check
            CHECK (address_family IN ('ipv4', 'ipv6'));
    END IF;
END $$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'scan_task_profile_check'
    ) THEN
        ALTER TABLE scan_task ADD CONSTRAINT scan_task_profile_check
            CHECK (scan_profile IN ('legacy', 'port_only', 'service_inventory'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS scan_task_execution (
	id SERIAL PRIMARY KEY,
	execution_id VARCHAR(36) NOT NULL UNIQUE,
	task_id INT NOT NULL REFERENCES scan_task(id) ON DELETE CASCADE,
	requested_scanner_id VARCHAR(36),
	assigned_scanner_id VARCHAR(36),
	execution_status TEXT NOT NULL DEFAULT 'pending',
	attempt_count INT NOT NULL DEFAULT 0,
	task_start_time BIGINT,
	task_end_time BIGINT,
	lease_expires_at BIGINT,
	failure_reason TEXT,
	cancel_requested BOOLEAN NOT NULL DEFAULT false,
	result_ip_count BIGINT,
	result_port_count BIGINT,
	result_observation_count BIGINT,
	CONSTRAINT uk_task_execution_scanner UNIQUE(task_id, requested_scanner_id)
);

ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS result_ip_count BIGINT;
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS result_port_count BIGINT;
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS result_observation_count BIGINT;

CREATE TABLE IF NOT EXISTS automatic_target_state (
	strategy TEXT PRIMARY KEY,
	cursor JSONB NOT NULL DEFAULT '{"position": 0}'::JSONB,
	policy_hash TEXT NOT NULL,
	last_generated_at TIMESTAMPTZ,
	last_error TEXT,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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

-- 资产标签独立于扫描执行保存。同一个 IP 的标签会应用到所有任务与历史结果。
CREATE TABLE IF NOT EXISTS asset_tag (
	id BIGSERIAL PRIMARY KEY,
	name VARCHAR(32) NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('info', 'malicious', 'benign')),
	description VARCHAR(256),
	is_active BOOLEAN NOT NULL DEFAULT TRUE,
	created_by INT REFERENCES users(id) ON DELETE SET NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_tag_active_name
	ON asset_tag (LOWER(name)) WHERE is_active;
CREATE INDEX IF NOT EXISTS idx_asset_tag_kind_active
	ON asset_tag (kind, is_active);

CREATE TABLE IF NOT EXISTS asset_ip_tag (
	ip_address INET NOT NULL,
	tag_id BIGINT NOT NULL REFERENCES asset_tag(id) ON DELETE CASCADE,
	assigned_by INT REFERENCES users(id) ON DELETE SET NULL,
	assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (ip_address, tag_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_ip_tag_address
	ON asset_ip_tag (ip_address);
CREATE INDEX IF NOT EXISTS idx_asset_ip_tag_tag_address
	ON asset_ip_tag (tag_id, ip_address);

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

-- Versioned, idempotent scanner uploads. A retry with the same execution/upload/batch
-- identity is acknowledged without inserting observations again.
CREATE TABLE IF NOT EXISTS scan_result_batch (
	id BIGSERIAL PRIMARY KEY,
	execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	upload_id VARCHAR(36) NOT NULL,
	batch_index INT NOT NULL CHECK (batch_index >= 0),
	is_final BOOLEAN NOT NULL,
	observation_count INT NOT NULL CHECK (observation_count >= 0),
	protocol_version SMALLINT NOT NULL DEFAULT 2 CHECK (protocol_version IN (1, 2)),
	payload_checksum VARCHAR(64),
	storage_backend TEXT NOT NULL DEFAULT 'postgres',
	storage_references JSONB NOT NULL DEFAULT '[]'::JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	UNIQUE(execution_id, upload_id, batch_index)
);

CREATE TABLE IF NOT EXISTS scan_storage_state (
	state_key TEXT PRIMARY KEY,
	state_value JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_projection_outbox (
	execution_id INT PRIMARY KEY REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	attempts INT NOT NULL DEFAULT 0,
	available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_error TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	processed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scan_projection_outbox_pending
	ON scan_projection_outbox(available_at, execution_id) WHERE processed_at IS NULL;

ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS protocol_version SMALLINT NOT NULL DEFAULT 2;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS payload_checksum VARCHAR(64);
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS storage_backend TEXT NOT NULL DEFAULT 'postgres';
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS storage_references JSONB NOT NULL DEFAULT '[]'::JSONB;
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid = 'scan_result_batch'::regclass
			AND conname = 'scan_result_batch_protocol_version_check'
	) THEN
		ALTER TABLE scan_result_batch
			ADD CONSTRAINT scan_result_batch_protocol_version_check
			CHECK (protocol_version IN (1, 2));
	END IF;
END $$;

CREATE TABLE IF NOT EXISTS scan_observation (
	id BIGSERIAL PRIMARY KEY,
	execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	batch_id BIGINT NOT NULL REFERENCES scan_result_batch(id) ON DELETE CASCADE,
	observation_key TEXT NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('port', 'service')),
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

-- 旧版结果允许协议为空；v2 上传仍由应用层要求协议非空。
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

-- One-time compatibility backfill. These are execution-level control-plane counters;
-- scan facts remain in scan_observation for PostgreSQL/dual mode or Elasticsearch after cutover.
UPDATE scan_task_execution execution SET
	result_ip_count = (SELECT COUNT(*) FROM ips WHERE execution_id = execution.id),
	result_port_count = (SELECT COUNT(*) FROM ports p JOIN ips i ON i.ip_id = p.ip_id WHERE i.execution_id = execution.id),
	result_observation_count = (SELECT COUNT(*) FROM scan_observation WHERE execution_id = execution.id)
WHERE execution.result_ip_count IS NULL
	OR execution.result_port_count IS NULL
	OR execution.result_observation_count IS NULL;
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
	IF to_regclass('public.scaninfo') IS NOT NULL THEN
		EXECUTE $sql$
			INSERT INTO scan_result_batch (
				execution_id, upload_id, batch_index, is_final, observation_count, protocol_version
			)
			SELECT e.id, e.execution_id, 0, true, COUNT(si.scan_info_id)::INT, 1
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
CREATE OR REPLACE VIEW scan_execution_endpoint_latest AS
SELECT
	ranked.id AS observation_id,
	ranked.execution_id,
	ranked.ip_address,
	ranked.port,
	ranked.kind,
	ranked.protocol,
	ranked.service,
	ranked.banner,
	ranked.source,
	ranked.data,
	ranked.observed_at,
	FLOOR(EXTRACT(EPOCH FROM ranked.observed_at) * 1000)::BIGINT AS scan_time
FROM (
	SELECT
		o.*,
		ROW_NUMBER() OVER (
			PARTITION BY o.execution_id, o.ip_address, o.port
			ORDER BY
				(o.kind = 'service') DESC,
				(o.service IS NOT NULL OR o.banner IS NOT NULL) DESC,
				o.observed_at DESC,
				o.id DESC
		) AS row_number
	FROM scan_observation o
) ranked
WHERE ranked.row_number = 1;

-- 数据分析查询按观察时间筛选，并通过端口、任务和执行记录进行权限过滤。
CREATE INDEX IF NOT EXISTS idx_ips_create_time_task
	ON ips(create_time, task_id);
CREATE INDEX IF NOT EXISTS idx_ips_address_update
	ON ips(ip_address, update_time DESC, ip_id DESC);

-- 表 session 用于存储cookie，其中包括在有效期内的和有效期外的
CREATE TABLE IF NOT EXISTS session (
	user_id INT NOT NULL,
	id SERIAL PRIMARY KEY,
	token TEXT NOT NULL,
	csrf_token TEXT NOT NULL,
	ttl INT DEFAULT 2700,
	totp_verify_successful boolean DEFAULT false,
	pending_totp_secret TEXT,
	pending_totp_expires_at BIGINT,
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT, 
	is_enable boolean DEFAULT true,
	deleted_at TIMESTAMPTZ,
	deletion_reason TEXT,
	deleted_by_user_id INT
);

-- Session 使用软删除保留认证历史，便于安全事件回溯。旧库升级时只补充审计字段，
-- 不物理删除既有失效记录；历史记录的精确失效时间未知，因此明确标记为迁移时间。
ALTER TABLE session ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE session ADD COLUMN IF NOT EXISTS deletion_reason TEXT;
ALTER TABLE session ADD COLUMN IF NOT EXISTS deleted_by_user_id INT;
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid = 'session'::regclass AND conname = 'session_deleted_by_user_fk'
	) THEN
		ALTER TABLE session ADD CONSTRAINT session_deleted_by_user_fk
			FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL;
	END IF;
END $$;
UPDATE session
SET deleted_at = NOW(), deletion_reason = 'legacy_inactive_migrated'
WHERE is_enable = FALSE AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_session_unique ON session (token, is_enable);
CREATE UNIQUE INDEX IF NOT EXISTS idx_csrf_token_unique ON session (csrf_token, is_enable);
CREATE INDEX IF NOT EXISTS idx_session_user_status ON session (user_id, is_enable);
CREATE INDEX IF NOT EXISTS idx_session_active_expiration
	ON session ((create_time + ttl::BIGINT * 1000), id)
	WHERE is_enable = TRUE AND deleted_at IS NULL;

ALTER TABLE session ALTER COLUMN ttl SET DEFAULT 2700;


-- 表 system_status 用于存储系统状态数据
CREATE TABLE IF NOT EXISTS system_status (
	id SERIAL PRIMARY KEY,
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT,   -- 为了便于筛选，使用秒级 UNIX 时间戳
	server_run_time BIGINT DEFAULT 0,
	cpu JSONB DEFAULT NULL,
	ram JSONB DEFAULT NULL,
	disk JSONB DEFAULT NULL,
	db_postgresql JSONB DEFAULT NULL,
	db_elasticsearch JSONB DEFAULT NULL,
	network JSONB DEFAULT NULL
);

ALTER TABLE system_status ADD COLUMN IF NOT EXISTS db_elasticsearch JSONB DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_system_status_create_time
	ON system_status(create_time);

-- 表 login_logs 用于存储用户登录日志，包括登陆成功和失败 
CREATE TABLE IF NOT EXISTS login_logs (
	id SERIAL PRIMARY KEY,
	event_at BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT,       -- 触发登录事件的时间，该列通常由数据库自动生成，当然也可能由后端生产，需要在后面看
	event_ip INET,                                                                 -- 触发登录事件的 IP 地址
	event_usage_id INT,                                                            -- 登录日志中触发该事件的用户 ID ，该参数可有可无
	is_successful boolean NOT NULL                                                 -- 登录日志中表示成功登录，True 表示登录成功，False 表示登录失败
);

-- 表 scanner_info 用于存储扫描器的各种信息，可以存放扫描器的 ID (UUIDV4) ，扫描器的版本，所支持的网络环境 IPV4/IPV6/ALL ，当前状态（RUN/STOP）
CREATE TABLE IF NOT EXISTS scanner_info (
	id SERIAL PRIMARY KEY,
	name VARCHAR(50),                                                               -- 扫描器的名称
	scanner_id VARCHAR(36) NOT NULL UNIQUE,                                         -- 该字段为扫描器的 ID ，UUIDV7
	create_user INT NOT NULL,                                                       -- 由谁创建
	registration_token_hash TEXT UNIQUE,                                            -- 一次性注册 token 的 HMAC 哈希
	registration_token_expires_at TIMESTAMPTZ,                                      -- 注册 token 过期时间
	registration_consumed_at TIMESTAMPTZ,                                           -- 注册 token 消费时间
	runtime_token_hash TEXT UNIQUE,                                                 -- 扫描器运行 token 的 HMAC 哈希
	runtime_token_rotated_at TIMESTAMPTZ,                                           -- 运行 token 最近轮换时间
	location TEXT,                                                                  -- 扫描器的位置描述
	system_version TEXT,                                                            -- 扫描器所在的系统名称及版本
	scanner_version TEXT,                                                           -- 扫描器的版本
	cpu_model TEXT,                                                                 -- 扫描器 CPU 型号
	cpus INT,                                                                       -- 扫描器 CPU 数量
	ram INT,                                                                        -- 扫描器 RAM 大小
	uptime INT,                                                                     -- 扫描器总共运行的时间
	create_time TIMESTAMPTZ,                                                        -- 扫描器创建的时间
	register_time TIMESTAMPTZ,                                                      -- 扫描器注册时间
	update_time TIMESTAMPTZ,                                                        -- 更新时间
	last_seen_at TIMESTAMPTZ,                                                       -- 最近一次收到心跳的时间
	runtime_state TEXT NOT NULL DEFAULT 'offline',                                  -- offline/idle/scanning/stopping
	ip_address INET,                                                                -- 扫描器的IP地址
	is_run boolean,                                                                 -- 扫描器是否在运行
	is_enable boolean,                                                              -- 扫描器是否启用
	remark TEXT,                                                                    -- 扫描器的备注
	tag TEXT,                                                                       -- 扫描器的标签
	deleted_at TIMESTAMPTZ                                                          -- 软删除时间
);

-- 旧版扫描器没有网络能力心跳，安全地按仅支持 IPv4 处理。
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS supports_ipv4 BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS supports_ipv6 BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS ipv4_ready BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS ipv6_ready BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS public_ipv4 INET;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS public_ipv6 INET;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS network_status_reason JSONB;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS network_capabilities_updated_at TIMESTAMPTZ;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS scan_capabilities JSONB NOT NULL
    DEFAULT '{"plan_versions":[],"profiles":["legacy"],"stages":["port_discovery"]}'::jsonb;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS scan_capabilities_updated_at TIMESTAMPTZ;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_rtt_us BIGINT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_network_rtt_us BIGINT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_server_processing_us BIGINT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_measured_at TIMESTAMPTZ;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_probe_id UUID;

-- 扫描器到服务端的 HTTPS 心跳延迟历史。最新值同时冗余在 scanner_info，
-- 避免扫描器列表查询历史表。
CREATE TABLE IF NOT EXISTS scanner_latency_sample (
	id BIGSERIAL PRIMARY KEY,
	scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id) ON UPDATE CASCADE,
	probe_id UUID NOT NULL,
	measured_at TIMESTAMPTZ NOT NULL,
	reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	rtt_us BIGINT NOT NULL CHECK (rtt_us >= 0),
	server_processing_us BIGINT NOT NULL CHECK (server_processing_us >= 0),
	network_rtt_us BIGINT NOT NULL CHECK (network_rtt_us >= 0),
	UNIQUE(scanner_id, probe_id)
);

CREATE INDEX IF NOT EXISTS idx_scanner_latency_scanner_time
	ON scanner_latency_sample(scanner_id, measured_at DESC);
CREATE INDEX IF NOT EXISTS idx_scanner_latency_time
	ON scanner_latency_sample(measured_at);

-- 扫描服务维护状态。单行表用于跨进程重启恢复；预计结束时间仅用于提示，
-- enabled 只能由管理员通过 Web 控制接口显式关闭。
CREATE TABLE IF NOT EXISTS scanner_maintenance_state (
	singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
	enabled BOOLEAN NOT NULL DEFAULT FALSE,
	phase TEXT NOT NULL DEFAULT 'off' CHECK (phase IN ('off', 'draining', 'active')),
	maintenance_id UUID,
	message TEXT NOT NULL DEFAULT '',
	expected_end_at TIMESTAMPTZ,
	retry_after_seconds INT NOT NULL DEFAULT 600 CHECK (retry_after_seconds BETWEEN 60 AND 86400),
	started_at TIMESTAMPTZ,
	started_by INT REFERENCES users(id),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	exited_at TIMESTAMPTZ,
	exited_by INT REFERENCES users(id),
	revision BIGINT NOT NULL DEFAULT 0
);

INSERT INTO scanner_maintenance_state (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS operation_audit (
	id BIGSERIAL PRIMARY KEY,
	actor_user_id INT,
	action TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	detail JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 统一安全审计事件。login_logs 与 operation_audit 暂时保留用于兼容旧数据，
-- 新代码只写入 audit_event。
CREATE TABLE IF NOT EXISTS audit_event (
	id BIGSERIAL PRIMARY KEY,
	event_id UUID NOT NULL UNIQUE,
	occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	category TEXT NOT NULL CONSTRAINT audit_event_category_check CHECK (category IN (
		'authentication', 'authorization', 'user_security', 'task', 'scanner',
		'automatic_target', 'configuration', 'data_access', 'audit', 'backup'
	)),
	action TEXT NOT NULL,
	outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
	severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
	actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'scanner', 'system', 'anonymous')),
	actor_id TEXT,
	actor_name TEXT,
	resource_type TEXT,
	resource_id TEXT,
	request_id UUID,
	source_ip INET,
	user_agent TEXT,
	http_method TEXT,
	request_path TEXT,
	response_status SMALLINT,
	reason_code TEXT,
	changes JSONB,
	metadata JSONB NOT NULL DEFAULT '{}'::JSONB
);

-- 兼容尚未包含新审计分类的已有审计表。
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'audit_event'::regclass
          AND conname = 'audit_event_category_check'
          AND (
              POSITION('automatic_target' IN pg_get_constraintdef(oid)) = 0
              OR POSITION('backup' IN pg_get_constraintdef(oid)) = 0
          )
    ) THEN
        ALTER TABLE audit_event DROP CONSTRAINT audit_event_category_check;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'audit_event'::regclass
          AND conname = 'audit_event_category_check'
    ) THEN
        ALTER TABLE audit_event ADD CONSTRAINT audit_event_category_check CHECK (category IN (
            'authentication', 'authorization', 'user_security', 'task', 'scanner',
            'automatic_target', 'configuration', 'data_access', 'audit', 'backup'
        ));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_event_time
	ON audit_event (occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_actor_time
	ON audit_event (actor_type, actor_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_resource_time
	ON audit_event (resource_type, resource_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_action_time
	ON audit_event (action, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_login_actor_time
	ON audit_event (actor_id, occurred_at DESC, id DESC)
	WHERE category = 'authentication' AND action = 'auth.login';
CREATE INDEX IF NOT EXISTS idx_audit_event_login_username_time
	ON audit_event ((COALESCE(actor_name, metadata->>'attempted_username')), occurred_at DESC, id DESC)
	WHERE category = 'authentication' AND action = 'auth.login' AND actor_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_audit_event_request
	ON audit_event (request_id) WHERE request_id IS NOT NULL;

-- 任务调度与结果索引。当前开发环境直接按上述定义创建全新表结构。
CREATE UNIQUE INDEX IF NOT EXISTS idx_ips_execution_address ON ips (execution_id, ip_address);
CREATE INDEX IF NOT EXISTS idx_scan_task_execution_dispatch
	ON scan_task_execution (execution_status, requested_scanner_id, lease_expires_at, task_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_task_execution_running_owner
	ON scan_task_execution (task_id, assigned_scanner_id)
	WHERE execution_status = 'running' AND assigned_scanner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_task_dispatch
	ON scan_task (task_status, lease_expires_at, task_level DESC, task_create_time);
CREATE INDEX IF NOT EXISTS idx_scan_task_user_list
	ON scan_task (user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_task_status_list
	ON scan_task (task_status, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_task_scanner_list
	ON scan_task (assigned_scanner_id, id DESC)
	WHERE assigned_scanner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_task_create_time_list
	ON scan_task (task_create_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_task_manual_list
	ON scan_task (id DESC) WHERE task_source <> 'automatic';
CREATE INDEX IF NOT EXISTS idx_scan_task_automatic_queue
	ON scan_task (task_status, task_create_time) WHERE task_source = 'automatic';
CREATE INDEX IF NOT EXISTS idx_scan_task_automatic_family_queue
	ON scan_task (address_family, task_status, task_create_time) WHERE task_source = 'automatic';
CREATE INDEX IF NOT EXISTS idx_scan_task_generation_key
	ON scan_task (generation_key, task_create_time DESC) WHERE generation_key IS NOT NULL;

-- 表 ip_list 用于存储 IP 名单信息，这个 IP 名单可用于多处，如：扫描白名单，访问白名单（黑名单）等···
CREATE TABLE IF NOT EXISTS ip_list (
	id SERIAL PRIMARY KEY,
	is_white boolean DEFAULT false,                                                 -- 该字段表示是否是白名单，默认为 false 
	ip INET NOT NULL,                                                               -- 该字段可以存储单个 IP 或 CIDR 地址段
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT,     -- 白名单 IP/CIDR 创建时间
	tag TEXT,                                                                       -- IP 列表的标签
	remark TEXT,                                                                    -- IP 列表的备注
	UNIQUE(ip, is_white)                                                            -- 限制了 ip 和 is_white 组合的唯一性
);


-- 国家简写表
CREATE TABLE IF NOT EXISTS country (
	id SERIAL PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	create_at TIMESTAMPTZ DEFAULT NOW(),
	remarks TEXT
);


-- 以下为 ASN 表所需要的组织信息表
CREATE TABLE IF NOT EXISTS org (
	id SERIAL PRIMARY KEY,
	org_name TEXT DEFAULT NULL,                                                    -- 组织名
	org_key TEXT,                                                                  -- 组织的唯一标识符
	org_type TEXT,                                                                 -- 组织类型
	descr TEXT DEFAULT NULL,                                                       -- 组织描述信息
	country TEXT,                                                                  -- 组织所属国家
	address TEXT,                                                                  -- 组织的物理地址
	phone TEXT,                                                                    -- 组织的电话
	email TEXT,                                                                    -- 组织的联系邮箱
	admin_c TEXT,                                                                  -- 管理联系人
	tech_c TEXT,                                                                   -- 组织技术联系人
	last_modified timestamptz,                                                     -- 该组织信息最后变动时间，该信息来自 RIR 数据
	create_at TEXT,                                                                -- 该条目创建的时间
	source TEXT,                                                                   -- 该条目数据来自哪一个 RIR
	unique_hash TEXT GENERATED ALWAYS AS (
		MD5(
			COALESCE(org_name, '') ||
			COALESCE(org_key, '') ||
			COALESCE(country, '') ||
			COALESCE(admin_c, '') ||
			COALESCE(source, '') 
		)
	) STORED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_unique_hash ON org (unique_hash);

-- 以下为 ASN 表，其中描述了 IP/CIDR 当前宣告的 asn号，对应 RIR 数据中的 route/route6 路由宣告表
CREATE TABLE IF NOT EXISTS asn (
	id SERIAL PRIMARY KEY,
	ip INET,
	asnumber TEXT DEFAULT NULL,
	descr TEXT,
	status TEXT,                                                                    -- 当前段的状态 常见值包括：
	                                                                                --   • ASSIGNED NON-PORTABLE：已分配给特定组织，不可转移
																					--   • ALLOCATED PORTABLE：可携带的分配（常用于 ISP）
																					--   • SUB-ALLOCATED：子分配
	mnt_by TEXT,                                                                    -- 当前段的主维护者
	mnt_irt TEXT,
	mnt_lower TEXT,
	created timestamptz,                                                            -- 创建时间，该时间来自 RIR
	last_modified timestamptz,                                                      -- 最后修改时间
	create_at TIMESTAMPTZ DEFAULT NOW(),                                            -- 在本地数据库中创建的时间
	remarks TEXT,
	source TEXT,
	unique_hash TEXT GENERATED ALWAYS AS (
		MD5(
			COALESCE(ip::TEXT, '') ||
			COALESCE(asnumber, '') ||
			COALESCE(status, '') ||
			COALESCE(mnt_by, '') ||
			COALESCE(remarks, '') ||
			COALESCE(source, '')
		)
	) STORED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asn_unique_hash ON asn (unique_hash);



-- 该表描述了当前 IP/CIDR 对应的 ISP  ，对应 RIR 数据中的 inetnum/inet6num 所属表
CREATE TABLE IF NOT EXISTS isp (
	id SERIAL PRIMARY KEY,
	ip INET,
	netname TEXT,
	descr TEXT,
	country TEXT,
	admin_c TEXT,
	tech_c TEXT,
	notify TEXT,
	status TEXT,
	mnt_by TEXT,
	mnt_irt TEXT,
	remarks TEXT,
	last_modified timestamptz,
	source TEXT,

	create_at TIMESTAMPTZ DEFAULT NOW(),              -- 该条目在本地数据库创建的时间
	unique_hash TEXT GENERATED ALWAYS AS (
        MD5(
            COALESCE(ip::TEXT, '') ||
            COALESCE(netname, '') ||
            COALESCE(descr, '') ||
            COALESCE(country, '') ||
            COALESCE(admin_c, '') ||
            COALESCE(tech_c, '') ||
            COALESCE(notify, '') ||
            COALESCE(status, '') ||
            COALESCE(mnt_by, '') ||
            COALESCE(mnt_irt, '') ||
            COALESCE(remarks, '') ||
            COALESCE(source, '')
        )
    ) STORED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_isp_unique_hash ON isp (unique_hash);

-- 存放配置
CREATE TABLE IF NOT EXISTS setting (
	id SERIAL PRIMARY KEY,
	item_type TEXT,
	key TEXT,
	value TEXT,
	create_at TIMESTAMPTZ DEFAULT NOW(),
	update_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_setting_item_type_key ON setting (item_type, key);

INSERT INTO setting (item_type, key, value)
VALUES ('security', 'session_ttl_seconds', '2700')
ON CONFLICT (item_type, key) DO NOTHING;

INSERT INTO setting (item_type, key, value)
VALUES ('scan', 'default_profile', 'legacy')
ON CONFLICT (item_type, key) DO NOTHING;

INSERT INTO setting (item_type, key, value)
VALUES ('network', 'trusted_proxies', '{"trustedProxyCidrs":[],"clientIpHeader":"x-forwarded-for"}')
ON CONFLICT (item_type, key) DO NOTHING;

-- 邮件模板元数据与版本。草稿不会影响正在使用的已发布版本。
CREATE TABLE IF NOT EXISTS mail_template (
	template_key TEXT PRIMARY KEY,
	display_name TEXT NOT NULL,
	active_version INT,
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	create_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	update_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mail_template_version (
	id BIGSERIAL PRIMARY KEY,
	template_key TEXT NOT NULL REFERENCES mail_template(template_key) ON DELETE CASCADE,
	version INT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('draft', 'published', 'archived')),
	subject_template TEXT NOT NULL,
	html_template TEXT NOT NULL,
	text_template TEXT NOT NULL,
	created_by INT REFERENCES users(id) ON DELETE SET NULL,
	create_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	update_at TIMESTAMPTZ,
	published_at TIMESTAMPTZ,
	UNIQUE (template_key, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_template_single_draft
ON mail_template_version (template_key)
WHERE status = 'draft';

CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_template_single_published
ON mail_template_version (template_key)
WHERE status = 'published';

INSERT INTO mail_template (template_key, display_name)
VALUES ('login_success', '登录成功')
ON CONFLICT (template_key) DO UPDATE SET display_name = EXCLUDED.display_name;

-- 请求日志（访问日志）：覆盖每一个业务请求，用于请求级分析与错误自动识别。
-- 与 audit_event（安全审计，只记录敏感操作）不同，本表不记录请求体、原始查询串、
-- Session、CSRF Token、Authorization 请求头、扫描器令牌。
CREATE TABLE IF NOT EXISTS request_log (
	id BIGSERIAL PRIMARY KEY,
	request_id UUID NOT NULL,
	occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	http_method TEXT NOT NULL,
	request_path TEXT NOT NULL,
	status_code SMALLINT NOT NULL,
	duration_ms INTEGER,
	duration_us BIGINT,
	route_pattern TEXT,
	client_ip INET,
	user_agent TEXT,
	actor_id INT,                        -- 已认证用户 id；匿名/扫描器请求为 NULL
	actor_name TEXT,                     -- 已认证用户名；匿名/扫描器请求为 NULL
	error_level TEXT NOT NULL DEFAULT 'ok'
		CHECK (error_level IN ('ok', 'client_error', 'server_error')),
	error_type TEXT                      -- bad_request / unauthorized / not_found / ...
);

-- 兼容已经创建 request_log 的部署：保留 duration_ms，新增微秒精度和标准化路由。
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS duration_us BIGINT;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS route_pattern TEXT;

-- 只保留 2 个索引：分页/趋势/保留清理走 time 索引，错误查询与错误率趋势走 error 索引。
CREATE INDEX IF NOT EXISTS idx_request_log_time
	ON request_log (occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_request_log_error
	ON request_log (error_level, occurred_at DESC);

-- 健康告警历史：记录慢请求、5xx 错误、慢 SQL 的告警事件，供告警历史页与跨重启冷却去重使用。
-- detail 为 JSONB，存储告警详情键值列表（结构与 health_alert 邮件模板的 details 一致）。
CREATE TABLE IF NOT EXISTS health_alert (
	id BIGSERIAL PRIMARY KEY,
	alert_type TEXT NOT NULL,
	alert_key TEXT NOT NULL,
	severity TEXT NOT NULL DEFAULT 'warning',
	summary TEXT NOT NULL DEFAULT '',
	detail JSONB NOT NULL DEFAULT '{}',
	occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_health_alert_key_time
	ON health_alert (alert_type, alert_key, occurred_at DESC);

-- pgBackRest Web 管理任务。仓库中的 backup.info 仍是备份集的权威数据源；
-- 本表只保存手动操作的执行状态、日志和审计关联。
CREATE TABLE IF NOT EXISTS backup_job (
	id UUID PRIMARY KEY,
	operation TEXT NOT NULL CHECK (operation IN ('full', 'diff', 'incr', 'check')),
	source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'scheduled')),
	status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
	requested_by INT REFERENCES users(id) ON DELETE SET NULL,
	remark TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	started_at TIMESTAMPTZ,
	finished_at TIMESTAMPTZ,
	exit_code INT,
	stdout TEXT NOT NULL DEFAULT '',
	stderr TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_backup_job_created_at
	ON backup_job (created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_backup_job_single_active
	ON backup_job ((1)) WHERE status IN ('queued', 'running');

-- 搜索读模型：按用户权限范围和管理员全局范围预先维护每个 IP:port 的当前状态。
-- 历史 observation 仍是权威事实；此表和 Elasticsearch 索引均可重建。
CREATE SEQUENCE IF NOT EXISTS asset_endpoint_projection_version_seq;

CREATE TABLE IF NOT EXISTS asset_endpoint_current (
	scope_type TEXT NOT NULL CHECK (scope_type IN ('global', 'user')),
	scope_id INT NOT NULL CHECK (
		(scope_type = 'global' AND scope_id = 0)
		OR (scope_type = 'user' AND scope_id > 0)
	),
	ip_address INET NOT NULL,
	port INT NOT NULL CHECK (port > 0 AND port <= 65535),
	protocol TEXT,
	service TEXT,
	banner TEXT,
	title TEXT,
	http_body TEXT,
	http_body_truncated BOOLEAN NOT NULL DEFAULT FALSE,
	tls_subject TEXT,
	source TEXT NOT NULL,
	scanner_name TEXT,
	first_seen_at TIMESTAMPTZ NOT NULL,
	last_seen_at TIMESTAMPTZ NOT NULL,
	asn TEXT,
	isp TEXT,
	as_org TEXT,
	country_code VARCHAR(2),
	country_name TEXT,
	region_name TEXT,
	city_name TEXT,
	latest_endpoint_observation_id BIGINT NOT NULL,
	latest_service_observation_id BIGINT,
	projection_version BIGINT NOT NULL DEFAULT nextval('asset_endpoint_projection_version_seq'),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (scope_type, scope_id, ip_address, port)
);

CREATE INDEX IF NOT EXISTS idx_asset_endpoint_current_scope_latest
	ON asset_endpoint_current(scope_type, scope_id, last_seen_at DESC, ip_address, port);
CREATE INDEX IF NOT EXISTS idx_asset_endpoint_current_ip
	ON asset_endpoint_current(ip_address, scope_type, scope_id);

-- Outbox 与扫描结果或标签变更位于同一 PostgreSQL 事务，ES 故障不会阻塞扫描写入。
CREATE TABLE IF NOT EXISTS search_index_outbox (
	id BIGSERIAL PRIMARY KEY,
	event_kind TEXT NOT NULL CHECK (event_kind IN ('execution', 'ip', 'full')),
	aggregate_key TEXT NOT NULL,
	payload JSONB NOT NULL DEFAULT '{}',
	attempts INT NOT NULL DEFAULT 0,
	available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	locked_at TIMESTAMPTZ,
	processed_at TIMESTAMPTZ,
	last_error TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_search_index_outbox_pending
	ON search_index_outbox(available_at, id)
	WHERE processed_at IS NULL;

CREATE TABLE IF NOT EXISTS search_projection_state (
	state_key TEXT PRIMARY KEY,
	state_value TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 该视图只在投影刷新/全量重建时读取。普通搜索直接读取 asset_endpoint_current，
-- 避免每个请求都在完整历史上执行窗口函数和聚合。
CREATE OR REPLACE VIEW asset_endpoint_search_source AS
WITH eligible AS MATERIALIZED (
	SELECT scope.scope_type, scope.scope_id, observation.*,
		COALESCE(scanner.name, execution.assigned_scanner_id, execution.requested_scanner_id) AS scanner_name
	FROM scan_observation observation
	JOIN scan_task_execution execution ON execution.id = observation.execution_id
	JOIN scan_task task ON task.id = execution.task_id
	LEFT JOIN scanner_info scanner
		ON scanner.scanner_id = COALESCE(execution.assigned_scanner_id, execution.requested_scanner_id)
	CROSS JOIN LATERAL (
		VALUES ('global'::TEXT, 0), ('user'::TEXT, task.user_id)
	) AS scope(scope_type, scope_id)
	WHERE execution.execution_status = 'succeeded' AND observation.port > 0
), endpoint_stats AS (
	SELECT scope_type, scope_id, ip_address, port,
		MIN(observed_at) AS first_seen_at, MAX(observed_at) AS last_seen_at
	FROM eligible
	GROUP BY scope_type, scope_id, ip_address, port
), latest_endpoint AS (
	SELECT DISTINCT ON (scope_type, scope_id, ip_address, port)
		scope_type, scope_id, ip_address, port, protocol, source, scanner_name, id
	FROM eligible
	ORDER BY scope_type, scope_id, ip_address, port, observed_at DESC, id DESC
), latest_service AS (
	SELECT DISTINCT ON (scope_type, scope_id, ip_address, port)
		scope_type, scope_id, ip_address, port, service, banner, title, http_body,
		http_body_truncated, tls_subject, source, id
	FROM eligible
	WHERE kind = 'service'
	ORDER BY scope_type, scope_id, ip_address, port, observed_at DESC, id DESC
), eligible_intel AS MATERIALIZED (
	SELECT scope.scope_type, scope.scope_id, intel.*
	FROM ips intel
	JOIN scan_task_execution execution ON execution.id = intel.execution_id
	JOIN scan_task task ON task.id = execution.task_id
	CROSS JOIN LATERAL (
		VALUES ('global'::TEXT, 0), ('user'::TEXT, task.user_id)
	) AS scope(scope_type, scope_id)
	WHERE execution.execution_status = 'succeeded'
), latest_intel AS (
	SELECT DISTINCT ON (scope_type, scope_id, ip_address)
		scope_type, scope_id, ip_address, asn, isp, as_org, country_code,
		country_name, region_name, city_name
	FROM eligible_intel
	ORDER BY scope_type, scope_id, ip_address, update_time DESC, ip_id DESC
)
SELECT stats.scope_type, stats.scope_id, stats.ip_address, stats.port,
	endpoint.protocol, service.service, service.banner, service.title, service.http_body,
	COALESCE(service.http_body_truncated, FALSE) AS http_body_truncated,
	service.tls_subject, COALESCE(service.source, endpoint.source) AS source,
	endpoint.scanner_name, stats.first_seen_at, stats.last_seen_at,
	intel.asn, intel.isp, intel.as_org, intel.country_code, intel.country_name,
	intel.region_name, intel.city_name, endpoint.id AS latest_endpoint_observation_id,
	service.id AS latest_service_observation_id
FROM endpoint_stats stats
JOIN latest_endpoint endpoint USING (scope_type, scope_id, ip_address, port)
LEFT JOIN latest_service service USING (scope_type, scope_id, ip_address, port)
LEFT JOIN latest_intel intel USING (scope_type, scope_id, ip_address);
