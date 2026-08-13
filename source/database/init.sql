

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
	CONSTRAINT uk_task_execution_scanner UNIQUE(task_id, requested_scanner_id)
);

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
ALTER TABLE ips ADD COLUMN IF NOT EXISTS city_name TEXT DEFAULT NULL;

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

-- 表 scaninfo 用于存储扫描数据，其中port_id通过外键关联到表ports
CREATE TABLE IF NOT EXISTS scaninfo ( 
	port_id INT NOT NULL, 
	scan_info_id SERIAL PRIMARY KEY, 
	scanner_name TEXT NOT NULL, 
	scan_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
	protocol TEXT DEFAULT NULL, 
	service TEXT DEFAULT NULL, 
	banner TEXT DEFAULT NULL, 
	other JSONB DEFAULT NULL,
	CONSTRAINT fk_port 
		FOREIGN KEY (port_id) 
		REFERENCES ports(port_id) 
		ON DELETE CASCADE 
		ON UPDATE CASCADE 
);

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
	is_enable boolean DEFAULT true
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_session_unique ON session (token, is_enable);
CREATE UNIQUE INDEX IF NOT EXISTS idx_csrf_token_unique ON session (csrf_token, is_enable);
CREATE INDEX IF NOT EXISTS idx_session_user_status ON session (user_id, is_enable);

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
	network JSONB DEFAULT NULL
);

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
	category TEXT NOT NULL CHECK (category IN (
		'authentication', 'authorization', 'user_security', 'task', 'scanner',
		'configuration', 'data_access', 'audit'
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
