

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
	last_error_at BIGINT                                                                  -- 最后一次登录出错的时间，以该时间为起点，判断是否将登录错误次数清零
);

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
	remarks TEXT DEFAULT NULL ,                                                               -- 扫描任务的备注
	CONSTRAINT fk_user
		FOREIGN KEY (user_id)
		REFERENCES users(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE,
	CONSTRAINT uk_task_id UNIQUE (task_id)
);

-- 表 ips 用于存储ip数据，并配置了级联更新
CREATE TABLE IF NOT EXISTS ips ( 
	task_id INT NOT NULL, 
	ip_id SERIAL PRIMARY KEY, 
	ip_address INET NOT NULL UNIQUE,
	asn TEXT DEFAULT NULL, 
	isp TEXT DEFAULT NULL, 
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
	update_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,
    CONSTRAINT fk_task
        FOREIGN KEY (task_id)
        REFERENCES scan_task(id)
        ON UPDATE CASCADE
);

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
	ttl INT DEFAULT 1200, 
	totp_verify_successful boolean DEFAULT false,
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT, 
	is_enable boolean DEFAULT true
);

-- 2FA 绑定在验证码确认前仅保存于当前会话，过期后不能被启用。
ALTER TABLE session ADD COLUMN IF NOT EXISTS pending_totp_secret TEXT;
ALTER TABLE session ADD COLUMN IF NOT EXISTS pending_totp_expires_at BIGINT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_session_unique ON session (token, is_enable);
CREATE UNIQUE INDEX IF NOT EXISTS idx_csrf_token_unique ON session (csrf_token, is_enable);


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
	tag TEXT                                                                        -- 扫描器的标签
);

-- 兼容已初始化的数据库：CREATE TABLE IF NOT EXISTS 不会补充新字段。
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS task_status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS assigned_scanner_id VARCHAR(36);
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS lease_expires_at BIGINT;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS attempt_count INT NOT NULL DEFAULT 0;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS failure_reason TEXT;
UPDATE scan_task SET task_status = CASE
	WHEN task_end_time IS NOT NULL THEN 'succeeded'
	WHEN task_start_time IS NOT NULL THEN 'running'
	ELSE 'pending'
END WHERE task_status IS NULL OR task_status = 'pending';

ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS cpu_model TEXT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS runtime_state TEXT NOT NULL DEFAULT 'offline';
CREATE INDEX IF NOT EXISTS idx_scan_task_dispatch
	ON scan_task (task_status, lease_expires_at, task_level DESC, task_create_time);

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
)
