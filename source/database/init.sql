

-- 表 users 用于存储平台用户信息
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(200) NOT NULL UNIQUE,
    password TEXT NOT NULL,
    create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,    -- 用户的创建时间
	limit_login INT DEFAULT 0,                                                            -- 表示用户是否是被限制登录
	enable_2fa boolean DEFAULT false                                                      -- 表示用户是否启用了 2FA
);

-- 表 scan_task 用于存储扫描任务信息，配置了级联更新和删除
CREATE TABLE IF NOT EXISTS scan_task( 
	user_id INT NOT NULL,
	task_id SERIAL PRIMARY KEY, 
	task_initiator VARCHAR(10) NOT NULL, 
	task_target INET NOT NULL,                                                                -- 扫描的目标 IP/CIDR
	task_create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,   -- 表示扫描任务的创建时间
	task_level INT NOT NULL CHECK ( task_level >= 0 AND task_level <=4 ),                     -- 表示任务的优先级
	task_start_time BIGINT DEFAULT NULL,                                                      -- 扫描开始时间
	task_end_time BIGINT DEFAULT NULL,                                                        -- 扫描结束时间
	remarks TEXT DEFAULT NULL ,                                                               -- 扫描任务的备注
	CONSTRAINT fk_user
		FOREIGN KEY (user_id)
		REFERENCES users(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE
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
        REFERENCES scan_task(task_id)
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
	token VARCHAR(36) NOT NULL UNIQUE,
	ttl INT DEFAULT 1200, 
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT, 
	is_enable boolean DEFAULT true,
	CONSTRAINT fk_user
		FOREIGN KEY (user_id)
		REFERENCES users(id)
		ON UPDATE CASCADE
);

-- 表 system_status 用于存储系统状态数据
CREATE TABLE IF NOT EXISTS system_status (
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT,
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

--表 scanner_info 用于存储扫描器信息
CREATE TABLE IF NOT EXISTS scanner_info (
	id SERIAL PRIMARY KEY,
	system_version TEXT,                                                            -- 扫描器所在的系统名称及版本
	scanner_version TEXT,                                                           -- 扫描器的版本
	cpus INT,                                                                       -- 扫描器 CPU 数量
	ram INT,                                                                        -- 扫描器 RAM 大小
	uptime INT,                                                                     -- 扫描器总共运行的时间
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT,     -- 扫描器创建的时间
	ip_address INET,                                                                -- 扫描器的IP地址
	is_enable boolean,                                                              -- 扫描器是否启用
	remark TEXT,                                                                    -- 扫描器的备注
	tag TEXT                                                                        -- 扫描器的标签
);

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


