# SQL 热路径优化与对比

本文记录 Session/CSRF 与扫描器认证热路径的优化范围、行为约束和前后对比方法。

## 优化范围

### 浏览器认证

以下请求的 Session、TOTP 状态和用户状态改为一次联表查询。认证成功后，预期 CSRF Token
通过请求扩展传给内层 CSRF 中间件，成功请求不再为 CSRF 单独查询 Session。

- 所有受保护的 `/api/**` 浏览器接口；
- `/logout`；
- 受保护前端页面，包括 `/`、`/create_scan`、`/task`、`/task/{uuid}`、`/scanner`、
  `/scanner/{uuid}`、`/analysis`、`/admin/users`、`/admin/backups`、`/audit`、
  `/requests`、`/health`、`/open-source`、`/testpage`、`/setting`、`/setting/scan`、
  `/setting/mail-templates`、`/user/info`、`/user/security`、`/search.html`、`/asset`、
  `/asset.html`。

下列扫描器接口和登录接口不经过浏览器 Session 认证：

- `POST /api/login`
- `GET /api/task/apply`
- `GET /api/scanner/network/public-ip`
- `POST /api/scanner/register`
- `POST /api/scanner/heartbeat`
- `POST /api/scanner/result`
- `POST /api/scanner/task/fail`
- `POST /api/scanner/task/cancelled`

浏览器 GET/HEAD 请求的认证查询由 2 条降为 1 条。需要 CSRF 的写请求，以及特殊 GET
`/logout`、`/api/totp/bind`、`/api/updaterir`，认证查询由 3 条降为 1 条。

### 扫描器认证

- `POST /api/scanner/heartbeat`：Token 条件合并进扫描器状态 `UPDATE ... RETURNING`，基础
  SQL 由认证 SELECT 加状态 UPDATE 两条降为一条，连接池获取由两次降为一次。
- `GET /api/task/apply`、`POST /api/scanner/task/fail`、
  `POST /api/scanner/task/cancelled`：认证和业务操作复用同一事务连接，连接池获取由两次降为一次。
- `GET /api/scanner/network/public-ip`、`POST /api/scanner/result`、
  `POST /api/scanner/register`：作为未调整的对照路径。

## Session 软删除审计

Session 不做物理删除。失效时同时写入：

- `deleted_at`：失效时间；
- `deletion_reason`：失效原因；
- `deleted_by_user_id`：触发失效的用户，系统过期或命令行重置时为空。

当前原因包括 `expired`、`logout`、`login_rollback`、`password_changed`、
`password_reset`、`totp_enabled`、`totp_disabled`、`user_disabled`、`admin_kick`、
`user_deleted`、`session_policy_changed` 和 `security_policy_changed`。旧版已失效记录升级时标记为
`legacy_inactive_migrated`，其 `deleted_at` 是迁移时间而非历史真实失效时间。

后台任务每小时分批把过期活动 Session 标记为软删除。认证和 Session 管理查询同时要求
`is_enable = TRUE` 和 `deleted_at IS NULL`。部分表达式索引
`idx_session_active_expiration` 按到期时间覆盖活动 Session，避免审计历史增长后拖慢过期扫描。

## 对比矩阵

| 路径 | 场景 | 预期变化 |
| --- | --- | --- |
| `GET /api/version` | 纯浏览器认证 | 2 条认证 SQL → 1 条 |
| `GET /api/task/all` | 认证加业务查询 | 认证部分 2 → 1 |
| `POST /api/search/v2` | 无副作用 POST，覆盖 CSRF | 认证部分 3 → 1 |
| `POST /api/totp/verify` | 未完成 TOTP 的特殊认证 | 3 → 1，响应语义不变 |
| `GET /api/totp/bind` | CSRF 保护 GET | 3 → 1 |
| `GET /logout` | Session 软删除 | 认证 3 → 1，新增失效审计字段 |
| `GET /api/task/apply?dryrun=true` | 扫描器认证基线 | 单次认证查询 |
| `POST /api/scanner/heartbeat` | 高频心跳 | 两次连接 → 一次；基础 SQL 2 → 1 |
| `POST /api/scanner/task/fail` | 认证加事务写入 | 两次连接 → 一次 |
| `POST /api/scanner/task/cancelled` | 认证加事务写入 | 两次连接 → 一次 |
| `POST /api/scanner/result` | 对照组 | 不应回归 |
| `GET /api/scanner/network/public-ip` | 对照组 | 不应回归 |

每轮使用相同数据量、并发和请求样本，记录请求 p50/p95/p99、状态码分布、每请求 SQL 数、
连接池等待时间，以及 `pg_stat_statements` 的 `calls`、`total_exec_time`、`mean_exec_time` 和
`rows`。浏览器 API 可使用 `request_log.duration_ms`；心跳使用 `NM-Server-Processing-Us`
或 `scanner_latency_sample.server_processing_us`。

## 行为验收

- 缺失、无效或过期 Session 仍返回 401，受保护页面仍跳转 `/login`；
- 被锁定、禁用或软删除的用户立即失去访问权限；
- 未完成 TOTP 的 Session 只能进入 `/api/totp/verify`；
- 缺失或错误 CSRF Token 仍返回 403；
- 登出、密码变更、2FA 变更、管理员踢出和禁用后 Session 立即失效并保留审计字段；
- 无效或被禁用的扫描器仍返回 401；任务未归属扫描器仍返回 409；
- 任务领取的 `FOR UPDATE SKIP LOCKED` 与租约语义不变。
