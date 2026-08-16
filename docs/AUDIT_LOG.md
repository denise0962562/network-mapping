# 审计日志

系统将安全审计事件写入 PostgreSQL 的 `audit_event` 表，运行和调试日志继续由
`tracing` 写入滚动文件。两类日志用途不同，不应混合用于审计取证。

## 事件范围

当前版本记录登录成功与失败、退出登录、密码修改、任务创建/取消/重试、系统目标生成、
扫描器配置变更，以及审计日志的查询与导出。系统自动生成目标使用
`automatic_target` 分类和 `task.auto_generate` 动作。心跳、健康检查和普通页面读取不会
产生审计事件。

所有 HTTP 响应包含 `X-Request-ID`。客户端提供合法 UUID 时会沿用该值，否则服务器
生成新 UUID。运行日志和审计事件可以通过该字段关联。

审计元数据禁止包含密码、Session、CSRF Token、TOTP Secret、Authorization 请求头、
扫描器注册/运行 Token 及其哈希。请求日志也不会记录原始查询字符串。

## 查询接口

仅 `role = 1` 的管理员可以访问：

- `GET /api/audit/events`：分页查询，支持 `category`、`action`、`outcome`、
  `actor_id`、`resource_type`、`resource_id`、`keyword`、`start`、`end`、`page` 和
  `page_size`。
- `GET /api/audit/events/{event_id}`：读取单个事件。
- `GET /api/audit/export`：按相同筛选条件导出 CSV，单次最多 10000 条。

`start` 和 `end` 使用 RFC 3339 时间，例如 `2026-08-10T09:00:00+08:00`。

## 数据库权限与留存

生产环境应使用不同角色管理审计表：

1. 应用角色只获得 `audit_event` 的 `INSERT`、`SELECT` 和序列 `USAGE` 权限，不获得
   `UPDATE`、`DELETE`、`TRUNCATE` 权限。
2. 迁移角色负责建表和索引，日常服务不得持有该角色凭据。
3. 维护角色按照组织策略归档和清理数据。建议在线保留 180 天、不可变归档保留一年，
   具体期限由合规要求决定。
4. 每日将审计数据备份到与应用数据库隔离、启用对象锁或 WORM 的存储。

初始化脚本仍保留 `login_logs` 和 `operation_audit` 以兼容已有数据库。新代码不再向
这两张旧表写入；旧数据应在上线前备份，后续通过单独的数据迁移批次归档。
可重复执行的迁移脚本位于 `source/database/migrate_audit.sql`。
