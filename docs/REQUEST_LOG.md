# 请求日志与错误识别

系统将每个业务请求记录到 PostgreSQL 的 `request_log` 表，用于请求级别的分析与错误自动识别。
与 `audit_event`（安全审计，只记录敏感操作）不同，`request_log` 是访问日志，覆盖每一个业务请求。

## 目标

1. 直接查看每一个业务请求，主要用于分析。
2. 自动识别各类错误（4xx / 5xx），并按错误类型细分。

## 采集范围

- 记录业务请求：`/api/*` 接口与页面路由，跳过静态资源（复用 `is_frontend_resource_path`）。
- 默认排除 `/api/scanner/heartbeat`（高频心跳，避免污染与放大数据量），其余扫描器接口保留。
- 采集开关可配置（见「配置」）。

## 数据模型

```sql
CREATE TABLE IF NOT EXISTS request_log (
    id BIGSERIAL PRIMARY KEY,
    request_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    http_method TEXT NOT NULL,
    request_path TEXT NOT NULL,
    status_code SMALLINT NOT NULL,
    duration_ms INTEGER,
    client_ip INET,
    user_agent TEXT,
    actor_id INT,                        -- 已认证用户 id；匿名/扫描器请求为 NULL
    actor_name TEXT,                     -- 已认证用户名；匿名/扫描器请求为 NULL
    error_level TEXT NOT NULL DEFAULT 'ok'
        CHECK (error_level IN ('ok', 'client_error', 'server_error')),
    error_type TEXT                      -- bad_request / unauthorized / not_found / ...
);

CREATE INDEX IF NOT EXISTS idx_request_log_time
    ON request_log (occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_request_log_error
    ON request_log (error_level, occurred_at DESC);
```

索引只保留 2 个：

- `idx_request_log_time`：分页、趋势、保留清理。
- `idx_request_log_error`：错误查询与错误率趋势。

不建 `request_path`、`status_code`、`request_id` 单列索引：`request_path` 仅偶尔排查、列表查询自带时间范围；
`status_code` 与 `error_level`/`error_type` 冗余；`request_log` 每请求一行，`request_id` 近乎唯一、索引无收益。


## 采集与错误分类

采集点在 `main.rs` 最外层 `wrap_fn`：

1. `service.call(req)` 之前抓取 `http_method`、`request_path`、`client_ip`、`user_agent`。
2. 响应后抓取 `status_code` 与 `duration_ms`（`Instant::elapsed`）。
3. 按状态码派生 `error_level` 与 `error_type`：

| status | error_level | error_type |
| --- | --- | --- |
| 400 | client_error | bad_request |
| 401 | client_error | unauthorized |
| 403 | client_error | forbidden |
| 404 | client_error | not_found |
| 408 | client_error | timeout |
| 409 | client_error | conflict |
| 422 | client_error | validation |
| 429 | client_error | rate_limited |
| 其他 4xx | client_error | client_error |
| 5xx | server_error | server_error |
| 其余 | ok | NULL |

## 操作者归属

`wrap_fn` 在最外层，鉴权通过的 `UserBaseI` 由内层 `AuthMiddleware` 注入 `extensions`，
而 `req` 已被 `service.call(req)` move 走，外层拿不到。因此**不通过 `audit_event` 关联操作者**
（`audit_event` 只记录敏感操作，多数请求没有对应事件），而是用共享槽位直接采集：

```rust
pub struct RequestActor(pub Arc<std::sync::Mutex<Option<(i32, String)>>>); // (user_id, username)
```

1. `wrap_fn` 在 `service.call` 前 `req.extensions_mut().insert(RequestActor(actor.clone()))`，自己保留克隆。
2. `AuthMiddleware` 鉴权成功后（现有 `Ok((true, uid))` 分支，拿到 `tmp_info` 之后）写槽位：
   `*slot.0.lock().unwrap() = Some((tmp_info.id, tmp_info.username.clone()))`。
3. `wrap_fn` 响应后读槽位，写入 `actor_id` / `actor_name`。

锁都在 `await` 完成后持有，无跨 `await` 持锁，使用 `std::sync::Mutex` 即可。
匿名请求、被 401/403 拒绝的请求、扫描器请求（`is_scanner_api_path` 直通、不注入 `UserBaseI`）均为 `NULL`。

## 写入策略与失败处理

不逐请求同步写库，使用「有界 channel + 后台 writer」：

- 入口（`wrap_fn`）：有界 `mpsc` channel（容量 8192），`try_send` 满则**同步丢弃该条**，请求响应零阻塞。
- 后台 writer（`main` 中 `tokio::spawn`，**永不退出**）：
  1. 攒批，每批 ≤500 行，单事务多行 `INSERT` 提交；或每 500ms 定时 flush。
  2. flush 失败 → 重试 2 次（间隔 50ms / 200ms），重试期间保留本批。
  3. 仍失败 → **整批丢弃 + `dropped` 计数自增 + `error!` 记一条日志**，继续下一轮循环。
  4. 绝不无限重入队、绝不阻塞、绝不退出。

`dropped` 计数通过日志暴露，当前未并入 summary。

## 查询接口

仅 `role = 1` 的管理员可访问：

- `GET /api/requests`：分页查询，支持 `method`、`path`（contains）、`status`、`error_level`、
  `error_type`、`request_id`、`start`、`end`、`page`、`page_size`。
- `GET /api/requests/summary`：聚合统计。

`start` / `end` 使用 RFC 3339 时间。

## 聚合与分位数

summary 拆两层语义，避免大表实时 `percentile_cont` 全表扫描：

| 聚合类型 | 支持范围 | 实现 |
| --- | --- | --- |
| 计数聚合 + 趋势（总请求、error_type 分布、`date_trunc` 时间分桶） | 任意时间范围 + 过滤 | COUNT / `date_trunc`，走 time/error 索引 |
| 延迟 P95 / P99 | 仅预设窗口：1h / 24h / 7d | `percentile_cont`，窗口内走 time 索引 |

不提供「任意范围 × 任意过滤 × 实时 P95/P99」。

## 前端

`/requests` 页面仅管理员可访问：

- 过滤栏：method、path、status、error_type、仅看错误、时间范围、request_id。
- 汇总卡片：总请求数、错误率、P95 耗时、5xx 数。
- 趋势图：请求量 + 错误数随时间（复用 ApexCharts，对齐 `analysis.vue`）。
- 可过滤分页表格：时间、方法、路径、状态徽章、耗时、IP、request_id、错误类型徽章。

## 保留与清理

- 配置 `retention_days`（默认 30 天）。
- 当前使用单表和分批 `DELETE` 清理，避免长事务锁。
- 当前未使用按天分区；应根据实际保留量和清理耗时评估容量。

## 配置

在“设置 → 运行时配置 → 请求日志”发布配置。对应 `requests` 数据库记录缺失时，以下 TOML 用于初始化；已有记录不会被修改文件或重启覆盖。发布接口与版本冲突规则见[服务端运行时配置](RUNTIME_CONFIGURATION.md)。

```toml
[requests]
enabled = true        # 是否采集请求日志
retention_days = 30   # 在线保留天数
```

## 隐私与安全

- `request_log` 不记录请求体、原始查询字符串、Session、CSRF Token、Authorization 请求头、
  扫描器注册/运行 Token 及其哈希。只记录 method、path（不含 query）、状态码、耗时、IP、UA 与操作者。
- 查询接口仅管理员可见，复用审计接口的鉴权方式。
- 生产环境建议沿用 `audit_event` 的角色权限模型：应用角色只持有 `request_log` 的 `INSERT` / `SELECT`。
