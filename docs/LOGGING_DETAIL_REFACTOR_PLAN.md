# 日志详细化改造任务

状态：代码实施完成；自动化验证完成；依赖真实 PostgreSQL/Elasticsearch 与故障注入的人工演练待运维环境执行

范围：`network-mapping` 服务端与 `Network-Mapping-Scanner` 扫描端

基线日期：2026-09-11

2026-10-01 补充：扫描端日志现带 event_id/boot_id，已实现固定目录远程快照采集、独立持久化错误上报、归一化去重和管理页面。协议与运维细节见[扫描器错误诊断与日志采集](SCANNER_DIAGNOSTICS.md)。本页保留原结构化日志改造的基线与验收记录。

## 1. 问题与目标

当前日志已经使用 `tracing` 输出 JSON，也有请求级 `request_id` 和错误链展开能力，但许多错误仍只记录 `event + message`。这能说明“哪里失败了”，不能回答“哪个业务对象、哪个阶段、服务当时做了什么、是否可重试、接下来会怎样”。

典型日志：

```json
{
  "level": "ERROR",
  "fields": {
    "event": "SaveScannerResultError",
    "operation": "persist_scan_results",
    "request_id": "02a6ef14-9adf-4117-bddd-2984ace255fe",
    "message": "无效扫描结果上传: an execution cannot contain batches from multiple upload_id values"
  },
  "span": {
    "request_id": "02a6ef14-9adf-4117-bddd-2984ace255fe",
    "name": "http_request"
  },
  "spans": [
    {
      "request_id": "02a6ef14-9adf-4117-bddd-2984ace255fe",
      "name": "http_request"
    }
  ]
}
```

这条日志有三个具体问题：

1. `request_id` 在 `fields`、`span`、`spans` 中重复，但没有扫描器和上传批次身份。
2. `InvalidUpload(String)` 把稳定的错误分类和诊断数据压成一句文本，无法按错误原因聚合，也无法看到收到值与已存在值。
3. `persist_scan_results` 范围太大，不能定位失败发生在协议校验、身份校验、批次回执、Elasticsearch 写入、任务完成还是事务提交阶段。

本任务的目标：

- 每条 `ERROR` 单独拿出来就能确定失败阶段、主要业务对象、根因、影响和重试属性。
- `WARN` 至少说明触发原因、被保留或丢弃的状态、重试次数和下次动作；只补对恢复有帮助的字段。
- 普通 `INFO` 不做全量翻修，只保留少量用于与错误配对的生命周期事件。
- 一个 HTTP 请求日志只保留一份 `request_id` 上下文，不再同时输出等价的 `span` 与 `spans`。
- 不记录 token、Cookie、Authorization、完整请求体、完整 banner/evidence、SQL 参数或无界 stderr。

## 2. 代码盘点结论

基于当前源码的静态盘点，服务端约有 126 个 `error!`、46 个 `warn!`；扫描端约有 34 个 `error!`、43 个 `warn!`。前端另有约 74 个 `console.error`，它们没有统一采集目的地，不纳入本轮结构化服务日志改造。

### 2.1 已有可复用基础

- `network-mapping/src/logs/write.rs` 的 `error_chain_diagnostics` 能遍历 `Error::source()`，并能把 PostgreSQL 错误展开成 SQLSTATE、severity、detail、hint、schema、table、column、constraint。
- `network-mapping/src/main.rs` 已为请求建立 `http_request` span，并把 `request_id` 放入 span。
- 扫描端的上传载荷天然包含 `scanner_id`、`task_id`、`upload_id`、`batch_index`、`is_final`、`protocol_version` 和观察数量。
- `ScanBatchContext`、分析快照 `ExecutionContext`、Elasticsearch outbox 事件及维护状态已经拥有大部分业务标识，只是错误日志没有稳定地带上这些字段。
- 扫描端 `ServerError` 已区分超时、连接、传输、认证、策略、HTTP 状态和响应解析错误，并提供 `is_retryable()`、`retry_after()`、`status()`。

### 2.2 共性缺口

| 区域 | 当前表现 | 直接后果 |
| --- | --- | --- |
| 请求日志格式 | 文件层同时启用 `with_current_span(true)` 与 `with_span_list(true)`，帮助函数又显式写 `request_id` | 单层 span 仍出现三份相同 ID，增加噪声和存储量 |
| 通用 HTTP 错误帮助函数 | `error_logs_error` 只有 `event`、`operation`、HTTP 元数据和字符串错误链 | 调用点的 task、scanner、user、tag、job、query 等身份全部丢失 |
| 扫描结果错误模型 | 多数校验失败汇总为 `InvalidUpload(String)`，`Storage(String)` 也丢失错误类型 | 只能全文搜索，无法稳定聚合或判断重试策略 |
| 数据库错误 | 有的路径使用完整诊断，有的只 `%error` 或 `to_string()` | 同类数据库故障输出质量不一致，约束冲突常缺 SQLSTATE/constraint |
| Elasticsearch/worker | 很多 worker 只写 `message`，或只有 outbox 自增 ID | 无法从日志直接回到 execution、task、upload、索引与尝试次数 |
| 扫描端主循环 | 多个终止错误只有 `%error`，上传重试还有一条泛化 `UPLOAD-RETRY` 和一条实际警告 | 缺 task/upload/batch，且一次故障产生两条语义重叠日志 |
| 外部扫描进程 | masscan、zgrab2、nuclei 的解析/退出日志字段不一致 | 很难比较命令阶段、退出码、耗时、无效行数和截断情况 |
| 前端控制台 | 直接 `console.error(..., error)` | 若未来集中采集，可能把 Axios config/header 一起带出；当前也无法稳定关联响应 `X-Request-ID` |

## 3. 统一日志字段契约

不引入任意动态字段 Map 作为通用日志接口。高价值业务错误应在最了解上下文的边界直接调用 `error!`；通用帮助函数只负责稳定的错误诊断和 HTTP 上下文。

### 3.1 ERROR 必填字段

所有新增或迁移后的错误事件必须包含：

| 字段 | 含义 | 示例 |
| --- | --- | --- |
| `event` | 稳定事件名，PascalCase，以 `Error`/`Failed` 结尾 | `SaveScannerResultError` |
| `operation` | 失败的窄阶段，使用 snake_case | `validate_execution_upload_identity` |
| `error_kind` | 粗粒度类别 | `validation`、`database`、`storage`、`transport`、`process_exit` |
| `error_code` | 稳定、可聚合的机器码 | `execution_upload_id_conflict` |
| `error_message` | 面向值班人员的当前层说明 | `execution already contains another upload identity` |
| `retryable` | 当前调用方是否应该重试 | `false` |
| `outcome` | 失败后状态 | `request_rejected`、`batch_retained`、`batch_dropped`、`process_stopping` |

有错误来源链时再记录：

- `error_chain`：完整但有界的 source chain，最长 4096 个字符。
- `root_cause`：最深层错误的有界文本，便于快速阅读。
- `error_truncated=true`：诊断文本发生截断时必须出现。
- PostgreSQL 错误额外拆出 `sqlstate`、`db_severity`、`schema`、`table`、`column`、`constraint`；`detail` 和 `hint` 经过长度限制后输出。不记录 SQL 参数。
- HTTP/Elasticsearch 错误额外记录 `http_status`、`endpoint_kind`、`index` 或 `index_family`、`attempt`、`retry_after_ms`；URL 只保留经过配置命名的 endpoint，不记录查询字符串。

业务上下文字段按对象补充，不用空字符串占位：

- 扫描上传：`scanner_id`、`task_id`、`execution_id`（已解析后）、`upload_id`、`batch_index`、`is_final`、`protocol_version`、`observation_count`、各 observation kind 数量。
- 任务/执行：`task_id`、`execution_id`、`scanner_id`、`task_source`、`scan_profile`、`address_family`。
- worker/outbox：`outbox_id`、`aggregate_key` 或 `execution_id`、`attempt`、`locked_at`、`elapsed_ms`、`next_retry_ms`。
- 用户与管理操作：只记录内部 `user_id`、`resource_type`、`resource_id`、`action`；不得记录密码、TOTP secret、session 或 token。
- 外部进程：`engine`、`stage`、`process_id`、`exit_code`、`elapsed_ms`、`result_count`、`invalid_line_count`、`stderr_bytes`、`stderr_truncated`。stderr 内容最多保留当前安全上限，并进行换行压缩。

### 3.2 WARN 与 INFO 规则

`WARN` 仅用于系统仍能继续、已降级、会重试或主动忽略坏输入的情况。至少包含 `event`、`operation`、`reason`、`outcome`；重试类再包含 `attempt`、`retry_after_ms` 和业务身份。批量坏数据警告应记录累计数量或采样序号，避免每行刷屏。

`INFO` 不做全量字段补齐。仅在以下场景保留或补充字段：

- 与错误形成开始/完成配对的批次、任务、迁移、备份和 worker 生命周期。
- 状态发生不可逆业务变化，如任务完成、结果批次确认、缓存清理。
- 启动配置摘要，但只记录非敏感配置与版本。

### 3.3 request_id 与 span 输出

文件 JSON 层保留 `with_current_span(true)`，关闭 `with_span_list(true)`。普通请求内事件从 `span.request_id` 获取关联 ID，`error_logs`、`warn_logs`、`info_logs`、`error_logs_error` 不再重复写同一个字段。

异步任务离开请求 span 后，如果业务上仍需请求关联，必须在创建任务时显式复制 `request_id` 到事件字段。审计写入这类可能脱离 span 的路径允许保留显式 `request_id`。实施前检查现有日志查询是否依赖 `fields.request_id`；如有，先同步查询路径，再删除重复字段。

## 4. P0：扫描结果上传链路

这是首个实施批次，也是示例问题的完整修复范围。

### 4.1 服务端错误类型结构化

修改 `network-mapping/src/lib.rs`：

- 为 `SaveScannerResultsError` 增加稳定的 `kind()`、`code()`、`retryable()` 和 `operation()`；HTTP handler 不再从显示文本推断分类。
- 把 `InvalidUpload(String)` 中影响排障的分支逐步改为具名 variant。首批至少拆出：
  - `UnsupportedProtocolVersion { received, supported }`
  - `InvalidBatchEnvelope { protocol_version, reason }`
  - `UploadIdentityConflict { execution_id, received_upload_id, conflicting_upload_id, conflicting_upload_count }`
  - `BatchPayloadConflict { execution_id, upload_id, batch_index, expected_checksum, received_checksum }`
  - `NonContiguousFinalBatch { upload_id, expected_batch_index, received_batch_index }`
  - `CompletedExecutionNewBatch { execution_id, upload_id, batch_index }`
  - `ObservationLimitExceeded { actual, limit }`
- `Database` 保留 source chain；`Storage(String)` 改为带 `storage_operation`、`retryable`、可选 HTTP 状态/索引的结构化错误，避免 Elasticsearch 细节只有一句拼接文本。
- 显示文本继续保持当前 HTTP 响应兼容性；日志使用结构化方法和 variant 数据，不解析 `Display`。

### 4.2 暴露 upload_id 冲突双方

修改 `validate_execution_upload_ids`：

- 将当前 `SELECT EXISTS` 改为查询不在本次允许集合中的 distinct `upload_id`，只取诊断所需的首个值和总数。
- 返回 `UploadIdentityConflict`，携带数据库 execution ID、收到的主 upload ID、冲突 upload ID 和冲突数量。
- DNS sidecar 仍把父/子 upload ID 作为同一允许集合；日志不能把合法 sidecar 误报为冲突。
- 查询只返回身份，不读取或记录 observation 正文。

### 4.3 handler 在上下文仍完整时记录一次错误

修改 `network-mapping/src/handlers/task.rs::upload_scanner_result_handler`，替换通用 `error_logs_error` 调用。失败日志统一带上：

- 请求载荷中的 `scanner_id`、`task_id`、`upload_id`、`batch_index`、`is_final`、`protocol_version`、`observation_count`、`legacy_result_count`。
- 由错误类型提供的 `operation`、`error_kind`、`error_code`、`retryable`、`error_message`、`error_chain`。
- `outcome` 与最终 HTTP 状态：400/401/404/409 为 `request_rejected`，503 的 busy/storage 为 `batch_retained_for_retry`，500 为 `server_error`。
- 不记录 Authorization、token、观察正文、IP/banner/evidence 列表。

深层存储函数只返回带上下文的错误，不重复写同一失败。只有“主请求之后又发生独立补偿失败”才允许额外日志，并使用不同 event/code。

目标日志形态：

```json
{
  "level": "ERROR",
  "fields": {
    "event": "SaveScannerResultError",
    "operation": "validate_execution_upload_identity",
    "error_kind": "validation",
    "error_code": "execution_upload_id_conflict",
    "error_message": "execution already contains another upload identity",
    "retryable": false,
    "outcome": "request_rejected",
    "http_status": 400,
    "scanner_id": "...",
    "task_id": "...",
    "execution_id": "...",
    "upload_id": "本次收到的 upload_id",
    "conflicting_upload_id": "数据库中已有的 upload_id",
    "conflicting_upload_count": 1,
    "batch_index": 0,
    "is_final": true,
    "protocol_version": 3,
    "observation_count": 42
  },
  "span": {
    "request_id": "02a6ef14-9adf-4117-bddd-2984ace255fe",
    "name": "http_request"
  }
}
```

### 4.4 扫描端保留服务端关联信息

修改 `Network-Mapping-Scanner/src/http_client.rs`、`error.rs`、`upload.rs`、`main.rs`：

- `response_error` 在消费响应体前读取 `X-Request-ID`，把合法 UUID 保存到所有基于 HTTP 响应的 `ServerError` variant，并提供 `request_id()`。
- 上传失败必须保留当前 batch 的 `task_id`、`upload_id`、`batch_index`、`is_final`、`protocol_version`、`observation_count`；在 `flush` 中用结构化 `UploadBatchError` 包装 `ServerError`，不把上下文拼入字符串。
- 将泛化的 `UPLOAD-RETRY` 事件和随后实际 `warn!` 合并为一条 `ResultBatchUploadRetry`，包含 `attempt`、`retry_after_ms`、服务端状态、服务端 request ID 和批次身份。
- 永久拒绝使用 `ResultBatchUploadRejected`，明确 `outcome=batch_retained` 或 `outcome=batch_discarded`。任何丢弃日志必须给出 task/upload 身份和丢弃原因。
- shutdown/final flush、租约过期、pending recovery 的错误都从 cache 提取相同身份；不能再只写 `final result upload failed: ...`。

## 5. P1：服务端其余 ERROR

逐组迁移，不以一次全局替换完成。每组提交前列出旧 event 到新 `error_code` 的映射，避免监控规则静默失效。

| 代码区域 | 重点事件/调用 | 必须补充的字段 |
| --- | --- | --- |
| `src/logs/{init,write}.rs` | JSON layer、通用错误诊断 | 去重 span；`error_message/error_chain/root_cause/error_truncated`；PostgreSQL 结构字段 |
| `src/handlers/task.rs` | apply/recover/lease/create/list/detail/export | `task_id`、`execution_id`、`scanner_id`、lease 状态、查询阶段、最终 HTTP 状态 |
| `src/handlers/{assets,operations,data_saa,search,tags}.rs` | Elasticsearch 查询与投影 | `operation`、`index_family`、资源 IP/task/tag ID、分页位置、用户作用域类型；禁止记录原始 DSL 与完整导出内容 |
| `src/elasticsearch.rs` | scan projection、tag outbox、bulk、初始化 | `outbox_id`、`aggregate_key/execution_id`、`attempt`、bulk 成败数量、首个失败状态、索引、next retry；claim 失败需 worker 实例/阶段 |
| `src/analytics_snapshot.rs` | reconcile、process_one、fail_execution | `execution_id`、`database_id`、`attempt`、`expected_observations`、索引数量、`elapsed_ms`、是否已安排重试 |
| `src/scanner_latency.rs` | history write/retention | `operation=pool/transaction/insert/commit/delete`、批次大小、probe 时间范围、retention_days/cutoff、dropped 数量 |
| `src/handlers/system_maintenance.rs`、`src/system_maintenance.rs` | enter/exit/history/hold/release/probe | `maintenance_id`、phase、revision、affected task count、transaction stage、补偿动作 |
| `src/handlers/backup.rs`、`src/main.rs` | job start/finish/recovery | `job_id`、backup type、stage、attempt、elapsed、进程退出状态；不得记录仓库口令或完整命令行 |
| `src/handlers/{user,admin_user,login_record}.rs`、`src/login.rs` | 用户、会话、2FA | `user_id`、action、reason_code、outcome；不得记录用户名之外的凭据、TOTP secret/session/token |
| `src/audit/mod.rs`、`src/request_log.rs` | audit/request writer | batch size、attempt、total dropped、category/action；统一数据库诊断；后台路径显式保留 request ID |
| `src/middlewares/*.rs` | pool/token/CSRF/rate-limit | middleware 名、认证阶段、reason_code、outcome、HTTP status；删除 `path="fn call"` 这类无检索价值字段 |
| `src/db/mod.rs`、`src/logs/write.rs` 的登录日志写入 | pool/transaction/execute/commit | database operation、表的逻辑名、affected rows、结构化 DB 错误；不记录 SQL 参数 |

`error_logs_error(..., "database_operation", ...)`、`error_logs(..., error.to_string())` 这两类调用是重点审查对象。只要调用点掌握资源 ID 或查询阶段，就改为局部结构化事件；确实没有业务上下文的基础设施错误才继续使用通用帮助函数。

## 6. P1：扫描端 ERROR

修改 `Network-Mapping-Scanner/src/main.rs`、`heartbeat.rs`、`scan/orchestrator.rs`、`scan/engines/{masscan,zgrab2,nuclei}.rs`：

- 所有会停止进程或扫描循环的错误补 `event`、`operation`、`error_kind`、`error_code`、`retryable=false`、`outcome=process_stopping|task_failed`。
- heartbeat/task fetch/recover/status report 统一记录 endpoint kind、task ID、attempt、retry delay、HTTP status、服务端 request ID；认证/策略拒绝不再先写一条泛化宏再写一条错误。
- cache begin/clear/mark uploaded 失败记录 cache 数据库路径的逻辑名、task/upload/batch、next batch index 和保留/丢弃结果；不输出本地绝对路径中的敏感目录部分。
- `ScanTaskFailed` 保留现有 task/profile/address family/elapsed 字段，并增加失败 stage 与 engine；错误从 stage 边界向上保留 source chain。
- masscan 非零退出、错误标记、wait/kill/stderr reader 分别使用稳定 code；日志包含退出码、耗时、发现数量、unknown 数量、stderr 字节数和截断标记。
- zgrab2/nuclei 非零退出与解析异常使用同一外部进程字段规范。可选 service detection 失败保持 `WARN`，但必须带 task/stage、已保留端口数量和 `outcome=port_results_preserved`。

## 7. P2：选择性补充 WARN

只处理能解释恢复行为或数据损失风险的警告：

- 重试/退避：补 attempt、retry delay、业务身份、retryable 和下次动作。
- 输入被忽略：补 engine、输入序号或累计 invalid count、reason code；只采样首条安全摘要，禁止逐行输出完整工具结果。
- 配置回退：补 namespace/revision、无效字段名和采用的默认策略，不记录配置值中的秘密。
- TTL/租约被 clamp：补原值、调整后值、task/scanner 身份和影响。
- 维护暂停：补 maintenance ID/phase/revision、保留的 task/upload 和恢复时间。
- 队列/通道丢弃：补 dropped_this_batch、total_dropped、capacity 和数据类型。

以下警告不为“字段统一”而改：已经有充分上下文的单次启动提示、纯开发诊断、对结果和后续动作没有影响的信息。普通 `INFO` 同样不批量修改。

## 8. 前端边界

本轮不修改 `network-mapping-vue` 的 74 处 `console.error`，原因是浏览器日志没有项目内的集中采集链路，不能解决服务端排障问题。后续如果引入前端错误采集，应先建立一个脱敏帮助函数，只允许 method、无 query 的 path、HTTP status、响应 `X-Request-ID`、页面 action 和稳定 error code；不得上传 Axios request config、headers、Cookie、响应正文或表单内容。

## 9. 测试与验收

### 9.1 自动化测试

- 为日志 JSON formatter 使用内存 writer 测试：请求内事件只有一个 `span.request_id`，不存在 `spans`，业务字段仍在 `fields`。
- 扩展 `logs/write.rs` 单元测试：多层 source、PostgreSQL 普通错误/数据库错误、去重、4096 字符截断和 `error_truncated`。
- 为 `SaveScannerResultsError` 测试每个 variant 的 `kind/code/operation/retryable`，保证显示文本变化不会改变机器码。
- 扩展现有可丢弃 PostgreSQL/Elasticsearch 存储测试：制造不同 upload ID，断言错误携带 execution、received/conflicting identity；覆盖合法 DNS sidecar 不误报。
- 添加 handler 日志捕获测试：示例冲突包含 scanner/task/upload/batch/protocol/count，不含 token 和 observation 正文。
- 扫描端测试 `X-Request-ID` 解析、缺失/非法 header、`UploadBatchError` 上下文和 retry 分类。
- 对 masscan/zgrab2/nuclei 的失败 fixture 断言稳定 error code、退出码/计数和截断标记。

### 9.2 人工故障矩阵

至少演练：

1. 同一 execution 换 upload ID 上传。
2. 同一 upload/batch 使用不同正文重传。
3. PostgreSQL pool、query、commit 分别失败。
4. Elasticsearch 429、503、部分 bulk 失败、永久 mapping 错误。
5. 扫描端上传超时、401、409、500/503 和带 `Retry-After` 响应。
6. 扫描进程非零退出、输出坏 JSON、stderr 超限、取消和租约丢失。
7. request/audit/latency writer 队列满或批量写入最终失败。

每个场景检查：日志是否能独立定位对象与阶段；是否只有一个主要失败事件；retryable/outcome 是否符合实际动作；服务端和扫描端能否通过服务端 request ID 关联；日志中是否无秘密和大正文。

### 9.3 完成门槛

- 示例 `SaveScannerResultError` 达到第 4.3 节的字段完整度，且 request ID 只出现一次。
- 所有服务端与扫描端 `ERROR` 完成逐条审查：已迁移，或在清单中写明保持现状的理由；不能以 grep 数量下降代替审查。
- 所有永久失败有稳定 `error_code`；所有重试错误有 `attempt` 与 retry delay；所有数据丢弃有对象身份、数量和原因。
- 相同故障不再由泛化宏和结构化事件重复记录；独立补偿失败除外。
- 故障测试中日志无 Authorization、runtime/registration token、Cookie、session、TOTP secret、完整请求/响应体、SQL 参数或无界外部进程输出。
- 两个 Rust 子项目分别通过 `cargo fmt --check`、`cargo clippy --all-targets`、`cargo test`、`cargo build --locked --release`。需要 PostgreSQL/Elasticsearch 的 ignored 测试在可丢弃环境单独运行并记录结果。

## 10. 实施拆分与提交顺序

1. 服务端日志基础：诊断结构、长度限制、JSON span 去重、兼容性测试。
2. 服务端扫描结果链路：结构化错误 variant、冲突双方、handler 日志、存储集成测试。
3. 扫描端 HTTP/上传链路：服务端 request ID、批次错误上下文、去重 retry/terminal 日志。
4. 服务端后台任务与数据库错误：Elasticsearch、analytics、latency、request/audit、maintenance、backup。
5. 服务端其余 handler/middleware：按业务域迁移通用帮助函数调用。
6. 扫描端扫描引擎与剩余终止错误；最后选择性处理 WARN。
7. 运行完整故障矩阵，更新运维检索/告警规则，并在本文记录逐事件审查结果。

服务端和扫描端分别提交，使用 Conventional Commits。每个提交必须同时包含对应测试和旧/新事件字段映射；不在日志改造提交中修改协议行为、存储顺序或发布版本。

## 11. 实施记录（2026-09-12）

### 11.1 已完成范围

- 服务端 JSON 文件日志关闭 span 列表，只保留当前 `http_request` span；内存 writer 测试验证 `request_id` 只出现一次。
- `SaveScannerResultsError` 已拆出稳定分类、机器码、窄操作名和重试属性。upload identity 冲突会同时记录 execution、收到的 upload ID、数据库中冲突的 upload ID 与冲突数量。
- 扫描结果 handler 在拥有完整载荷上下文的位置输出一次主错误，包含 scanner/task/upload/batch/protocol/数量、HTTP 状态和最终结果，不记录 observation 正文或认证信息。
- 通用服务端错误帮助函数统一补充 `error_kind`、`error_code`、`error_message`、`retryable`、`outcome`、route pattern、actor/resource 上下文和有界错误链；泛化 `database_operation` 会按 event 生成可检索的窄操作名与机器码。
- PostgreSQL 错误统一展开 SQLSTATE、severity、detail、hint、schema、table、column、constraint，并对错误链、根因、detail、hint 进行长度限制和截断标记。
- Elasticsearch outbox、扫描投影、分析快照、审计、请求日志、延迟历史、系统维护、备份、登录/用户管理、中间件、自动目标生成、监控与启动数据库路径的错误已补充业务对象、失败阶段、影响和重试信息；同一失败在深层与外层重复记录的路径已合并。
- 扫描端保存服务端 `X-Request-ID`，上传错误保留 scanner/task/upload/batch 上下文；retry、永久拒绝、final flush、租约丢失与恢复路径使用稳定事件和结果字段。
- masscan、zgrab2、nuclei 的外部进程失败统一携带 engine、stage、exit code、耗时、结果数、无效行数、stderr 字节数和截断状态。外部进程只在任务边界输出一次主 `ERROR`；引擎层返回结构化错误。
- 对会影响恢复或数据完整性的 `WARN` 做了选择性迁移：heartbeat/task fetch/recover/status 重试、维护暂停、运行时配置回退、无效工具输出采样、stderr reader 与临时文件清理均说明原因和后续状态。单次启动提示和纯开发诊断保持简洁。
- 前端没有集中日志采集链路，仍按第 8 节保持不变。

### 11.2 主要事件映射

| 原事件或旧日志 | 实施后的稳定事件/机器码 | 主要新增上下文 |
| --- | --- | --- |
| `SaveScannerResultError` + 文本原因 | `SaveScannerResultError` / `execution_upload_id_conflict` 等具名 code | scanner/task/execution/upload/batch/protocol/count、冲突双方、HTTP status、outcome |
| 泛化 `database_operation` | 保留业务 event，生成 `<event>_failed` | 窄 operation、actor/resource/route、PostgreSQL 诊断 |
| 重复的上传 retry 宏和 warning | `ResultBatchUploadRetry` | attempt、retry_after_ms、server request ID、batch identity |
| 泛化上传终止错误 | `ResultBatchUploadRejected`、`FinalResultUploadFailed` 等 | retryable、retained/discarded 状态、cache batch identity |
| 引擎内 `masscan/zgrab2/nuclei ... failed` | `ScanTaskFailed` / 引擎专用 code | engine/stage/exit/elapsed/count/stderr metadata |
| 泛化 heartbeat/fetch/recover warning | `HeartbeatRetry`、`TaskFetchRetry`、`TaskRecoveryRetry` | ServerError 分类、HTTP status、server request ID、attempt、retry_after_ms |
| 逐行坏 JSON warning | `Zgrab2OutputLineIgnored`、`NucleiOutputLineIgnored` | 首条采样、engine、reason、累计 invalid count |

旧 event 在可行处保持名称以减少检索规则迁移成本；含义过宽或存在重复的事件才拆分。稳定的 `error_code` 用于聚合，展示文本不再作为机器分类依据。

### 11.3 验证结果与限制

- 服务端：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`、`cargo build --locked --release` 通过；测试结果为 277 passed、23 ignored、0 failed。三个需要本地 HTTP socket 的测试首次在文件系统沙箱内被系统拒绝，获准在沙箱外重跑后通过。
- 扫描端：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`、`cargo build --locked --release` 通过；测试结果为 94 passed、0 failed。
- ignored 测试需要可丢弃 PostgreSQL、真实 Elasticsearch 或已配置的测试账号，本次没有可用外部基础设施，因此未把它们记为通过。
- 第 9.2 节中依赖真实 PostgreSQL/Elasticsearch 断连、429/503、mapping 错误和生产式队列压力的人工故障矩阵尚未执行。代码已为这些路径补齐字段，但上线前仍应在隔离运维环境核对实际 JSON、告警查询和脱敏结果。
