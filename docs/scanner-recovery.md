# 扫描器任务恢复协议

`GET /api/task/current` 支持 `scannerid`、`taskid`、`uploadid`，以及一对可选的失败报告参数：

- `failure_taskid`：本扫描器发生恢复失败的任务 UUID。
- `failure_count`：扫描器持久化的累计失败次数，范围 1–3。

两者必须一起提供。验证扫描器凭证后，在任务恢复事务内仅更新该扫描器仍持有的 running 执行。使用累计次数的最大值，重复请求不会重复计数；到三次时执行标记 failed，清除租约并刷新任务汇总状态。上传冲突导致执行替换时，失败次数转移到替代执行。原有客户端不传这两个字段时行为保持兼容。

服务识别的运行配置包含 `batch_endpoints`、`idle_timeout_seconds` 和 `max_runtime_seconds`，默认值分别为 512、120 和 1800；未提供时使用默认值，`schema_version` 为 1。

## 数据库升级

`init.sql` 已包含幂等的新增列语句。服务端启动时运行配置指定的初始化 SQL；已有环境如使用自定义初始化文件，需要先执行 `source/database/migrate_scanner_recovery.sql`，再启动新服务端。该迁移仅新增 scan_task_execution.recovery_failure_count，不删除或重写已有结果。

准备上线时先备份扫描器 SQLite 和 PostgreSQL，应用数据库迁移并更新服务端，再更新扫描器。回退服务端可以保留新增列；回退扫描器需要升级前的 SQLite 备份。

## 测试

常规检查：`cargo fmt --check`、`cargo clippy --all-targets --locked -- -D warnings`、`cargo test --locked`、`cargo build --locked --release`。

集成测试在独立 PostgreSQL 数据库内创建并删除临时 schema。设置 `STORAGE_TEST_DATABASE_URL` 后，执行 `cargo test --locked recovery_ -- --ignored`，验证上传冲突执行替换、累计失败报告幂等和三次失败上限。现有 storage 测试覆盖批次重传、混合结果、执行接管和并发领取；不要将测试变量指向生产数据库。

心跳增加 `ScannerLeaseRenewCompleted` 耗时事件，可与请求日志、数据库连接池及代理日志联合定位请求延迟。

## 诊断与领取任务

心跳报告诊断能力、健康状态和 `accepting_tasks`。启动引擎检查失败时仍维持心跳/诊断采集，但服务端阻止新任务分配；已经运行的任务恢复仍按原租约协议处理。诊断事件和日志任务使用独立队列，规则见[扫描器错误诊断与日志采集](SCANNER_DIAGNOSTICS.md)。
