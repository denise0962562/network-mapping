# 开放平台实现说明与检查

## 实现范围

当前版本实现同一 allowlist 的 80 个外部操作、22 个 scopes、独立应用凭据、批准的业务范围及完整 Web 接入流程，同时覆盖个人和合作方应用。用户、系统、扫描器和备份等敏感管理功能没有加入外部路由。

`src/open_api/catalog.rs` 定义白名单，`contract.rs` 生成 OpenAPI；`mod.rs` 挂载外部和内部管理入口。没有把历史 `/api/*` 管理接口包装后对外，也不生成管理员 UserBaseI 供外部调用。

| 模块 | 职责 |
| --- | --- |
| auth / model | 哈希 Bearer、生命周期、权限交集、来源限制、原子共享配额、字段投影 |
| console | 会话角色、审批、二次验证、编辑版本、凭据生命周期、操作审计、真实应用调试 |
| query / business | 获批 ES/PG 查询、成功执行集合、时间/CIDR/域名/标签/字段边界、游标 |
| tasks | 显式目标验证、幂等创建、并发预算、任务归属、取消/重试、DNS 后续授权 |
| analytics | 范围化精确聚合、业务时区、历史口径、前期对比和明细 |
| resources / worker | 应用私有资源、生成队列/租约、归档文件、持久事件、签名投递和保留清理 |

迁移 `migrate_open_api.sql` 新增 api_client、api_credential、api_policy_revision、审批、console role/verification、用量、调用日志、审计、幂等、游标、生成任务、注释、保存查询、事件和回调投递表，给 scan_task 增加应用/凭据来源。`api_scan_task_enabled` 供既有任务领取/恢复检查授权，非 API 任务保持原行为。

投影 outbox 执行成功后仍写原全局和用户 scope，API 来源执行另写 `scope_type=api_client`。DNS 跟进任务继承应用、凭据与策略版本，并在生成时交叉检查全局策略和应用 CIDR。撤销后的未执行任务由后台对账取消，执行中的任务请求取消。

## 事务与边界

业务写入在 PG 事务内锁应用行与凭据共享锁并重核生命周期/策略版本，和暂停、撤销、发布策略协调。任务额度、幂等记录、实际任务与审计在同一事务。配额用 UPSERT 条件更新，应用多凭据和多进程共用计数。

生成队列用 SKIP LOCKED 和 claim_token/租约，导出/报告租约 60 秒、单次生成预算 45 秒，投递租约 30 秒、单次尝试预算 20 秒；完成写回要求相同 claim_token，旧持有者不能覆盖新结果。生成中、下载时与发送回调前都核验授权，结果与生成事件一起提交。

公开失败只返回稳定错误码/简短消息；5xx 不输出数据库或 ES 诊断。现有 API 错误中间件保留开放平台错误格式，包括 step_up_required。外部 namespace 单独免除 Cookie CSRF，但每个入口仍先鉴权；管理 Web 保持会话与 CSRF。

## 当前能力边界

- owner/application 两种数据来源；没有任意跨用户共享、OAuth、SDK 包、计费或自助签约。
- 沙箱限制真实扫描，读取实际批准数据；没有模拟数据服务。
- 实时资产及导出没有 PIT 快照。DNS 是获批成功执行观察，关联域名只取直接引用。
- 漏洞原始 data 在现有 ES 中不索引，分页后筛选；摘要达到预算会失败。
- 统计与平台共用两槽 PG advisory lock，范围精确计算；没有开放 API 结果缓存。报告捕获输入执行集合，但不能证明历史保留完整；只有发现/端口/服务三部分，未复用内部全局邮件报告。
- PG 存储生成文件，硬上限 8 MiB、7 天。部分资源列表有 100/200 项上限，没有全历史分页；上限在文档明确。
- 回调通过可信域名、逐次公网 DNS 验证、禁重定向和 TLS 校验；代理解析目的地址时还需要出口网关实施等效规则。
- 撤销阻止新授权行为；已发送请求依靠超时，已下发扫描依靠既有取消协议，不承诺瞬间物理停止。

## 构建与回归

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo run --example export_openapi > docs/open-api/openapi.json
```

开放平台数据库测试为 ignored，以免误用真实环境。只在专用空测试数据库运行，测试为每个用例创建随机 schema 并在成功后删除。HTTP fixture 只模拟 ES 协议与数据投影，不替代真实 ES 集群的部署验收。

```bash
export OPEN_API_TEST_DATABASE_URL='host=/path/to/disposable/socket user=postgres dbname=test_database'
cargo test --lib open_api::tests -- --include-ignored --test-threads=1
# 现有扫描存储与投影回归也只使用隔离数据库
export STORAGE_TEST_DATABASE_URL="$OPEN_API_TEST_DATABASE_URL"
cargo test --lib elasticsearch::storage_tests -- --ignored --test-threads=1
```

前端在 network-mapping-vue 仓库：

```bash
pnpm test:open-api
pnpm build
```

测试覆盖白名单无敏感操作、数据/字段交集、扫描排除与预算、DSL 越权、时间解析、回调目的地、CSV 转义、重复迁移、并发共享额度、凭据生命周期、审批/密钥/版本、任务幂等与撤销门禁、查询约束/游标绑定、DNS 地址脱敏、生成文件校验与授权变化。上线需额外验收真实 ES 数据口径、扫描器取消、反向代理来源 IP、TLS 和可信回调接收方。
