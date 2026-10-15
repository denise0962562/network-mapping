# 开放平台实施验证记录

验证日期：2026-10-14。代码在本地工作区完成，未部署到生产，外部 API 默认关闭。

| 检查 | 结果 |
| --- | --- |
| Rust workspace 测试 | 400 项通过；依赖外部服务的默认 ignored 用例仍保持隔离运行 |
| 开放平台专项测试（包含专用 PostgreSQL schema 与 HTTP fixture） | 11 项通过 |
| 现有扫描存储/投影隔离回归 | 31 项通过，包括新增 api_client 独立投影 |
| cargo fmt --all -- --check | 通过 |
| cargo clippy --workspace --all-targets -- -D warnings | 通过，无警告 |
| OpenAPI | 80 个操作，引用和路径参数完整；规范与运行时路由一致性测试通过 |
| Vue 工具测试 | 13 个测试文件全部通过（提交 PR 前同步前端 main 后重新验证）；开放平台辅助函数 7 项通过 |
| pnpm build | 生产构建通过 |
| Chromium 管理页面交互（模拟管理 API） | 管理员、开发者、审计角色通过，无 Vue 运行时错误 |

专项覆盖：重复迁移、应用审批、二次验证、一次性凭据、跨应用不可见、字段和标签过滤、扫描目标排除、共享原子配额、DNS 子任务额度预留与回滚、幂等重放、撤销后的调度/调用限制、旧事件清理后不重新生成、游标身份绑定、DNS 地址过滤、导出/报告生成、校验值和授权变化后的下载限制。

浏览器检查包括申请/审批表单、凭据生成与二次验证重试、密钥关闭后清除且不写 localStorage、平台设置版本提交、角色按钮限制、接口目录和文档。浏览器使用 HTTP 模拟响应；业务数据边界由 PostgreSQL 与 ES HTTP 协议 fixture 的后端测试验证。

没有配置真实 Elasticsearch 测试集群，因此两项 `live_elasticsearch` 用例未执行，也未向实际合作方发送回调或下发生产扫描。上线前按 `OPEN_API_MANAGEMENT.md` 验收真实 ES、扫描器取消、可信代理来源 IP 和 Webhook 接收方。这些检查不由模拟测试替代。

检查命令与数据库隔离要求见 `OPEN_API_IMPLEMENTATION.md`。所有真实数据库测试只使用临时专用容器和随机 schema。

## 2026-10-15 Codex review 修复

以下 8 条意见均沿实际代码路径确认，修复后更新原服务端 PR #98 与前端 PR #3。

| Review | 修复与验证 |
| --- | --- |
| [统计明细字段授权](https://github.com/wshijiang/network-mapping/pull/98#discussion_r4272194684) | 端口/服务明细和聚合共用字段授权检查；无字段授权时返回 403，测试确认不向 ES 发查询，恢复授权后可查询。 |
| [任务漏洞筛选](https://github.com/wshijiang/network-mapping/pull/98#discussion_r4272194711) | 任务路径复用漏洞查询与 severity/template_id 筛选，保留任务约束；验证组合筛选、无效 severity 和过滤后空页的后续游标。 |
| [Webhook 测试事件 ID](https://github.com/wshijiang/network-mapping/pull/98#discussion_r4272194728) | 返回 outbox 中持久化的公共事件 UUID；与投递记录、事件列表保持一致。 |
| [导出与报告共享额度](https://github.com/wshijiang/network-mapping/pull/98#discussion_r4272194743) | 共用原子 `generation.day` 计数；限额为 1 时导出成功、相同幂等重放不重复扣费，随后报告返回 429。 |
| [调试输出密钥残留](https://github.com/wshijiang/network-mapping-vue/pull/3#discussion_r4272168308) | 调试结果递归遮盖一次性密钥；浏览器确认关闭弹窗后，弹窗与结果区均无密钥。 |
| [应用订阅串用](https://github.com/wshijiang/network-mapping-vue/pull/3#discussion_r4272168321) | 切换应用/凭据清空并重载订阅，按身份与请求序号丢弃过时响应；浏览器验证 A 的慢响应不会覆盖 B。 |
| [审批草稿干扰授权对比](https://github.com/wshijiang/network-mapping-vue/pull/3#discussion_r4272168331) | 主页面对比只读取应用草稿；审批弹窗关闭时清除独立状态，浏览器验证重新编辑应用后显示正确差异。 |
| [审计角色停用按钮](https://github.com/wshijiang/network-mapping-vue/pull/3#discussion_r4272168345) | 审计角色不渲染订阅写操作，停用按钮补齐调用条件，处理函数也检查角色；浏览器验证只读行没有写按钮。 |

同步服务端与前端最新 `main`，保留智能扫描路由和 API 授权两项调度条件，并将数据库测试 fixture 补齐两项迁移。Docker 构建上下文精确放行并复制 Rust 内嵌的 3 份公开文档与 OpenAPI，避免容器编译缺少 `include_str!` 输入；新增契约测试同时确认任意本地文档和配置仍被排除。

本轮已通过 Rust workspace 408 项、开放平台专项 13 项、扫描存储与独立应用投影 31 项（含 20 万任务领取查询计划检查）、智能调度 PostgreSQL 回归 15 项、Docker 契约测试 29 项、前端 13 个工具测试文件（开放平台辅助函数 8 项）、生产构建、上述 4 项 Chromium review 场景，以及 Rust 格式和 Clippy 检查。浏览器使用模拟 API；Webhook 测试只验证事件身份，不访问实际接收方。

## 2026-10-15 第二轮新增意见

新增 6 条均已确认并修复。前端原 PR #3 已合并，因此前端修复从最新 main 建立补充 PR，后端继续更新 #98，并同步固定前端引用。

| Review | 修复与验证 |
| --- | --- |
| [任务统计授权时间](https://github.com/wshijiang/network-mapping/pull/98#discussion_r4277667524) | SQL 与逐事件计数共用请求/策略的有效交集；验证窗口前创建、窗口内结束，以及窗口内创建、结束恰好位于排除上界的对称情况，只有授权事件计数。 |
| [漏洞摘要检查预算](https://github.com/wshijiang/network-mapping/pull/98#discussion_r4277667528) | 分开记录检查数和匹配数，在 severity/template_id 筛选前累计预算；10,000 条未匹配观察可返回 count=0，第 10,001 条触发 422，避免继续遍历。 |
| [凭据刷新失败丢失密钥](https://github.com/wshijiang/network-mapping-vue/pull/3#discussion_r4277670660) | 创建/轮换成功后先显示密钥；浏览器覆盖详情、用量、日志、任务 4 类后续刷新失败及轮换刷新失败，关闭弹窗仍清除密钥。 |
| [订阅刷新失败丢失签名密钥](https://github.com/wshijiang/network-mapping-vue/pull/3#discussion_r4277670665) | 创建 Webhook 后先显示签名密钥再刷新列表；模拟刷新 503 仍可保存，调试结果不留密钥。 |
| [过时页面响应](https://github.com/wshijiang/network-mapping-vue/pull/3#discussion_r4277670672) | 页面、筛选、文档、应用上下文与请求序号共同约束回写；浏览器延迟返回旧任务及旧应用日志，确认不覆盖投递、当前行或游标。 |
| [夏令时重复时间](https://github.com/wshijiang/network-mapping-vue/pull/3#discussion_r4277670680) | 保留原始当地时间直到选择偏移，合法后才更新策略；浏览器验证纽约重复小时 UTC-04:00/UTC-05:00 对应不同的正确毫秒值，无效/未选择偏移时禁止提交，春季不存在时间同样阻止发布。 |

本轮 Rust workspace 408 项、开放平台专项 15 项、格式和 Clippy 检查通过。前端 13 个工具测试文件、生产构建及新增 9 个 Chromium 场景通过，上一轮 4 个浏览器 review 场景也通过。使用隔离 PostgreSQL 和本地 HTTP fixture，浏览器模拟管理接口，没有部署、生产扫描或实际对外回调。
