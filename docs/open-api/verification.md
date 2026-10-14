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

没有配置真实 Elasticsearch 测试集群，因此两项 `live_elasticsearch` 用例和大数据压力用例未执行，也未向实际合作方发送回调或下发生产扫描。上线前按 `OPEN_API_MANAGEMENT.md` 验收真实 ES、扫描器取消、可信代理来源 IP 和 Webhook 接收方。这些检查不由模拟测试替代。

检查命令与数据库隔离要求见 `OPEN_API_IMPLEMENTATION.md`。所有真实数据库测试只使用临时专用容器和随机 schema。
