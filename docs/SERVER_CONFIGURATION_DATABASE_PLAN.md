# 服务端配置部分入库方案

## 目标与边界

将需要由管理员调整、需要审计、且可在不中断服务或受控重启后生效的**运行策略**保存到 PostgreSQL；保留启动链路、密钥和本机资源相关配置在 `config.toml`（或环境变量/密钥管理系统）。数据库不是服务启动的前置依赖：数据库连接本身仍只能来自文件或环境变量。

配置的有效值按以下优先级解析：

```text
固定启动配置（文件/环境变量）
    > 数据库中已发布的运行策略
        > 程序内置安全默认值
```

其中“固定启动配置”仅用于不可入库的字段；对已迁移的策略域，文件值只作为首次部署/数据库记录缺失时的种子默认值，不能在每次启动时覆盖管理员已发布的数据库值。

## 配置归类

| 配置域 | 当前来源 | 目标来源 | 生效方式 |
| --- | --- | --- | --- |
| `server.host`、`port`、`max_body_size` | TOML | TOML/环境变量 | 重启 |
| 数据库连接、TLS 证书路径、日志路径、模板/前端/MaxMind 路径 | TOML | TOML/环境变量 | 重启 |
| `server.encrypt_key`、`security.scanner_token_pepper`、数据库/ES/SMTP 密钥、备份 sudo 路径 | TOML/加密 `setting` | 密钥管理或环境变量；保持现状的 SMTP 密钥加密存储 | 重启或专门轮换流程 |
| 请求日志开关与保留期（`requests`） | TOML | 数据库 | 热更新：启停 writer/重建保留任务 |
| 健康监控阈值与冷却期（`monitor`） | TOML | 数据库 | 热更新：通知器读取最新快照，轮询间隔变更后重建轮询任务 |
| 自动目标生成策略（`automatic_target`） | TOML | 数据库 | 热更新：替换策略快照；生成循环在下一轮使用新值 |
| DNS 后续扫描策略（`dns_follow_up`） | TOML | 数据库 | 热更新：请求处理使用策略快照 |
| 分析快照模式与间隔（`analytics_snapshot`） | TOML | 数据库 | 受控重启 worker；API 在切换前后都返回明确状态 |
| ES 索引、认证、迁移与副本策略（`elasticsearch`） | TOML | 保持 TOML | 重启；索引/认证变化不应由普通管理接口在线修改 |
| pgBackRest 二进制、stanza、sudo 用户（`backup`） | TOML | 保持 TOML | 重启；属于主机命令执行边界 |
| SMTP、会话时长、默认扫描模板、可信代理、维护状态 | 已入库 | 维持现状并逐步迁移到新读写层 | 当前行为不变 |

`automatic_target` 和 `dns_follow_up` 会影响实际扫描目标，属于高风险运行策略：默认必须是禁用状态，修改权限仅限管理员，且每次发布必须审计。任何解析、校验或加载失败均回退到“禁用”，不能回退到可能扩大扫描范围的旧值。

## 数据模型

不继续向现有 `setting(item_type, key, value TEXT)` 加入复杂对象。该表保留给既有的简单兼容配置。新增按配置域存储 JSONB 的当前版本和不可变修订历史，避免键值分散更新、类型丢失和无版本并发覆盖。

```sql
CREATE TABLE IF NOT EXISTS runtime_configuration (
    namespace TEXT PRIMARY KEY,
    document JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    schema_version INT NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by_user_id INT REFERENCES users(id),
    CHECK (jsonb_typeof(document) = 'object')
);

CREATE TABLE IF NOT EXISTS runtime_configuration_revision (
    id BIGSERIAL PRIMARY KEY,
    namespace TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    schema_version INT NOT NULL,
    document JSONB NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by_user_id INT REFERENCES users(id),
    change_reason TEXT NOT NULL DEFAULT '',
    UNIQUE (namespace, revision),
    CHECK (jsonb_typeof(document) = 'object')
);
```

第一期 namespace 为 `requests`、`monitor`、`automatic_target`、`dns_follow_up` 和 `analytics_snapshot`。每个 namespace 存完整对象，例如 `automatic_target` 对应当前 `AutomaticTargetConfig` 的可持久化字段。结构化对象可复用 Rust 的 `Deserialize` 与既有 `validate`/`try_check` 逻辑，避免 SQL 中复制业务校验。

## 读取、发布与并发控制

1. 进程启动时先读取 TOML，连接数据库并执行 `init.sql`，随后加载每个 runtime namespace。
2. 数据库没有记录时，使用 TOML 值作为有效值，并在同一事务内写入当前表和 revision 1（`ON CONFLICT DO NOTHING`）。首次部署由文件初始化，后续以数据库为准。
3. 已有记录必须先反序列化并校验。无效记录写错误日志和健康事件；一般策略回退到 TOML 安全值，扫描相关策略强制禁用。
4. 管理端读取接口返回 `document`、`revision`、`updated_at` 和来源；不返回任何密文或密钥状态以外的敏感信息。
5. 保存接口要求 `expectedRevision`。用 `UPDATE ... WHERE namespace = $1 AND revision = $2 RETURNING ...` 实现乐观锁；未更新返回 HTTP 409 与当前 revision，避免两个管理员静默互相覆盖。
6. 当前表更新、历史表插入和 `operation_audit` 写入必须在一个事务中完成。审计只保存变更摘要或已脱敏后的字段。
7. 回滚是“以历史 document 新建一个更高 revision 的发布”，禁止直接修改或删除历史行。

建议的发布请求为：

```json
{
  "expectedRevision": 12,
  "document": { "enabled": false },
  "changeReason": "暂停自动生成任务"
}
```

服务端先按 namespace 做反序列化、范围和跨字段校验，再允许事务写入；不能接受任意 JSON 或由前端决定 schema version。

## 运行时同步

新增 `RuntimeConfigStore`，对每个配置域持有经过校验的不可变快照（`ArcSwap` 或 `Arc<RwLock<T>>`）与 revision。HTTP handler 和后台任务只读取快照，避免每个请求查询数据库。

单实例先采用“保存后本进程立即替换快照 + 15 秒轮询 revision”作为可靠基线。多实例部署增加 PostgreSQL `NOTIFY runtime_configuration_changed, '<namespace>:<revision>'` 以降低传播延迟；收到通知后重新读取并校验，轮询作为通知丢失和连接重建的兜底。配置实例要在日志和健康接口中暴露已应用 revision，便于识别配置尚未传播的节点。

不同策略域的应用动作由 `ConfigApplier` 明确实现，不能只替换内存 JSON：

- `automatic_target`：构造并校验新的 `AutomaticTargetService` 后原子替换；失败保持旧的有效策略。
- `dns_follow_up`：原子替换 `DnsFollowUpConfig` 快照；新请求使用新策略，在途执行保持原策略。
- `requests` 与 `monitor`：以 supervisor 管理 worker 的取消和重启，防止更新后留下重复的保留/轮询任务。
- `analytics_snapshot`：先启动新 worker 并确认就绪，再停止旧 worker；模式切换必须记录一次运维审计。

## API 与权限

新增管理员接口：

- `GET /api/config/runtime/{namespace}`：当前已发布文档和 revision。
- `PUT /api/config/runtime/{namespace}`：带 `expectedRevision` 的发布。
- `GET /api/config/runtime/{namespace}/revisions`：分页读取历史（不含密文）。
- `POST /api/config/runtime/{namespace}/rollback/{revision}`：创建新 revision 的回滚发布。

接口沿用现有登录、CSRF、`role == 1` 管理员校验和 `operation_audit`。前端设置页需要展示“未保存变更”“已被他人更新”和“本节点/所有节点已应用的 revision”；扫描范围、可信代理和会话策略应要求填写变更原因。

## 迁移步骤

1. 在 `init.sql` 增加两张表、索引和 `NOTIFY` 触发/显式发布函数；不改变现有 `setting` 表和已有接口。
2. 抽取每个 TOML 配置域的 DTO、默认值和校验函数；先实现只读的 `RuntimeConfigStore`、种子和状态日志。
3. 先迁移低风险的 `requests` 与 `monitor`，加入管理 API、审计、revision 冲突测试和 worker 重配置测试。
4. 再迁移 `dns_follow_up` 与 `automatic_target`；上线前要求管理员显式确认授权 CIDR，首次种子保持 `enabled=false`，即使 TOML 曾启用也不自动开启。
5. 最后迁移 `analytics_snapshot`。稳定一个发布周期后，将迁移完成的 TOML 段标记为“仅首次种子”，后续大版本再移除。

每一步均支持回退：删除/停用新的 runtime namespace 后，进程使用文件配置；已经写入的历史不删除。生产切换前先导出当前 TOML 的脱敏配置和 `runtime_configuration` 当前表，并做一次恢复演练。

## 验收条件

- 空数据库启动后可由 TOML 创建初始 revision，之后重启不覆盖数据库发布值。
- 无效 JSON、字段越界、CIDR/端口非法和乐观锁冲突均被拒绝，且旧有效快照继续服务。
- 两个服务实例在轮询窗口内收敛到相同 revision；`NOTIFY` 可加速但不是唯一依赖。
- 配置发布、失败发布和回滚均留下操作者、时间、原因、版本和脱敏变更摘要。
- 任意数据库配置损坏都不会扩大扫描授权范围、泄露密钥或阻塞数据库连接启动。
