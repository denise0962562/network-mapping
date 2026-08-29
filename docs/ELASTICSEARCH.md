# Elasticsearch 9.5.2 扫描存储与搜索

Elasticsearch 可以从可选搜索副本升级为扫描事实的权威存储。PostgreSQL 始终保留用户、
权限、标签、任务、执行状态、扫描器和上传回执等控制面数据；切换完成后不再向
`scan_observation`、`ips`、`ports` 写入新的扫描事实。

## 存储模式

| 模式 | 扫描事实写入 | 扫描事实读取 | 用途 |
|---|---|---|---|
| `postgres` | PostgreSQL | PostgreSQL；旧 ES 搜索副本可选 | 默认与回滚 |
| `dual` | ES 与 PostgreSQL | PostgreSQL/旧搜索副本 | 历史迁移、对比和观察期 |
| `elasticsearch` | ES | ES | 完成切换后的正式模式 |

禁止从 `postgres` 直接切换到 `elasticsearch`。服务启动会检查迁移标记、所有批次的内容
校验和、执行计数和待发布投影；前置条件不完整时拒绝启动，避免页面静默返回空数据。

## 索引与提交协议

- `network-mapping-scan-observations-v1-YYYY.MM`：追加式原始观察事实。月份取扫描器产生的
  `observed_at`，重试始终落到同一具体索引。
- `network-mapping-execution-endpoints-v1`：每次执行的 `(execution, IP, port)` 当前投影。
- `network-mapping-endpoints-current-v2`：`global/user` 权限范围内的当前端点投影。
- `network-mapping-assets-v1`：旧 PostgreSQL 搜索副本，仅兼容模式使用。

原始观察使用 `create` 和确定性 `_id = SHA-256(execution_id + observation_key)`。Bulk 响应
逐项检查：非 2xx 立即失败；409 通过 `_mget` 回读并比较文档校验和，只有内容完全相同才
视为幂等重试。原始 evidence 的 `data` 保留在 `_source`，mapping 使用 `enabled:false`。

扫描器先将稳定 `upload_id`、观察和下一批序号原子写入本地 `scanner-state.json`。服务端
验证扫描器和任务后先写 ES，再写 PostgreSQL 回执、payload SHA-256 和实际索引引用。最终批
使用 `refresh=wait_for`，所有 Bulk 请求使用 `wait_for_active_shards=all`；批次必须从 0 连续、
只有一个 final，随后才写执行计数并将任务置为 `succeeded`。current 端点不会在中间批次对
外可见；最终状态与投影 outbox 同一事务提交后才发布，发布失败由扫描器重试和后台 outbox
共同补偿。

ES 写失败不会提交回执或成功状态。若 ES 已成功但 PostgreSQL 提交前进程退出，相同批次
重试会通过确定性 ID 和校验和安全收敛。

## 配置

```toml
[elasticsearch]
enabled = true
read_enabled = false
scan_storage = "dual"
url = "https://127.0.0.1:9200"
index = "network-mapping-assets-v1"
observation_index_prefix = "network-mapping-scan-observations-v1"
execution_endpoint_index = "network-mapping-execution-endpoints-v1"
current_endpoint_index = "network-mapping-endpoints-current-v2"
scan_number_of_replicas = 1
expected_version = "9.5.2"
api_key = "base64-encoded-api-key"
ca_certificate_file = "elasticsearch/http_ca.crt"
request_timeout_seconds = 30
poll_interval_ms = 500
bulk_batch_size = 500
fallback_to_postgres = true
```

生产权威存储要求 `scan_number_of_replicas >= 1`，并应有足够数据节点使主副本均活动。单节点
开发环境只能在 `dual` 模式设为 0。索引固定使用 `translog.durability=request`。

API Key 至少需要读取集群版本、管理目标 index template/index、Bulk/Create/Update、MGet、
Search/Count 和 Update By Query 权限。认证信息和 CA 私钥不得提交仓库或写入日志。

## 迁移与切换

1. 备份 PostgreSQL，并为 ES 配置快照仓库和定期快照。
2. 部署新服务端和扫描器，但保持 `scan_storage="postgres"`。
3. 改为 `dual`；生产保持至少一份副本。
4. 停止常规服务，在维护窗口幂等迁移历史事实：

```sh
cargo run --release -- \
  --config /etc/network-mapping/config.toml \
  --migrate-scan-data-to-elasticsearch
```

命令按 PostgreSQL 批次顺序回填原始事实和端点投影，更新回执引用和执行计数，全部成功后
写迁移标记；失败修复后可原样重跑。迁移和 `--rebuild-elasticsearch` 会立即显示当前阶段，
并每 5 秒输出已完成数量、总量、耗时和当前批次等进度；进度写入标准错误，最终摘要仍写入
标准输出，便于终端观察和脚本分别收集。

5. 正常运行 `dual`，核对新任务、任务详情、资产、导出、分析和搜索。
6. 检查 `GET /api/search/elasticsearch/status` 的版本、连接、读就绪状态和索引名。
7. 比较代表性普通用户与管理员的总数、分页和权限边界。
8. 确认快照成功后设置并重启：

```toml
read_enabled = true
scan_storage = "elasticsearch"
fallback_to_postgres = false
```

启动切换检查通过后，扫描事实查询和新写入均使用 ES。不要立即删除 PostgreSQL 历史事实
表。回滚时先停止写入，切回 `dual/postgres` 并补齐切换后产生的 ES-only 数据，不能直接
假设 PostgreSQL 已包含它们。

## 查询覆盖与权限

ES 权威模式覆盖简单搜索、高级布尔搜索、`NOT`、`has_endpoint(...)`、资产概览/端口/历史、
任务详情/导出以及分析分布/热力图。`has_endpoint` 通过 composite aggregation 解析同资产
端点集合；匹配资产超过 65,536 时要求增加限定条件。

用户、权限、任务元数据、标签定义和审计继续读 PostgreSQL。普通用户查询自己的 `user`
scope，管理员查询 `global` scope。权威模式绝不回退到停止更新的 PostgreSQL 扫描事实表，
索引不可用时返回 503。

## 运维与验收

- ES 成为权威存储前必须部署主副本、磁盘水位监控、TLS/API Key 轮换和自动快照。
- 文件系统复制不是可靠备份；使用 Snapshot/Restore 并定期恢复演练。
- Bulk 部分失败、mapping 冲突或活动分片不足都会阻止任务成功，扫描器持久缓存会重试。
- 标签事务写入搜索 outbox；即时 ES 刷新失败后，后台任务会按 IP 重新加载 PostgreSQL 标签
  并修复 current 投影。
- 月度事实索引按保留策略快照后才能删除；mapping 变更创建新版本索引并重跑迁移。
- `--rebuild-elasticsearch` 只重建旧搜索副本；扫描事实使用独立迁移命令。

验收至少包括：历史迁移可重复、批次/观察数一致；重复批次幂等而不同内容被拒绝；缺批或
多个 final 不能成功；扫描器重启保持上传身份和观察时间；用户权限不串数据；标签操作刷新
ES；ES 中断时任务不成功且恢复后能续传；快照已校验并完成独立恢复。
