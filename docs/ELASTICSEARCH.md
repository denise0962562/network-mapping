# Elasticsearch 9.5.2 搜索接入

本文描述 Network-Mapping 服务端的 Elasticsearch 9.5.2 搜索读模型、配置、首次回填、
权限、健康检查、故障回退和索引重建流程。Elasticsearch 只承担资产搜索；PostgreSQL 仍是
扫描事实、用户权限、标签和当前端点投影的权威数据源，本方案不接入 ClickHouse。

## 1. 数据流与一致性

```text
Scanner -> PostgreSQL transaction
             ├─ scan_observation
             ├─ asset_endpoint_current
             └─ search_index_outbox
                         |
                         v
                 background worker -> Elasticsearch 9.5.2
```

- 扫描器只写 PostgreSQL，不直接访问 Elasticsearch。
- execution 成功时，同一事务刷新当前端点投影并写入 Outbox。
- 标签分配、移除、修改或删除也在原事务内写入对应 IP 的 Outbox 事件。
- 后台 worker 使用 Bulk NDJSON 写入 ES；失败按指数退避重试，不影响扫描结果提交。
- 文档使用 PostgreSQL `projection_version` 和 `external_gte`，重复投递与乱序投递不会让旧
  快照覆盖新快照。
- PostgreSQL 投影和 ES 索引均可从 `scan_observation` 重建。

每个普通用户拥有独立的 `(user, user_id, ip, port)` 文档；管理员使用独立的
`(global, 0, ip, port)` 文档。不能以一个全局文档附加 `owner_ids` 替代，因为不同用户对
同一端点可能拥有不同的最新可见结果。

## 2. 版本和客户端

服务端启动握手固定要求 Elasticsearch `9.5.2`，实际版本不一致时写入和读取均不会就绪。
应用使用 `reqwest 0.12` 直接调用稳定的 Elasticsearch REST API，没有采用仍标记为
experimental/alpha 的 Rust Elasticsearch 9.x 客户端。

实现依据：

- [Elasticsearch 客户端兼容策略](https://www.elastic.co/docs/reference/elasticsearch-clients)
- [Bulk API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk)
- [Wildcard 字段](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/keyword)
- [IP 字段](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/ip)

## 3. Elasticsearch 准备

安装官方 Elasticsearch 9.5.2，并保持安全功能和 TLS 开启。单节点开发环境可使用官方镜像：

```sh
docker run --name network-mapping-elasticsearch \
  --detach \
  --publish 9200:9200 \
  --env discovery.type=single-node \
  --env ELASTIC_PASSWORD='<仅用于本地开发的强密码>' \
  docker.elastic.co/elasticsearch/elasticsearch:9.5.2
```

生产环境应使用受管密钥、私有 CA、独立数据卷、快照仓库和适当的节点/分片规划。不要把
真实密码、API Key、CA 私钥或 Elasticsearch 数据目录写入本仓库。

推荐为应用签发 API Key，并将权限限制在目标索引。应用需要：读取集群版本、检查/创建/
删除目标索引、Bulk 写入和 Search 读取。若组织不允许应用管理索引，可以由管理员预建
完全相同 mapping，再给应用只读写权限；此时一键全量重建不可用。

## 4. 服务端配置

首次启用时保持 `read_enabled = false`：

```toml
[elasticsearch]
enabled = true
read_enabled = false
url = "https://127.0.0.1:9200"
index = "network-mapping-assets-v1"
expected_version = "9.5.2"
api_key = "base64-encoded-api-key"
ca_certificate_file = "elasticsearch/http_ca.crt"
request_timeout_seconds = 30
poll_interval_ms = 500
bulk_batch_size = 500
fallback_to_postgres = true
```

认证二选一：

```toml
api_key = "..."
```

或：

```toml
username = "network-mapping"
password = "..."
```

禁止把用户名/密码放进 `url`。相对 CA 路径以 `config.toml` 所在目录为基准，证书校验
不会被关闭。

配置含义：

| 字段 | 说明 |
|---|---|
| `enabled` | 启动索引初始化、Outbox worker 和增量写入 |
| `read_enabled` | 允许兼容查询从 ES 读取；要求 `enabled=true` 且全量同步完成 |
| `expected_version` | 固定为 `9.5.2` |
| `bulk_batch_size` | 单次从 PostgreSQL 读取并 Bulk 写入的文档数，1–2000 |
| `fallback_to_postgres` | ES 请求失败时是否回退 PostgreSQL 当前投影 |

## 5. 首次接入

建议按以下顺序执行：

1. 备份 PostgreSQL。
2. 部署包含新表结构的服务端，设置 `enabled=true`、`read_enabled=false`。
3. 停止常规服务进程后执行一次显式重建：

```sh
cargo run --release -- \
  --config /etc/network-mapping/config.toml \
  --rebuild-elasticsearch
```

该命令会：

- 为旧 observation 提取可搜索的 HTTP/TLS 字段；
- 重建 `asset_endpoint_current`；
- 删除并按当前 mapping 重建配置的 ES 索引；
- 分批写入全部 user/global 文档；
- 写入全量同步完成标记后退出。

4. 正常启动服务。
5. 管理员查询状态：

```text
GET /api/search/elasticsearch/status
```

确认：

```json
{
  "enabled": true,
  "read_enabled": false,
  "connected": true,
  "read_ready": true,
  "server_version": "9.5.2",
  "pending_events": 0
}
```

6. 使用代表性查询对比 PostgreSQL 与 ES 结果。
7. 设置 `read_enabled=true` 并重启。

即使没有显式执行重建命令，首次升级也会自动创建 PostgreSQL 当前投影并排队全量 ES
同步；显式命令更适合可控维护窗口和结果核验。

## 6. 索引模型

每条 ES 文档代表一个权限范围内的当前 `(IP, port)` 端点，主要字段包括：

```json
{
  "scope_type": "user",
  "scope_id": 42,
  "ip": "1.2.3.4",
  "port": 443,
  "service": "https",
  "title": "Hikvision Network Camera",
  "banner": "HTTP/1.1 200 OK",
  "http_body": "...",
  "http_body_truncated": false,
  "tls_subject": "CN=camera.example",
  "country_code": "CN",
  "asn": "4134",
  "first_seen": "2026-08-01T00:00:00Z",
  "last_seen": "2026-08-27T00:00:00Z",
  "projection_version": 12345
}
```

- IP 使用 `ip`；端口和 ASN 数字使用数值类型。
- 精确维度使用带 lowercase normalizer 的 `keyword`。
- Banner、TLS Subject 和字面包含辅助字段使用 `wildcard`。
- HTTP Body 使用 `match_only_text`，并 `copy_to` 到字面包含字段；复制字段不进入 `_source`。
- 搜索响应排除完整 `http_body`，防止分页响应放大；资产历史接口仍可读取原始 evidence。
- mapping 使用 `dynamic: strict`，意外字段会进入 Outbox 重试并暴露错误，不会静默污染索引。

当前索引是持续更新的当前状态，不按时间 rollover。mapping 变更应创建新的版本索引、全量
回填、核验并切换配置；不要让同一端点同时散落在多个时间索引中。

## 7. HTTP/TLS 规范化和安全限制

扫描器的 zgrab2 evidence 入库前已经移除 NUL 并受 `max_result_bytes` 限制。服务端进一步：

- 最多索引 256 KiB HTTP Body，并在 UTF-8 边界截断；
- 保存 `http_body_truncated`；
- 从 HTML `<title>` 提取最多 512 字符标题；
- 从版本化 evidence 中提取最多 4096 字符 TLS subject；
- 不把完整 Body 写入搜索结果列表。

HTTP Body 仍可能含密钥、个人信息和内部地址。生产扫描策略应限制允许的目标、响应类型和
数据保留范围；ES 快照、日志、API Key 和管理员搜索权限必须按敏感数据处理。

## 8. 查询路由和语义

以下查询在 ES 就绪时使用 ES：

- IP/CIDR、ASN、国家、端口、协议、服务；
- Banner、标题、HTTP Body、TLS Subject 字面包含；
- 标签、扫描器、首次/最近发现时间；
- 上述条件的 `AND`、`OR`、`IN`、比较和 `EXISTS` 组合。

以下查询继续使用 PostgreSQL 当前投影：

- `has_endpoint(...)` 跨端点条件；
- 通用 `NOT expression`，避免 SQL 三值逻辑和 ES `must_not` 在缺失字段上的差异；
- ES 未就绪或请求失败且 `fallback_to_postgres=true`。

`!=`、`!~`、`NOT IN` 已按原字段缺失语义单独编译。查询语法和 API 不变，客户端无需知道
实际使用的搜索后端。

## 9. 故障与恢复

### ES 不可用

- 扫描写入继续成功；Outbox 保留待处理事件。
- `read_ready` 变为 false。
- 开启 fallback 时查询读取 PostgreSQL 当前投影；关闭时返回 503。
- worker 使用指数退避重试，恢复后继续处理。

### mapping 错误或毒文档

Bulk API 逐项检查错误。非 409 错误会保留 Outbox 并在状态接口显示积压。修复 mapping 或
规范化逻辑后执行全量重建，不要手工将事件标记成功。

### 索引被误删

worker 会重新创建索引、清除同步就绪标记并排队全量同步；在同步完成前不会启用 ES 读取。

### 手工重建

在维护窗口停止常规服务，然后执行 `--rebuild-elasticsearch`。该命令会删除配置指定的 ES
索引，属于有意的可恢复操作；权威 PostgreSQL 数据不会删除。

## 10. 验收清单

- [ ] 根接口报告版本恰好为 9.5.2。
- [ ] TLS 证书校验开启，认证信息未提交仓库或写入日志。
- [ ] 状态接口 `connected=true`、`read_ready=true`、积压为 0。
- [ ] 普通用户只能得到自己的 scope，管理员只查询 global scope。
- [ ] IPv4、IPv6、CIDR、标签否定、时间和全文查询与 PostgreSQL 结果一致。
- [ ] `has_endpoint` 和 `NOT` 查询成功回退且结果不变。
- [ ] 停止 ES 后扫描上传仍成功；恢复后 Outbox 清空。
- [ ] 重复 Outbox 投递不会让旧文档覆盖新文档。
- [ ] 大 Body 被截断且搜索响应不返回完整正文。
