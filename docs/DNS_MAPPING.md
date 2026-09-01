# DNS 测绘（第一阶段）

本阶段将 DNS 数据分为不可变查询证据和可更新的当前 RR。PostgreSQL 继续负责任务、扫描器身份、执行租约和上传回执；DNS 原始响应与当前解析状态由 Elasticsearch 管理。

## 数据模型

- `network-mapping-dns-observations`：Data Stream。每次查询产生一条追加事件，包含问题、rcode、answer/authority/additional、解析器、延迟、扫描器、任务和 DNS view。
- `network-mapping-dns-records-v1`：当前 RR 索引。每个文档是一条 DNS resource record，而非一整个 domain 或 IP 文档。

当前 RR 的 `_id` 是规范化 `tenant_id`、`dns_view_id`、owner、class、type 和完整 `canonical_rdata` 的 SHA-256。域名统一为小写、去末尾点；A/AAAA 统一为规范 IP；MX 包含 priority；SRV 包含 priority、weight、port 和 target。TTL 不属于身份，变化只更新当前文档。

`tenant_id` 和 `dns_view_id` 目前固定为 `default`，以保持上传协议兼容。生产多租户或 split-horizon 部署接入前必须将二者变成服务端授权的任务属性，不能让扫描器任意声明。

## 状态语义

成功 `NOERROR` answer 会 upsert 为 `active` 并刷新 `last_seen_at`。`NXDOMAIN`、NODATA、`SERVFAIL`、拒绝和超时始终写入 observations，但不会将已有 RR 标为失活，避免短暂解析器故障误删资产。

“失活”需要后续完整覆盖确认：按 `(domain, record_type, dns_view)` 记录成功扫描代次，仅当该代次确认 RR 缺失时增加 `missing_completed_scans`。该状态机尚未启用，因此本阶段不会自动失活记录。

## 扫描器和任务

```toml
[dns]
enabled = true
record_types = ["A", "AAAA"]
query_timeout_seconds = 5
```

初始 DNS engine 使用系统递归解析器，只主动查询 A/AAAA；服务端 ingestion 模型已能接收 CNAME、NS、MX、PTR、SRV、TXT、CAA、SOA、SVCB、HTTPS 的规范化 payload，扩展扫描器支持时不需改变索引身份规则。

DNS 任务由管理员 API 创建，仅自动分配给 heartbeat 中声明 `dns_records` / `dns_lookup` 能力的 scanner：

```http
POST /api/task/create-dns
Content-Type: application/json

{"domains":["api.example.com","www.example.com"],"level":2,"remark":"authorized inventory"}
```

该 API 只接受显式域名列表（1–500）；不会从 DNS answer 自动创建端口扫描任务。自动 IP 扫描必须先增加资产范围 allowlist、私网/保留地址策略、CDN 高扇出抑制、去重与队列上限。

## Elasticsearch 配置与保留

```toml
[elasticsearch]
enabled = true
dns_observation_data_stream = "network-mapping-dns-observations"
dns_record_index = "network-mapping-dns-records-v1"
dns_observation_retention_days = 180
```

首次 DNS 上传会创建 Data Stream template、Data Stream 与 current-record index。观测使用确定性 `create`，重传 409 视为幂等成功；当前 RR 使用带 `retry_on_conflict` 的脚本化 upsert。部署账户需拥有管理该 template/Data Stream、向 Data Stream `create` 和向 RR index `update` 的最小权限。

不要把 `dns-records` 嵌入 IP、服务或 HTTP 文档。查询 Domain→IP 或 IP→Domain 时以 `ip` 字段关联，由后端组合查询。`domain-assets` 是可重建详情页投影，尚未创建；大规模 CDN 域名必须设置每种 RR 的数量上限和截断标记后才可启用。
