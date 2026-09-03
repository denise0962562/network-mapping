# 扫描计划与结果协议

## 任务计划

任务创建 API 可选传入 `scan_profile`：

- `legacy`：兼容旧扫描器，由节点本地配置决定是否识别服务；
- `port_only`：只执行 `port_discovery`；
- `service_inventory`：依次执行 `port_discovery` 和 `service_detection`；
- `vulnerability_scan`：依次执行端口发现、可选服务识别和必需的 `vulnerability_detection`；
- `dns_records`：只执行 `dns_lookup`，目标为显式 domain 列表；
- `dns_ports`：对显式 domain 查询 A/AAAA 后扫描解析地址的端口；
- `dns_full`：归档 DNS 记录，并扫描解析地址的端口。

未传入时默认 `legacy`。服务端将 profile 展开为版本 1 `scan_plan` 并保存，客户端不能传入
任意命令、二进制路径或 CLI 参数。任务领取响应包含完整计划。

漏洞扫描计划固定为：

```json
{
  "version": 1,
  "profile": "vulnerability_scan",
  "stages": [
    { "type": "port_discovery", "required": true },
    { "type": "service_detection", "required": false },
    { "type": "vulnerability_detection", "required": true }
  ]
}
```

服务识别是可选阶段：节点没有启用 zgrab2 或识别失败时仍可继续 Nuclei；漏洞检测是必需阶段，
Nuclei 启动失败、非零退出、输出无效、超时或超过本地安全上限都会使执行失败。

创建 IP 漏洞扫描任务的请求示例：

```json
{
  "ip": "192.0.2.10",
  "port": "80,443,8080,8443",
  "level": 1,
  "scan_profile": "vulnerability_scan",
  "dispatch_mode": "automatic"
}
```

任务目标必须属于调用方已获授权的范围。服务端只负责调度和结果校验，不会代替组织完成扫描
授权审批。

## 能力调度

扫描器心跳的 `scan_capabilities` 包含 `plan_versions`、`profiles` 和 `stages`。服务端保存该
结构，并仅把非 legacy 任务分配给声明支持相应 profile 的扫描器。旧扫描器按仅支持
`legacy` 处理。

可领取漏洞任务的节点必须同时满足：

- 心跳 `scan_capabilities.plan_versions` 包含 `1`；
- `scan_capabilities.profiles` 包含 `vulnerability_scan`；
- `scan_capabilities.stages` 包含 `vulnerability_detection`；
- 目标地址族当前就绪；
- 节点在线、启用且没有被其他执行占用。

扫描器只有在本地启用 Nuclei，并通过二进制和模板目录启动检查后才声明这些能力。指定扫描器
和全部扫描器模式仍逐个应用相同的能力条件。

## 类型化结果协议

结果协议版本 3 在版本 2 的 `port` 和 `service` observations 基础上增加
`vulnerability` observation。漏洞记录保存模板 ID、名称、严重级别、匹配位置、修复建议和
引用，不接收 Nuclei 的原始请求/响应，避免将凭据、Cookie 或响应正文写入结果库。每个请求
最多 500 条，并携带：

- `upload_id`：一个任务缓存周期内保持稳定；
- `batch_index`：从 0 开始的批次序号；
- `is_final`：是否为最后一批。
- `observed_at`：观察产生时的 Unix epoch 毫秒时间，重试时保持不变。

### 漏洞 observation

```json
{
  "kind": "vulnerability",
  "ip": "192.0.2.10",
  "port": 443,
  "protocol": "https",
  "template_id": "cve-example",
  "name": "Example vulnerability",
  "severity": "high",
  "matcher_name": "body",
  "matched_at": "https://192.0.2.10:443/",
  "description": "Structured template description",
  "remediation": "Apply the vendor update.",
  "tags": ["cve"],
  "references": ["https://example.invalid/advisory"],
  "classification": {},
  "extracted_results": [],
  "source": "nuclei",
  "observed_at": 1788393600000
}
```

| 字段 | 约束 |
|---|---|
| `template_id` | 必填，最多 256 字节 |
| `name` | 必填，最多 512 字节 |
| `severity` | info、low、medium、high、critical 之一 |
| `matcher_name` | 可选，最多 256 字节 |
| `matched_at` | 必填，最多 4096 字节 |
| `description` / `remediation` | 可选，各最多 8192 字节 |
| `tags` | 最多 128 项，每项最多 128 字节 |
| `references` | 最多 64 项，每项最多 2048 字节，且仅允许 HTTP(S) URL |
| `extracted_results` | 最多 64 项，每项最多 2048 字节 |

单条 observation 的 `data` 序列化后不得超过 1 MiB。字符串中的 NUL 会被清理或拒绝。服务端
不接收 Nuclei 原始 request/response；这些字段也不会出现在扫描器缓存、PostgreSQL 或
Elasticsearch observation 中。

扫描器将任务、稳定上传身份、观察和已确认批次序号持久化到本地状态文件，重启后先恢复
未完成上传。服务端通过 `(execution_id, upload_id, batch_index)` 回执和 payload SHA-256
实现批次幂等，并要求最终批形成从 0 开始的连续序列。

`elasticsearch.scan_storage=postgres` 时，观察写入 `scan_observation` 并投影到 `ips`、
`ports`；`dual` 同时写入 ES；`elasticsearch` 时 PostgreSQL 只保存控制面和上传回执，原始
观察及执行/当前端点投影均由 ES 保存。迁移和恢复流程参见
[`ELASTICSEARCH.md`](ELASTICSEARCH.md)。
只有最终批提交后任务执行才进入 `succeeded`。协议版本 1 的 `results` 和版本 2 的端口/服务
请求继续支持，便于滚动升级旧扫描器；版本 2 不接受漏洞 observation。

漏洞 observation 使用端点、模板 ID、matcher 和匹配位置生成稳定键。同一执行内的上传重试
不会重复入库；不同执行仍分别保留，用于追踪扫描历史。

DNS task 使用同一批次/回执机制，但一个批次只能包含 `dns` observations，不能与端口、服务或漏洞 observation 混合。DNS query 的 `observed_at`、question、rcode、answer sections 和解析器元数据写入 Elasticsearch Data Stream；详情见 [`DNS_MAPPING.md`](DNS_MAPPING.md)。

PostgreSQL 模式下 `scan_observation` 是事实来源，`ips`、`ports` 是资产与端口索引；ES
权威模式下对应角色分别由月度 observation 索引和 execution/current endpoint 索引承担。
读取接口按
`scan_execution_endpoint_latest` 定义的顺序选择一次执行内的端点展示结果：服务观察优先于端口观察，
再按观察时间和记录 ID 排序。端点列表使用参数化查询，仅检查当前端点的观察记录，避免为分页
结果计算全表窗口；漏洞 observation 单独展示，不参与端点当前状态投影。任务详情、搜索、导出和分析查询均不依赖 `scaninfo`。协议版本
1 的结果会直接转换为 observation，并绑定到 execution 对应的合成批次。

## 任务详情响应

`GET /api/task/{task_id}` 返回所选执行的漏洞摘要和明细：

```json
{
  "success": true,
  "data": {
    "summary": {
      "ip_count": 1,
      "port_count": 2,
      "result_count": 5,
      "vulnerability_count": 1
    },
    "vulnerabilities": [
      {
        "template_id": "cve-example",
        "name": "Example vulnerability",
        "severity": "high",
        "ip": "192.0.2.10",
        "port": 443,
        "protocol": "https",
        "matched_at": "https://192.0.2.10:443/",
        "observed_at": 1788393600000
      }
    ]
  }
}
```

`vulnerability_count` 是该执行的总数；`vulnerabilities` 最多返回最近 500 条。普通端点结果仍
通过既有分页参数读取，漏洞列表目前没有独立分页接口，也不会出现在任务导出文件中。

## 上线、兼容与回滚

跨仓库部署顺序必须为：

1. 部署服务端并执行 `source/database/init.sql` 中的幂等初始化，使约束接受新 profile、协议 3
   和 vulnerability kind；
2. 部署前端，使任务创建和详情页识别新字段；
3. 在少量扫描节点安装 Nuclei 和审核模板，启用 `[nuclei]` 并重启；
4. 完成隔离测试目标验收后再逐步扩大节点范围。

服务端必须先于扫描器升级，因为旧服务端会拒绝协议版本 3。协议 1、2 客户端可以继续与新
服务端工作，因此服务端先升级不会中断旧扫描器。

新版扫描器对所有类型化结果都使用协议 3，而不只对漏洞结果使用。回滚服务端前，必须先停止
新版扫描器领取任务，在新服务端上排空协议 3 待上传批次，再回滚扫描器二进制并确认其恢复
协议 2，最后才能回滚服务端。扫描器会把任务和批次持久化到本地 SQLite；直接降级服务端或
删除节点状态可能造成持续上传失败或结果丢失。

## 验收与排障

- 漏洞任务一直 pending：检查是否存在在线、地址族就绪并声明 `vulnerability_scan` 的节点；
- 任务在漏洞阶段失败：检查扫描器的 Nuclei stderr 摘要、模板签名、超时和结果上限；
- 前端漏洞数为 0：确认查询的是正确 `execution_id`，并检查协议 3 批次是否已提交最终批；
- PostgreSQL 有记录但页面不可用：确认当前 `scan_storage` 模式及对应 Elasticsearch 可用性；
- 端点服务突然变成 Nuclei：这是异常，检查数据库视图和 ES projection 是否仍排除
  vulnerability kind。

扫描节点的参数、安全边界、模板治理和详细排障参见 Scanner 仓库的
`docs/NUCLEI.md`。

升级时，若遗留 `scaninfo` 仍存在，数据库初始化只读取它并幂等回填尚无 observation 的旧
execution；新安装或用户已手动删除该表时会跳过回填。初始化和服务端运行路径都不会创建、
清空或删除 `scaninfo`。

资产当前状态和端口历史接口参见 [`ASSET_PORT_HISTORY.md`](ASSET_PORT_HISTORY.md)。
