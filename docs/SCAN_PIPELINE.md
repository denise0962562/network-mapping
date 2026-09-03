# 扫描计划与结果协议

## 任务计划

任务创建 API 可选传入 `scan_profile`：

- `legacy`：兼容旧扫描器，由节点本地配置决定是否识别服务；
- `port_only`：只执行 `port_discovery`；
- `service_inventory`：依次执行 `port_discovery` 和 `service_detection`。
- `vulnerability_scan`：依次执行端口发现、可选服务识别和必需的 `vulnerability_detection`；
- `dns_records`：只执行 `dns_lookup`，目标为显式 domain 列表。

未传入时默认 `legacy`。服务端将 profile 展开为版本 1 `scan_plan` 并保存，客户端不能传入
任意命令、二进制路径或 CLI 参数。任务领取响应包含完整计划。

## 能力调度

扫描器心跳的 `scan_capabilities` 包含 `plan_versions`、`profiles` 和 `stages`。服务端保存该
结构，并仅把非 legacy 任务分配给声明支持相应 profile 的扫描器。旧扫描器按仅支持
`legacy` 处理。

## 类型化结果协议

结果协议版本 3 在版本 2 的 `port` 和 `service` observations 基础上增加
`vulnerability` observation。漏洞记录保存模板 ID、名称、严重级别、匹配位置、修复建议和
引用，不接收 Nuclei 的原始请求/响应，避免将凭据、Cookie 或响应正文写入结果库。每个请求
最多 500 条，并携带：

- `upload_id`：一个任务缓存周期内保持稳定；
- `batch_index`：从 0 开始的批次序号；
- `is_final`：是否为最后一批。
- `observed_at`：观察产生时的 Unix epoch 毫秒时间，重试时保持不变。

扫描器将任务、稳定上传身份、观察和已确认批次序号持久化到本地状态文件，重启后先恢复
未完成上传。服务端通过 `(execution_id, upload_id, batch_index)` 回执和 payload SHA-256
实现批次幂等，并要求最终批形成从 0 开始的连续序列。

`elasticsearch.scan_storage=postgres` 时，观察写入 `scan_observation` 并投影到 `ips`、
`ports`；`dual` 同时写入 ES；`elasticsearch` 时 PostgreSQL 只保存控制面和上传回执，原始
观察及执行/当前端点投影均由 ES 保存。迁移和恢复流程参见
[`ELASTICSEARCH.md`](ELASTICSEARCH.md)。
只有最终批提交后任务执行才进入 `succeeded`。协议版本 1 的 `results` 和版本 2 的端口/服务
请求继续支持，便于滚动升级旧扫描器；版本 2 不接受漏洞 observation。

DNS task 使用同一批次/回执机制，但一个批次只能包含 `dns` observations，不能与端口、服务或漏洞 observation 混合。DNS query 的 `observed_at`、question、rcode、answer sections 和解析器元数据写入 Elasticsearch Data Stream；详情见 [`DNS_MAPPING.md`](DNS_MAPPING.md)。

PostgreSQL 模式下 `scan_observation` 是事实来源，`ips`、`ports` 是资产与端口索引；ES
权威模式下对应角色分别由月度 observation 索引和 execution/current endpoint 索引承担。
读取接口按
`scan_execution_endpoint_latest` 定义的顺序选择一次执行内的端点展示结果：服务观察优先于端口观察，
再按观察时间和记录 ID 排序。端点列表使用参数化查询，仅检查当前端点的观察记录，避免为分页
结果计算全表窗口；漏洞 observation 单独展示，不参与端点当前状态投影。任务详情、搜索、导出和分析查询均不依赖 `scaninfo`。协议版本
1 的结果会直接转换为 observation，并绑定到 execution 对应的合成批次。

升级时，若遗留 `scaninfo` 仍存在，数据库初始化只读取它并幂等回填尚无 observation 的旧
execution；新安装或用户已手动删除该表时会跳过回填。初始化和服务端运行路径都不会创建、
清空或删除 `scaninfo`。

资产当前状态和端口历史接口参见 [`ASSET_PORT_HISTORY.md`](ASSET_PORT_HISTORY.md)。
