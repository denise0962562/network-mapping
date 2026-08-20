# 扫描计划与结果协议

## 任务计划

任务创建 API 可选传入 `scan_profile`：

- `legacy`：兼容旧扫描器，由节点本地配置决定是否识别服务；
- `port_only`：只执行 `port_discovery`；
- `service_inventory`：依次执行 `port_discovery` 和 `service_detection`。

未传入时默认 `legacy`。服务端将 profile 展开为版本 1 `scan_plan` 并保存，客户端不能传入
任意命令、二进制路径或 CLI 参数。任务领取响应包含完整计划。

## 能力调度

扫描器心跳的 `scan_capabilities` 包含 `plan_versions`、`profiles` 和 `stages`。服务端保存该
结构，并仅把非 legacy 任务分配给声明支持相应 profile 的扫描器。旧扫描器按仅支持
`legacy` 处理。

## 类型化结果协议

结果协议版本 2 使用 `port` 和 `service` observations。每个请求最多 500 条，并携带：

- `upload_id`：一个任务缓存周期内保持稳定；
- `batch_index`：从 0 开始的批次序号；
- `is_final`：是否为最后一批。

服务端通过 `(execution_id, upload_id, batch_index)` 唯一约束实现批次幂等。观察结果写入
`scan_observation`，同时镜像到现有 `ips`、`ports`、`scaninfo` 表以兼容现有查询界面。
只有最终批提交后任务执行才进入 `succeeded`。协议版本 1 的 `results` 请求继续支持，便于
滚动升级旧扫描器。

`scan_observation` 是扫描结果的事实来源；`ips`、`ports` 是资产与端口索引。读取接口通过
`scan_execution_endpoint_latest` 统一选择一次执行内的展示结果：服务观察优先于端口观察，
再按观察时间和记录 ID 排序。迁移期仍写入 `scaninfo`，但任务详情、搜索、导出和分析查询
不再依赖该表。协议版本 1 的结果会转换为 observation，并绑定到 execution 对应的合成批次。

资产当前状态和端口历史接口参见 [`ASSET_PORT_HISTORY.md`](ASSET_PORT_HISTORY.md)。
