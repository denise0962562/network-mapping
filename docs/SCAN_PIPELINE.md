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
`scan_observation`，并投影到 `ips`、`ports` 供资产索引与地理信息查询使用，不再写入
`scaninfo`。服务端以单条集合化 SQL 写入整批观察结果，并按 IP 和 `(IP, port)` 去重后更新
资产投影；同一端点的端口观察和服务观察不会重复执行资产 UPSERT。
只有最终批提交后任务执行才进入 `succeeded`。协议版本 1 的 `results` 请求继续支持，便于
滚动升级旧扫描器。

`scan_observation` 是扫描结果的事实来源；`ips`、`ports` 是资产与端口索引。读取接口按
`scan_execution_endpoint_latest` 定义的顺序选择一次执行内的展示结果：服务观察优先于端口观察，
再按观察时间和记录 ID 排序。端点列表使用参数化查询，仅检查当前端点的观察记录，避免为分页
结果计算全表窗口。任务详情、搜索、导出和分析查询均不依赖 `scaninfo`。协议版本
1 的结果会直接转换为 observation，并绑定到 execution 对应的合成批次。

升级时，若遗留 `scaninfo` 仍存在，数据库初始化只读取它并幂等回填尚无 observation 的旧
execution；新安装或用户已手动删除该表时会跳过回填。初始化和服务端运行路径都不会创建、
清空或删除 `scaninfo`。

资产当前状态和端口历史接口参见 [`ASSET_PORT_HISTORY.md`](ASSET_PORT_HISTORY.md)。
