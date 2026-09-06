# 扫描分析快照

扫描分析页面原先在每次请求时聚合全部 observation。该行为在 Elasticsearch 成为扫描事实源后，
会因高基数 composite aggregation 而明显变慢。现在可以将统计改为后台快照：扫描事实仍保留在
PostgreSQL 或 Elasticsearch，分析接口只读取 PostgreSQL 中的紧凑统计事实。

## 升级步骤

升级后的默认配置是 `mode = "realtime"`，接口行为不变。请按以下顺序切换：

1. 部署服务，让数据库初始化新增 `analytics_*` 表。
2. 在管理员运行时设置中将模式改为 `shadow`。后台 worker 会自动补偿升级前所有已成功的 IP 扫描执行；
   新版本服务会在 execution 成功的同一事务中写入 outbox。
3. 正常升级无需手动全量重建。仅在需要重新计算已完成的统计事实时，在维护窗口运行：

   ```sh
   cargo run --release -- --config /etc/network-mapping/config.toml \
     --rebuild-analytics-snapshots
   ```

   命令只替换 `analytics_*` 紧凑统计事实，不会删除或修改扫描 observation、任务或资产数据。
   已有可读水位会保留；失败会报告错误，不会把尚未完成的队列报告为重建成功。
4. 使用原有 `/api/analysis/distribution` 和 `/api/analysis/discovery-heatmap` 对典型用户、扫描器、
   任务来源和时间范围做结果核验。
5. 确认首次回填水位已生成后，在运行时设置中改为 `snapshot`。首次快照尚未完整时接口返回 503，
   不会静默回退到可能很慢的实时 ES 聚合。

## 配置

```toml
[analytics_snapshot]
# realtime: 保持旧实时查询；shadow: 后台构建、接口仍实时；snapshot: 接口只读快照。
mode = "realtime"
# 历史补偿检查及下一轮固定回填范围的建立周期；不是队列消费休眠时间。
interval_minutes = 30
```

TOML 仅首次初始化 `runtime_configuration`。数据库已有 `analytics_snapshot` 配置后，修改 TOML
并重启不会覆盖运行时设置。以管理员接口 `GET /api/config/runtime/analytics_snapshot` 返回的
`data.document` 和 `data.revision` 为准。

worker 每批最多处理 100 个 execution，有积压时只让出 1 秒后继续，空闲时每 5 秒检查新任务及重试。
历史全量补偿不再发生在每次领取任务时。失败项延迟五分钟重试，ES 读取、统计写入及事务错误均进入
同一重试路径；单次处理限时 30 分钟，进程中断遗留的领取记录 60 分钟后可重新领取。

首次启动固定当前待处理执行集合到 `analytics_snapshot_build_execution`。之后新增执行不会扩张
这一集合。每个执行的统计事实、队列完成标记和集合移除在同一事务中提交；集合清空时发布水位。
下一轮集合的建立及处理不删除已有水位。空数据库也会生成有效空快照。历史失败任务仍会阻止其所属
回填范围完成，系统不会通过跳过失败来伪造完整性。

领取使用 `FOR UPDATE SKIP LOCKED`，写入前校验领取时间并加锁，防止重试或重新上传后旧计算覆盖
新任务。统计事实每 1,000 行批量写入；写入失败整笔事务回滚，保留旧事实。ES 超时、失败分片、分页
游标异常或读取观察数少于执行记录的计数时，不发布该执行的统计结果。

## 进度与排错

管理员接口 `GET /api/config/runtime/analytics_snapshot` 除配置外返回 `progress`：

- `data_as_of`：最近完成的回填范围水位，首次尚未完成时为空。
- `build_started_at` / `build_completed_at`：当前固定范围的建立和完成时间。
- `remaining`：当前范围剩余执行数，后续新任务不计入。
- `pending` / `running` / `completed` / `retrying`：整个统计队列状态。
- `failed_execution_id` / `last_error`：最近一个未完成失败任务及原因。

首次快照不可读时，分析接口对管理员返回相同进度，页面显示剩余数量及最近失败原因。
普通用户只收到通用回填提示，不暴露其他用户的任务或错误。
水位 SQL 出错与回填未完成使用不同错误码，不再把数据库错误伪装成未回填。

升级时部署更新后的 `source/database/init.sql`，服务初始化会幂等创建两张回填范围表。
无须清空已有统计表或重新运行全量重建；开启 `shadow` / `snapshot` 后自动接续原队列。

## 统计口径

- 服务/端口分布按执行内的代表性端点计数；同一 endpoint 的首次 observation 决定其 30 分钟窗口。
- 服务名以 `LOWER(BTRIM(service))` 归一化；空服务名不进入服务分布。
- 发现 IP 按执行和上海自然日记录，并在接口查询时按 IP 去重。
- 统计响应的 `meta.data_as_of` 表示最近完成的固定执行集合的建立时间，是后台处理进度水位，
  不是 ES refresh 时间或任意 observation 时间范围的完整性保证。统计表按执行原子更新，可能已含
  水位之后处理完成的执行；它不是按全局版本冻结的历史数据库视图。

Elasticsearch 权威模式会按 `execution_id` 读取 observation 文档。旧索引缺少该字段或必要元数据时，
应先完成现有的扫描事实迁移，再执行快照重建。
