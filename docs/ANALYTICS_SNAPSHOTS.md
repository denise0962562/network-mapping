# 扫描分析快照

扫描分析页面原先在每次请求时聚合全部 observation。该行为在 Elasticsearch 成为扫描事实源后，
会因高基数 composite aggregation 而明显变慢。现在可以将统计改为后台快照：扫描事实仍保留在
PostgreSQL 或 Elasticsearch，分析接口只读取 PostgreSQL 中的紧凑统计事实。

## 升级步骤

升级后的默认配置是 `mode = "realtime"`，接口行为不变。请按以下顺序切换：

1. 部署服务，让数据库初始化新增 `analytics_*` 表。
2. 将配置改为 `mode = "shadow"` 并重启。后台 worker 会补偿升级前所有已成功的 IP 扫描执行；
   新版本服务会在 execution 成功的同一事务中写入 outbox。
3. 对大规模历史数据，在维护窗口运行：

   ```sh
   cargo run --release -- --config /etc/network-mapping/config.toml \
     --rebuild-analytics-snapshots
   ```

   命令只替换 `analytics_*` 紧凑统计事实，不会删除或修改扫描 observation、任务或资产数据。
4. 使用原有 `/api/analysis/distribution` 和 `/api/analysis/discovery-heatmap` 对典型用户、扫描器、
   任务来源和时间范围做结果核验。
5. 确认 backfill 无积压后，将配置改为 `mode = "snapshot"` 并重启。快照尚未完整时接口返回 503，
   不会静默回退到可能很慢的实时 ES 聚合。

## 配置

```toml
[analytics_snapshot]
# realtime: 保持旧实时查询；shadow: 后台构建、接口仍实时；snapshot: 接口只读快照。
mode = "realtime"
# worker 调度周期。推荐 30 分钟。
interval_minutes = 30
```

worker 每轮最多处理 100 个 execution，失败项延迟五分钟后重试，其他 execution 不会被阻塞。多个
服务实例使用 PostgreSQL advisory lock 和 `FOR UPDATE SKIP LOCKED` 协调，不会重复消费同一个 outbox
项。`analytics_watermark` 只会在全部积压处理完成后推进，因此首次历史回填期间不会把不完整快照
对外发布。

## 统计口径

- 服务/端口分布按执行内的代表性端点计数；同一 endpoint 的首次 observation 决定其 30 分钟窗口。
- 服务名以 `LOWER(BTRIM(service))` 归一化；空服务名不进入服务分布。
- 发现 IP 按执行和上海自然日记录，并在接口查询时按 IP 去重。
- 统计响应的 `meta.data_as_of` 表示最近一次完整快照；新前端会显示该时间，旧前端可忽略此新增字段。

Elasticsearch 权威模式会按 `execution_id` 读取 observation 文档。旧索引缺少该字段或必要元数据时，
应先完成现有的扫描事实迁移，再执行快照重建。
