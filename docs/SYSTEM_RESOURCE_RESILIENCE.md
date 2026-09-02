# 系统资源读取与慢依赖隔离

## 背景

部署日志中的 `scanner_info` 更新、任务租约续期和 `/api/scanner/network/public-ip`
慢请求具有同一根因：扫描结果上传在 PostgreSQL 事务持有任务行锁和连接时等待
Elasticsearch。Elasticsearch 写入又使用 `wait_for_active_shards=all`；在单节点且索引
配置一个副本时，副本永远无法分配，重试会把一次上传放大到数分钟。后续心跳在锁上
排队，普通请求则在连接池上排队。

开发配置与部署配置是两套独立状态。本次代码不假定部署日志中的重试次数或连接池大小
与仓库 `config.toml` 相同；服务启动日志和部署配置应作为最终生效值的依据。

## 新的读取和持久化路径

系统资源采集仍按 `log.status_duration` 周期运行：

1. 采集 CPU、RAM、磁盘、网络和 PostgreSQL 指标；数据库指标最多等待 3 秒。
2. 先把完整快照发布到进程内 `SystemResourceCache`。
3. 再采集 Elasticsearch 容量（同样最多 3 秒）并将同一快照写入 `system_status`。

若一次采集超过周期，定时器会跳过错过的 tick，不会在依赖恢复后突发补跑。

`GET /api/data/system-data` 与 `GET /api/data/system-resource-history` 只读内存，不申请
PostgreSQL 连接。`system_status` 仍是持久化、审计和重启恢复的数据源；启动后后台按
10,000 行一页恢复最近 30 天的轻量 CPU/RAM/磁盘样本，页间释放连接。数据库容量历史
仍读取 PostgreSQL，因为它属于低频持久化报表，不是实时系统资源接口。

缓存边界：详细快照最多保存 720 条，趋势样本最多保存 30 天。缓存为空时接口返回空
数据而不是等待数据库；第一个采集周期完成后自动可用。

## 扫描上传事务边界

写入 Elasticsearch 的普通扫描和 DNS 批次采用两个短事务：

1. 校验扫描器与任务、检查序列和 checksum，写入 `storage_backend='pending'` 回执并提交。
2. 不持有 PostgreSQL 连接或行锁，执行幂等 Elasticsearch Bulk。
3. 重新开启短事务，锁定执行记录，把回执改为 `dual`/`elasticsearch`，写 PostgreSQL
   事实（dual 模式）并完成任务。

若进程在步骤 2 或 3 中断，回执保留为 `pending`；扫描器使用相同 execution/upload/batch
和 checksum 重试时会继续幂等写入。不同内容复用同一批次身份仍返回 400。

心跳也拆成 scanner 状态更新和任务租约续期两个事务。事务使用本地
`lock_timeout=1500ms`，并设置 5–15 秒的语句上限；锁冲突会快速返回可重试错误，不再
形成分钟级锁队列。

## 配置建议

单节点 Elasticsearch：

```toml
[elasticsearch]
scan_number_of_replicas = 0
write_wait_for_active_shards = "1"
bulk_total_timeout_seconds = 25
bulk_max_concurrency = 2
```

`scan_number_of_replicas` 只影响新建/由服务管理的索引。部署环境已有业务索引需在维护
窗口单独把副本数改为 0；不要批量修改系统索引：

```bash
curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic \
  -X PUT 'https://localhost:9200/network-mapping-*/_settings' \
  -H 'Content-Type: application/json' \
  -d '{"index":{"number_of_replicas":0}}'
```

多节点环境可配置副本，但 `write_wait_for_active_shards` 不应高于故障期间实际可用的
分片副本数。

PostgreSQL 连接池默认快速失败边界：

```toml
[database]
pool_max_size = 10
pool_wait_timeout_ms = 2000
pool_create_timeout_ms = 5000
pool_recycle_timeout_ms = 3000
```

连接池扩容不能替代事务拆分。应先观察 `pending` 回执、锁等待和 Bulk 延迟，再根据稳定
并发量调整 `pool_max_size`。

## 上线检查

- 确认启动日志中的连接池和 Elasticsearch 配置与部署文件一致。
- 确认单节点业务索引 `number_of_replicas=0`，集群无业务副本未分配。
- 连续观察两个扫描周期：系统资源接口不应出现数据库连接等待。
- 检查未完成回执：

  ```sql
  SELECT execution_id, upload_id, batch_index, created_at
  FROM scan_result_batch
  WHERE storage_backend = 'pending'
  ORDER BY created_at;
  ```

- 正常运行时 `pending` 只在 Bulk 执行期间短暂存在；长期存在表示扫描器尚未重试或
  Elasticsearch 仍不可用。
- 监控 PostgreSQL `wait_event_type='Lock'`、连接池 wait timeout、Elasticsearch Bulk
  总预算超时，以及 HTTP 503。快速 503 比占满所有 worker 的长时间挂起更可恢复。
