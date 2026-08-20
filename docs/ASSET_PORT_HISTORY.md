# 资产端口状态与历史

## 数据语义

`scan_observation` 保存每次执行产生的端口和服务观察，是扫描结果的事实来源。
`ips`、`ports` 继续用于资产分页、地理信息和端口索引。`scaninfo` 仅在迁移期双写，供必要时
回滚，不再作为业务查询来源。

扫描器当前只上传开放端口，因此系统不会根据“某次没有发现”推断端口已经关闭：

- `open`：最近 30 天内至少有一次成功 execution 观察到该端口；
- `stale`：曾观察到开放，但超过配置的展示阈值没有再次观察到；
- 系统暂不产生 `closed`，直到 execution 能记录并证明完整扫描覆盖范围。

服务信息取该端口最新的 `service` observation。若端口在服务观察之后又被发现，接口会返回
`service_stale: true`，页面仍展示旧服务，同时明确标记信息可能过期。

## API

### 当前端口

```text
GET /api/assets/ports?ip=192.0.2.1&stale_after_days=30
```

普通用户只能查看自己任务产生的 observation；管理员可以查看全部任务。接口只使用状态为
`succeeded` 的 execution 计算当前状态。

### 端口历史

```text
GET /api/assets/port-history?ip=192.0.2.1&port=443&limit=50&offset=0
```

返回 observation 类型、协议、服务、banner、来源、批次、execution、任务和观察时间。
`superseded` execution 不参与历史查询。

## 历史回填

启动时的 `source/database/init.sql` 为还没有 observation 的旧 execution 创建协议版本 1
合成批次，并从 `scaninfo -> ports -> ips` 回填事实记录。回填键使用
`legacy:<scan_info_id>`，可以安全重复执行；已有 v2 observation 的 execution 不会再次导入
兼容镜像。

## 后续覆盖模型

如需可靠显示 `closed`，需要增加 execution 覆盖记录，至少包含目标 IP/CIDR、端口范围、阶段、
完成状态和覆盖完整性。只有成功且完整覆盖指定 IP、端口的扫描未发现开放时，才能把旧的开放
状态转为关闭。
