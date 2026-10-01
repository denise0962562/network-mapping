# 平台周报与月报

报告中心位于 `/reports`，仅管理员可访问。扫描器不需要升级。

## 启用

1. 服务启动会在初始化事务中执行内嵌的 `migrate_reports.sql`，兼容已有数据库。所有新计划默认关闭，原有 `reportWeekly=true` 不会自动启用计划。
2. 在运行时配置中将分析快照模式设为 `shadow`（保留现有分析读取路径）或 `snapshot`，检查历史回填进度。默认 `realtime` 不运行统计快照 worker。
3. 可以先手动生成上一个完整周期，检查报告内容。手动生成与修订版只归档；同一周期重复手动生成返回初始版本。
4. 配置 SMTP 和管理员邮箱，在报告中心选择收件人、时间并保存启用计划。保存计划会同步旧邮件通知开关；在邮件设置中关闭对应通知开关会暂停自动处理和投递。
5. 新启用/重新启用的计划从当前周期结束后开始，不发送启用前的历史。收件人留空表示所有有有效邮箱、未锁定/禁用/删除的管理员。每周一或每月 1 日按上海时间发送。

## 指标

- 周期采用 `Asia/Shanghai`，所有查询使用 `[start,end)`；周一为周起点，月报使用自然月。
- 新建任务按创建时间统计；终态任务按完成时间统计。成功率为成功 /（成功 + 失败 + 部分完成），取消单列，无分母显示 `--`。
- 扫描产出来自本期成功完成的 IP 扫描执行，包括跨周期执行的全部观察结果。IP 跨执行去重，端口/服务计数跨执行累加，不代表资产存量或新增资产。
- 成功执行平均耗时、P50、P95只包含有效起止时间。图表显示每日终态任务，扫描器表显示完成执行。
- 月报不累加周报或每日去重 IP。日均去重 IP 指周期去重 IP 除以周期天数。上期为零不计算增长率，上期缺少保留历史或统计未齐时不显示环比。
- 本版不包含 DNS 统计、资产消失判断、漏洞修复状态或扫描器在线率。历史清理之前没有额外事实留存时，不能恢复已删除数据；报告说明会注明“基于生成时保留的历史”。

## 归档与恢复

生成请求在 repeatable-read 事务中固定任务汇总、每日趋势、扫描器表现和成功执行集合。迟到执行不进入原报告；创建修订版时重新固定输入。成功执行统计必须完整且观测数量与固定输入一致，才能归档。

统计未齐进入 `waiting_data`，每分钟重试，24 小时后明确失败；输入执行被删除则失败。修复快照问题后可重试，重试重新开始 24 小时等待；输入变化需新建修订版。上期统计不足不阻塞本期归档，但关闭环比。

生成队列采用 `SKIP LOCKED`、5 分钟租约、UUID 领取令牌和条件回写。生成限时 50 秒，SQL 限时 30 秒；过期任务重新领取，数据库/计算错误最多重试 5 次。每实例每次处理一个报告。维护期间暂停生成和投递，自动计划每分钟扫描，最多补处理 8 个周期。

归档结果、统计口径版本、模板版本、渲染后邮件和 SHA-256 保存在 PostgreSQL，不会随扫描历史删除。页面、CSV、打印和邮件使用归档结果。邮件模板渲染失败不阻止统计归档，详情显示原因，修订后可再次生成邮件摘要。

邮件队列逐收件人处理，发送前重新验证用户角色、邮箱、计划、通知偏好和模板状态。使用稳定 Message-ID，SMTP 失败最多重试 5 次。SMTP 接受后、成功状态落库前崩溃仍可能重复发送；不提供 exactly-once 保证。手动发送明确选择收件人，不受自动计划开关限制；已有未完成投递时拒绝重复重发。

## 接口

- `GET /api/reports?page=1&page_size=20&period_type=weekly`
- `GET /api/reports/{id}`
- `POST /api/reports/generate`：`{"period_type":"weekly","date":"2026-09-21"}`；日期可省略。仅最近一年内已结束周期。
- `POST /api/reports/{id}/revisions`
- `POST /api/reports/{id}/retry`
- `GET /api/report-schedules`
- `PUT /api/report-schedules/{weekly|monthly}`：`enabled,send_hour,send_minute,recipient_ids,expected_revision`。计划更新使用乐观并发控制。
- `GET /api/reports/{id}/deliveries`
- `POST /api/reports/{id}/deliveries`：`{"recipient_ids":[1]}`。

所有接口要求登录管理员；写操作使用现有 CSRF 与限流。计划与投递变更写入审计。

## 验证

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test
# 仅使用一次性数据库，每个用例创建、清理独立 schema：
REPORT_TEST_DATABASE_URL='host=/path/to/test/socket port=55439 user=test dbname=postgres' cargo test --lib reports:: -- --include-ignored
```

集成用例覆盖去重、跨期观察、半开区间、部分完成/取消口径、快照等待、迟到输入、修订、归档保留、重启领取、并发创建、自动调度和发送前权限重验。默认测试跳过需要临时 PostgreSQL 的用例；没有连接真实 SMTP。
