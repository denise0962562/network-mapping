# 开放平台管理与上线操作

## Web 功能

现有侧栏新增「开放平台」，入口 `/open-platform`，支持独立 URL 刷新。页面包括总览、应用与凭据、接口目录与调试、申请与审批、调用日志、操作审计、导出与报告、事件投递、接入文档、平台设置及管理权限。

总览展示应用状态与近 24 小时调用量、错误量和 P95；应用页面管理用途、授权字段和数据范围、配额、有效凭据、密钥轮换/撤销、用量、生成任务与回调。接口目录提供 80 项搜索、scope 提示、路径参数、JSON 示例、cURL 和调试结果。调试使用选定应用的真实凭据身份，并记录当前登录操作者；不能借管理员身份越过应用策略。

文档页面内嵌接入、管理与实现文档，可下载 OpenAPI。敏感密钥不进入 URL、浏览器持久存储或日志，只在弹窗内一次显示，关闭与离开页面时清除。

## 角色和审批

| 角色 | 能力 |
| --- | --- |
| 已有平台管理员 | 查看全部；审批、调整策略与配额、平台设置、分配开放平台管理角色 |
| operator 运营 | 查看全部应用、日志、审计；管理凭据和暂停/归档；不审批/扩大授权或更改平台设置 |
| auditor 审计 | 只读查看应用、日志、审计、任务和投递；不调试或执行写操作 |
| developer 开发者 | 申请并管理自己的个人应用、凭据、范围调整申请、调试及用量 |

管理角色只在开放平台生效，不改变已有用户角色。管理员给现有用户 ID 分配 operator/auditor，developer 表示移除该额外角色；不在此创建、修改或删除用户。

创建应用为 pending 且没有有效授权。管理员检查责任用户、用途、owner/application 数据来源、目标和排除 CIDR、域名、字段、标签 ID、扫描模式、来源 IP 与配额后批准。应用在 pending 状态不能绕过审批直接启用；只允许管理员恢复 paused，archived 不可恢复。每用户最多 20 个未归档应用，每应用最多 20 个有效凭据。

功能较多时仍应按实际用途批准 scopes；vulnerability_scan、漏洞证据、banner/TLS 详细信息、tasks:create/cancel/retry、webhooks:manage 等独立授予。读取范围和扫描范围的空列表含义不同，见接入文档。

创建/轮换/撤销凭据、审批、状态切换、发布授权或有效期、平台设置和管理角色要求最近 5 分钟重新验证当前会话密码；已有账号启用 2FA 时还要求 TOTP。每用户每分钟最多 5 次验证，验证记录保存会话哈希，不保存密码/TOTP。

发布编辑须携带 `expected_revision`；冲突返回 409，刷新并重新审阅。应用 `revision` 是编辑版本，`policy_revision` 是数据授权版本；名称和用途编辑不会让既有文件失效。

## 密钥与回调运维

密钥最长有效期 365 天，默认 Web 创建 90 天；按用途与来源 IP 拆分凭据。轮换创建新密钥，可给旧密钥 0–24 小时重叠窗口，先更新调用方、确认新密钥 last_used，再撤销旧密钥。旧密钥绑定的生成任务/回调随后不能继续使用旧授权；需要迁移订阅时先创建并验证新订阅。

管理员在平台设置中维护可信 Webhook 接收方的精确域名，不允许通配符；URL 与解析地址仍由服务逐次验证。服务保留环境的代理、CA 与 TLS 校验。如出口 HTTP 代理替服务解析 DNS，应用侧地址固定不能约束代理的实际目的地，必须在代理/出口网关设置相同的公网限制和批准域名规则，再启用该域名。不要通过关闭 TLS 或绕过公司出口规则解决问题。

投递详情只显示状态码和公开原因，不读取接收方响应正文。5 次失败后的任务可在「事件投递」点击重试，或在调试目录调用 `/webhook-deliveries/{delivery_id}/retry`；接收端必须按事件 ID 去重。检查管理员允许域、DNS、TLS、签名、时间窗口及 2xx 响应，再重试。

## 部署与验证顺序

1. 备份当前 PostgreSQL，审阅 `source/database/migrate_open_api.sql`。迁移由已有启动流程应用；默认 `enabled=false`，不会自动开放已有资产。
2. 按原部署流程构建后端与 Vue，将前端 dist 配置给现有服务器。反向代理必须同时路由 `/open-api/v1/*`、`/open-api/openapi.json`、`/api/open-platform/*` 和新的 SPA 页面。
3. 外部使用 HTTPS。保留已有可信代理/ClientIp 配置，不信任任意客户端伪造的 Forwarded/X-Forwarded-For。JSON 请求上限与代理设置协调为 128 KiB；文件上限 8 MiB。
4. 保持现有 ES 成功执行历史与 current endpoint 投影可读；新扫描任务会发布 api_client 投影。历史用户数据通过明确批准的 owner 模式提供，旧扫描不会自动归入新应用。
5. 数据库备份应包含开放平台表、凭据哈希、加密回调签名密钥与生成文件。妥善保存原有服务器 encrypt_key，变更前迁移加密数据；丢失密钥需重建回调。
6. 在沙箱应用验证批准的只读范围；在显式 CIDR 内批准最小生产扫描，通过 validate、create、幂等重放、投影完成、导出、事件、撤销测试。
7. 管理员启用平台。逐步增加应用和配额，观察共享统计预算、PG 连接池、BYTEA 文件容量、ES 查询延时和失败率。

公开规范不含应用、用户、凭据或目标清单，可以在平台关闭时读取。生产接入测试需批准测试应用；不要直接使用管理员 Cookie 代替外部凭据。

## 故障定位、保留与停用

调用日志保存 request_id、应用/凭据 ID、模板路由、HTTP 状态、耗时、原因和来源 IP；不记录 Authorization、请求体或查询原文。审计记录申请、审批、设置、密钥生命周期、任务与应用私有写操作。日志写入失败会记录服务器告警；不把临时日志故障伪装成业务失败。

默认调用日志 30 天（可配 1–90），审计 180 天（30–730），事件/投递 30 天，用量桶 366 天；幂等记录 24 小时、游标 10 分钟、生成文件与报告数据 7 天。后台每小时清理过期数据；生成物的元信息继续保留。当前没有对象存储和平台级审计导出 UI，大规模使用时需规划 PG 容量和既有备份/归档策略。

出现异常可先暂停单应用或撤销凭据，再检查 request_id、投递与审计。关闭全局开关会拒绝新外部调用；待执行扫描在调度检查中停止，已下发任务通过现有取消协议退出，后台生成与投递检查失效授权。系统维护期间拒绝业务写入，并暂停生成任务领取。

回滚代码前先关闭 API 并停止新任务。保留新增表、列和生成物，不通过删除 users/scan_task 数据回滚。旧版本扫描调度器没有 API 授权门禁，回滚到旧版本前必须取消或完成所有 API 扫描任务，避免旧调度器继续下发。核心普通用户/扫描器接口仍按原权限体系运行。

## 管理 API 约定

管理 API 前缀 `/api/open-platform`，仅 Web 会话可调用；敏感操作除 CSRF 外还需 step-up。该前缀不属于外部接口目录。

| 功能 | 路由 |
| --- | --- |
| 当前角色/目录/规范/内嵌文档 | GET session、catalog、openapi.json、documentation/{integration\|management\|implementation} |
| 验证 | POST step-up，body password/totp |
| 应用 | GET/POST apps，GET/PATCH apps/{id} |
| 状态与授权申请 | POST apps/{id}/state、apps/{id}/requests |
| 审批 | GET approvals，POST approvals/{id}/review |
| 凭据 | POST apps/{id}/credentials、credentials/{key}/rotate、credentials/{key}/revoke |
| 调试 | POST apps/{id}/invoke，body credential_id/method/path/payload |
| 总览/日志/审计/用量/任务/投递 | GET overview、logs、audit、usage、jobs、deliveries |
| 设置与管理角色 | GET/PUT settings，GET roles，PUT roles/{existing_user_id} |

settings 写入为 `{document,expected_revision}`；app PATCH/state 带 expected_revision；审批带 approved、可选 policy/note。日志/审计可用 client_id 与 after；其余管理列表有固定上限，详见接入文档。
