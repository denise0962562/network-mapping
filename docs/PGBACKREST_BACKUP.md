# pgBackRest 备份管理使用指南

本文说明如何为 Network Mapping 使用的 PostgreSQL 部署 pgBackRest，并通过系统管理页面
查看备份、手动执行备份、检查 WAL 归档以及查看任务日志。文中的路径、PostgreSQL 版本、
服务账户和存储参数都是示例，上线前必须按实际环境调整。

## 1. 功能范围

当前实现包含：

- pgBackRest stanza 状态和备份集查询；
- 管理员手动执行全量、差异和增量备份；
- 管理员手动执行 `check`，验证 stanza 和 WAL 归档链路；
- 手动任务状态、退出码、标准输出和错误输出；
- 手动任务创建与完成审计；
- 独立于 Web 服务的 systemd 定时备份模板。

当前不包含：

- 在页面中修改 systemd timer 的执行时间；
- 在页面中删除备份集或执行 `expire`；
- 在页面中执行数据库恢复；
- 自动替代恢复演练、仓库异地复制或容量监控。

生产恢复具有覆盖数据的风险，必须在隔离环境验证并经过人工审批，不能通过普通 Web
操作直接执行。

## 2. 组件和数据来源

```text
管理员浏览器
    │
    ▼
Vue 数据备份页面
    │ 管理员会话 + CSRF
    ▼
Network Mapping Actix Web API
    │ 固定二进制 + 白名单参数
    ▼
pgBackRest ───── PostgreSQL 数据目录和 WAL
    │
    └────────── 备份仓库 repo1（可扩展异地对象存储仓库）

systemd timers ── 直接定时执行 pgBackRest
```

页面中的“备份集”来自 `pgbackrest info --output=json`，是仓库实际状态；“手动任务”来自
应用数据库中的 `backup_job` 表，只记录页面发起的任务。systemd 任务不会出现在手动任务
表中，但它生成的备份会出现在备份集列表。

## 3. 上线前检查清单

开始配置前确认：

1. 已知 PostgreSQL 主版本、数据目录、端口和服务账户。
2. 已评估数据库大小、每日 WAL 量、备份窗口和恢复目标。
3. 备份仓库不位于 PostgreSQL 数据目录内，并有足够空间。
4. PostgreSQL 主机和备份仓库时钟已同步。
5. pgBackRest 可执行文件由 root 管理，配置、数据目录和仓库对 postgres 可用。
6. 已预留独立恢复环境，不能把首次恢复测试直接指向生产数据目录。

可先收集环境信息：

```sh
postgres --version
pgbackrest version
sudo -u postgres psql -Atqc "show data_directory; show port; show archive_mode; show archive_command;"
df -h /var/lib/pgbackrest
```

pgBackRest 与 PostgreSQL 的安装方式因发行版而异。优先使用发行版或 pgBackRest 官方提供的
受支持软件包，并在升级前核对版本变更说明。

## 4. 配置 pgBackRest

### 4.1 创建目录和权限

以下为本地 POSIX 仓库示例：

```sh
sudo install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrest
sudo install -d -o postgres -g postgres -m 0750 /var/log/pgbackrest
sudo install -d -o postgres -g postgres -m 0750 /var/spool/pgbackrest
sudo install -d -o root -g postgres -m 0750 /etc/pgbackrest
```

不要把仓库目录设为所有用户可写。配置中含仓库口令或对象存储凭据时，配置文件建议由
root 拥有、备份执行组只读，例如 `0640`。

### 4.2 pgBackRest 配置示例

创建 `/etc/pgbackrest/pgbackrest.conf`：

```ini
[global]
repo1-type=posix
repo1-path=/var/lib/pgbackrest
repo1-retention-full=4
repo1-retention-diff=14
repo1-retention-archive=4
repo1-retention-archive-type=full

compress-type=zst
start-fast=y
archive-async=y
spool-path=/var/spool/pgbackrest
log-path=/var/log/pgbackrest
log-level-console=info
log-level-file=detail

[network_mapping]
pg1-path=/var/lib/postgresql/<version>/main
pg1-port=5432
```

需要替换：

- `<version>`：实际 PostgreSQL 主版本目录；
- `pg1-path`：`show data_directory` 返回的真实数据目录；
- `pg1-port`：实际 PostgreSQL 端口；
- `repo1-path`：实际备份仓库挂载点；
- 保留数量：根据空间预算和恢复窗口计算。

`repo1-retention-full=4` 表示按全量备份数量保留，不等同于固定保留 28 天。差异、增量备份
以及为恢复所需的 WAL 会受到备份链和归档保留策略共同影响。修改保留参数前，应先检查
现有备份链，并在测试环境验证 `expire` 的影响。

如使用 S3、MinIO、Azure 或 GCS 等对象存储，应把访问凭据放入受限配置或密钥管理系统，
不要写入本仓库、页面字段、systemd unit 或应用日志。建议至少保留一份与数据库主机故障域
隔离的仓库副本。

### 4.3 PostgreSQL 连续归档

在 `postgresql.conf` 中配置：

```ini
archive_mode = on
archive_command = 'pgbackrest --stanza=network_mapping archive-push %p'
```

如果 pgBackRest 不使用默认配置文件，需要在归档命令中显式指定：

```ini
archive_command = 'pgbackrest --config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping archive-push %p'
```

`archive_mode` 通常需要重启 PostgreSQL 才能生效。完成重启后再次查询配置，不能只确认文件
内容：

```sh
sudo systemctl restart postgresql
sudo -u postgres psql -Atqc "show archive_mode; show archive_command;"
```

## 5. 初始化和第一次备份

按以下顺序执行：

```sh
sudo -u postgres pgbackrest --stanza=network_mapping stanza-create
sudo -u postgres pgbackrest --stanza=network_mapping check
sudo -u postgres pgbackrest --stanza=network_mapping --type=full backup
sudo -u postgres pgbackrest --stanza=network_mapping info
```

注意事项：

- `stanza-create` 要求目标 stanza 的 archive/backup 仓库目录为空，不能把不相关文件放进去；
- `check` 会核对数据目录、数据库身份、`archive_mode` 和 `archive_command`，并触发 WAL
  切换以确认归档文件确实到达仓库；
- 首次上线优先执行全量备份，差异和增量备份都依赖已有备份链；
- 必须看到成功的全量备份后再启用定时任务。

JSON 状态可用于与 Web 页面比对：

```sh
sudo -u postgres pgbackrest --stanza=network_mapping --output=json info
```

`info` 命令能成功运行，不代表 stanza 一定健康。JSON 内的 stanza `status.code` 仍可能是：

| 状态码 | 含义 | 常见处理 |
|---:|---|---|
| 0 | 正常 | 继续检查最近备份时间和任务日志 |
| 1 | stanza 路径不存在 | 检查仓库路径并运行 `stanza-create` |
| 2 | 没有有效备份 | 完成第一次全量备份 |
| 3 | stanza 元数据缺失 | 检查仓库完整性、权限和初始化步骤 |
| 4 | 多仓库信息不一致 | 分别检查各仓库配置和同步状态 |
| 5 | 数据库身份不匹配 | 确认 `pg1-path` 指向正确实例，禁止混用旧仓库 |
| 6 | 指定备份不存在 | 核对备份标签和仓库编号 |
| 99 | 其他仓库错误 | 查看详细日志，检查网络、权限和对象存储配置 |

## 6. 配置 Network Mapping Web 服务

在 Network Mapping 的 `config.toml` 中启用：

```toml
[backup]
enabled = true
binary = "/usr/bin/pgbackrest"
stanza = "network_mapping"
config_file = "/etc/pgbackrest/pgbackrest.conf"
run_as_user = "postgres"
sudo_binary = "/usr/bin/sudo"
command_timeout_seconds = 21600
max_output_bytes = 1048576
```

参数说明：

| 参数 | 说明 |
|---|---|
| `enabled` | 是否开放后端查询和手动操作；默认 `false` |
| `binary` | pgBackRest 或经过审计的本机代理绝对路径 |
| `stanza` | 允许管理的固定 stanza，只允许字母、数字、下划线和连字符 |
| `config_file` | pgBackRest 配置文件；可省略以使用其默认搜索路径 |
| `run_as_user` | 可选的固定执行账户；推荐设置为 `postgres`，设置后使用非交互 sudo |
| `sudo_binary` | sudo 绝对路径，仅在配置 `run_as_user` 时使用 |
| `command_timeout_seconds` | 手动备份/check 最大执行时间，超时会终止子进程 |
| `max_output_bytes` | 每个 stdout/stderr 字段最大保存量，超出时保留末尾内容 |

修改后重启 Network Mapping 服务。启动时会自动创建 `backup_job` 表；升级前仍建议按正常
流程备份应用数据库。

### 6.1 推荐权限模型

仓库已经提供可直接落地的 sudo 模式，不需要让 Network Mapping 读取 PostgreSQL 数据目录，
也不需要把 Web 服务改成 root 或 postgres：

```text
network-mapping 服务账户
    │ 只能提交五条完全固定的 sudoers 命令
    ▼
sudo -n -u postgres -- /usr/bin/pgbackrest <固定参数>
    │
    ▼
postgres 账户读取数据目录、pgBackRest 配置和仓库
```

当 `run_as_user = "postgres"` 时，后端实际生成的命令前缀固定为：

```sh
/usr/bin/sudo -n -u postgres -- /usr/bin/pgbackrest
```

`-n` 表示非交互模式；如果 sudoers 不允许或仍要求密码，命令会立即失败，不会让 Web
请求卡在密码提示。后端仍只生成以下五种 pgBackRest 参数组合：

```text
--config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping --output=json info
--config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping check
--config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping --type=full backup
--config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping --type=diff backup
--config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping --type=incr backup
```

`run_as_user` 不允许设置为 root，也不接受空格、`#0` 或命令行片段。Web 请求不能覆盖
`binary`、`sudo_binary`、`run_as_user`、`config_file` 或 `stanza`。

### 6.2 安装精确 sudoers 规则

以下步骤假设：

- Network Mapping systemd 服务账户是 `network-mapping`；
- pgBackRest 运行账户是 `postgres`；
- 二进制为 `/usr/bin/pgbackrest`；
- 配置为 `/etc/pgbackrest/pgbackrest.conf`；
- stanza 为 `network_mapping`。

先确认实际值：

```sh
systemctl show network-mapping-server.service -p User -p Group -p NoNewPrivileges
command -v sudo
command -v pgbackrest
id network-mapping
id postgres
```

如果该 unit 显示 `NoNewPrivileges=yes`，set-user-ID sudo 无法切换到 postgres。不要盲目关闭
这项防护；应由安全管理员在“保留 NoNewPrivileges 并部署只暴露固定操作的本机代理”
和“对该 unit 允许精确 sudoers 桥接”之间做明确选择。本节的 sudo 方案要求
`NoNewPrivileges=no`。

如果服务账户尚未创建，应在安装 Network Mapping 服务时创建系统账户，并让应用目录由部署
账户管理、运行所需文件只读。示例：

```sh
sudo useradd --system --home-dir /var/lib/network-mapping --create-home \
  --shell /usr/sbin/nologin network-mapping
```

账户已存在时不要重复执行 `useradd`。如果实际账户或路径不同，必须同时修改
`config.toml` 和 `deploy/sudoers/network-mapping-pgbackrest`，不能只改一边。

先检查仓库提供的规则：

```sh
sudo visudo -cf deploy/sudoers/network-mapping-pgbackrest
```

确认输出 `parsed OK` 后安装：

```sh
sudo install -o root -g root -m 0440 \
  deploy/sudoers/network-mapping-pgbackrest \
  /etc/sudoers.d/network-mapping-pgbackrest
sudo visudo -cf /etc/sudoers.d/network-mapping-pgbackrest
sudo visudo -c
```

模板使用完整命令和完整参数，不包含 `*`、目录授权、正则表达式或 shell：

```sudoers
Cmnd_Alias NM_PGBACKREST = \
    /usr/bin/pgbackrest --config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping --output=json info, \
    /usr/bin/pgbackrest --config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping check, \
    /usr/bin/pgbackrest --config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping --type=full backup, \
    /usr/bin/pgbackrest --config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping --type=diff backup, \
    /usr/bin/pgbackrest --config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping --type=incr backup

network-mapping ALL=(postgres) NOPASSWD: NM_PGBACKREST
```

sudoers 在规则中指定参数时，请求参数必须匹配；如果不写参数，则意味着该命令可携带任意
参数。因此不能简化成下面任何一种形式：

```sudoers
# 错误：允许 pgBackRest 的任意命令和参数，包括 restore 和其他配置路径
network-mapping ALL=(postgres) NOPASSWD: /usr/bin/pgbackrest

# 错误：参数通配符会跨空格匹配，边界比看起来更宽
network-mapping ALL=(postgres) NOPASSWD: /usr/bin/pgbackrest *

# 错误：允许直接获得 postgres shell
network-mapping ALL=(postgres) NOPASSWD: /bin/sh
```

### 6.3 正向和反向验证

查看服务账户实际获得的权限：

```sh
sudo -l -U network-mapping
```

以服务账户测试页面查询所需的精确命令：

```sh
sudo -u network-mapping sudo -n -u postgres -- \
  /usr/bin/pgbackrest \
  --config=/etc/pgbackrest/pgbackrest.conf \
  --stanza=network_mapping \
  --output=json info
```

再测试 `check`；它会触发 WAL 切换，应在允许的维护窗口执行：

```sh
sudo -u network-mapping sudo -n -u postgres -- \
  /usr/bin/pgbackrest \
  --config=/etc/pgbackrest/pgbackrest.conf \
  --stanza=network_mapping \
  check
```

还必须确认下面三种越权尝试全部被 sudo 拒绝：

```sh
# 修改 stanza：必须失败
sudo -u network-mapping sudo -n -u postgres -- \
  /usr/bin/pgbackrest --config=/etc/pgbackrest/pgbackrest.conf --stanza=other info

# 执行 restore：必须失败
sudo -u network-mapping sudo -n -u postgres -- \
  /usr/bin/pgbackrest --config=/etc/pgbackrest/pgbackrest.conf --stanza=network_mapping restore

# 获取 shell：必须失败
sudo -u network-mapping sudo -n -u postgres -- /bin/sh -c id
```

拒绝时 sudo 应返回非零退出码并记录 `not allowed to execute` 或等效信息。如果任意负向测试
成功，立即删除或禁用该 sudoers 规则并重新检查，不要启用 Web 备份。

### 6.4 文件权限和启动验证

使用 sudo 模式时，Network Mapping 服务账户只需要执行 `/usr/bin/sudo`；pgBackRest 配置、
PostgreSQL 数据目录和备份仓库继续只授权给 postgres：

```sh
sudo chown root:postgres /etc/pgbackrest/pgbackrest.conf
sudo chmod 0640 /etc/pgbackrest/pgbackrest.conf
sudo chown -R postgres:postgres /var/lib/pgbackrest /var/log/pgbackrest /var/spool/pgbackrest
sudo chmod 0750 /var/lib/pgbackrest /var/log/pgbackrest /var/spool/pgbackrest
```

最后重启 Network Mapping，进入数据备份页面。页面应显示“sudo → postgres”，能够刷新状态
并运行检查；标准错误中不应出现密码提示。

## 7. 安装定时任务

仓库的 `deploy/systemd/` 提供以下模板：

| Unit | 默认时间 | 操作 |
|---|---|---|
| `pgbackrest-backup-full.timer` | 周日 02:10 | 全量备份 |
| `pgbackrest-backup-diff.timer` | 周一至周六 02:10 | 差异备份 |
| `pgbackrest-backup-incr.timer` | 每天 08:10、14:10、20:10 | 增量备份 |
| `pgbackrest-check.timer` | 每天 01:30 | stanza/WAL 归档检查 |

安装前先打开 unit 文件，确认 `User`、`Group`、stanza、二进制和时间符合当前环境。然后执行：

```sh
sudo install -m 0644 deploy/systemd/pgbackrest-* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now \
  pgbackrest-backup-full.timer \
  pgbackrest-backup-diff.timer \
  pgbackrest-backup-incr.timer \
  pgbackrest-check.timer
```

验证 timer：

```sh
systemctl list-timers 'pgbackrest-*'
systemctl status pgbackrest-backup-full.timer
systemctl status pgbackrest-check.timer
```

修改 `OnCalendar` 后，可在安装前检查表达式：

```sh
systemd-analyze calendar 'Sun *-*-* 02:10:00'
systemd-analyze verify deploy/systemd/pgbackrest-*.service deploy/systemd/pgbackrest-*.timer
```

`Persistent=true` 会在主机错过触发时间后补跑。`RandomizedDelaySec=5m` 会把实际开始时间在
五分钟内随机错开，因此日志时间可能不是精确的 02:10。

手动验证一次 systemd 服务：

```sh
sudo systemctl start pgbackrest-check.service
sudo journalctl -u pgbackrest-check.service -n 100 --no-pager
```

不要在首次验证时直接启动全量 timer；先通过命令行或 Web 明确执行并观察一份全量备份。

## 8. 使用 Web 数据备份页面

管理员登录后进入“系统设置 → 数据备份”。普通用户看不到导航入口，直接访问 API 也会
返回 403。

### 8.1 页面状态

- **Stanza**：当前后端允许管理的固定 stanza；“命令可用”和 stanza 健康状态应分别看待。
- **最近成功备份**：仓库中结束时间最新的备份，不只包含 Web 手动任务。
- **可用备份集**：从 pgBackRest 仓库元数据读取的备份数量。
- **任务状态**：本实例是否有手动任务执行，以及最近任务失败数量。
- **备份集**：定时和手动任务共同产生的实际备份。
- **手动任务**：仅页面提交的任务，可打开查看 stdout、stderr 和退出码。

页面每 10 秒自动刷新，也可点击“刷新”。备份运行时不要反复提交；并发请求会返回 409。

### 8.2 选择备份类型

| 类型 | 读取范围 | 典型用途 | 代价 |
|---|---|---|---|
| 全量 `full` | 完整数据库集群 | 首次备份、重大变更前、建立新基线 | 时间和空间最大 |
| 差异 `diff` | 相对最近全量发生的变化 | 日常备份、恢复链路较短 | 中等 |
| 增量 `incr` | 相对最近一次备份发生的变化 | 缩短备份间隔、降低单次写入量 | 恢复依赖链更长 |

推荐操作：

1. 首次部署、仓库重建或 PostgreSQL 大版本切换后执行全量备份。
2. 发布普通应用版本前可执行增量；涉及大规模数据迁移时优先差异或全量。
3. 填写能说明原因的备注，如工单号、发布版本或变更窗口。
4. 提交后观察手动任务状态；成功后确认备份集出现新标签。
5. 失败时打开任务日志，优先看 stderr 最后部分，不要只重复点击。

### 8.3 运行检查

“运行检查”不创建数据库备份。它用于核对 stanza、数据库配置和 WAL 归档链路。以下情况应
主动执行：

- 首次部署和修改 pgBackRest/PostgreSQL 配置后；
- 更换仓库、凭据、证书或网络策略后；
- 发现 WAL 归档告警或备份等待归档超时后；
- 恢复演练前后。

检查成功不能替代备份和恢复演练，只说明当前检查链路工作正常。

## 9. 日常运行建议

### 每日

- 查看最近备份时间是否满足 RPO；
- 确认最近定时任务没有失败；
- 关注 WAL 归档错误和仓库剩余空间。

### 每周

- 确认至少有一份新的全量备份；
- 执行或检查 `check` 结果；
- 检查 systemd timer 的下一次触发时间和失败计数。

### 每月或每季度

- 在隔离环境执行一次真实恢复；
- 记录恢复耗时、恢复到的数据时间点和业务校验结果；
- 复核保留策略是否覆盖审计、合规和事件调查窗口；
- 可按部署版本评估运行 `pgbackrest verify` 对仓库做更完整的校验。

## 10. 隔离恢复演练

以下命令只能在隔离恢复主机执行。目标 PostgreSQL 必须停止，目标数据目录必须为空且权限
正确。先在源环境记录备份标签：

```sh
sudo -u postgres pgbackrest --stanza=network_mapping info
```

在隔离环境恢复最新备份：

```sh
sudo systemctl stop postgresql
sudo install -d -o postgres -g postgres -m 0700 /srv/postgresql-restore
sudo -u postgres pgbackrest \
  --stanza=network_mapping \
  --pg1-path=/srv/postgresql-restore \
  restore
```

恢复指定备份标签：

```sh
sudo -u postgres pgbackrest \
  --stanza=network_mapping \
  --pg1-path=/srv/postgresql-restore \
  --set=<backup-label> \
  restore
```

指定时间点恢复示例：

```sh
sudo -u postgres pgbackrest \
  --stanza=network_mapping \
  --pg1-path=/srv/postgresql-restore \
  --type=time \
  --target='2026-08-22 10:30:00+08:00' \
  --target-action=promote \
  restore
```

时间点必须带明确时区，并且仓库中必须存在覆盖目标时间的基础备份和 WAL。pgBackRest 可根据
目标时间选择合适备份，也可以用 `--set` 明确指定。多仓库部署还应明确测试从异地仓库恢复。

恢复后使用隔离端口启动 PostgreSQL，至少检查：

1. PostgreSQL 能正常进入可读写状态；
2. 关键表存在且数量合理；
3. Network Mapping 能在隔离配置下登录和查询；
4. 恢复时间点符合预期；
5. 实际 RTO 是否达标。

不要把恢复演练的 `pg1-path` 指向生产数据目录，也不要为节省空间复用生产端口或生产应用
配置。

## 11. 常见问题排查

### 页面提示“管理功能未启用”

检查 Network Mapping `config.toml` 中 `[backup].enabled` 是否为 `true`，并确认修改的是
服务实际使用的配置文件。重启服务后查看启动日志中的 backup 配置摘要。

### 页面提示无法执行 pgBackRest

先确认页面显示的执行模式。使用本文推荐的 `run_as_user = "postgres"`
时，应在 Network Mapping 服务账户下测试与后端完全相同的命令：

```sh
sudo -u network-mapping sudo -n -u postgres -- \
  /usr/bin/pgbackrest \
  --config=/etc/pgbackrest/pgbackrest.conf \
  --stanza=network_mapping \
  --output=json info
```

处理顺序：

1. 如果 sudo 返回“password is required”或“not allowed”，运行
   `sudo visudo -cf /etc/sudoers.d/network-mapping-pgbackrest` 并核对服务账户、二进制路径、
   config、stanza、参数和顺序。
2. 如果 sudo 报“no new privileges”，检查 systemd unit 的 `NoNewPrivileges`，按 6.2 节选择
   本机代理或精确 sudoers 桥接。
3. 如果 sudo 已允许，但 pgBackRest 返回 permission denied，检查 postgres 对配置、
   数据目录、spool、日志、仓库和远端存储的访问。
4. 如果命令行成功而页面失败，确认 systemd 服务实际读取的 `config.toml`，然后
   重启后端并查看任务 stderr。

不要为了消除权限错误把服务改为 root，也不要将 sudoers 改成任意参数。

### stanza 显示 no valid backups

说明 stanza 元数据可读取但没有有效备份。完成一次全量备份，再刷新页面。

### database mismatch / pg1-path 错误

立即停止继续写入该仓库，核对 `show data_directory`、PostgreSQL system-id 和 pgBackRest
配置。不要对旧集群仓库重复执行 `stanza-create` 来掩盖问题。

### check 报 archive timeout

检查：

- `archive_mode` 和 `archive_command` 的实际运行值；
- PostgreSQL 日志中的 archive command 失败；
- pgBackRest archive-push 日志；
- spool、仓库目录权限；
- 对象存储 DNS、TLS、凭据和防火墙。

### 页面返回 409

已有 queued/running 手动任务。等待其结束并刷新页面。如果服务异常重启，启动恢复逻辑会把
中断任务标为失败；仍需确认操作系统中没有其他 pgBackRest/systemd 任务运行。

### 任务长时间执行

先查看任务 stderr、pgBackRest 文件日志和 systemd journal。pgBackRest 锁文件包含进程和
阶段性进度信息，可用于判断是否仍在推进。不要直接删除锁文件或强制终止进程；先确认进程
状态、仓库 I/O、数据库负载和网络状况。

### 定时备份没有出现在“手动任务”

这是预期行为。systemd 直接运行 pgBackRest，不写 `backup_job` 表。检查“备份集”是否出现
新标签，并通过 `journalctl -u pgbackrest-backup@full.service` 等命令查看 systemd 日志。

### Web 任务日志不完整

每个 stdout/stderr 字段受 `max_output_bytes` 限制，超出时只保留末尾内容。完整日志应在
pgBackRest `log-path` 或 systemd journal 中查看。

## 12. 安全和变更要求

- 仅管理员可以访问备份 API，所有写操作受 CSRF 中间件保护。
- 不在页面、Git、systemd unit 或审计事件中保存仓库密钥。
- 配置文件和仓库目录使用最小权限，Network Mapping 服务不以 root 运行。
- 修改 stanza、仓库地址、加密口令、保留策略或 timer 前先备份配置并记录变更。
- 多仓库和对象存储配置必须验证 TLS、凭据轮换、网络故障和异地恢复。
- 备份成功、`check` 成功和 `verify` 成功都不能替代真实恢复。

## 13. 停用定时任务

需要暂停计划任务时，只停用 timer，不要删除仓库：

```sh
sudo systemctl disable --now \
  pgbackrest-backup-full.timer \
  pgbackrest-backup-diff.timer \
  pgbackrest-backup-incr.timer \
  pgbackrest-check.timer
```

然后确认没有正在运行的服务：

```sh
systemctl list-units 'pgbackrest-*'
```

停用 Web 手动功能可将 `[backup].enabled` 改为 `false` 并重启 Network Mapping。删除仓库、
执行 `expire` 或更换加密口令属于高风险操作，不包含在停用步骤中。

## 14. 上线验收

- [ ] `stanza-create`、`check` 和第一次全量备份成功。
- [ ] `info --output=json` 中 stanza 状态码为 0。
- [ ] 数据备份页面显示“sudo → postgres”，服务本身仍以非 root 账户运行。
- [ ] sudoers 中只有五条完整命令，不包含通配符、脚本或 shell。
- [ ] info 和 check 正向测试成功，更换 stanza、restore 和 `/bin/sh` 反向测试被拒绝。
- [ ] 管理员能打开数据备份页面，普通用户 API 返回 403。
- [ ] 页面能提交一次手动增量或差异备份并查看完整任务结果。
- [ ] 备份成功后，新标签出现在备份集列表。
- [ ] 四个 timer 已启用且下一次触发时间正确。
- [ ] 主机重启后 `Persistent=true` 的行为符合运维预期。
- [ ] 仓库容量和 WAL 增长已纳入监控。
- [ ] 已在隔离环境完成恢复并记录 RPO/RTO。
