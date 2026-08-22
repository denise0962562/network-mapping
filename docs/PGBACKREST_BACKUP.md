# pgBackRest 备份管理

服务端提供管理员专用的 pgBackRest 状态、备份集、手动备份和检查接口。定时任务由
systemd 独立执行，因此 Network Mapping Web 服务停机时不会漏掉计划任务。

## 前提

在 PostgreSQL 主机安装 pgBackRest，创建 `network_mapping` stanza，并配置连续 WAL
归档。下面是最小配置框架，路径和保留数量应按实际环境调整：

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

[network_mapping]
pg1-path=/var/lib/postgresql/<version>/main
pg1-port=5432
```

PostgreSQL 配置：

```ini
archive_mode = on
archive_command = 'pgbackrest --stanza=network_mapping archive-push %p'
```

初始化并验证：

```sh
sudo -u postgres pgbackrest --stanza=network_mapping stanza-create
sudo -u postgres pgbackrest --stanza=network_mapping check
sudo -u postgres pgbackrest --stanza=network_mapping --type=full backup
```

## Web 服务配置

确认运行 Network Mapping 服务的账户能够以受限方式执行配置的 pgBackRest 二进制，并能
读取 pgBackRest 配置。不要赋予 Web 服务账户 root 权限，也不要开放任意 sudo 命令。

```toml
[backup]
enabled = true
binary = "/usr/bin/pgbackrest"
stanza = "network_mapping"
config_file = "/etc/pgbackrest/pgbackrest.conf"
command_timeout_seconds = 21600
max_output_bytes = 1048576
```

Web 服务只接受 `full`、`diff`、`incr` 和 `check` 白名单操作，并使用进程参数数组调用
二进制，不会执行 shell 字符串。同一服务实例一次只允许一个备份或检查任务。

如果 pgBackRest 只能由 `postgres` 账户执行，建议通过独立的本机执行代理或严格限定的
sudoers 规则接入；不要将 `/bin/sh`、任意脚本或带通配符的命令授予 Web 服务账户。

## 定时任务

复制 `deploy/systemd/` 中的 unit 文件，并在需要时修改 stanza、用户和执行时间：

```sh
sudo install -m 0644 deploy/systemd/pgbackrest-* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now \
  pgbackrest-backup-full.timer \
  pgbackrest-backup-diff.timer \
  pgbackrest-backup-incr.timer \
  pgbackrest-check.timer
systemctl list-timers 'pgbackrest-*'
```

默认计划为：周日 02:10 全量、周一至周六 02:10 差异、每天 08:10/14:10/20:10
增量、每天 01:30 执行 WAL 归档检查。`Persistent=true` 会让主机在错过执行时间后补跑。

systemd 定时任务直接运行 pgBackRest，因此不会出现在 Web 的“手动任务”列表，但完成的
备份会通过 `pgbackrest info --output=json` 显示在备份集列表中。

## API

- `GET /api/admin/backups/summary`：stanza 状态和真实备份集。
- `GET /api/admin/backups/jobs`：手动任务历史。
- `GET /api/admin/backups/jobs/{id}`：任务输出和错误日志。
- `POST /api/admin/backups/jobs`：提交 `full`、`diff` 或 `incr` 备份。
- `POST /api/admin/backups/check`：验证 stanza 与 WAL 归档。

所有接口都要求已登录管理员并受现有 CSRF 中间件保护。

## 恢复验证

正式使用前必须在隔离环境完成全量、差异/增量链路和指定时间点恢复。生产恢复不在当前
Web 管理功能范围内，避免页面误操作覆盖正在运行的数据库。
