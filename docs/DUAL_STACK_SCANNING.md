# 双栈扫描、协议能力与自动目标

本文说明服务端如何区分 IPv4/IPv6 任务、接收扫描器公网协议探测结果、选择兼容扫描器，
以及分别维护 IPv4/IPv6 自动目标队列。

## 设计原则

- 一个任务只包含一种地址族：`ipv4` 或 `ipv6`。
- 地址族由服务端解析目标后得出，不信任客户端提交的地址族字段。
- 扫描器连接服务端时使用的来源 IP 不代表扫描能力；能力必须通过心跳显式上报。
- `supported` 表示该协议没有被扫描端配置禁用，`ready` 表示最近一次公网探测成功。
- 服务端不会把 IPv6 任务分配给 IPv4-only 或 IPv6 探测失败的扫描器。
- 自动目标永远限定在配置的授权 CIDR 内，不发现或扩展未经授权的地址范围。

当前探测验证的是扫描器操作系统能否通过指定协议访问 HTTPS IP 回显 API。它适合判断
公网出口能力，但不能证明扫描器可以访问任意私有网段，也不能替代路由、ACL 和扫描引擎
的实际运行验证。私网专用扫描器应使用部署环境内的自建探测接口，并在投入生产前执行
一次目标网段验证。

## 数据流

```text
扫描器 IPv4/IPv6 公网探测
          │
          ▼
POST /api/scanner/heartbeat
          │
          ├── 保存 supported/ready、公网地址、失败原因
          └── 刷新 network_capabilities_updated_at
                              │
创建或自动生成单地址族任务 ───┤
                              ▼
                    GET /api/task/apply
                              │
                    地址族与扫描器能力匹配
                              │
                              ▼
                         扫描器执行
```

## 心跳协议

扫描器在原心跳字段之外提交 `network_capabilities`：

```json
{
  "scanner_id": "019c0000-0000-7000-8000-000000000001",
  "state": "idle",
  "active_task_id": null,
  "scanner_version": "0.1.0",
  "system": {
    "os_name": "Linux",
    "os_version": "6.x",
    "cpu_model": "Example CPU",
    "cpu_cores": 8,
    "ram_total_mb": 16384,
    "uptime_seconds": 3600
  },
  "network_capabilities": {
    "ipv4": {
      "supported": true,
      "ready": true,
      "public_ip": "203.0.113.10",
      "reason": null
    },
    "ipv6": {
      "supported": true,
      "ready": false,
      "public_ip": null,
      "reason": "probe_request_failed: ..."
    }
  }
}
```

服务端会验证 `public_ip` 的格式和地址族。IPv4 字段携带 IPv6 地址或反之时返回 400。
失败原因以 JSON 保存并在扫描器详情接口返回；扫描端会将原因截断，避免错误响应无限增长。

旧版扫描器省略 `network_capabilities` 时，服务端按以下值兼容：

```text
IPv4: supported=true, ready=true
IPv6: supported=false, ready=false
```

## 数据库字段

`scan_task`：

| 字段 | 类型 | 说明 |
|---|---|---|
| `address_family` | TEXT | `ipv4` 或 `ipv6` |

`scanner_info`：

| 字段 | 类型 | 说明 |
|---|---|---|
| `supports_ipv4` / `supports_ipv6` | BOOLEAN | 扫描端是否启用对应协议 |
| `ipv4_ready` / `ipv6_ready` | BOOLEAN | 最近一次探测是否成功 |
| `public_ipv4` / `public_ipv6` | INET | 探测得到的公网地址 |
| `network_status_reason` | JSONB | 两种协议的失败原因 |
| `network_capabilities_updated_at` | TIMESTAMPTZ | 最近一次能力心跳时间 |

启动时执行的 `source/database/init.sql` 会为已有数据库补列。已有纯 IPv6 任务会根据
`task_target` 回填为 `ipv6`，其余旧任务保留为 `ipv4`。

## 创建任务

请求格式保持不变：

```json
{
  "ip": "2001:db8:100::10/128,2001:db8:100::20/128",
  "port": "22,80,443",
  "level": 1,
  "remark": "IPv6 check",
  "dispatch_mode": "automatic",
  "scanner_ids": []
}
```

规则：

- 所有目标都是 IPv4 时写入 `address_family=ipv4`。
- 所有目标都是 IPv6 时写入 `address_family=ipv6`。
- 混合目标返回 400，调用方应拆成两个任务。
- `selected` 模式下任一指定扫描器不兼容时返回 400。
- `all` 模式仅为当前兼容的扫描器创建执行实例；没有兼容扫描器时返回 409。
- `automatic` 模式允许任务先进入等待队列，之后由兼容扫描器领取。

任务领取响应增加：

```json
{
  "task_id": "019c0000-0000-7000-8000-000000000002",
  "task_target": ["2001:db8:100::10/128"],
  "task_port": "22,80,443",
  "address_family": "ipv6"
}
```

扫描器在执行前仍会检查本地最新能力。如果领取后协议状态发生变化，它会先刷新心跳，
再将任务作为可重试失败上报，避免继续执行不兼容任务。

## 调度条件

| 任务地址族 | 必须满足的扫描器字段 |
|---|---|
| IPv4 | `supports_ipv4 AND ipv4_ready` |
| IPv6 | `supports_ipv6 AND ipv6_ready` |

自动目标生成还要求扫描器：

- `is_enable=true`；
- 未软删除；
- 最近 90 秒收到过心跳。

## 自动目标配置

```toml
[automatic_target]
# IPv4 开关，为兼容旧配置继续使用 enabled
enabled = true
strategy = "sequential_subnet"
interval_seconds = 30
pending_low_watermark = 2
pending_high_watermark = 5
priority = 0
authorized_cidrs = ["10.20.0.0/16"]
ipv4_task_prefix = 24

# IPv6 独立开关、授权范围和队列水位
ipv6_enabled = false
ipv6_authorized_cidrs = ["2001:db8:100::/64"]
ipv6_task_prefix = 120
ipv6_pending_low_watermark = 1
ipv6_pending_high_watermark = 2

common_ports = "22,80,443"
repeat_after_seconds = 604800
```

### 生成行为

- 每个地址族的待领取任务低于低水位时，补充到对应高水位。
- IPv4 和 IPv6 使用独立游标，互不占用队列配额。
- 没有对应地址族的在线就绪扫描器时暂停生成，不删除已有等待任务。
- `repeat_after_seconds` 内不会为同一地址族和 CIDR 重复生成任务。
- IPv4 延续原有状态键和 generation key，升级不会主动重置现有 IPv4 游标。
- IPv6 子网数量使用 64 位游标；授权前缀与任务前缀之差不能超过 63。

IPv6 地址空间非常大。默认 `/120` 使单任务最多覆盖 256 个地址；即使配置允许，也不应
直接生成 `/64` 扫描任务。对于稀疏 IPv6 资产，建议把 `ipv6_authorized_cidrs` 配置为已知
活跃的小网段，后续可将生成策略替换为资产清单驱动。

### 状态接口

管理员调用 `GET /api/automatic-target/status`，响应按地址族返回：

- 是否启用；
- 授权 CIDR 和任务前缀；
- 低/高水位；
- pending/running 数量；
- 当前就绪扫描器数量；
- 游标位置、总子网数；
- 最近生成时间和错误。

## 扫描器查询接口

`GET /api/scanner/list` 和 `GET /api/scanner/{id}` 会返回网络能力字段。公网出口地址属于
部署信息，只有已有扫描器管理权限的用户才能通过这些接口查看，不应写入公开日志或截图。

## 升级与回滚注意事项

1. 先升级服务端，使数据库字段和兼容逻辑生效。
2. 再逐台升级扫描器。未升级设备在过渡期间继续承担 IPv4 任务。
3. 确认扫描器详情页出现能力检测时间和公网地址。
4. 最后按需配置并启用 IPv6 自动目标。

旧版服务端无法识别新版心跳中的额外字段时通常会由 Serde 忽略，但不具备地址族调度；
因此不建议先大规模升级扫描端并创建 IPv6 任务后再回滚服务端。

## 故障排查

### IPv6 始终不可用

1. 查看扫描器详情中的 `network_status_reason.ipv6`。
2. 在扫描器主机上确认 DNS 能解析 IPv6 探测域名。
3. 确认主机存在 IPv6 地址、默认路由并允许 HTTPS 出站。
4. 如果禁止访问第三方 API，将扫描器配置改成自建 IP 回显接口。
5. 等待下一次探测周期，或重启扫描器触发启动探测。

### IPv6 任务一直 pending

检查是否至少有一台启用、最近 90 秒在线且 `supports_ipv6=true`、`ipv6_ready=true` 的扫描器。
任务不会回退到 IPv4 扫描器。

### 自动目标没有生成

检查对应地址族开关、授权 CIDR、队列水位、在线扫描器数量和
`GET /api/automatic-target/status` 中的 `last_error`。配置校验失败会阻止服务端启动，
而没有就绪扫描器只会暂停该地址族生成。
