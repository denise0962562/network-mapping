# Network-Mapping

这是一个开源的网络测绘系统，使用 Rust 开发，采用 MIT 协议分发。

## 使用方法
首先打开设备终端，然后输入下面的指令以克隆项目
```
git clone https://github.com/wshijiang/network-mapping.git
```

然后切换至项目目录
```
cd network-mapping
```

编译项目
```
cargo build --release
```

启动前需要在 `config.toml` 中配置 TLS 证书链和私钥。相对路径以配置文件所在目录为基准：

```toml
[tls]
certificate_chain_file = "ssl/cert.pem"
private_key_file = "ssl/key.pem"
```

扫描器令牌还需要一个长期固定的 HMAC Pepper。使用以下命令生成：

```sh
openssl rand -hex 32
```

将输出写入配置文件；修改该值会使已有扫描器令牌失效：

```toml
[security]
scanner_token_pepper = "生成的随机值"
```

可以通过 `--config` 指定其他配置文件：

```sh
cargo run -- --config /etc/network-mapping/config.toml
```

终端日志默认使用精简模式，只显示启动摘要、警告和错误。需要查看完整终端日志时使用：

```sh
cargo run -- --verbose
```

`--verbose` 只影响终端输出，不会改变滚动 JSON 日志文件的内容或级别。需要同时查看
DEBUG 级别日志时，可组合使用 `--verbose --debug-model`，也可以通过 `RUST_LOG` 指定
过滤规则。

## 前端页面托管

服务端直接托管 Vue/Vite 的生产构建产物。先在 `network-mapping-vue/` 中执行
`pnpm build`，再通过配置指定构建目录；相对路径以服务端配置文件所在目录为基准：

```toml
[frontend]
directory = "../network-mapping-vue/dist"
```

服务端只为已声明的 Vue Router 页面路径返回 `index.html`，包括 `/task/{uuid-v7}` 和
`/scanner/{uuid}` 等动态详情路径。`/login`、`/search.html` 使用各自的独立入口，
`/assets/*` 只提供实际存在的构建资源。未知路径、错误格式的详情路径、未匹配 API
和缺失资源均返回真实的 HTTP 404，不会回退到 SPA 页面。未登录访问受保护页面时会
重定向至 `/login`，API 的未认证响应仍为 401。前端入口文件或资源目录缺失时，服务端
启动阶段只输出 warn 警告并继续运行，访问对应页面或资源时返回 404。

## MaxMind IP 情报

将 `GeoLite2-City.mmdb`、`GeoLite2-Country.mmdb` 和 `GeoLite2-ASN.mmdb` 放入配置的
目录，服务端会在扫描结果入库时保存 ASN、AS 组织、国家和城市信息：

```toml
[maxmind]
directory = "source/maxmind"
```

相对路径以配置文件所在目录为基准。数据库文件缺失时服务仍会启动，相关字段保持为空。
更新 MMDB 文件后需要重启服务；刷新历史记录可执行：

```sh
cargo run -- --refresh-ip-intel
```

## 扫描器调度

创建任务接口 `POST /api/task/create` 支持 `dispatch_mode`：`automatic` 由下一台可用扫描器领取一次，`selected` 配合 `scanner_ids` 指定一台或多台扫描器，`all` 会为创建时所有已启用扫描器分别创建执行实例。离线的指定扫描器会在重新上线后领取任务。

任务详情接口 `GET /api/task/{task_id}` 返回 `executions`，并可通过 `execution_id` 查询参数选择某个执行实例的分页结果。同一个逻辑任务下，各扫描器的状态、失败原因和扫描结果相互独立；导出的 CSV/JSON 也包含执行实例和扫描器标识。

## 自动目标生成

服务端可以从明确授权的 IPv4 CIDR 中顺序生成扫描任务，并使用现有任务队列自动分配给
任意已启用扫描器。默认关闭；启用前必须配置授权范围：

```toml
[automatic_target]
enabled = true
strategy = "sequential_subnet"
interval_seconds = 30
pending_low_watermark = 2
pending_high_watermark = 5
priority = 0
authorized_cidrs = ["10.20.0.0/16"]
ipv4_task_prefix = 24
common_ports = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017"
repeat_after_seconds = 604800
```

待领取的自动任务低于低水位时，服务端补充至高水位。生成游标存储在数据库中，服务重启
后继续；同一目标在冷却期内不会重复生成。管理员可通过
`GET /api/automatic-target/status` 查看当前策略、队列水位和生成状态。第一版仅支持 IPv4，
不会随机生成或扫描配置范围之外的公网目标。

## 开源项目清单

`GET /api/open-source/projects` 返回编译进服务端的主要直接依赖清单。升级 `Cargo.toml`、扫描器依赖或前端 `package.json` 后，应同步复核 `source/open_source_projects.json` 中的版本、许可证和上游链接。

清理缓存（可选项）

```
cargo clean
```
