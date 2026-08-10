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

## 扫描器调度

创建任务接口 `POST /api/task/create` 支持 `dispatch_mode`：`automatic` 由下一台可用扫描器领取一次，`selected` 配合 `scanner_ids` 指定一台或多台扫描器，`all` 会为创建时所有已启用扫描器分别创建执行实例。离线的指定扫描器会在重新上线后领取任务。

任务详情接口 `GET /api/task/{task_id}` 返回 `executions`，并可通过 `execution_id` 查询参数选择某个执行实例的分页结果。同一个逻辑任务下，各扫描器的状态、失败原因和扫描结果相互独立；导出的 CSV/JSON 也包含执行实例和扫描器标识。

## 开源项目清单

`GET /api/open-source/projects` 返回编译进服务端的主要直接依赖清单。升级 `Cargo.toml`、扫描器依赖或前端 `package.json` 后，应同步复核 `source/open_source_projects.json` 中的版本、许可证和上游链接。

清理缓存（可选项）

```
cargo clean
```
