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

## 开源项目清单

`GET /api/open-source/projects` 返回编译进服务端的主要直接依赖清单。升级 `Cargo.toml`、扫描器依赖或前端 `package.json` 后，应同步复核 `source/open_source_projects.json` 中的版本、许可证和上游链接。

清理缓存（可选项）

```
cargo clean
```
