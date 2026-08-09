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

可以通过 `--config` 指定其他配置文件：

```sh
cargo run -- --config /etc/network-mapping/config.toml
```

清理缓存（可选项）

```
cargo clean
```
