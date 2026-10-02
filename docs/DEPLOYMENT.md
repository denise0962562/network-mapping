# 服务端部署指南

[返回项目首页](../README.md) · [文档索引](README.md)

本指南说明服务端启动配置、前端托管和可选 IP 情报。首次部署请先准备 PostgreSQL、Elasticsearch 9.5.3、TLS 证书以及前端构建产物；ES 配置与历史数据迁移见[扫描结果存储](ELASTICSEARCH.md)。

[启动配置与日志](#启动配置与日志) · [前端页面托管](#前端页面托管) · [MaxMind IP 情报](#maxmind-ip-情报)

## 启动配置与日志

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

服务端还提供创建用户、修改密码、清除 2FA、登录限制、IP/CIDR 白名单、会话和登录记录
查询等本地管理命令，详见[用户管理 CLI](USER_MANAGEMENT_CLI.md)。

JSON 请求体使用 `[server]` 下的 `max_body_size`，单位为字节，省略时默认为
`67108864`（64 MiB），用于容纳扫描结果批量上传。诊断实时事件接口单独使用 8 MiB
上限，日志分块上传按每块最多 4 MiB 流式校验；具体限制和错误码见
[扫描器诊断与日志采集](SCANNER_DIAGNOSTICS.md#固定目录与文件语义)。

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
目录，服务端会在扫描结果入库时保存 ASN、AS 组织、国家、地区和城市信息：

```toml
[maxmind]
directory = "source/maxmind"
```

相对路径以配置文件所在目录为基准。数据库文件缺失时服务仍会启动，相关字段保持为空。
更新 MMDB 文件后需要重启服务；仅在 PG → ES 迁移前补充旧记录情报时执行：

```sh
cargo run -- --refresh-ip-intel --migrate-scan-data-to-elasticsearch
```

刷新和迁移期间持续输出进度。该选项不再支持单独刷新 PG 结果；已经迁入 ES 的历史情报不会由此重写。
