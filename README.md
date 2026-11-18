# Rust Proxy

一个 Rust 可执行文件同时提供本地代理和只读 Web 流量面板。每个请求使用配置文件中的同一个上游。上游断开、认证失败或 TLS 校验失败时，请求失败或隧道关闭。

| 默认地址 | 用途 |
| --- | --- |
| `127.0.0.1:20808` | HTTP/1.1 正向代理、CONNECT 和 SOCKS5 TCP。配置证书后同端口支持 HTTPS 代理入口 |
| `http://127.0.0.1:20809/` | 当前上游、活动流量、请求记录和失败原因 |

## 启动

需要 Rust 1.89 或更新版本。SQLite 和前端页面随程序编译。

```sh
cargo build --release --locked
cp proxy.example.toml proxy.toml
```

在 `proxy.toml` 中把 `upstream` 换成自己的代理地址，然后运行：

```sh
./target/release/rust-proxy --config proxy.toml
```

省略 `--config` 时读取工作目录下的 `proxy.toml`。数据库和证书的相对路径以配置文件所在目录为基准。修改配置后重启程序。

## 配置上游

`upstream` 接受 `socks5://host:port`、`http://host:port` 或 `https://host:port`。HTTP(S) 上游支持 Basic 认证，SOCKS5 上游支持用户名和密码。URL 写法为 `https://user:password@host:port`，凭据中的特殊字符使用百分号编码。Web、请求日志和启动输出中只显示上游协议、主机和端口。

HTTPS 上游验证系统信任链和证书主机名；私有 CA 可以通过 `upstream_ca` 指定。要让客户端通过 TLS **连接本地代理**，在配置中同时设置 PEM 格式的 `inbound_cert` 和 `inbound_key`，让客户端信任该证书。用普通 HTTP 入口访问 HTTPS 网站时无需本地证书。

`connect_timeout_seconds` 控制上游建连与隧道握手期限，默认 10 秒。普通 HTTP 请求从转发开始到收到上游响应头的总期限由 `response_timeout_seconds` 控制，默认 300 秒。已建立的隧道和流式响应可以继续传输。

## 让客户端使用代理

```sh
export http_proxy=http://127.0.0.1:20808
export https_proxy=http://127.0.0.1:20808
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$https_proxy"
curl https://example.com
```

指定 SOCKS5 入口并由上游解析目标域名：

```sh
curl --noproxy '' --proxy socks5h://127.0.0.1:20808 https://example.com
```

程序仅拨号到上游代理，上游地址本身为域名时会在本机解析。目标域名通过代理协议传给上游。此约束覆盖送入本程序的请求。客户端忽略代理变量、预先解析域名或匹配自身的 `NO_PROXY` 规则时，连接行为由客户端决定。限制整个应用的出站权限需要操作系统网络策略。

## 流量记录

页面的「代理出口」显示落地 IPv4 或 IPv6、IP 归属国家或地区、城市、运营商和自治系统号。打开面板时，后端通过已配置的上游访问 ipwho.is，使用查询服务观测到的来源 IP。归属地是 IP 数据库提供的近似位置；使用轮换出口时，以页面显示的检测时间为准。[查询服务文档](https://ipwhois.io/documentation)

成功结果缓存 10 分钟，点击「重新检测」可立即更新。上游不可达、证书错误或查询服务限流时，页面显示检测失败并清空当前出口信息。查询失败不会影响客户端代理流量。

打开 `http://127.0.0.1:20809/` 查看实时记录。页面每秒更新，可筛选活动请求并翻阅历史，每页最多 100 条。两个监听端口默认都只对本机开放，入口和面板均无客户端身份验证。

* 明文 HTTP 逐请求记录方法、目标路径、响应码、耗时和双向正文字节数。
* CONNECT 与 SOCKS5 按 TCP 隧道记录目标地址、时间和双向传输字节。HTTPS 站点的 URL 路径和响应内容处于客户端到站点的加密隧道内。
* 查询串、请求头和正文不会写入日志。记录保存在 `traffic.sqlite3`，持续保留。连接结束时写入最终计数，进程异常退出时仍在进行的记录在下次启动时标记为中断。

## 验证

```sh
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
python3 tests/e2e.py
```

端到端测试需要 Python 3 和 OpenSSL CLI，在临时目录和回环端口上运行。覆盖三种上游、入口 TLS、CONNECT、认证拒绝、错误证书、超时、断连、日志持久化，以及上游不可用时对可直连目标的零连接断言。
