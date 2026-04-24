# ForgeDNS

[中文](README.md) | [English](README_EN.md)

[文档地址](https://forgedns.cn/)

**⚡ 一个面向现代网络的高性能、可编排 DNS 服务器。**

ForgeDNS 使用 Rust 编写，围绕 `server -> DnsContext -> matcher / executor / provider -> upstream` 这条主路径构建。它的目标不是堆功能，而是在缓存、过滤、回退、重写、本地应答和系统联动这些真实需求下，依然保持清晰结构和稳定性能。

项目仍在持续开发中。

## 一眼看懂

- ⚡ 面向性能边界设计，关注热路径、连接复用、TTL 感知缓存和副作用隔离
- 🧩 用统一的 `matcher / executor / provider / sequence` 管线编排策略
- 🔐 同时支持 UDP、TCP、DoT、DoQ、DoH 的服务端与上游
- 🛟 内置缓存、回退、本地应答、查询/响应重写、ECS、双栈偏好等常见能力
- 🛰️ 支持 `ipset`、`nftset`、MikroTik 路由同步等系统联动
- 📈 提供健康检查、全量/Provider 级热重载、配置校验、Prometheus 指标，以及结构化查询记录与实时日志流

## 核心能力

| 类别 | 能力 |
| --- | --- |
| 协议 | UDP、TCP、DoT、DoQ、DoH |
| 策略 | `sequence`、`matcher`、`executor`、`provider` |
| 执行器 | `forward`、`cache`、`fallback`、`hosts`、`arbitrary`、`redirect`、`ecs_handler`、`ttl`、`download`、`upgrade`、`reload`、`reload_provider`、`script`、`http_request`、`query_summary`、`query_recorder`、`metrics_collector` |
| 匹配器 | `qname`、`question`、`qtype`、`qclass`、`client_ip`、`resp_ip`、`rcode`、`rate_limiter` 等 |
| 数据集 | `domain_set`、`ip_set`、`geoip`、`geosite`、`adguard_rule` |
| 系统联动 | `ipset`、`nftset`、`ros_address_list`、`reverse_lookup` |

## 快速开始

```bash
cargo build --release
cargo run -- -c config.yaml
cargo run -- -c config.yaml -l debug
cargo test
```

如果你准备直接下载 GitHub Releases，可按系统选择：

| 系统 / 环境 | 推荐 release 文件 |
| --- | --- |
| Linux x86_64 | `forgedns-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 | `forgedns-aarch64-unknown-linux-musl.tar.gz` |
| Debian / Ubuntu x86_64 服务安装 | `*_amd64.deb` |
| Debian / Ubuntu ARM64 服务安装 | `*_arm64.deb` |
| Alpine Linux x86_64 | `forgedns-x86_64-unknown-linux-musl.tar.gz` |
| Alpine Linux ARM64 | `forgedns-aarch64-unknown-linux-musl.tar.gz` |
| 32 位 ARM Linux（如部分树莓派） | `forgedns-arm-unknown-linux-musleabihf.tar.gz` |
| macOS Intel | `forgedns-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `forgedns-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `forgedns-x86_64-pc-windows-msvc.zip` |
| Windows ARM64 | `forgedns-aarch64-pc-windows-msvc.zip` |
| FreeBSD x86_64 | `forgedns-x86_64-unknown-freebsd.tar.gz` |

Linux 下如果不确定兼容性，尽量优先选 `musl` 版本，不要默认选 `gnu`。

不确定自己机器的系统和架构时，可先执行 `uname -s && uname -m`。

Windows 可在 PowerShell 中执行 `[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture`。

更完整的安装说明见文档中的快速开始页面。

## 文档导航

- [配置总览](https://forgedns.cn/configuration)
- [快速开始](https://forgedns.cn/quickstart)
- [插件总览](https://forgedns.cn/plugin-reference/overview)
- [管理 API](https://forgedns.cn/api)
- [MikroTik 策略路由](https://forgedns.cn/mikrotik-policy-routing)
- [常见场景](https://forgedns.cn/scenarios)
- [架构与设计](https://forgedns.cn/architecture-and-design)
- [性能与基准](https://forgedns.cn/benchmarks)

## 适合什么场景

- 家庭网络、网关、旁路由
- 多上游并发、主备回退、协议混合接入
- 基于域名和响应结果的策略路由与过滤
- 需要长期演进、自建可控 DNS 基础设施的场景

## 许可证

[MIT](LICENSE)
