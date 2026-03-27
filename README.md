# ForgeDNS

[中文](README.md) | [English](README_EN.md)

文档地址：[https://forgedns.gitbook.io/docs](https://forgedns.gitbook.io/docs)

**⚡ 一个面向现代网络的高性能、可编排 DNS 服务器。**

ForgeDNS 使用 Rust 编写，围绕 `server -> DnsContext -> matcher / executor / provider -> upstream` 这条主路径构建。它的目标不是堆功能，而是在缓存、过滤、回退、重写、本地应答和系统联动这些真实需求下，依然保持清晰结构和稳定性能。

项目仍在持续开发中。

## 一眼看懂

- ⚡ 面向性能边界设计，关注热路径、连接复用、TTL 感知缓存和副作用隔离
- 🧩 用统一的 `matcher / executor / provider / sequence` 管线编排策略
- 🔐 同时支持 UDP、TCP、DoT、DoQ、DoH 的服务端与上游
- 🛟 内置缓存、回退、本地应答、查询/响应重写、ECS、双栈偏好等常见能力
- 🛰️ 支持 `ipset`、`nftset`、MikroTik 路由同步等系统联动
- 📈 提供健康检查、热重载、配置校验和 Prometheus 指标

## 核心能力

| 类别 | 能力 |
| --- | --- |
| 协议 | UDP、TCP、DoT、DoQ、DoH |
| 策略 | `sequence`、`matcher`、`executor`、`provider` |
| 执行器 | `forward`、`cache`、`fallback`、`hosts`、`arbitrary`、`redirect`、`ecs_handler`、`ttl` |
| 匹配器 | `qname`、`qtype`、`qclass`、`client_ip`、`resp_ip`、`rcode`、`rate_limiter` 等 |
| 数据集 | `domain_set`、`ip_set` |
| 系统联动 | `ipset`、`nftset`、`mikrotik`、`reverse_lookup` |

## 快速开始

```bash
cargo build --release
cargo run -- -c config.yaml
cargo run -- -c config.yaml -l debug
cargo test
```

示例配置见 [`config.yaml`](/Users/sven/Codes/Rust/forgedns/config.yaml)。

## 文档导航

- 配置总览：[`docs/01-configuration.md`](/Users/sven/Codes/Rust/forgedns/docs/01-configuration.md)
- 插件手册：[`docs/02-plugin-reference/README.md`](/Users/sven/Codes/Rust/forgedns/docs/02-plugin-reference/README.md)
- 管理 API：[`docs/03-api.md`](/Users/sven/Codes/Rust/forgedns/docs/03-api.md)
- 常见场景：[`docs/05-scenarios.md`](/Users/sven/Codes/Rust/forgedns/docs/05-scenarios.md)
- 架构与设计：[`docs/06-architecture-and-design.md`](/Users/sven/Codes/Rust/forgedns/docs/06-architecture-and-design.md)
- 性能与基准：[`docs/07-benchmarks.md`](/Users/sven/Codes/Rust/forgedns/docs/07-benchmarks.md)

## 适合什么场景

- 家庭网络、网关、旁路由
- 多上游并发、主备回退、协议混合接入
- 基于域名和响应结果的策略路由与过滤
- 需要长期演进、自建可控 DNS 基础设施的场景

## 许可证

[MIT](LICENSE)
