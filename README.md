![OxiDNS Banner](.github/img/logo-banner.png)

[![oxidns downloads](https://img.shields.io/github/downloads/SvenShi/oxidns/total)](https://github.com/SvenShi/oxidns/releases)
[![Rust CI](https://github.com/svenshi/oxidns/actions/workflows/rust-ci.yml/badge.svg?branch=main)](https://github.com/svenshi/oxidns/actions/workflows/rust-ci.yml)
[![WebUI CI](https://github.com/svenshi/oxidns/actions/workflows/webui-ci.yml/badge.svg)](https://github.com/svenshi/oxidns/actions/workflows/webui-ci.yml)

[中文](README.md) | [English](README_EN.md) · [文档](https://forgedns.cn/) · [快速开始](https://forgedns.cn/quickstart) · [插件参考](https://forgedns.cn/plugin-reference/overview)

# OxiDNS

**面向复杂网络的高性能 DNS 策略编排引擎。**

OxiDNS 是一个使用 Rust 构建的现代 DNS 引擎，受 [mosdns](https://github.com/IrineSistiana/mosdns) 启发，但不止于规则分流。

它关注的是 DNS 查询在真实网络环境中的完整生命周期：接入、匹配、缓存、转发、回退、改写、本地应答与系统联动，并逐步补齐指标、日志和调试能力。

OxiDNS 的核心不是“提供更多开关”，而是提供一套清晰、可组合、可调试的策略管线，让你能够用声明式配置描述复杂 DNS 行为。

```text
server -> DnsContext -> matcher / executor / provider -> upstream
```

项目仍在持续开发中，适合需要精细化控制 DNS 行为，并愿意理解其策略模型的用户。

---

## 为什么是 OxiDNS

DNS 在复杂网络里往往不只是“查询一个域名”。

你可能需要：

- 根据域名、客户端、查询类型、响应 IP、返回码选择不同上游
- 为不同设备、网段或场景应用不同策略
- 在多个上游之间并发、回退、兜底或按结果决策
- 对响应进行 TTL 调整、ECS 处理、重写或本地应答
- 将 DNS 结果同步到 `ipset`、`nftset` 或 MikroTik RouterOS
- 记录查询过程，并通过日志、查询记录和基础指标理解系统状态
- 在不中断服务的情况下热更新配置、规则和 Provider

OxiDNS 为这些场景提供的是一套统一的编排模型，而不是分散的功能补丁。

---

## 设计原则

### 可组合

OxiDNS 将 DNS 处理过程拆分为 `matcher`、`executor`、`provider` 和 `sequence`。

每个组件只负责一类明确职责，再通过管线组合成完整策略。

### 可调试

DNS 策略一旦复杂，最重要的问题不是“能不能跑”，而是“为什么这样跑”。

OxiDNS 正在围绕查询记录、实时日志、指标采集和配置校验补齐调试能力。当前重点是让用户能够理解一次查询经过了哪些匹配、执行了哪些动作、选择了哪个上游，以及为什么进入回退路径。

### 可演进

OxiDNS 面向长期运行的自建网络环境设计。

它支持全量热重载、Provider 级热重载、独立构建的 WebUI 托管，并保留面向插件化和运维能力继续演进的空间。

### 可控

OxiDNS 不试图替你隐藏复杂性。

它更适合希望明确掌控 DNS 行为的用户，而不是只想要一个一键安装面板的用户。

---

## 核心能力

| 类别 | 能力 |
| --- | --- |
| 协议 | UDP、TCP、DoT、DoQ、DoH |
| 策略模型 | `sequence`、`matcher`、`executor`、`provider` |
| 执行器 | `forward`、`cache`、`fallback`、`hosts`、`arbitrary`、`redirect`、`ecs_handler`、`ttl`、`download`、`upgrade`、`reload`、`reload_provider`、`script`、`http_request`、`query_summary`、`query_recorder`、`metrics_collector` |
| 匹配器 | `qname`、`question`、`qtype`、`qclass`、`client_ip`、`resp_ip`、`rcode`、`rate_limiter` 等 |
| 数据集 | `domain_set`、`ip_set`、`geoip`、`geosite`、`adguard_rule` |
| 系统联动 | `ipset`、`nftset`、`ros_address_list`、`reverse_lookup` |
| 调试与运维 | 健康检查、配置校验、热重载、查询记录、基础指标、实时日志 |
| 部署能力 | 多平台构建、Debian 包、独立 WebUI 托管、服务化安装 |

---

## 适合的使用场景

OxiDNS 适合部署在需要长期运行、可调试、可扩展的 DNS 环境中。

典型场景包括：

- 家庭网关、旁路由、OpenWrt、NAS、Homelab
- 多上游并发查询、主备回退、协议混合接入
- 基于域名、客户端、响应结果的精细化策略路由
- DNS 结果驱动的 `ipset` / `nftset` / MikroTik 地址列表同步
- 广告过滤、域名分流、本地覆盖、双栈偏好和 ECS 控制
- 自建可控、可调试的 DNS 基础设施
- 需要通过同一管理端口托管独立 WebUI 的轻量部署

---

## 不适合的场景

OxiDNS 不是一个面向所有人的一键 DNS 面板。

如果你主要需要：

- 简单、开箱即用的家庭广告过滤
- 完整的图形化 DNS 管理体验
- 权威 DNS 托管服务
- Kubernetes Service Discovery 插件框架
- 不需要理解配置模型的即装即用工具

那么 AdGuard Home、Pi-hole、Technitium DNS Server 或 CoreDNS 可能更合适。

OxiDNS 更适合希望以配置方式明确描述 DNS 行为，并愿意为控制力承担一定复杂度的用户。

---

## 与其他项目的关系

OxiDNS 受 mosdns 启发，并继承了“DNS 策略编排”这一重要思想。

但 OxiDNS 的目标不是复刻 mosdns，而是用 Rust 重新构建一套更强调性能边界、结构清晰、可组合性和长期可维护性的 DNS 引擎。

它也不试图替代所有 DNS 工具：

| 项目 | 更适合的方向 |
| --- | --- |
| AdGuard Home | 开箱即用的家庭广告过滤和 DNS 管理 |
| Pi-hole | 简单、成熟、社区广泛的家庭 DNS 过滤 |
| CoreDNS | 云原生和服务发现插件框架 |
| Technitium DNS Server | 功能完整的通用 DNS 服务器 |
| mosdns | 灵活的 DNS 分流与策略处理 |
| OxiDNS | 高性能、可调试、可扩展的 DNS 策略编排引擎 |

---

## 下载

如果你准备直接下载 GitHub Releases，可按系统选择：

| 系统 / 环境 | 推荐 release 文件 |
| --- | --- |
| Linux x86_64 | `oxidns-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 | `oxidns-aarch64-unknown-linux-musl.tar.gz` |
| Debian / Ubuntu x86_64 服务安装 | `*_amd64.deb` |
| Debian / Ubuntu ARM64 服务安装 | `*_arm64.deb` |
| Alpine Linux x86_64 | `oxidns-x86_64-unknown-linux-musl.tar.gz` |
| Alpine Linux ARM64 | `oxidns-aarch64-unknown-linux-musl.tar.gz` |
| 32 位 ARM Linux，如部分树莓派 | `oxidns-arm-unknown-linux-musleabihf.tar.gz` |
| macOS Intel | `oxidns-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `oxidns-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `oxidns-x86_64-pc-windows-msvc.zip` |
| Windows ARM64 | `oxidns-aarch64-pc-windows-msvc.zip` |
| FreeBSD x86_64 | `oxidns-x86_64-unknown-freebsd.tar.gz` |

Linux 下如果不确定兼容性，建议优先选择 `musl` 构建。

不确定当前系统和架构时，可执行：

```bash
uname -s && uname -m
```

Windows 可在 PowerShell 中执行：

```powershell
[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
```

完整安装流程请参考 [快速开始](https://forgedns.cn/quickstart)。

---

## 文档

- [配置总览](https://forgedns.cn/configuration)
- [快速开始](https://forgedns.cn/quickstart)
- [插件总览](https://forgedns.cn/plugin-reference/overview)
- [管理 API](https://forgedns.cn/api)
- [MikroTik 策略路由](https://forgedns.cn/mikrotik-policy-routing)
- [常见场景](https://forgedns.cn/scenarios)
- [架构与设计](https://forgedns.cn/architecture-and-design)
- [性能与基准](https://forgedns.cn/benchmarks)

---

## 状态

OxiDNS 仍处于持续开发阶段。

当前版本适合高级用户、测试环境和自建网络场景试用。对于生产环境，请在充分理解配置、日志和回退策略后再部署。

可观测性仍在持续完善中。当前版本侧重基础日志、查询记录、健康检查和运维接口，后续会继续强化策略链路追踪、指标面板和故障定位能力。

欢迎提交 Issue、反馈真实场景、改进文档或贡献插件。

---

## 许可证

本项目基于 [GNU General Public License v3.0 or later](LICENSE) 开源。