---
title: 版本更新
sidebar_position: 4
---

import ReleaseCard from '@site/src/components/ReleaseCard';

# 版本更新

## 2026-04

<div className="release-stack">
  <ReleaseCard version="v0.2.0" badge="Feature Release" date="2026-04-02" defaultOpen>
      **Highlights**

      - 新增 `download` executor，支持将远程 `http/https` 文件下载到本地目录。
      - `download` 支持 `SOCKS5` 代理、HTTP 重定向跟随、启动时自动补齐缺失文件。
      - `startup_if_missing` 默认启用，更适合首次部署和规则文件自举场景。
      - 新增 `cron` executor，可按固定间隔或标准 5 字段 cron 表达式执行后台任务。
      - 新增 `reload` executor，可触发一次完整的应用级 reload。
      - 新增 `script` executor，可执行外部命令并注入稳定上下文字段。
      - 新增 `geoip`、`geosite`、`adguard_rule` provider。
      - 新增 `question` matcher。
      - `qname` 域名匹配新增对 `adguard_rule` 规则集的支持。

      **Core Changes**

      - cache 新增 `stale lazy refresh` 行为，提升热点缓存过期后的可用性。
      - rule matcher 完成结构拆分与热路径优化，并补充 domain / ip benchmark。
      - 新增可配置日志文件轮转能力，方便长期运行部署。
      - 移除 `app_clock` 的后台任务依赖，简化运行时钟模型。
      - `ros_address_list` 支持 `fixed_ttl=0`，表示无超时。
      - `hosts`、`black_hole`、`cache` 的 quick setup 新增 `short_circuit` 支持。

      **Fixes And Compatibility**

      - 修复 IP matcher 规则在 finalize 和增量更新后丢失的问题。
      - 修复 Windows 下集成测试和规则文件路径相关问题。
      - 从 `serde_yml` 迁移到 `serde_yaml_ng`。
      - 同步更新部分依赖和 CI 工具链。
      - 移除 `hosts` quick setup，收敛早期不够稳定的快速配置入口。

      **Docs And Tooling**

      - 新增 docs-site CI。
      - 系统更新 `executor`、`matcher`、`provider`、`server`、`quickstart`、`scenarios` 等文档。
      - 补充订阅更新示例、sequence quick setup、默认配置说明和版本更新页。
  </ReleaseCard>
</div>

## 2026-03

<div className="release-stack">
  <ReleaseCard version="v0.1.1" badge="Compatibility Update" date="2026-03-29">
      **Highlights**

      - 将 MikroTik 相关 executor 正式重命名为 `ros_address_list`，统一命名风格并贴近实际行为。

      **Fixes**

      - 修正文档中的功能描述和示例错误。
      - 补充格式化修正，保持代码与文档的一致性。

      **Upgrade Note**

      - 如果你在 `v0.1.0` 中使用了旧的 MikroTik executor 名称，升级到 `v0.1.1` 时需要同步调整配置中的插件类型名。
  </ReleaseCard>

  <ReleaseCard version="v0.1.0" badge="First Public Release" date="2026-03-28">
      **Highlights**

      - 建立了 ForgeDNS 的插件化主架构：`server -> DnsContext -> matcher / executor / provider -> upstream or side effects`。
      - 完成 UDP、TCP、DoT、DoQ、DoH 的 server 与 upstream 支持。
      - 提供与 MosDNS 风格接近的 `sequence` 编排、`jump/goto/return` 控制流和 `$tag` 引用方式。
      - 提供 `cache`、`forward`、`fallback`、`hosts`、`redirect`、`ecs_handler`、`dual_selector` 等核心 executor。
      - 提供 `domain_set`、`ip_set`、查询/响应条件、客户端 IP、响应 IP、CNAME 等 matcher / provider 能力。

      **Platform And Runtime**

      - 管理 API、健康检查、控制接口与插件相关 API 完成接入。
      - CLI 增加 service-manager 集成，支持服务化部署。
      - 新增 Debian 打包、Docker 工作流和多平台 release 基础设施。
      - Tokio worker 线程数可从配置调整，增强部署期可控性。

      **Performance**

      - 为 UDP/TCP/DoT/DoH/DoQ upstream 建立复用连接池和复用连接获取器。
      - 优化 matcher、缓存、连接池、请求映射与时钟更新等热路径。
      - 引入高性能 `domain_set` / `ip_set` 实现，并持续减少非服务器热路径上的阻塞 I/O。

      **Ecosystem**

      - 提供 MikroTik RouterOS 动态路由与地址列表同步能力。
      - 支持 Linux 下 `ipset` / `nftset` 系统命令集成与测试覆盖。
      - 完成中英文 README、Quick Start、配置和模块文档的首轮建设。
  </ReleaseCard>
</div>
