---
title: 版本更新
sidebar_position: 4
---

import ReleaseCard from '@site/src/components/ReleaseCard';

# 版本更新

## 2026-04

<div className="release-stack">
  <ReleaseCard version="v0.3.2" badge="Patch Release" date="2026-04-16" defaultOpen>
      **Fixes**

      - 调整 UDP、TCP、DoT、DoQ 上游连接池的初始化策略，不再在启动时预创建空闲连接，减少部分上游主动关闭空闲连接时产生的误报 EOF / reset 日志。
      - TCP 上游连接复用流程现在把预期内的 EOF、连接回收和失效连接淘汰视为 `debug` 级事件，避免正常连接生命周期被误记为告警。
      - DoH 服务端将浏览器或代理主动中断引发的 TLS、HTTP/2、HTTP/3 握手失败，以及客户端提前关闭响应流导致的发送失败，下调为 `debug` 日志，显著降低无效噪音。

      **Observability**

      - Debug 日志中的 DNS 请求与响应信息现在直接输出 `questions`、消息 ID、EDNS 和 answers 内容，排障时不再只有计数值。
      - `Record` 新增更易读的 `Debug` / `Display` 输出格式，便于跟踪响应记录内容。

      **Upgrade Notes**

      - 这次发布不引入新的配置字段，现有 `0.3.x` 配置可直接升级。
      - 如果你的监控依赖 warning 日志计数，升级到 `v0.3.2` 后，正常的上游断连和 DoH 客户端中断将不再放大告警噪音。
  </ReleaseCard>

  <ReleaseCard version="v0.3.1" badge="Patch Release" date="2026-04-14">
      **Highlights**

      - 修正 `sequence` 的内建控制流语义：`accept` / `reject` 现在会稳定终止当前链路，`return` 会显式返回调用方，`jump` 与 `goto` 在嵌套 `sequence` 中的恢复行为也更一致。
      - 移除依赖内部 flow state 的控制方式，改为由 `ExecStep` 显式传播控制流结果，减少 `sequence`、`with_next` executor 和嵌套调用混用时的语义歧义。
      - 补强 `sequence` 的单元测试与集成测试，覆盖 `accept`、`return`、`reject`、`jump`、`goto` 以及 `adguard_rule` / `question` 组合分支，降低后续回归风险。

      **Packaging And Ecosystem**

      - 为 `forgedns-proto`、`forgedns-zoneparser`、`forgedns-ripset` 补齐 crates.io 发布所需的包元数据、README、仓库信息和依赖版本声明，方便 workspace 内部 crate 独立发布与复用。
      - 主包依赖声明同步改为显式引用这些内部 crate 的版本，便于 release、打包和后续生态集成保持一致。

      **Docs**

      - 更新 `configuration`、`executor`、`matcher` 文档，对 `sequence` 内建控制流、`mark` 语法，以及 `qtype` / `qclass` 数值写法给出更明确说明。
      - 补充 `jump` / `goto` 的示例和行为边界，降低升级到 `v0.3.1` 时对控制流语义的理解成本。

      **Upgrade Notes**

      - 如果你的配置依赖嵌套 `sequence`、`jump` / `goto` / `return` 组合，建议升级到 `v0.3.1` 以获得更稳定且可预测的控制流行为。
      - 这次发布不引入新的配置字段，主要是控制流修正、测试补强和发布元数据整理。
  </ReleaseCard>

  <ReleaseCard version="v0.3.0" badge="Minor Release" date="2026-04-14">
      **Highlights**

      - 新增 `http_request` executor，支持在 `before/after` 两个阶段向外部 `http/https` 服务发起同步或异步回调，并支持模板变量、`json/form/body`、SOCKS5、重定向和错误策略。
      - CLI 新增 `check` 与 `export-dat` 命令；`check --graph` 可静态校验配置并输出插件依赖图，`export-dat` 可把 `geosite.dat` / `geoip.dat` 按 selector 导出为 ForgeDNS 或原始文本规则。
      - `hosts` 语义向 mosdns 对齐；`arbitrary` 引入更完整的 zone parser，支持 `$ORIGIN`、`$TTL`、`$INCLUDE`、`$GENERATE`、RFC3597 等更丰富记录语法。
      - 继续补充和统一多个 executor 的 `short_circuit` 说明与行为边界，便于在命中本地响应、缓存或分支胜出后显式停止后续 executor 链；`hosts` 在空本地答复场景下的短路语义也更明确。
      - Linux `ipset` / `nftset` executor 改为内置 Rust netlink 后端，不再依赖运行时 `ipset` / `nft` 命令。

      **Core And Performance**

      - workspace 新增 `forgedns-proto`、`zoneparser`、`ripset` 三个内部 crate，明确协议编解码、zone 解析和 Linux 集成边界。
      - 网络热路径引入可复用 wire buffer 池，并优化 UDP/TCP/上游 socket 参数，减少短生命周期分配与连接侧开销。
      - 新增低并发延迟基准脚本，补充 `v0.3.0` 公布基准快照，并系统整理 benchmark 文档。
      - 修复 Windows 构建兼容性以及若干 benchmark / CI 配置问题。

      **Upgrade Notes**

      - `hosts` 中无前缀规则现在等价于 `full:`；正向本地答案 TTL 固定为 `10`；域名命中但地址家族不匹配时会返回 `NoError + 空 Answer + fake SOA`，默认不再透传后续 executor。
      - `arbitrary` 不再提供旧 quick setup 语法，建议升级时改为显式 `rules` / `files` 配置。

      **Docs And Tooling**

      - docs 新增 CLI 页面，并更新 `executor`、`provider`、`quickstart`、`benchmarks`、`releases` 等章节。
      - quickstart 新增 Docker Compose 示例，补充 Docker 镜像仓库、Windows release 资产与服务部署说明。
  </ReleaseCard>

  <ReleaseCard version="v0.2.1" badge="Patch Release" date="2026-04-03">
      **Fixes**

      - 修复 DoH over HTTP/2 上游 GET 请求未正确结束 stream，导致部分上游在 5 秒后超时的问题。
      - 完善 `Question` 的 `Display` 输出，统一日志和调试信息中的查询展示格式。
      - 放宽 cache TTL 单测中的时间边界假设，避免 CI 在跨秒时出现偶发失败。

      **Docs**

      - quickstart 文档移除 Docker `linux/arm/v7` 支持说明。
      - quickstart 文档新增 `docker compose` 部署示例。
  </ReleaseCard>

  <ReleaseCard version="v0.2.0" badge="Feature Release" date="2026-04-02">
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
