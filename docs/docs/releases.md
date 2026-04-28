---
title: 版本更新
sidebar_position: 4
---

import ReleaseCard from '@site/src/components/ReleaseCard';

# 版本更新

## 2026-04

<div className="release-stack">

  <ReleaseCard version="v0.5.1" badge="Patch Release" date="2026-04-28" defaultOpen>
      **Fixes**

      - 修复 `any_match` 在依赖分析阶段会丢失 quick setup 表达式的问题。现在 `qname $provider`、`qtype 1` 等 quick setup matcher 会按原表达式解析并展开依赖，避免启动和 quick setup 分析时遗漏 provider 或内联 matcher 依赖。
      - 修复 `query_recorder` 的保留期清理与分页游标边界：清理截止时间改为基于真实时间戳计算，分页列表会多取一条记录判断是否还有下一页，避免最后一页继续返回无效 `next_cursor`。
      - 调整 `query_recorder` 记录时间字段的存取类型，避免时间戳在写入、读取和清理路径中发生不必要的无符号转换。
      - 同步修正 `upgrade` CLI 默认缓存和备份目录为 `./upgrade-cache` 与 `./upgrade-backups`，并修复对应默认值测试。

      **Upgrade Notes**

      - 本次发布不引入新的配置字段，`v0.5.0` 配置可直接升级。
      - 如果已经启用 `query_recorder` 或在 `any_match` 中使用 quick setup 表达式，建议升级到 `v0.5.1`。
      - `query_recorder` 仍处于 **Experimental** 阶段，其 API 与配置字段后续仍可能调整。
  </ReleaseCard>

  <ReleaseCard version="v0.5.0" badge="Minor Release" date="2026-04-27">
      **Highlights**

      - 新增 `query_recorder` executor：支持将查询记录落盘、按保留策略清理，并通过插件 API 查询统计、分页读取和单条记录详情，方便审计与排障。
      - `query_recorder` 当前为**试验性（Experimental）**能力，后续小版本中其 API 与配置字段可能发生调整，请避免在强依赖稳定性的生产流程中直接绑定其细节。
      - 新增 `any_match` matcher：支持在一个 matcher 中聚合多条 matcher 表达式，只要任意一条命中即返回 true，并支持 `!$tag` 形式的否定表达式。
      - HTTP server 在启用 HTTP/3 时，会在 HTTP/2 响应中自动宣告 `Alt-Svc: h3=":<listen-port>"; ma=86400`，帮助客户端平滑发现并升级到 H3。

      **Fixes And Runtime**

      - 修复 `sequence` 中否定 matcher（如 `!$has_resp`）未正确纳入依赖跟踪的问题，避免 quick setup / 依赖分析阶段出现遗漏（Closed #75）。
      - 时间相关逻辑统一到 `jiff + AppClock`，使 cron 触发、日志时间和系统时间获取路径更一致，降低跨时区和时钟边界下的行为偏差。

      **Upgrade Notes**

      - 本次发布不引入必须变更的全局配置字段，现有 `v0.4.x` 配置可直接升级。
      - 如需启用查询审计，可在 `sequence` 中按需插入 `query_recorder`，并结合 retention 参数控制磁盘占用。
      - 如需让 DoH 客户端自动发现 HTTP/3，请确认 HTTP server 已启用 `enable_http3: true` 且证书配置完整。
  </ReleaseCard>

  <ReleaseCard version="v0.4.2" badge="Patch Release" date="2026-04-24">
      **Highlights**

      - 修复在配置多个并发 upstream、启用 fallback 等存在上游竞争的场景下，部分连接未被正确释放的问题。
      - 新增 `upgrade` CLI 工具及插件，支持自动更新并替换二进制文件；当应用以 Linux Service 方式运行时，还支持更新后自动重启应用。

  </ReleaseCard>

  <ReleaseCard version="v0.4.1" badge="Patch Release" date="2026-04-23">
      **Fixes**

      - 修复 upstream `request_map` 在连接关闭、请求超时和异常回收场景下的内存泄漏问题，避免 pending query waiter 与 sender 残留，减少长连接运行时的隐性内存增长。
      - 重写 `request_map` 为固定容量的稀疏表实现，不再为每条连接预留完整 `u16` DNS ID 空间，进一步降低 TCP/DoT/DoQ/DoH 上游连接的常驻内存占用。
      - 修复 DoH 响应头生成逻辑：现在会为 `application/dns-message` 响应写入正确的 `Content-Length`，并按实际 DNS TTL 生成 `Cache-Control: max-age=...`，提升 `dig`、浏览器和代理链路下的兼容性。

      **Behavior Notes**

      - `NoError`、`NXDOMAIN`、`NODATA` 等常见 DoH 响应现在会分别从 answer TTL 或 SOA negative TTL 推导 HTTP 缓存时间。
      - 对没有安全 TTL 可用的拒绝类响应，不再强行附带缓存头，避免客户端拿到误导性的 HTTP 缓存指令。
      - `request_map` 在空表时会主动清理 tombstone，ID 回绕和高频复用场景下的探测链长度更稳定。

      **Upgrade Notes**

      - 这次发布不引入新的配置字段，`v0.4.0` 配置可直接升级到 `v0.4.1`。
      - 由于修复的是 upstream `request_map` 的内存泄漏问题，建议所有用户升级到 `v0.4.1`，尤其是长期运行、长连接较多或上游并发较高的部署。
      - 如果你通过 `dig +https://...`、浏览器、反向代理或网关缓存访问 DoH，升级后也会获得更稳定的 HTTP 响应兼容性。
  </ReleaseCard>

  <ReleaseCard version="v0.4.0" badge="Minor Release" date="2026-04-19">
      **Highlights**

      - 新增 `reload_provider` executor，以及 provider 级管理接口 `POST /plugins/<provider_tag>/reload`。现在下载或覆盖规则文件后，可以只刷新受影响的 provider，而不必触发应用级全量 `reload`。
      - 重构 provider 组合模型：`domain_set` / `ip_set` 只编译自身本地规则，运行时继续查询 `sets` 中引用的 provider。下游 provider 单独 reload 后，上层聚合 provider 无需 reload 即可看到新结果，同时减少规则副本和内存占用。
      - runtime 初始化现在会跳过没有 live dependents 的 provider，避免未被消费的规则集在启动阶段做无意义的文件读取、dat 解析和内存占用。

      **Core And Runtime**

      - quick setup 依赖分析扩展到了 `sequence` / `cron` 等运行时引用场景，插件依赖图与初始化顺序对 quick setup 表达式更准确，减少隐藏依赖导致的启动阶段歧义。
      - provider 创建阶段现在可拿到 live dependents 上下文，为按需初始化与后续扩展更细粒度的 runtime 行为打下基础。
      - 移除 `hickory-proto` 兼容性测试及相关 dev 依赖，并同步一轮依赖升级，缩小测试依赖面。

      **Docs**

      - docs 新增 targeted provider reload 的 API 与 `reload_provider` executor 说明，并补充下载后刷新 provider 的串联示例。
      - `provider` 参考文档现在更明确地区分“本地规则编译”和“运行时 provider 组合”语义，也说明了 reload 边界和未被使用 provider 的初始化行为。
      - plugin reference 文档顺序调整为更贴近请求路径，便于按 `server -> executor -> matcher -> provider` 理解配置。

      **Upgrade Notes**

      - 如果你已有“`download` 覆盖文件后再全量 `reload`”的流程，现在通常可以改为“`download -> reload_provider`”，降低对其它插件的重建影响。
      - `reload_provider` 只适用于刷新 provider 的既有配置和外部数据文件；如果变更涉及 `config.yaml`、provider tag、`sets` 拓扑或插件列表，仍需要使用全量 `reload`。
      - 未被任何 live 路径引用的 provider 将不会进入 runtime registry；如果你依赖其运行时 API 或行为，请确保它被 `server`、`executor`、`matcher` 直接或间接引用。
  </ReleaseCard>

  <ReleaseCard version="v0.3.2" badge="Patch Release" date="2026-04-16">
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
