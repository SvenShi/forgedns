# 仓库指南

## 项目定位
- ForgeDNS 是一个用 Rust 编写的高性能、插件驱动型 DNS 服务器。
- 当前 README 描述的项目形态包括：UDP/TCP/DoT/DoQ/DoH 服务端与上游支持、基于 `sequence` 的策略编排、带负缓存的 TTL 感知缓存、主备回退链路、本地与合成应答、查询与响应重写、ECS 处理、双栈偏好控制、基于 provider 的域名/IP 规则集，以及 `ipset`、`nftset`、MikroTik 路由同步等系统联动能力。
- 设计时优先保持核心请求路径清晰稳定：`server -> DnsContext -> matcher/executor/provider pipeline -> upstream or side effects -> response`。

## 项目结构与模块组织
- `src/main.rs` 负责启动 Tokio 运行时、解析 CLI 参数、加载配置、初始化日志、启动插件并处理优雅退出。
- `src/lib.rs` 暴露库接口，供测试和嵌入式使用场景复用。
- `src/core/` 包含运行时选项、日志、错误、`DnsContext`、缓存基础设施和请求处理工具。
- `src/config/` 定义运行时 YAML 配置结构与校验逻辑。
- `src/network/` 包含传输层协议、TLS 配置、上游解析、连接池、bootstrap 逻辑，以及 Linux 平台相关网络辅助模块。
- `src/plugin/` 是主要扩展面，当前拆分为四类插件：
- `src/plugin/server/` 处理入站 DNS 协议，包括 UDP、TCP、QUIC 以及基于 HTTP 的 DNS。
- `src/plugin/executor/` 包含请求处理插件，如 `sequence`、`forward`、`cache`、`fallback`、`hosts`、`arbitrary`、`redirect`、`ecs_handler`、`prefer_ipv4`、`prefer_ipv6`，以及观测类和系统联动类插件。
- `src/plugin/matcher/` 包含规则匹配器，如 qname/qtype/qclass、客户端 IP、响应 IP、mark、env、随机放量、限速等谓词。
- `src/plugin/provider/` 包含可复用的域名/IP 数据集，供 matcher 和 executor 使用。
- `tests/plugin_integration.rs` 覆盖配置解析、插件注册表装配、`sequence` 快速写法以及真实 UDP 服务集成测试。
- `config.yaml` 是当前推荐的、可直接运行的插件装配示例。
- `README.md` 与 `README_EN.md` 描述整体架构和能力边界；行为变化时应保持同步。

## 构建、测试与开发命令
- `cargo check` 是日常迭代时最快的默认检查方式。
- `cargo build --release` 构建用于真实性能验证的优化二进制。
- `cargo run -- -c config.yaml` 使用示例配置运行 ForgeDNS。
- `cargo run --release -- -c config.yaml` 是验证真实运行行为或性能相关改动时更推荐的方式。
- `cargo run -- -c config.yaml -l debug` 在不改配置文件的情况下覆盖日志级别，便于本地调试。
- `cargo test` 运行单元测试和集成测试。
- `cargo test --test plugin_integration` 直接运行端到端的插件与配置集成测试。
- `cargo fmt` 统一代码格式。
- `cargo clippy --all-targets --all-features` 在修改共享基础设施或热路径逻辑时建议运行。

## 编码风格与命名约定
- 使用 Rust 2024 版，并通过 `cargo fmt` 保持格式一致。
- 函数和字段使用 `snake_case`，类型使用 `CamelCase`，常量使用 `SCREAMING_SNAKE_CASE`。
- 保持模块内聚，辅助逻辑尽量与所属功能就近放置。
- 注释使用英文。
- 插件实现应包含足够详细的注释，说明用途、配置形态、依赖关系、生命周期，以及热路径或副作用行为中不够直观的部分。
- 优先复用现有抽象，如 `DnsContext`、`Executor`、`Matcher`、`Provider`、`RequestHandle`、上游连接池和插件注册表，而不是再引入一套并行框架。
- 新插件类型通过 `register_plugin_factory!` 注册，并保持依赖校验逻辑明确可追踪。
- 平台相关集成要有清晰边界，尤其是 Linux 专属的 netlink、`ipset`、`nftset` 行为。

## 性能与架构原则
- 把请求热路径当成一等约束。任何额外分配、克隆、重复解析、锁竞争或阻塞 I/O 都需要充分理由。
- 能在启动期或插件初始化期完成的工作，不要放到每个请求上重复执行。
- 优先复用现有上游连接池和传输状态，不要在快路径里临时建立一次性连接。
- 指标、持久化、反向解析、路由同步等副作用应尽量避开最敏感的响应路径，除非正确性明确要求同步执行。
- 修改缓存、回退、重写或合成响应逻辑时，要严格尊重 DNS 语义，尤其是 TTL 和负缓存行为。
- 保持插件可组合性。新增能力通常应该作为插件或 trait 扩展落地，而不是写成某个 server 的特例分支。
- 任何新增到核心路径中的 `Arc`、`DashMap`、队列或后台任务，都需要明确说明其必要性和成本。

## 测试指南
- 使用 Rust 内置测试框架，并将聚焦明确的单元测试放在逻辑较重的模块附近。
- `tests/plugin_integration.rs` 主要用于覆盖装配层行为，如配置解析、依赖解析、`sequence` 快速写法和服务端集成。
- 涉及 server、upstream、cache 或插件编排的修改，既要覆盖成功路径，也要覆盖失败路径。
- 网络相关测试优先使用临时端口、受控超时和可复现输入。
- 行为变更至少运行 `cargo test`；如果改动涉及插件注册、配置解析、`sequence` 行为或服务启动链路，还应运行 `cargo test --test plugin_integration`。

## 配置与文档
- 保持 `config.yaml` 可运行、可读，并用于展示当前推荐的装配方式，而不是堆满所有可选项。
- 如果改动新增或重命名了插件类型、配置字段、默认行为、支持协议或用户可见能力，必要时应在同一次变更中同步更新 `config.yaml`、`README.md` 和 `README_EN.md`。
- 配置中的插件 tag 应尽量语义明确，例如 `forward_main`、`cache_main`、`udp_server`、`seq_main`。
- `sequence` 示例保持易读；当逻辑开始复杂时，优先拆成带 tag 的可复用插件。

## 提交与 PR 规范
- 使用 Conventional Commits，例如 `feat(cache): add negative cache persistence`。
- 提交信息保持简洁、动作导向，并尽量带上子系统 scope。
- PR 需要说明行为变化、协议或平台影响范围、配置影响，以及实际执行过的测试命令。
- 任何影响请求热路径、默认配置行为或跨平台支持的变更，都应在 PR 描述中明确指出。
