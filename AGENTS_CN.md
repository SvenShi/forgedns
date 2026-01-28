# 仓库指南

## 项目结构与模块组织
- `src/` 为 Rust 源码目录，`src/main.rs` 是入口与运行时初始化。
- 核心基础设施在 `src/core/`，配置结构在 `src/config/`，协议与上游逻辑在 `src/network/`。
- 插件实现位于 `src/plugin/`（服务端与执行器插件）。
- 运行配置在 `config.yaml`，示例插件与服务配置也在其中。
- 构建产物在 `target/`（由 Cargo 生成）。

## 构建、测试与开发命令
- `cargo build --release` 构建优化后的发布二进制。
- `cargo run -- -c config.yaml` 使用默认配置运行。
- `cargo run -- -l debug` 覆盖日志级别便于调试。
- `cargo test` 运行源码中的单元测试。

## 编码风格与命名约定
- 使用 Rust 2024 版，格式化遵循 `cargo fmt`，注释使用英文。
- 4 空格缩进，模块聚合并与功能就近组织。
- 函数与字段用 `snake_case`，类型用 `CamelCase`，常量用 `SCREAMING_SNAKE_CASE`。
- 配置中插件标签应清晰易懂（如 `forward`、`udp_server`、`seq`）。

## 性能与架构原则
- 本项目对性能要求极高，DNS 作为基础服务，任何额外开销都需被严肃评估。
- 优先低延迟、低分配、可复用方案，避免热路径引入不必要的锁或阻塞。
- 强调可扩展与插件化，新增能力应通过插件或清晰模块边界实现。

## 测试指南
- 使用 Rust 内置测试框架（`#[test]`），通常与被测模块同文件。
- 优先为逻辑复杂模块添加单测（见 `src/network/upstream/mod.rs`）。
- 无硬性覆盖率目标，但需覆盖协议处理与插件行为。

## 提交与 PR 规范
- 提交信息遵循Conventional Commits，带scope，例如  `fix(scope): Fix ...` 使用英文。
- 描述简洁、动词驱动，涉及子系统请标注 scope。
- PR 需说明行为变化与配置调整，并附测试命令。
- 修改默认配置需说明对 `config.yaml` 的影响。

## 配置提示
- `config.yaml` 定义日志、插件链与监听器。
- 新增插件或协议处理时请同步更新示例配置与 README。
