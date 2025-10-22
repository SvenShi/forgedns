# RustDNS

[中文文档](README_CN.md) | [English](README.md)

**状态：开发中** 🚧

一个使用 Rust 编写的高性能 DNS 服务器，基于现代异步 Rust 架构重新设计 mosdns。

## 特性

- ⚡ **高性能**：基于 Tokio 异步运行时，配备 8 个工作线程
- 🔌 **插件架构**：可扩展的插件系统，支持自定义 DNS 处理逻辑
- 🌐 **多协议支持**：支持 UDP、TCP、DoT、DoQ 和 DoH
- 🔄 **连接池管理**：高级连接管理，支持流水线和复用策略
- 📊 **智能日志**：结构化日志，可配置日志级别和可选文件输出
- ⏱️ **高效时间追踪**：无锁应用时钟，为热路径提供高性能支持

## 支持的 DNS 协议

- **UDP**：标准 DNS over UDP（端口 53）
- **TCP**：DNS over TCP（端口 53），支持可选的流水线模式
- **DoT**：DNS over TLS（端口 853）
- **DoQ**：DNS over QUIC（端口 853）
- **DoH**：DNS over HTTPS，支持 HTTP/2 或 HTTP/3（端口 443）

## 项目结构

```
rustdns/
├── src/
│   ├── main.rs                 # 入口点和运行时设置
│   ├── core/                   # 核心基础设施
│   │   ├── runtime.rs          # 命令行参数解析
│   │   ├── log.rs              # 自定义日志格式化器
│   │   ├── app_clock.rs        # 高性能时钟
│   │   └── context.rs          # DNS 请求/响应上下文
│   ├── config/                 # 配置管理
│   │   └── config.rs           # YAML 配置结构
│   ├── plugin/                 # 插件系统
│   │   ├── server/             # 服务器插件（UDP、TCP）
│   │   └── executable/         # 执行器插件（转发、过滤）
│   └── pkg/
│       └── upstream/           # 上游 DNS 解析器
│           ├── bootstrap.rs    # 引导 DNS 解析
│           └── pool/           # 连接池
│               ├── udp_conn.rs
│               ├── tcp_conn.rs
│               ├── quic_conn.rs
│               ├── h2_conn.rs
│               ├── h3_conn.rs
│               ├── pipeline.rs  # 流水线连接池
│               └── reuse.rs     # 复用连接池
└── config.yaml                 # 服务器配置文件
```

## 性能优化

- **无锁设计**：热路径使用原子操作（请求映射、时钟）
- **连接复用**：在多个请求间摊销握手成本
- **请求流水线**：每个 TCP/TLS 连接支持多个并发请求
- **高效时间追踪**：后台任务每毫秒更新一次时间，实现零系统调用读取
- **零拷贝**：尽可能减少内存分配和拷贝
- **自动扩展**：连接池根据负载自动增长/收缩

## 构建

```bash
cargo build --release
```

## 运行

```bash
# 使用默认的 config.yaml
./target/release/rustdns

# 指定自定义配置文件
./target/release/rustdns -c /path/to/config.yaml

# 覆盖日志级别
./target/release/rustdns -l debug
```

## 配置

参见 `config.yaml` 获取配置示例。配置文件支持：

- **日志配置**：级别（off/trace/debug/info/warn/error）和可选的文件输出
- **插件配置**：插件列表及其特定类型的配置
  - `udp_server`：UDP DNS 服务器监听器
  - `forward`：DNS 转发到上游解析器

## 许可证

GPL-3.0-or-later

## 作者

Sven Shi <isvenshi@gmail.com>

