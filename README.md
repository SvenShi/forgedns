# ForgeDNS

[中文文档](README_CN.md) | [English](README.md)

**Status: Under Active Development** 🚧

A high-performance DNS server written in Rust, reimagining mosdns with modern async Rust architecture.

## Features

- ⚡ **High Performance**: Built on Tokio async runtime with 8 worker threads
- 🔌 **Plugin Architecture**: Extensible plugin system for custom DNS processing logic
- 🌐 **Multiple Protocols**: Support for UDP, TCP, DoT, DoQ, and DoH
- 🔄 **Connection Pooling**: Advanced connection management with pipelining and reuse strategies
- 📊 **Smart Logging**: Structured logging with configurable levels and optional file output
- ⏱️ **Efficient Time Tracking**: Lock-free application clock for hot-path performance

## Supported DNS Protocols

- **UDP**: Standard DNS over UDP (port 53)
- **TCP**: DNS over TCP (port 53) with optional pipelining
- **DoT**: DNS over TLS (port 853)
- **DoQ**: DNS over QUIC (port 853)
- **DoH**: DNS over HTTPS via HTTP/2 or HTTP/3 (port 443)

## Project Structure

```
forgedns/
├── src/
│   ├── main.rs                 # Entry point and runtime setup
│   ├── core/                   # Core infrastructure
│   │   ├── runtime.rs          # CLI argument parsing
│   │   ├── log.rs              # Custom log formatter
│   │   ├── app_clock.rs        # High-performance clock
│   │   └── context.rs          # DNS request/response context
│   ├── config/                 # Configuration management
│   │   └── config.rs           # YAML config structures
│   ├── plugin/                 # Plugin system
│   │   ├── server/             # Server plugins (UDP, TCP)
│   │   └── executable/         # Executor plugins (forward, filter)
│   └── pkg/
│       └── upstream/           # Upstream DNS resolver
│           ├── bootstrap.rs    # Bootstrap DNS resolution
│           └── pool/           # Connection pooling
│               ├── udp_conn.rs
│               ├── tcp_conn.rs
│               ├── quic_conn.rs
│               ├── h2_conn.rs
│               ├── h3_conn.rs
│               ├── pipeline.rs  # Pipeline connection pool
│               └── reuse.rs     # Reuse connection pool
└── config.yaml                 # Server configuration
```

## Performance Optimizations

- **Lock-Free Design**: Atomic operations for hot paths (request mapping, clock)
- **Connection Reuse**: Amortizes handshake costs across multiple requests
- **Request Pipelining**: Multiple concurrent requests per TCP/TLS connection
- **Efficient Time Tracking**: Background task updates time every 1ms for zero-syscall reads
- **Zero-Copy**: Minimizes allocations and copies where possible
- **Automatic Scaling**: Connection pools grow/shrink based on load

## Building

```bash
cargo build --release
```

## Running

```bash
# Use default config.yaml
./target/release/forgedns

# Specify custom config
./target/release/forgedns -c /path/to/config.yaml

# Override log level
./target/release/forgedns -l debug
```

## Configuration

See `config.yaml` for configuration examples. The config supports:

- **Logging**: Level (off/trace/debug/info/warn/error) and optional file output
- **Plugins**: List of plugins with type-specific configurations
  - `udp_server`: UDP DNS server listener
  - `forward`: DNS forwarding to upstream resolvers
- sequence built-in matcher plugins: `qname`, `qtype`, `qclass`, `ptr_ip`, `client_ip`, `has_resp`, `resp_ip`, `cname`, `rcode`, `has_wanted_ans`, `mark`, `string_exp`, `_true`, `_false`, `env`, `random`
- `sequence.matches` quick setup supports direct matcher plugin syntax, e.g. `qname example.com`, `qtype A`, `has_resp`, `random 0.5`

## License

GPL-3.0-or-later

## Author

Sven Shi <isvenshi@gmail.com>
