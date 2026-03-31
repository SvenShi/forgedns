# ForgeDNS

[中文](README.md) | [English](README_EN.md)

[Documentation](https://forgedns.cn/en/)

**⚡ A high-performance, programmable DNS server for modern networks.**

ForgeDNS is written in Rust and built around the request path `server -> DnsContext -> matcher / executor / provider -> upstream`. The goal is not to accumulate features, but to keep DNS fast and structurally clean while handling real-world policy needs such as cache, filtering, fallback, rewriting, local answers, and system integrations.

The project is under active development.

## At A Glance

- ⚡ Performance-oriented design with a short hot path, connection reuse, TTL-aware cache, and side-effect isolation
- 🧩 Unified policy orchestration through `matcher / executor / provider / sequence`
- 🔐 Server-side and upstream support for UDP, TCP, DoT, DoQ, and DoH
- 🛟 Built-in cache, fallback, local answers, query/response rewriting, ECS, and dual-stack helpers
- 🛰️ System-facing integrations including `ipset`, `nftset`, and MikroTik route sync
- 📈 Health checks, hot reload, config validation, and Prometheus metrics support

## Core Capabilities

| Category | Capabilities |
| --- | --- |
| Protocols | UDP, TCP, DoT, DoQ, DoH |
| Policy | `sequence`, `matcher`, `executor`, `provider` |
| Executors | `forward`, `cache`, `fallback`, `hosts`, `arbitrary`, `redirect`, `ecs_handler`, `ttl` |
| Matchers | `qname`, `question`, `qtype`, `qclass`, `client_ip`, `resp_ip`, `rcode`, `rate_limiter`, and more |
| Data Sets | `domain_set`, `ip_set`, `adguard_rule` |
| Integrations | `ipset`, `nftset`, `ros_address_list`, `reverse_lookup` |

## Quick Start

```bash
cargo build --release
cargo run -- -c config.yaml
cargo run -- -c config.yaml -l debug
cargo test
```

See the runnable example in [`config.yaml`](config.yaml).

## Documentation Map

- [Configuration](https://forgedns.cn/en/configuration)
- [Plugin overview](https://forgedns.cn/en/plugin-reference/overview)
- [Management API](https://forgedns.cn/en/api)
- [MikroTik policy routing](https://forgedns.cn/en/mikrotik-policy-routing)
- [Common scenarios](https://forgedns.cn/en/scenarios)
- [Architecture and design](https://forgedns.cn/en/architecture-and-design)
- [Performance and benchmarks](https://forgedns.cn/en/benchmarks)

## Good Fits

- Home networks, gateways, and side-router deployments
- Multi-upstream racing, fallback chains, and mixed protocol environments
- Domain-driven routing and filtering
- Teams building long-lived, self-hosted DNS infrastructure

## License

[MIT](LICENSE)
