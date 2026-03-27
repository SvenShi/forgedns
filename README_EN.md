# ForgeDNS

[中文](README.md) | [English](README_EN.md)

Documentation: [https://forgedns.gitbook.io/docs](https://forgedns.gitbook.io/docs)

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
| Matchers | `qname`, `qtype`, `qclass`, `client_ip`, `resp_ip`, `rcode`, `rate_limiter`, and more |
| Data Sets | `domain_set`, `ip_set` |
| Integrations | `ipset`, `nftset`, `mikrotik`, `reverse_lookup` |

## Quick Start

```bash
cargo build --release
cargo run -- -c config.yaml
cargo run -- -c config.yaml -l debug
cargo test
```

See the runnable example in [`config.yaml`](/Users/sven/Codes/Rust/forgedns/config.yaml).

## Documentation Map

- Configuration: [`docs/01-configuration.md`](/Users/sven/Codes/Rust/forgedns/docs/01-configuration.md)
- Plugin reference: [`docs/02-plugin-reference/README.md`](/Users/sven/Codes/Rust/forgedns/docs/02-plugin-reference/README.md)
- Management API: [`docs/03-api.md`](/Users/sven/Codes/Rust/forgedns/docs/03-api.md)
- Common scenarios: [`docs/05-scenarios.md`](/Users/sven/Codes/Rust/forgedns/docs/05-scenarios.md)
- Architecture and design: [`docs/06-architecture-and-design.md`](/Users/sven/Codes/Rust/forgedns/docs/06-architecture-and-design.md)
- Performance and benchmarks: [`docs/07-benchmarks.md`](/Users/sven/Codes/Rust/forgedns/docs/07-benchmarks.md)

## Good Fits

- Home networks, gateways, and side-router deployments
- Multi-upstream racing, fallback chains, and mixed protocol environments
- Domain-driven routing and filtering
- Teams building long-lived, self-hosted DNS infrastructure

## License

[MIT](LICENSE)
