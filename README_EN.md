![OxiDNS Banner](.github/img/logo-banner.png)

[中文](README.md) | [English](README_EN.md)

[Documentation](https://forgedns.cn/en/)

**⚡ A high-performance, programmable DNS server for modern networks.**

OxiDNS is written in Rust and built around the request path `server -> DnsContext -> matcher / executor / provider -> upstream`. The goal is not to accumulate features, but to keep DNS fast and structurally clean while handling real-world policy needs such as cache, filtering, fallback, rewriting, local answers, and system integrations.

The project is under active development.

## At A Glance

- ⚡ Performance-oriented design with a short hot path, connection reuse, TTL-aware cache, and side-effect isolation
- 🧩 Unified policy orchestration through `matcher / executor / provider / sequence`
- 🔐 Server-side and upstream support for UDP, TCP, DoT, DoQ, and DoH
- 🛟 Built-in cache, fallback, local answers, query/response rewriting, ECS, and dual-stack helpers
- 🛰️ System-facing integrations including `ipset`, `nftset`, and MikroTik route sync
- 📈 Health checks, full and provider-scoped hot reload, config validation, Prometheus metrics, and structured query recording with real-time log streaming

## Core Capabilities

| Category | Capabilities |
| --- | --- |
| Protocols | UDP, TCP, DoT, DoQ, DoH |
| Policy | `sequence`, `matcher`, `executor`, `provider` |
| Executors | `forward`, `cache`, `fallback`, `hosts`, `arbitrary`, `redirect`, `ecs_handler`, `ttl`, `download`, `upgrade`、`reload`, `reload_provider`, `script`, `http_request`, `query_summary`, `query_recorder`, `metrics_collector` |
| Matchers | `qname`, `question`, `qtype`, `qclass`, `client_ip`, `resp_ip`, `rcode`, `rate_limiter`, and more |
| Data Sets | `domain_set`, `ip_set`, `geoip`, `geosite`, `adguard_rule` |
| Integrations | `ipset`, `nftset`, `ros_address_list`, `reverse_lookup` |

## Download

If you want to download a GitHub release directly, use this platform guide:

| System / Environment | Recommended release asset |
| --- | --- |
| Linux x86_64 | `oxidns-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 | `oxidns-aarch64-unknown-linux-musl.tar.gz` |
| Debian / Ubuntu x86_64 service install | `*_amd64.deb` |
| Debian / Ubuntu ARM64 service install | `*_arm64.deb` |
| Alpine Linux x86_64 | `oxidns-x86_64-unknown-linux-musl.tar.gz` |
| Alpine Linux ARM64 | `oxidns-aarch64-unknown-linux-musl.tar.gz` |
| 32-bit ARM Linux, including some Raspberry Pi installs | `oxidns-arm-unknown-linux-musleabihf.tar.gz` |
| macOS Intel | `oxidns-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `oxidns-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `oxidns-x86_64-pc-windows-msvc.zip` |
| Windows ARM64 | `oxidns-aarch64-pc-windows-msvc.zip` |
| FreeBSD x86_64 | `oxidns-x86_64-unknown-freebsd.tar.gz` |

On Linux, prefer `musl` by default if you are unsure about compatibility instead of assuming `gnu` will work.

If you are unsure which platform you are on, run `uname -s && uname -m`.

On Windows PowerShell, run `[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture`.

The full install flow is documented in Quick Start.

## Documentation Map

- [Configuration](https://forgedns.cn/en/configuration)
- [Quick start](https://forgedns.cn/en/quickstart)
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
