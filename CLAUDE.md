# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Repository Guidelines

## Project Focus

- OxiDNS is a high-performance, plugin-driven DNS server written in Rust.
- The current project already includes UDP/TCP/DoT/DoQ/DoH server and upstream support, sequence-based policy orchestration, TTL-aware cache with negative caching, fallback chains, local and synthetic answers, query/response rewriting, ECS handling, dual-stack selection, provider-backed domain/IP rule sets, management APIs, health endpoints, metrics, and system integrations such as `ipset`, `nftset`, and MikroTik route sync.
- Prefer designs that preserve the core request path: `server -> DnsContext -> matcher/executor/provider pipeline -> upstream or side effects -> response`.

## Project Structure & Module Organization

- `src/main.rs` boots the Tokio runtime, parses CLI options, loads config, initializes logging, starts the application, and handles graceful shutdown.
- `src/lib.rs` exposes the library surface used by tests and embedding scenarios, including `api`, `app`, `config`, `core`, `message`, `network`, `plugin`, and `service`.
- `src/app/` contains bootstrap and logging setup for wiring the runtime from config to live services.
- `src/api/` contains the management/control and health HTTP endpoints.
- `src/message/` contains OxiDNS's DNS message model and wire codec implementation.
- `src/core/` contains shared runtime types such as `DnsContext`, errors, rule matching helpers, task orchestration, and TTL cache primitives.
- `src/config/` defines the YAML schema and validation for runtime configuration.
- `src/network/` contains listeners, protocol transports, TLS setup, upstream resolution, bootstrap logic, pooling, and Linux-specific networking helpers.
- `src/plugin/` is the main extension surface and is split into server, executor, matcher, and provider categories.
- `src/plugin/server/` handles inbound DNS protocols, including UDP, TCP, QUIC, and HTTP-based DNS with dedicated HTTP/2 and HTTP/3 support under `src/plugin/server/http/`.
- `src/plugin/executor/` contains request processors such as `sequence`, `forward`, `cache`, `fallback`, `hosts`, `arbitrary`, `redirect`, `ecs_handler`, `ttl`, `dual_selector`, observability plugins, and system-integration plugins.
- `src/plugin/matcher/` contains rule matchers for qname/qtype/qclass, client IP, response IP, CNAME, response presence, RCODE, marks, env, random rollout, rate limits, and related predicates.
- `src/plugin/provider/` contains reusable domain/IP datasets consumed by matchers and executors.
- `src/service.rs` contains service-management integration for installing or controlling OxiDNS as a system service.
- `crates/macros/` provides proc-macros used by the plugin registration system (`register_plugin_factory!` and related derives).
- `crates/ripset/` is a pure-Rust Linux netlink implementation for ipset/nftset operations, used by the ipset and nftset executor plugins.
- `crates/proto/` contains the low-level DNS wire protocol types (header, name, question, record, rdata) that back `src/message/`.
- `crates/zoneparser/` is a standalone zone-file parser used for loading hosts and local zone data.
- `tests/plugin_integration.rs` covers config parsing, plugin registry wiring, sequence quick-setup, and live server integration.
- `tests/message_hickory_compat.rs` validates message codec compatibility behavior against Hickory.
- `config.yaml` is the canonical runnable default configuration for the current plugin composition.
- `README.md` and `README_EN.md` describe the architecture and capability set; keep them aligned with behavior changes.
- WebUI-specific guidance lives in `webui/CLAUDE.md`; follow it for changes under `webui/`.

## Build, Test, and Development Commands

**Toolchain note:** `rustfmt.toml` uses `unstable_features = true`, so formatting and the pre-commit hook both require the nightly toolchain (`cargo +nightly fmt`). Install it with `rustup toolchain install nightly` if needed.

**Git hooks:** Run `just install-hooks` once per clone to activate the pre-commit hook (`cargo +nightly fmt --check` + `cargo +nightly clippy -- -D warnings`).

**Preferred quality gates (via `just`):**
- `just check` — full gate: fmt check + clippy (`-D warnings`) + tests. Run this before opening a PR.
- `just fix` — auto-applies fmt and Clippy fixes; use during active development.
- `just lint` — fmt check + clippy only, no tests; faster iteration cycle.

**Individual commands:**
- `cargo check` — fastest sanity check during iteration.
- `cargo build --release` — builds the optimized binary.
- `cargo run -- -c config.yaml` — runs OxiDNS with the default config.
- `cargo run --release -- -c config.yaml` — preferred for performance-sensitive validation.
- `cargo run -- -c config.yaml -l debug` — overrides the log level for local debugging.
- `cargo test` — runs all unit and integration tests.
- `cargo test --test plugin_integration` — runs the end-to-end plugin/config integration suite.
- `cargo test <filter>` — runs tests whose names match the filter string (e.g., `cargo test cache` runs all cache-related tests).
- `cargo test --test plugin_integration <filter>` — runs a specific integration test by name.
- `cargo clippy --all-targets --all-features -- -D warnings` — lints with warnings as errors; required to match CI and the pre-commit hook.

## Coding Style & Naming Conventions

- Rust 2024 edition; format with `cargo +nightly fmt`.
- Use `snake_case` for functions and fields, `CamelCase` for types, and `SCREAMING_SNAKE_CASE` for constants.
- Keep modules cohesive and place helpers close to the feature they serve.
- Comments should be written in English.
- Plugin implementations should include detailed comments about purpose, config shape, dependency expectations, lifecycle, and hot-path or side-effect behavior when that is not obvious from the code.
- Reuse the existing abstractions (`DnsContext`, `Executor`, `Matcher`, `Provider`, `RequestHandle`, upstream pools, plugin registry) before introducing parallel frameworks.
- Register new plugin types with `#[plugin_factory("type")]` on a unit or empty braced struct. Fall back to `register_plugin_factory!("type", expr)` only when the factory requires state at construction time (e.g. `DualSelectorFactory::new(RecordType::A)`) or when a single factory struct must register under multiple type names.
- Keep platform-specific integrations clearly guarded, especially Linux-only netlink, `ipset`, and `nftset` behavior.

## Performance & Architecture Principles

- Treat the request hot path as a first-class design constraint. Avoid unnecessary allocation, cloning, parsing, locking, or blocking I/O in per-request code.
- Prefer work that can be done once at startup or plugin initialization over work repeated for every query.
- Reuse connections and transport state through the existing upstream pool design instead of creating one-off connections on the fast path.
- Keep side effects such as metrics, persistence, reverse lookup, and route synchronization away from the most latency-sensitive response path unless correctness requires otherwise.
- Respect DNS semantics when touching cache, fallback, rewrite, or synthetic-response code, especially TTL and negative-cache behavior.
- Preserve plugin composability. New behavior should usually be added as a plugin or trait extension, not as a server-specific special case.
- Watch lock contention and shared-state growth; any `Arc`, `DashMap`, queue, or background task added to the core path needs a clear justification.

## Testing Guidelines

- Use Rust's built-in test framework and keep focused unit tests close to logic-heavy modules.
- Use `tests/plugin_integration.rs` for wiring-level behavior: config parsing, dependency resolution, sequence quick-setup, and server integration.
- For changes in servers, upstreams, cache, or plugin orchestration, cover both success paths and failure paths.
- Prefer ephemeral ports, bounded timeouts, and deterministic inputs for network-facing tests.
- Run at least `cargo test` for behavior changes. Also run `cargo test --test plugin_integration` when changing plugin registration, config parsing, sequence behavior, or server startup paths.

## Configuration & Documentation

- If a change adds or renames plugin types, config fields, default behaviors, supported protocols, or user-visible capabilities, update `README.md`, and `README_EN.md` in the same change when applicable.
- If a change adds, removes, or modifies a plugin, also sync the dedicated documentation in `docs/` for both Chinese and English. Treat plugin code changes and plugin docs updates as part of the same change whenever the behavior, config shape, dependencies, lifecycle, side effects, or examples are affected.
- When a Rust plugin is added or its config shape changes, update the corresponding entry in `webui/lib/plugin-definitions/` (one file per category: `executor.ts`, `matcher.ts`, `provider.ts`, `server.ts`) to keep the WebUI console aligned. Adding an entry to the right category file is sufficient — the catalog, create dialog, cards, detail drawer, sequence composer, and YAML editor all auto-derive from it.
- Prefer descriptive plugin tags such as `forward_main`, `cache_main`, `udp_server`, or `seq_main`.
- Keep `sequence` examples readable; use tagged reusable plugins once logic becomes non-trivial.

## Commit & Pull Request Guidelines

- Use Conventional Commits, for example `feat(cache): add negative cache persistence`.
- Keep commit messages short, action-oriented, and scoped to the subsystem when possible.
- PRs should describe behavior changes, protocol or platform scope, config impact, and the test commands that were run.
- Call out any change that affects the request hot path, default config behavior, or cross-platform support.
