---
title: Release Notes
sidebar_position: 4
---

import ReleaseCard from '@site/src/components/ReleaseCard';

# Release Notes

## 2026-04

<div className="release-stack">
  <ReleaseCard version="v0.4.1" badge="Patch Release" date="2026-04-23" defaultOpen>
      **Fixes**

      - Fixed an upstream `request_map` memory leak during connection close, request timeout, and abnormal cleanup paths, preventing pending query waiters and senders from being retained over time.
      - Reworked `request_map` into a fixed-capacity sparse table so each connection no longer reserves the full `u16` DNS ID space, further reducing the resident memory footprint of TCP/DoT/DoQ/DoH upstream connections.
      - Fixed DoH response header generation so `application/dns-message` replies now carry the correct `Content-Length`, and `Cache-Control: max-age=...` is derived from the actual DNS TTL for better compatibility with `dig`, browsers, and proxies.

      **Behavior Notes**

      - Common `NoError`, `NXDOMAIN`, and `NODATA` DoH responses now derive HTTP cache lifetime from answer TTLs or SOA negative TTLs.
      - Responses without a safe cache lifetime, such as refusal-style replies, no longer advertise a misleading HTTP cache header.
      - Tombstones are reset when the table becomes empty, keeping probe chains stable under ID wraparound and heavy reuse.

      **Upgrade Notes**

      - This release does not add any new configuration fields. Existing `v0.4.0` configs can be upgraded directly to `v0.4.1`.
      - This release fixes an upstream `request_map` memory leak, so upgrading to `v0.4.1` is recommended for all users, especially long-running deployments with many persistent or concurrent upstream connections.
      - If you access DoH through `dig +https://...`, browsers, reverse proxies, or HTTP caches, the upgrade also improves HTTP response compatibility.
  </ReleaseCard>

  <ReleaseCard version="v0.4.0" badge="Minor Release" date="2026-04-19">
      **Highlights**

      - Added the `reload_provider` executor plus the provider-scoped management API `POST /plugins/<provider_tag>/reload`. After downloading or overwriting rule files, ForgeDNS can now refresh only the affected providers instead of forcing a full application reload.
      - Reworked provider composition so `domain_set` and `ip_set` compile only their own local rules and keep querying referenced providers from `sets` at runtime. When a downstream provider reloads, aggregated providers see the new result immediately without reloading themselves, while also reducing rule duplication and memory usage.
      - Runtime initialization now skips providers that have no live dependents, so unused rule sets no longer spend startup time on file reads, dat parsing, or memory allocation.

      **Core And Runtime**

      - Expanded quick-setup dependency analysis into runtime reference paths such as `sequence` and `cron`, so plugin dependency graphs and init ordering are more accurate for quick-setup expressions.
      - Provider factories now receive live-dependent context during creation, which lays the groundwork for more demand-aware initialization and future runtime optimizations.
      - Removed the `hickory-proto` compatibility test and related dev dependency, and refreshed part of the dependency stack to reduce test-surface overhead.

      **Docs**

      - Added docs for targeted provider reload through both the API and the new `reload_provider` executor, including chained download-and-refresh examples.
      - Updated the `provider` reference to separate local rule compilation from runtime provider composition, and clarified reload boundaries plus the new skipped-unused-provider behavior.
      - Reordered the plugin reference docs to follow the request path more closely, which makes `server -> executor -> matcher -> provider` easier to navigate.

      **Upgrade Notes**

      - If your current workflow does `download` and then a full `reload`, you can usually switch that flow to `download -> reload_provider` to avoid rebuilding unrelated plugins.
      - `reload_provider` only refreshes an existing provider's config snapshot and external data files. If `config.yaml`, provider tags, `sets` topology, or the plugin list changes, keep using the full `reload` path.
      - Providers that are not reachable from any live runtime path are no longer inserted into the runtime registry. If you rely on a provider's runtime API surface or behavior, make sure it is referenced directly or indirectly by a live `server`, `executor`, or `matcher`.
  </ReleaseCard>

  <ReleaseCard version="v0.3.2" badge="Patch Release" date="2026-04-16">
      **Fixes**

      - Adjusted UDP, TCP, DoT, and DoQ upstream pool initialization so ForgeDNS no longer pre-creates idle connections during startup, which reduces false EOF / reset warnings when upstreams close idle sockets on their own.
      - Expected TCP upstream lifecycle events such as EOF, connection recycling, and invalid-connection eviction are now logged at `debug` instead of `warn`, so normal connection churn no longer looks like an operational fault.
      - Downgraded DoH server-side TLS, HTTP/2, and HTTP/3 handshake aborts plus client-closed response-send failures to `debug`, which removes warning noise from browsers or proxies that disconnect early.

      **Observability**

      - Debug request/response logging now prints DNS `questions`, message IDs, EDNS data, and answers directly instead of only showing counters.
      - `Record` now has a more readable `Debug` / `Display` representation, making response records easier to inspect in logs.

      **Upgrade Notes**

      - This release does not introduce any new configuration fields; existing `0.3.x` configs can be upgraded as-is.
      - If you rely on warning-count based alerting, expect a noticeable drop in noise after `v0.3.2` because normal upstream disconnects and DoH client aborts are no longer treated as warnings.
  </ReleaseCard>

  <ReleaseCard version="v0.3.1" badge="Patch Release" date="2026-04-14">
      **Highlights**

      - Fixed `sequence` builtin control-flow semantics so `accept` / `reject` now stop the current chain consistently, `return` explicitly resumes the caller, and nested `jump` / `goto` behavior is easier to reason about.
      - Removed the old internal flow-state dependency from control-flow propagation and now relies on `ExecStep` directly, reducing ambiguity when `sequence`, `with_next` executors, and nested calls are combined.
      - Expanded unit and integration coverage around `sequence`, including `accept`, `return`, `reject`, `jump`, `goto`, and `adguard_rule` / `question` driven branches, to reduce regression risk.

      **Packaging And Ecosystem**

      - Added the metadata, README files, repository links, and versioned dependency declarations needed to publish `forgedns-proto`, `forgedns-zoneparser`, and `forgedns-ripset` to crates.io cleanly.
      - Updated the main package dependency declarations to reference those internal crates with explicit versions, which keeps release packaging and downstream reuse aligned.

      **Docs**

      - Refreshed the `configuration`, `executor`, and `matcher` docs to explain builtin `sequence` control flow, `mark` syntax, and the numeric `qtype` / `qclass` forms more clearly.
      - Added clearer `jump` / `goto` examples and edge-case notes to reduce upgrade friction for `v0.3.1`.

      **Upgrade Notes**

      - If your policy layout depends on nested `sequence` calls or `jump` / `goto` / `return` combinations, `v0.3.1` is the recommended upgrade for predictable control-flow behavior.
      - This release does not introduce new config fields; it focuses on control-flow fixes, test hardening, and release metadata cleanup.
  </ReleaseCard>

  <ReleaseCard version="v0.3.0" badge="Minor Release" date="2026-04-14">
      **Highlights**

      - Added the `http_request` executor for synchronous or asynchronous `http/https` callbacks in either the `before` or `after` phase, with template placeholders, `json/form/body` payloads, SOCKS5, redirect handling, and configurable error modes.
      - Added the `check` and `export-dat` CLI commands. `check --graph` now performs static validation and prints the plugin dependency graph, while `export-dat` can export selected rules from `geosite.dat` / `geoip.dat` into ForgeDNS or original text formats.
      - Aligned `hosts` behavior with mosdns semantics, and upgraded `arbitrary` with a fuller zone parser that supports `$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`, RFC3597, and broader record syntax.
      - Expanded and clarified `short_circuit` coverage and behavior notes across multiple executors, so local responses, cache hits, or winning branches can stop the remaining executor chain explicitly; `hosts` now also documents its short-circuit behavior for empty local replies.
      - Switched the Linux `ipset` / `nftset` executors to an embedded Rust netlink backend, removing the runtime dependency on the `ipset` / `nft` shell commands.

      **Core And Performance**

      - Split protocol, zone parsing, and Linux integration internals into three workspace crates: `forgedns-proto`, `zoneparser`, and `ripset`.
      - Added a reusable wire-buffer pool on the network hot path and tuned UDP/TCP/upstream socket parameters to reduce short-lived allocations and connection-side overhead.
      - Added a low-concurrency latency benchmark script, published the `v0.3.0` benchmark snapshot, and expanded the benchmark documentation.
      - Fixed Windows build compatibility issues plus several benchmark and CI configuration problems.

      **Upgrade Notes**

      - Unprefixed `hosts` rules now behave as `full:` rules; positive local answers now use a fixed TTL of `10`; and a name hit without a matching address family now returns `NoError + empty answer + fake SOA` instead of falling through the rest of the executor chain.
      - `arbitrary` no longer provides the old quick-setup syntax. Migrate those cases to explicit `rules` / `files` configuration when upgrading.

      **Docs And Tooling**

      - Added a dedicated CLI docs page and refreshed the `executor`, `provider`, `quickstart`, `benchmarks`, and `releases` chapters.
      - Added a Docker Compose quickstart example and clarified Docker image registry, Windows release assets, and service deployment guidance.
  </ReleaseCard>

  <ReleaseCard version="v0.2.1" badge="Patch Release" date="2026-04-03">
      **Fixes**

      - Fixed a DoH over HTTP/2 bug where GET requests did not close the request stream, causing some upstreams to time out after 5 seconds.
      - Completed the `Question` `Display` implementation so logs and debug output render DNS questions consistently.
      - Relaxed the cache TTL unit test to tolerate cross-second timing drift in CI.

      **Docs**

      - Removed the Docker `linux/arm/v7` support note from quickstart.
      - Added a `docker compose` deployment example to quickstart.
  </ReleaseCard>

  <ReleaseCard version="v0.2.0" badge="Feature Release" date="2026-04-02">
      **Highlights**

      - Added the `download` executor for downloading remote `http/https` files to local storage.
      - `download` now supports SOCKS5 proxying, HTTP redirect following, and startup bootstrap for missing files.
      - `startup_if_missing` is enabled by default for smoother first-deployment behavior.
      - Added the `cron` executor for background jobs with interval or standard 5-field cron triggers.
      - Added the `reload` executor for full application reloads.
      - Added the `script` executor for running external commands with injected context fields.
      - Added `geoip`, `geosite`, and `adguard_rule` providers.
      - Added the `question` matcher.
      - Extended `qname` matching to support `adguard_rule` rule sets directly.

      **Core Improvements**

      - Cache now supports stale lazy refresh.
      - Rule matcher internals were split and optimized, with dedicated domain / ip benchmarks added.
      - Added configurable log file rotation for long-running deployments.
      - Removed the background-task dependency from `app_clock`.
      - `ros_address_list` now supports `fixed_ttl=0` for no-timeout behavior.
      - Added `short_circuit` support to quick setup for `hosts`, `black_hole`, and `cache`.

      **Fixes And Compatibility**

      - Fixed IP matcher rules being lost after finalize and incremental updates.
      - Fixed Windows integration-test and fixture path issues.
      - Migrated from `serde_yml` to `serde_yaml_ng`.
      - Updated several dependencies and CI-related tooling.
      - Removed the `hosts` quick setup to tighten early quick-setup behavior.

      **Docs And Tooling**

      - Added docs-site CI.
      - Expanded documentation for `executor`, `matcher`, `provider`, `server`, `quickstart`, and `scenarios`.
      - Added subscription refresh examples, improved sequence quick setup docs, and introduced this release history page.
  </ReleaseCard>
</div>

## 2026-03

<div className="release-stack">
  <ReleaseCard version="v0.1.1" badge="Compatibility Update" date="2026-03-29">
      **Highlights**

      - Renamed the MikroTik-related executor to `ros_address_list` to better match its actual behavior and naming style.

      **Fixes**

      - Corrected documentation examples and feature descriptions.
      - Applied formatting cleanup to keep code and docs aligned.

      **Upgrade Note**

      - If you used the old MikroTik executor name in `v0.1.0`, update the plugin type in your configuration when upgrading to `v0.1.1`.
  </ReleaseCard>

  <ReleaseCard version="v0.1.0" badge="First Public Release" date="2026-03-28">
      **Highlights**

      - Established the ForgeDNS plugin architecture around `server -> DnsContext -> matcher / executor / provider -> upstream or side effects`.
      - Completed server and upstream support for UDP, TCP, DoT, DoQ, and DoH.
      - Delivered MosDNS-style `sequence` orchestration, `jump/goto/return` control flow, and `$tag` references.
      - Added core executors such as `cache`, `forward`, `fallback`, `hosts`, `redirect`, `ecs_handler`, and `dual_selector`.
      - Added `domain_set`, `ip_set`, query / response predicates, client IP, response IP, and CNAME-based matching capabilities.

      **Platform And Runtime**

      - Added the management API, health checks, control endpoints, and plugin-related API surfaces.
      - Added CLI commands with service-manager integration for service deployments.
      - Added Debian packaging, Docker workflow support, and the initial multi-platform release pipeline.
      - Made Tokio worker-thread count configurable from runtime config.

      **Performance**

      - Built reusable upstream connection pools and fetchers for UDP, TCP, DoT, DoH, and DoQ.
      - Optimized matchers, cache, pools, request mapping, and clock updates on the hot path.
      - Added high-performance `domain_set` and `ip_set` implementations while reducing blocking I/O on latency-sensitive paths.

      **Ecosystem**

      - Added MikroTik RouterOS dynamic-route and address-list integration.
      - Added Linux `ipset` / `nftset` command integration and test coverage.
      - Shipped the first round of Chinese and English README, quickstart, configuration, and module documentation.
  </ReleaseCard>
</div>
