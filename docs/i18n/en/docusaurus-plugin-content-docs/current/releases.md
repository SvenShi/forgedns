---
title: Release Notes
sidebar_position: 4
---

import ReleaseCard from '@site/src/components/ReleaseCard';

# Release Notes

## 2026-05

<div className="release-stack">
  <ReleaseCard version="v0.5.2" badge="Patch Release" date="2026-05-04" defaultOpen>
      **Release Scope**

      - Patch Release focused on DoH / DoH3 upstream long-connection reuse and upstream duration parsing.

      **Changes**

      - Fixed an issue where DoH (HTTP/2) and DoH3 (HTTP/3) upstream connection pools could reuse already closed connections. After the remote peer closes an idle connection, the pool now evicts unavailable connections and recreates fresh ones, avoiding repeated `H2 send_request error` or `H3 send_request error` failures (Closed #78).
      - Fixed upstream `timeout` configuration parsing. Values such as `timeout: 3` and `timeout: "3s"` now deserialize correctly and can be used during forward plugin initialization (Closed #79).
      - Added unified duration parsing for duration-based fields, supporting units such as `ms`, `s`, `m`, `h`, and `d`. Bare numeric values are interpreted as seconds by default.

      **Compatibility and Upgrade Notes**

      - This release does not introduce new required configuration fields. Existing `v0.5.1` configurations can be upgraded directly.
      - Duration-based fields such as `timeout` and `idle_timeout` support formats including `3`, `"3"`, `"3s"`, and `"500ms"`.
      - Bare duration numbers are interpreted as seconds. Use an explicit `ms` suffix for millisecond-level values.
      - Upgrading to `v0.5.2` is recommended for deployments that configure upstream `timeout`, or use DoH / DoH3 upstreams and have seen repeated request failures after long runtimes.
  </ReleaseCard>
</div>

## 2026-04

<div className="release-stack">
  <ReleaseCard version="v0.5.1" badge="Patch Release" date="2026-04-28">
      **Release Scope**

      - Patch Release focused on `any_match` quick-setup dependency analysis and `query_recorder` pagination and cleanup boundaries.

      **Changes**

      - Fixed `any_match` dependency analysis so quick-setup matcher expressions are preserved and expanded correctly. Expressions such as `qname $provider` and `qtype 1` now keep their original meaning during startup and dependency analysis.
      - Fixed `query_recorder` retention cleanup and pagination cursor boundaries. Cleanup cutoff time now uses real timestamps, and paginated listing fetches one extra row to detect whether another page exists.
      - Adjusted `query_recorder` timestamp storage and read paths to avoid unnecessary unsigned conversions around record creation time.
      - Updated the `upgrade` CLI default cache and backup directories to `./upgrade-cache` and `./upgrade-backups`, and fixed the matching default-value tests.

      **Compatibility and Upgrade Notes**

      - This release does not introduce new configuration fields. Existing `v0.5.0` configurations can be upgraded directly.
      - Upgrading to `v0.5.1` is recommended for deployments that use `query_recorder` or quick-setup expressions inside `any_match`.
      - `query_recorder` remains **Experimental**, and its API surface or configuration fields may still change in future releases.
  </ReleaseCard>

  <ReleaseCard version="v0.5.0" badge="Minor Release" date="2026-04-27">
      **Release Scope**

      - Minor Release adding query auditing, aggregate matcher support, and HTTP/3 discovery improvements.

      **Changes**

      - Added the `query_recorder` executor for persisted query logging with retention cleanup, plus plugin API endpoints for stats, paginated record listing, and single-record details.
      - Added the `any_match` matcher so one matcher can aggregate multiple matcher expressions and return true when any branch matches, including negated expressions like `!$tag`.
      - When HTTP/3 is enabled on the HTTP server, HTTP/2 responses now automatically advertise `Alt-Svc: h3=":<listen-port>"; ma=86400` so clients can discover and upgrade to H3.
      - Fixed dependency tracking for negated matchers, for example `!$has_resp`, inside `sequence`, so quick setup and dependency analysis no longer miss those references (Closed #75).
      - Unified time handling around `jiff + AppClock`, making cron scheduling, log time formatting, and system-time access paths more consistent.

      **Compatibility and Upgrade Notes**

      - This release does not require global config migrations. Existing `v0.4.x` configurations can be upgraded directly.
      - `query_recorder` is currently **Experimental**. Its API surface and configuration fields may change in upcoming minor releases.
      - To enable query auditing, insert `query_recorder` into the `sequence` chain and tune retention parameters according to disk budget.
      - For automatic HTTP/3 discovery by DoH clients, ensure `enable_http3: true` is set and TLS certificate/key are configured correctly.
  </ReleaseCard>

  <ReleaseCard version="v0.4.2" badge="Patch Release" date="2026-04-24">
      **Release Scope**

      - Patch Release fixing connection release in upstream race scenarios and adding automatic upgrade support.

      **Changes**

      - Fixed an issue where some connections were not properly released in upstream race scenarios, such as when multiple concurrent upstreams were configured or fallback was enabled.
      - Added the `upgrade` CLI tool and plugin to support automatic updates and binary replacement.
      - When the application is running as a Linux service, `upgrade` can also restart it automatically after the update.

      **Compatibility and Upgrade Notes**

      - This release does not introduce new required configuration fields.
      - Deployments that rely on concurrent upstream racing, fallback, or automatic upgrade flows can upgrade to `v0.4.2`.
  </ReleaseCard>

  <ReleaseCard version="v0.4.1" badge="Patch Release" date="2026-04-23">
      **Release Scope**

      - Patch Release fixing an upstream `request_map` memory leak and improving DoH HTTP response compatibility.

      **Changes**

      - Fixed an upstream `request_map` memory leak during connection close, request timeout, and abnormal cleanup paths, preventing pending query waiters and senders from being retained over time.
      - Reworked `request_map` into a fixed-capacity sparse table so each connection no longer reserves the full `u16` DNS ID space.
      - Fixed DoH response header generation so `application/dns-message` replies carry the correct `Content-Length`, and `Cache-Control: max-age=...` is derived from the actual DNS TTL.
      - Common `NoError`, `NXDOMAIN`, and `NODATA` DoH responses now derive HTTP cache lifetime from answer TTLs or SOA negative TTLs. Refusal-style replies no longer advertise misleading cache headers.

      **Compatibility and Upgrade Notes**

      - This release does not add new configuration fields. Existing `v0.4.0` configs can be upgraded directly to `v0.4.1`.
      - Because this release fixes an upstream `request_map` memory leak, upgrading to `v0.4.1` is recommended for long-running deployments with many persistent or concurrent upstream connections.
      - For DoH access through `dig +https://...`, browsers, reverse proxies, or HTTP caches, the upgrade also improves HTTP response compatibility.
  </ReleaseCard>

  <ReleaseCard version="v0.4.0" badge="Minor Release" date="2026-04-19">
      **Release Scope**

      - Minor Release adding provider-scoped hot reload and reworking provider composition and initialization.

      **Changes**

      - Added the `reload_provider` executor plus the provider-scoped management API `POST /plugins/<provider_tag>/reload`. After downloading or overwriting rule files, OxiDNS can refresh only the affected providers instead of forcing a full application reload.
      - Reworked provider composition so `domain_set` and `ip_set` compile only their own local rules and keep querying referenced providers from `sets` at runtime.
      - Runtime initialization now skips providers that have no live dependents, so unused rule sets no longer spend startup time on file reads, dat parsing, or memory allocation.
      - Expanded quick-setup dependency analysis into runtime reference paths such as `sequence` and `cron`, making plugin dependency graphs and init ordering more accurate.
      - Added docs for targeted provider reload through both the API and the new `reload_provider` executor, including chained download-and-refresh examples.

      **Compatibility and Upgrade Notes**

      - Existing workflows that run `download` and then a full `reload` can usually switch to `download -> reload_provider` to avoid rebuilding unrelated plugins.
      - `reload_provider` only refreshes an existing provider's config snapshot and external data files. If `config.yaml`, provider tags, `sets` topology, or the plugin list changes, keep using the full `reload` path.
      - Providers that are not reachable from any live runtime path are no longer inserted into the runtime registry. Deployments that rely on a provider's runtime API surface or behavior must reference it directly or indirectly from a live `server`, `executor`, or `matcher`.
  </ReleaseCard>

  <ReleaseCard version="v0.3.2" badge="Patch Release" date="2026-04-16">
      **Release Scope**

      - Patch Release reducing false warning logs from normal connection lifecycles and improving debug output.

      **Changes**

      - Adjusted UDP, TCP, DoT, and DoQ upstream pool initialization so OxiDNS no longer pre-creates idle connections during startup, reducing false EOF / reset warnings when upstreams close idle sockets on their own.
      - Expected TCP upstream lifecycle events such as EOF, connection recycling, and invalid-connection eviction are now logged at `debug` instead of `warn`.
      - Downgraded DoH server-side TLS, HTTP/2, and HTTP/3 handshake aborts plus client-closed response-send failures to `debug`.
      - Debug request/response logging now prints DNS `questions`, message IDs, EDNS data, and answers directly. `Record` now has a more readable `Debug` / `Display` representation.

      **Compatibility and Upgrade Notes**

      - This release does not introduce new configuration fields. Existing `0.3.x` configs can be upgraded as-is.
      - Warning-count based alerting should see a noticeable drop in noise after `v0.3.2` because normal upstream disconnects and DoH client aborts are no longer treated as warnings.
  </ReleaseCard>

  <ReleaseCard version="v0.3.1" badge="Patch Release" date="2026-04-14">
      **Release Scope**

      - Patch Release fixing `sequence` builtin control-flow semantics and completing release metadata.

      **Changes**

      - Fixed `sequence` builtin control-flow semantics so `accept` / `reject` stop the current chain consistently, `return` explicitly resumes the caller, and nested `jump` / `goto` behavior is more consistent.
      - Removed the old internal flow-state dependency from control-flow propagation and now relies on `ExecStep` directly, reducing ambiguity when `sequence`, `with_next` executors, and nested calls are combined.
      - Expanded unit and integration coverage around `sequence`, including `accept`, `return`, `reject`, `jump`, `goto`, and `adguard_rule` / `question` driven branches.
      - Added the metadata, README files, repository links, and versioned dependency declarations needed to publish `oxidns-proto`, `oxidns-zoneparser`, and `oxidns-ripset` to crates.io cleanly.
      - Refreshed the `configuration`, `executor`, and `matcher` docs to explain builtin `sequence` control flow, `mark` syntax, and numeric `qtype` / `qclass` forms more clearly.

      **Compatibility and Upgrade Notes**

      - For policy layouts that depend on nested `sequence` calls or `jump` / `goto` / `return` combinations, `v0.3.1` is the recommended upgrade for predictable control-flow behavior.
      - This release does not introduce new config fields; it focuses on control-flow fixes, test hardening, and release metadata cleanup.
  </ReleaseCard>

  <ReleaseCard version="v0.3.0" badge="Minor Release" date="2026-04-14">
      **Release Scope**

      - Minor Release adding HTTP callbacks, config checking, dat export, zone parsing, and Linux netlink integration.

      **Changes**

      - Added the `http_request` executor for synchronous or asynchronous `http/https` callbacks in either the `before` or `after` phase, with template placeholders, `json/form/body` payloads, SOCKS5, redirect handling, and configurable error modes.
      - Added the `check` and `export-dat` CLI commands. `check --graph` performs static validation and prints the plugin dependency graph, while `export-dat` can export selected rules from `geosite.dat` / `geoip.dat` into OxiDNS or original text formats.
      - Aligned `hosts` behavior with mosdns semantics, and upgraded `arbitrary` with a fuller zone parser that supports `$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`, RFC3597, and broader record syntax.
      - Switched the Linux `ipset` / `nftset` executors to an embedded Rust netlink backend, removing the runtime dependency on the `ipset` / `nft` shell commands.
      - Split protocol, zone parsing, and Linux integration internals into three workspace crates: `oxidns-proto`, `zoneparser`, and `ripset`. Added a reusable wire-buffer pool on the network hot path and tuned UDP/TCP/upstream socket parameters.
      - Added a dedicated CLI docs page and refreshed the `executor`, `provider`, `quickstart`, `benchmarks`, and `releases` chapters.

      **Compatibility and Upgrade Notes**

      - Unprefixed `hosts` rules now behave as `full:` rules; positive local answers now use a fixed TTL of `10`; and a name hit without a matching address family now returns `NoError + empty answer + fake SOA` instead of falling through the rest of the executor chain.
      - `arbitrary` no longer provides the old quick-setup syntax. Migrate those cases to explicit `rules` / `files` configuration when upgrading.
      - Quickstart added a Docker Compose example and clarified Docker image registry, Windows release assets, and service deployment guidance.
  </ReleaseCard>

  <ReleaseCard version="v0.2.1" badge="Patch Release" date="2026-04-03">
      **Release Scope**

      - Patch Release fixing DoH over HTTP/2 upstream GET handling and updating quickstart documentation.

      **Changes**

      - Fixed a DoH over HTTP/2 bug where GET requests did not close the request stream, causing some upstreams to time out after 5 seconds.
      - Completed the `Question` `Display` implementation so logs and debug output render DNS questions consistently.
      - Relaxed the cache TTL unit test to tolerate cross-second timing drift in CI.
      - Removed the Docker `linux/arm/v7` support note from quickstart and added a `docker compose` deployment example.

      **Compatibility and Upgrade Notes**

      - This release does not introduce new configuration fields.
      - Upgrading to `v0.2.1` is recommended for deployments using DoH over HTTP/2 upstream GET requests.
  </ReleaseCard>

  <ReleaseCard version="v0.2.0" badge="Feature Release" date="2026-04-02">
      **Release Scope**

      - Feature Release adding subscription download, scheduled jobs, script execution, and geodata provider support.

      **Changes**

      - Added the `download` executor for downloading remote `http/https` files to local storage, with SOCKS5 proxying, HTTP redirect following, and startup bootstrap for missing files.
      - Added the `cron` executor for background jobs with interval or standard 5-field cron triggers.
      - Added the `reload` executor for full application reloads.
      - Added the `script` executor for running external commands with injected context fields.
      - Added `geoip`, `geosite`, and `adguard_rule` providers, plus the `question` matcher. Extended `qname` matching to support `adguard_rule` rule sets directly.
      - Cache now supports stale lazy refresh, rule matcher internals were split and optimized, and configurable log file rotation was added.
      - Expanded documentation for `executor`, `matcher`, `provider`, `server`, `quickstart`, and `scenarios`, and added docs-site CI.

      **Compatibility and Upgrade Notes**

      - `startup_if_missing` is enabled by default for smoother first-deployment and rule-file bootstrap behavior.
      - `ros_address_list` supports `fixed_ttl=0` for no-timeout behavior.
      - Added `short_circuit` support to quick setup for `hosts`, `black_hole`, and `cache`.
      - Removed the `hosts` quick setup to tighten early quick-setup behavior.
      - Migrated from `serde_yml` to `serde_yaml_ng`, with several dependency and CI tooling updates.
  </ReleaseCard>
</div>

## 2026-03

<div className="release-stack">
  <ReleaseCard version="v0.1.1" badge="Compatibility Update" date="2026-03-29">
      **Release Scope**

      - Compatibility Update standardizing the MikroTik-related executor name.

      **Changes**

      - Renamed the MikroTik-related executor to `ros_address_list` to better match its actual behavior and naming style.
      - Corrected documentation examples and feature descriptions.
      - Applied formatting cleanup to keep code and docs aligned.

      **Compatibility and Upgrade Notes**

      - Deployments that used the old MikroTik executor name in `v0.1.0` need to update the plugin type when upgrading to `v0.1.1`.
  </ReleaseCard>

  <ReleaseCard version="v0.1.0" badge="First Public Release" date="2026-03-28">
      **Release Scope**

      - First Public Release providing the initial OxiDNS plugin architecture and core capability set.

      **Changes**

      - Established the OxiDNS plugin architecture around `server -> DnsContext -> matcher / executor / provider -> upstream or side effects`.
      - Completed server and upstream support for UDP, TCP, DoT, DoQ, and DoH.
      - Delivered MosDNS-style `sequence` orchestration, `jump/goto/return` control flow, and `$tag` references.
      - Added core executors such as `cache`, `forward`, `fallback`, `hosts`, `redirect`, `ecs_handler`, and `dual_selector`.
      - Added `domain_set`, `ip_set`, query / response predicates, client IP, response IP, and CNAME-based matching capabilities.
      - Added the management API, health checks, control endpoints, and plugin-related API surfaces. Added CLI commands with service-manager integration.
      - Added Debian packaging, Docker workflow support, and the initial multi-platform release pipeline.
      - Built reusable upstream connection pools and fetchers for UDP, TCP, DoT, DoH, and DoQ, and optimized matchers, cache, pools, request mapping, and clock updates on the hot path.

      **Compatibility and Upgrade Notes**

      - Tokio worker-thread count is configurable from runtime config.
      - MikroTik RouterOS dynamic-route and address-list integration is available.
      - Linux `ipset` / `nftset` command integration and test coverage are available.
      - The first round of Chinese and English README, quickstart, configuration, and module documentation is included.
  </ReleaseCard>
</div>
