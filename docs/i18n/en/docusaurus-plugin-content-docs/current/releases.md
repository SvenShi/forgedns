---
title: Release Notes
sidebar_position: 4
---

import ReleaseCard from '@site/src/components/ReleaseCard';

# Release Notes

## 2026-04

<div className="release-stack">
  <ReleaseCard version="v0.2.0" badge="Feature Release" date="2026-04-02" defaultOpen>
      **Highlights**

      - Added the `script` executor so external scripts can participate in sequence orchestration.
      - Added the `download` executor, including SOCKS5 proxy support for remote file downloads.
      - Extended the `download` executor to bootstrap missing files on startup and follow HTTP redirects.
      - Added the `reload` executor to refresh selected datasets or persistent state at runtime.
      - Added `cron` scheduling support and duration parsing helpers for periodic workflows.
      - Added `geoip`, `geosite`, and `adguard_rule` providers, plus the new `question` matcher.

      **Core Changes**

      - Cache now supports stale lazy refresh to keep hot data available after expiration.
      - Rule matcher internals were split and optimized, with dedicated benchmarks added.
      - Removed the background-task dependency from `app_clock` and simplified the runtime clock model.
      - Added configurable log file rotation for long-running deployments.
      - `ros_address_list` now supports `fixed_ttl=0` to mean no timeout.

      **Fixes And Compatibility**

      - Fixed IP matcher rules being lost after finalize and incremental updates.
      - Fixed Windows integration-test and rule-fixture path issues.
      - Migrated from `serde_yml` to `serde_yaml_ng` and pulled in dependency security updates.

      **Docs And Tooling**

      - Added docs-site CI for the documentation site.
      - Expanded documentation for `executor`, `matcher`, `provider`, `server`, `quickstart`, and `scenarios`.
      - Improved sequence quick setup, default config, and module-level documentation.
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
