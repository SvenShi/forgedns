---
title: Common Scenarios
sidebar_position: 6
---

This page summarizes common ForgeDNS policy combinations.

## 1. Cache + Upstream Forwarding

Use `cache` in front of `forward` for the default fast path:

```yaml
- tag: seq_main
  type: sequence
  args:
    - exec: "$cache_main"
    - matches: "!$has_resp"
      exec: "$forward_main"
```

## 2. Domain-Based Split Routing

Use `domain_set` plus `qname`-style matching to steer queries to different upstreams.

Typical uses:

- domestic vs. global upstream split
- ad / tracking filtering
- service-specific routing

## 3. LAN Policy + ECS

Use `client_ip` plus `ecs_handler` when answers should depend on client network identity or geolocation hints.

## 4. Fallback Chains

Use `fallback` when:

- one upstream is low-latency but incomplete
- one upstream is trusted but slower
- you need a controlled degraded mode

## 5. Local Synthetic Answers

Use:

- `hosts`
- `arbitrary`
- `redirect`

These are useful for internal names, sinkholes, testing, or synthetic records.

## 6. DNS-Driven System Integration

Use executors such as:

- `ipset`
- `nftset`
- `mikrotik`
- `reverse_lookup`

These allow DNS answers to drive routing, firewall, and inventory state outside the DNS server itself.

## 7. Observability

Use:

- `query_summary`
- `metrics_collector`
- plugin-specific HTTP endpoints

Keep observability available, but avoid pushing every side effect directly into the latency-critical path unless necessary.

