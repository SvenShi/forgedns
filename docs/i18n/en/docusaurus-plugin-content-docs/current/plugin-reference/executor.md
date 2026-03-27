---
title: Executor Plugins
sidebar_position: 3
---

Executors perform work on the request path. Some read state, some mutate requests or responses, and some trigger side effects.

## Core Policy Executors

### `sequence`

The primary orchestration executor. Evaluates rules in order and dispatches to other executors based on match results.

### `forward`

Queries one or more upstream DNS servers.

### `fallback`

Builds controlled fallback chains or racing strategies across upstream groups.

### `cache`

Handles DNS cache reads and writes, including TTL-aware behavior and negative caching semantics.

## Local Answer Executors

### `hosts`

Returns answers from static host mappings.

### `arbitrary`

Builds synthetic records directly from config.

### `redirect`

Rewrites queries or redirects names to other targets.

## Rewrite and Preference Executors

### `ecs_handler`

Reads or rewrites EDNS Client Subnet related information.

### `forward_edns0opt`

Controls EDNS0 option forwarding behavior.

### `ttl`

Adjusts response TTLs.

### `prefer_ipv4` and `prefer_ipv6`

Bias dual-stack results toward one IP family.

## Control Flow Executors

### `black_hole`

Absorbs requests without forwarding.

### `drop_resp`

Drops the response.

### `sleep`

Delays execution for testing or controlled pacing.

## Observability Executors

### `debug_print`

Prints request or response state for debugging.

### `query_summary`

Emits structured query summaries.

### `metrics_collector`

Collects metrics for operational dashboards and Prometheus-style exporters.

## Integration Executors

### `reverse_lookup`

Stores or uses reverse lookup information for later policy or diagnostics.

### `ipset`

Pushes response IPs into Linux `ipset`.

### `nftset`

Pushes response IPs into nftables sets.

### `mikrotik`

Synchronizes selected response results into MikroTik routing or address policies.

## Guidance

- Keep `sequence` as the main coordination point.
- Avoid placing expensive side effects early in the critical path unless needed.
- Reuse shared datasets and upstream pools instead of duplicating logic in executor config.

