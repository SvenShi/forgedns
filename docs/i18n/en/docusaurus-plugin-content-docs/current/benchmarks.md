---
title: Benchmarks
sidebar_position: 8
---

This page documents the benchmarking direction of ForgeDNS and how to reason about the results.

## Benchmark Goals

ForgeDNS benchmarks are intended to answer these questions:

- How short is the hot path under realistic policy composition?
- How much throughput is preserved when cache, fallback, and rewrites are enabled?
- How stable is latency under concurrent upstream traffic?
- How expensive are side effects such as metrics or route sync?

## Recommended Commands

```bash
cargo build --release
cargo run --release -- -c config.yaml
```

For local validation:

```bash
cargo test
cargo test --test plugin_integration
```

## What Matters

When reading benchmark numbers, focus on:

- p50 and p99 latency
- behavior under mixed workloads
- cache hit / miss performance
- upstream connection reuse
- impact of system integrations

Raw QPS alone is not enough. ForgeDNS is designed for policy-heavy DNS deployments where correctness, predictable latency, and composability matter together.

## Benchmark Methodology

- Use release builds.
- Use ephemeral environments with fixed upstream targets.
- Separate warm-up from steady-state runs.
- Compare simple forwarding, cache-heavy traffic, and policy-heavy scenarios independently.
- Record both latency and error behavior.

## Interpreting Results

High performance is only meaningful when the policy graph remains readable and operationally safe. ForgeDNS favors designs that scale with policy complexity, not just minimal toy workloads.

