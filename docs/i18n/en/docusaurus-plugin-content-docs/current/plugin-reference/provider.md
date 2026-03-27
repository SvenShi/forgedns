---
title: Provider Plugins
sidebar_position: 5
---

Providers hold reusable datasets that can be shared across matchers and executors.

## `domain_set`

Stores reusable domain collections.

Typical uses:

- domestic / global splits
- ad or telemetry filtering
- service-specific policy groups

## `ip_set`

Stores reusable IP and CIDR collections.

Typical uses:

- LAN and infra network definitions
- allow / deny rules
- routing targets

## Why Providers Matter

Without providers, large policies become repetitive and hard to maintain. Providers let you define datasets once and reuse them everywhere.

Benefits:

- better readability
- less duplication
- easier updates
- cleaner separation between data and execution logic

