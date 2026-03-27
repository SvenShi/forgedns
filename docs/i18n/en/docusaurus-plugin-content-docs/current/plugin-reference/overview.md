---
title: Plugin Overview
sidebar_position: 1
---

ForgeDNS plugins are organized into four layers:

- `server`
  - Network ingress. Accepts traffic and hands it to the policy entrypoint.
- `executor`
  - Performs actions such as forwarding, caching, rewriting, observability, and system integrations.
- `matcher`
  - Evaluates branch conditions for `sequence`.
- `provider`
  - Provides reusable datasets consumed by matchers and executors.

Recommended reading order:

1. Server plugins: understand how requests enter the system.
2. Executor plugins: understand what actually happens to requests and responses.
3. Matcher plugins: understand policy branching.
4. Provider plugins: understand how reusable rule sets are organized.

Typical composition:

```text
server -> sequence
  -> matcher decides
  -> executor acts
  -> provider supplies datasets
  -> upstream or side effect
```

