---
title: Configuration Overview
sidebar_position: 2
---

## Overview

ForgeDNS configuration is written in YAML. The top-level structure is composed of four sections:

```yaml
runtime:
  worker_threads: 4

api:
  http: "127.0.0.1:9088"

log:
  level: info
  file: ./forgedns.log

plugins:
  - tag: seq_main
    type: sequence
    args:
      - exec: "forward 1.1.1.1"
```

- `runtime`
  - Runtime parameters.
- `api`
  - Management API listeners and authentication.
- `log`
  - Log level and optional output file.
- `plugins`
  - All plugin instances. ForgeDNS assembles the full DNS path through plugins.

## Top-Level Fields

### `runtime`

```yaml
runtime:
  worker_threads: 4
```

- `worker_threads`
  - Number of Tokio multi-threaded worker threads.
  - Default: system parallelism.
  - Constraint: must not be `0`.

### `log`

```yaml
log:
  level: info
  file: ./forgedns.log
```

- `level`
  - Available values: `off` `trace` `debug` `info` `warn` `error`
  - Default: `info`
- `file`
  - Optional log file path. If omitted, logs are written to stdout only.

### `api`

`api.http` supports both shorthand and expanded syntax.

Shorthand:

```yaml
api:
  http: "127.0.0.1:9088"
```

Expanded:

```yaml
api:
  http:
    listen: "127.0.0.1:9443"
    ssl:
      cert: "/etc/forgedns/api.crt"
      key: "/etc/forgedns/api.key"
      client_ca: "/etc/forgedns/client-ca.crt"
      require_client_cert: true
    auth:
      type: basic
      username: "admin"
      password: "secret"
```

- `http.listen`
  - Listener address.
- `http.ssl.cert`
  - Server certificate path.
- `http.ssl.key`
  - Server private key path.
- `http.ssl.client_ca`
  - Optional client CA bundle.
- `http.ssl.require_client_cert`
  - Whether mutual TLS is required.
- `http.auth`
  - Currently supports `basic`.

Validation rules:

- `listen` must not be empty.
- `cert` and `key` must appear together.
- `require_client_cert: true` requires `client_ca`.
- `basic.username` and `basic.password` must both be non-empty.

### `plugins`

Each plugin instance uses a shared shape:

```yaml
- tag: cache_main
  type: cache
  args:
    size: 4096
```

- `tag`
  - Unique plugin instance identifier in the whole config.
- `type`
  - Registered plugin type name.
- `args`
  - Plugin-specific arguments. Depending on the plugin, this can be an object, string, array, or null.

## Plugin Responsibilities

### `server`

Receives DNS requests and hands them into an executor entrypoint.

- Focuses on listening sockets and transport details.
- Typically configures bind addresses, TLS, and an entry executor.

### `executor`

Performs actions such as:

- Upstream lookup
- Local answer generation
- Cache read/write
- TTL rewriting
- ECS handling
- Fallback and racing
- Observability and system integration

### `matcher`

Evaluates conditions for `sequence` rules, for example:

- Query name, type, class
- Client IP
- Response IP
- RCODE
- Environment variables
- Random rollout
- Rate limit state

### `provider`

Supplies reusable datasets for matchers and executors.

Current built-ins:

- `domain_set`
- `ip_set`

## The `sequence` Model

`sequence` is the control plane of non-trivial ForgeDNS configurations.

```yaml
- tag: seq_main
  type: sequence
  args:
    - matches:
        - "$lan_clients"
        - "qtype A"
      exec: "$cache_main"
    - matches: "!$has_resp"
      exec: "$forward_main"
    - exec: "accept"
```

Each rule has two core fields:

- `matches`
  - One matcher expression or an array of expressions.
  - All expressions in the array must evaluate to true.
- `exec`
  - The executor to run after the rule matches.

Execution semantics:

1. Rules are evaluated in order.
2. A rule runs when all match conditions succeed.
3. Some executors continue the pipeline, while others terminate it.
4. Typical terminal operations include local answers, upstream responses, `accept`, or `return`.

## Naming Suggestions

Prefer descriptive plugin tags such as:

- `udp_server`
- `seq_main`
- `forward_main`
- `cache_main`
- `fallback_main`

This makes large policy graphs much easier to read and maintain.

