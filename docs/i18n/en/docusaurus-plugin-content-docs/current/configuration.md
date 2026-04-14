---
title: Configuration Overview
sidebar_position: 2
---

## Before You Start

ForgeDNS uses YAML configuration. The current top-level layout has four parts:

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

Where:

- `runtime`
  - Runtime parameters.
- `api`
  - Management API settings.
- `log`
  - Log output settings.
- `plugins`
  - All plugin instance definitions. ForgeDNS composes the full DNS pipeline from plugins.

## Top-Level Fields

### `runtime`

```yaml
runtime:
  worker_threads: 4
```

Field notes:

- `worker_threads`
  - Meaning: Number of Tokio multi-thread runtime workers.
  - Default: Uses system available parallelism when omitted.
  - Constraint: Must not be `0`.

### `log`

```yaml
log:
  level: info
  file: ./forgedns.log
  rotation:
    type: daily
    max_files: 7
```

Field notes:

- `level`
  - Allowed values: `off` `trace` `debug` `info` `warn` `error`
  - Default: `info`
- `file`
  - Meaning: Optional log file path.
  - If omitted, logs go only to stdout.
  - When configured, ForgeDNS writes to both stdout and the log file.
  - Log files are written as UTF-8 plain text without terminal ANSI color escape codes.
- `rotation`
  - Meaning: Log file rotation policy.
  - Default: `never`

`rotation` supports the following forms:

- `type: never`
- `type: minutely`
  - Rotate every minute.
- `type: hourly`
  - Rotate every hour.
- `type: daily`
  - Rotate every day.
- `type: weekly`
  - Rotate every week.
  - Optional `max_files` controls how many rotated files are retained; `0` disables automatic cleanup.

### `api`

`api.http` supports two forms.

Shorthand:

```yaml
api:
  http: "127.0.0.1:9088"
```

Expanded form:

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

Field notes:

- `http.listen`
  - API listen address.
- `http.ssl.cert`
  - API certificate file.
- `http.ssl.key`
  - API private key file.
- `http.ssl.client_ca`
  - Optional client certificate CA.
- `http.ssl.require_client_cert`
  - Whether mutual TLS is required.
- `http.auth`
  - Currently supports `basic`.
  - See the Management API chapter for the Basic Auth header encoding rules.

Validation rules:

- `listen` must not be empty.
- `cert` and `key` must be configured together.
- `require_client_cert: true` requires `client_ca`.
- `basic.username` and `basic.password` must both be non-empty.

### `plugins`

Each plugin definition uses the same outer structure:

```yaml
- tag: cache_main
  type: cache
  args:
    size: 4096
```

General rules:

- `tag`
  - Unique plugin instance identifier.
  - Must not be empty.
  - Must be unique across the whole config.
- `type`
  - Plugin type name.
  - Must match a registered plugin factory.
- `args`
  - Plugin parameters.
  - Different plugins accept different shapes: object, string, array, or null.

## Responsibilities of the Four Plugin Categories

### `server`

Purpose: Accept DNS requests and send them into an executor entry.

Traits:

- Does not implement complex policy logic.
- Usually configures a bind address, TLS parameters, and an entry executor.

### `executor`

Purpose: Perform actions.

Typical actions include:

- Query upstreams
- Generate local answers
- Read and write cache
- Adjust TTL
- Handle ECS
- Run fallback and concurrent races
- Perform observability and system integrations

### `matcher`

Purpose: Evaluate conditions for use in `sequence` rules.

Typical match dimensions include:

- Query name
- Query type
- Client IP
- Response IP
- Response code
- Environment variables
- Sampling outcome
- Rate-limit state

### `provider`

Purpose: Provide reusable datasets for matchers or other plugins.

Current main provider types:

- `domain_set`
- `ip_set`
- `geoip`
- `geosite`
- `adguard_rule`

## The `sequence` Orchestration Model

`sequence` is the policy hub of ForgeDNS. Most non-trivial configs use it as the primary entry.

Example:

```yaml
- tag: seq_main
  type: sequence
  args:
    - matches:
        - "$lan_clients"
        - "qtype 1"
      exec: "$cache_main"
    - matches: "!$has_resp"
      exec: "$forward_main"
    - exec: "accept"
```

Each rule has two key fields:

- `matches`
  - One matcher expression or an array of expressions.
  - When it is an array, every condition must be true for the rule to match.
- `exec`
  - The action to execute when the rule matches.

## Referencing Plugins and Quick Setup

### Reference Existing Plugins

Use `$tag` to reference a plugin that has already been defined:

```yaml
- exec: "$forward_main"
- matches:
    - "$is_internal"
    - "!$has_resp"
  exec: "$cache_main"
```

### Quick Setup

If a `sequence` rule uses `type + arguments` instead of `$tag`, ForgeDNS creates a temporary plugin on the fly.

Example:

```yaml
- exec: "forward 1.1.1.1 8.8.8.8"
- matches: "qname domain:example.com"
  exec: "ttl 300"
```

Common quick setup forms today:

- matcher
  - `_true`
  - `_false`
  - `qname ...`
  - `qtype ...`
  - `qclass ...`
  - `client_ip ...`
  - `resp_ip ...`
  - `ptr_ip ...`
  - `cname ...`
  - `mark ...`
  - `env ...`
  - `random ...`
  - `rate_limiter ...`
  - `rcode ...`
  - `has_resp`
  - `has_wanted_ans`
  - `string_exp ...`
- executor
  - `forward ...`
  - `ttl ...`
  - `sleep ...`
  - `debug_print ...`
  - `query_summary ...`
  - `metrics_collector ...`
  - `black_hole ...`
  - `drop_resp`
  - `ecs_handler ...`
  - `forward_edns0opt ...`
  - `ipset ...`
  - `nftset ...`

## Built-In `sequence` Control Flow

Besides calling plugins, `sequence.args[].exec` can also use built-in control flow:

### `accept`

- Ends the current `sequence` immediately.
- Marks the request flow as broken, so callers do not continue with later rules.
- Does not build a response by itself.
- Typical use:
  - Close out the pipeline after `cache`, `hosts`, or `arbitrary` has already written a response.
  - Stop later `forward` or side-effect stages once a branch has already made the decision.

### `return`

- Ends the current `sequence` immediately and returns control to the caller.
- Does not build a response and does not mark the flow as `Broken`.
- If the current `sequence` was entered via `jump`, the caller resumes at the rule after `jump`.
- If the current `sequence` is the top-level entry, this acts like an early exit from the current rule chain.

### `reject [rcode]`

- Builds a DNS response from the current request immediately and ends the current `sequence`.
- The default `rcode` is `REFUSED`, so plain `reject` means “reject this request”.
- You can provide a decimal numeric code explicitly, for example:
  - `reject 2` => `SERVFAIL`
  - `reject 3` => `NXDOMAIN`
- The parameter currently accepts decimal integers only, not mnemonic names such as `SERVFAIL`.
- Marks the request flow as broken, so callers do not continue with later rules.

### `mark ...`

- Inserts one or more unsigned integer marks into `DnsContext.marks`.
- Supported forms:
  - `mark 1`
  - `mark 1 2 3`
  - `mark 1,2,3`
- Continues to the next rule in the current `sequence`.
- Does not build a response and does not terminate the current `sequence`.

### `jump seq_tag`

- Calls another `sequence`; conceptually this behaves like a subroutine call.
- The parameter must be the target `sequence` tag without a leading `$`.
- If the called `sequence`:
  - reaches its tail normally, the current `sequence` resumes at the rule after `jump`.
  - executes `return`, the current `sequence` also resumes at the rule after `jump`.
  - executes `accept`, `reject`, or another flow-breaking operation, the current `sequence` stops as well.

### `goto seq_tag`

- Transfers control to another `sequence`; conceptually this behaves like a one-way jump.
- The parameter must be the target `sequence` tag without a leading `$`.
- The current `sequence` never resumes after `goto`:
  - If the target `sequence` reaches its tail, control does not return to the rules after `goto`.
  - If the target `sequence` executes `return`, control still does not return to the rules after `goto`.
  - If the target `sequence` executes `accept` or `reject`, that result propagates outward directly.
- This is useful when ownership of the request should be handed off permanently to another policy branch.

Example:

```yaml
- matches: "$rate_ok"
  exec: "mark 100"
- matches: "!$rate_ok"
  exec: "reject 2"
```

Example showing the difference between `jump` and `goto`:

```yaml
- tag: child_seq
  type: sequence
  args:
    - exec: "mark 2"
    - exec: "return"

- tag: parent_jump
  type: sequence
  args:
    - exec: "mark 1"
    - exec: "jump child_seq"
    - exec: "mark 3"

- tag: parent_goto
  type: sequence
  args:
    - exec: "mark 1"
    - exec: "goto child_seq"
    - exec: "mark 3"
```

- `parent_jump` ends with marks `1,2,3` because execution resumes after `jump`.
- `parent_goto` ends with marks `1,2` because execution never returns after `goto`.

## Common Rule Syntax

### Domain Rules

These forms appear in plugins such as `qname`, `cname`, `domain_set`, `hosts`, and `redirect`:

- `full:example.com`
  - Exact match.
- `domain:example.com`
  - Suffix match.
- `keyword:cdn`
  - Substring match.
- `regexp:^api[0-9]+\\.example\\.com$`
  - Regular-expression match.
- `example.com`
  - Without a prefix, this usually behaves like `domain:example.com`.

### IP Rules

These forms appear in `client_ip`, `resp_ip`, `ptr_ip`, `ip_set`, and related plugins:

- Single IP: `1.1.1.1`
- CIDR: `192.168.0.0/16`
- IPv6 CIDR: `2400:3200::/32`

### Provider References

Matchers and providers can reference providers through:

- `$tag`
  - References a defined provider with the required match capability.
  - Domain-oriented references can target `domain_set` or `geosite`.
  - IP-oriented references can target `ip_set` or `geoip`.
- `&/path/to/file`
  - Loads rules directly from a file.

Example:

```yaml
args:
  - "domain:example.com"
  - "$core_domains"
  - "&/etc/forgedns/domains.txt"
```

## Unified Upstream Structure

`forward.upstreams` uses a shared `UpstreamConfig` shape.

Example:

```yaml
upstreams:
  - addr: "udp://1.1.1.1:53"
  - addr: "https://resolver.example/dns-query"
    bootstrap: "8.8.8.8:53"
    timeout: 5s
    enable_http3: true
```

Common fields:

- `addr`
  - Upstream address.
  - Defaults to UDP when no scheme is given.
  - Supports `udp://`, `tcp://`, `tcp+pipeline://`, `tls://`, `tls+pipeline://`, `quic://`, `doq://`, `https://`, `doh://`, and `h3://`.
  - DoH should include the full path, for example `https://resolver.example/dns-query`.
- `dial_addr`
  - Actual connection IP, while keeping the hostname from `addr` for SNI and certificate validation.
- `port`
  - Overrides the port.
- `bootstrap`
  - Bootstrap DNS used to resolve the upstream hostname when `addr` is domain-based.
- `bootstrap_version`
  - `4` or `6`.
- `socks5`
  - SOCKS5 proxy.
  - Supports `host:port` and `user:pass@host:port`.
  - IPv6 must use `[addr]:port`.
- `idle_timeout`
  - Idle connection timeout in seconds.
- `max_conns`
  - Maximum pool size.
- `insecure_skip_verify`
  - Skips TLS certificate validation. Recommended only for test environments.
- `timeout`
  - Per-query timeout. Default: `5s`.
- `enable_pipeline`
  - Enables TCP or DoT pipelining.
- `enable_http3`
  - Uses HTTP/3 for DoH.
- `so_mark`
  - Linux `SO_MARK`.
- `bind_to_device`
  - Linux `SO_BINDTODEVICE`.
