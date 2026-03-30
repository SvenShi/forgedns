---
title: Executor Plugins
sidebar_position: 3
---

Executors are the core action layer in ForgeDNS. They can read or write requests, set responses, query upstreams, cache results, perform fallback logic, emit logs, or trigger system integrations.

When reading this chapter, keep two questions in mind:

1. Does this plugin act only in the forward stage, or can it also rewrite results on the return path?
2. Is it part of the main resolution path, or an observability and side-effect plugin?

---

## `sequence`

### Purpose

Orchestrates matchers and executors into a pipeline. This is the most common entry executor.

### Parameters

```yaml
- tag: seq_main
  type: sequence
  args:
    - matches: "$cache_hit"
      exec: "accept"
    - matches: "qname $local_domains"
      exec: "$hosts_main"
    - matches: "!$has_resp"
      exec: "$forward_main"
```

Each rule supports:

- `matches`
  - Optional matcher string or array of matcher strings.
- `exec`
  - Optional action, which can be a `$tag`, quick setup form, or built-in control flow.

### Configuration Details

#### `args`

- Type: `array`; Required: yes; Default: none
- Purpose: Defines the rule chain.
- Runtime impact:
  - Rules execute in order.
  - Initialization fails when the array is empty.

#### `args[].matches`

- Type: `string` or `array`
- Required: no
- Purpose: Match condition for the current rule.
- Runtime impact:
  - Multiple conditions are combined with logical AND.
  - Omitted means the rule has no precondition.

#### `args[].exec`

- Type: `string`; Required: no; Default: none
- Purpose: Action to run when the rule matches.
- Supports:
  - plugin references
  - quick setup expressions
  - built-in control flow

### Behavior

- Rules run sequentially.
- A rule with multiple `matches` requires all of them to be true.
- Other `sequence` instances can be called with `jump` or `goto`.

### Typical Uses

- One readable top-level entry.
- Split cache, local answers, forwarding, and integrations into understandable policy layers.
- Build complex branches with marks and matchers.

### Notes

- Referenced plugins must already exist.
- A `sequence` needs at least one rule.

---

## `forward`

### Purpose

Sends DNS queries to upstreams.

### Parameters

```yaml
- tag: forward_main
  type: forward
  args:
    concurrent: 2
    upstreams:
      - addr: "udp://1.1.1.1:53"
      - addr: "https://resolver.example/dns-query"
        bootstrap: "8.8.8.8:53"
        timeout: 5s
        enable_http3: true
```

### Configuration Details

#### `concurrent`

- Type: `integer`; Required: no; Default: `1`
- Runtime range is clamped to `1..=3`.
- Purpose: Number of concurrent upstream fan-out requests.

#### `upstreams`

- Type: `array`; Required: yes; Default: none
- Purpose: Defines one or more upstream targets.
- Runtime impact:
  - One upstream means normal forwarding.
  - More than one enables racing behavior.

#### `upstreams[].addr`

- Type: `string`; Required: yes
- Purpose: Upstream address, protocol, and target.
- Supports:
  - `udp://`
  - `tcp://`
  - `tcp+pipeline://`
  - `tls://`
  - `tls+pipeline://`
  - `quic://` / `doq://`
  - `https://` / `doh://`
  - `h3://`
- Notes:
  - No scheme means UDP.
  - DoH addresses should include the full request path.

#### `upstreams[].tag`

- Type: `string`; Required: no
- Purpose: Per-upstream log label.

#### `upstreams[].dial_addr`

- Type: `ip`; Required: no
- Purpose: Actual connection IP while preserving the hostname from `addr` for SNI, Host, and certificate validation.

#### `upstreams[].port`

- Type: `integer`; Required: no
- Purpose: Override the protocol default port.

#### `upstreams[].bootstrap`

- Type: `string`; Required: no
- Purpose: Bootstrap resolver for domain-based upstreams.

#### `upstreams[].bootstrap_version`

- Type: `integer`; Required: no
- Allowed values: `4`, `6`
- Purpose: Force bootstrap resolution toward IPv4 or IPv6.

#### `upstreams[].socks5`

- Type: `string`; Required: no
- Purpose: SOCKS5 proxy for upstream connections.
- Supports:
  - `host:port`
  - `username:password@host:port`

#### `upstreams[].idle_timeout`

- Type: `integer`; Required: no
- Unit: seconds
- Purpose: Idle pooled connection lifetime.

#### `upstreams[].max_conns`

- Type: `integer`; Required: no
- Purpose: Maximum pooled connections.

#### `upstreams[].insecure_skip_verify`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Skip TLS certificate validation.

#### `upstreams[].timeout`

- Type: `duration`; Required: no; Default: `5s`
- Purpose: Per-upstream query timeout.

#### `upstreams[].enable_pipeline`

- Type: `boolean`; Required: no
- Purpose: Enable pipelining for TCP or DoT.

#### `upstreams[].enable_http3`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Use HTTP/3 for DoH.

#### `upstreams[].so_mark`

- Type: `integer`; Required: no
- Purpose: Linux `SO_MARK`.

#### `upstreams[].bind_to_device`

- Type: `string`; Required: no
- Purpose: Linux `SO_BINDTODEVICE`.

### quick setup

```yaml
- exec: "forward 1.1.1.1"
- exec: "forward 1.1.1.1 8.8.8.8"
```

Quick setup accepts only upstream addresses. Use the full plugin form for bootstrap, proxy, HTTP/3, or pool settings.

### Behavior

- Single-upstream mode queries the configured upstream directly.
- Multi-upstream mode races queries from a randomized starting point and keeps the first successful answer.
- When combined with `prefer_ipv4` or `prefer_ipv6`, it can run preferred-family probes.

### Typical Uses

- Standard forwarding
- Multi-upstream resilience
- Mixed-protocol upstream groups

### Notes

- More upstreams are not automatically better. Keep upstream groups semantically clear.

---

## `cache`

### Purpose

Provides TTL-aware response caching with negative cache support and persistence.

### Parameters

```yaml
- tag: cache_main
  type: cache
  args:
    size: 8192
    short_circuit: true
    cache_negative: true
```

### Configuration Details

#### `size`

- Type: `integer`; Required: no; Default: implementation default
- Purpose: Cache capacity.

#### `lazy_cache_ttl`

- Type: `duration`; Required: no
- Purpose: Serve stale entries briefly while refreshing lazily.

#### `dump_file`

- Type: `string`; Required: no
- Purpose: Persistence dump file path.

#### `dump_interval`

- Type: `duration`; Required: no
- Purpose: Periodic dump interval.

#### `short_circuit`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Stop the chain when the cache produces a response.

#### `cache_negative`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Cache negative responses.

#### `max_negative_ttl`

- Type: `duration`; Required: no
- Purpose: Cap negative-cache TTL.

#### `negative_ttl_without_soa`

- Type: `duration`; Required: no
- Purpose: Fallback TTL for negative answers without SOA.

#### `max_positive_ttl`

- Type: `duration`; Required: no
- Purpose: Cap positive-cache TTL.

#### `ecs_in_key`

- Type: `boolean`; Required: no
- Purpose: Include ECS information in the cache key.

### Behavior

- Reads from cache on the forward path and writes responses on the return path.
- Respects DNS TTL semantics instead of using a fixed timeout.
- Can persist cache contents through dump and load operations.

### Plugin API

- `GET /plugins/<cache_tag>/flush`
- `GET /plugins/<cache_tag>/dump`
- `POST /plugins/<cache_tag>/load_dump`

### Typical Uses

- Lower upstream latency
- Protect upstreams from repeated identical traffic
- Preserve warm cache state across restarts

### Notes

- Decide carefully whether ECS should be part of the cache key. It improves correctness for ECS-aware policies but reduces hit ratio.

---

## `fallback`

### Purpose

Runs a primary executor first and falls back to a secondary executor when the primary is too slow or fails.

### Parameters

```yaml
- tag: fallback_main
  type: fallback
  args:
    primary: "forward_fast"
    secondary: "forward_stable"
    threshold: 200
    always_standby: false
```

### Configuration Details

#### `primary`

- Type: `string`; Required: yes
- Purpose: Primary executor tag.

#### `secondary`

- Type: `string`; Required: yes
- Purpose: Secondary executor tag.

#### `threshold`

- Type: `integer`; Required: no
- Unit: milliseconds
- Purpose: Delay before the secondary is allowed to take over.

#### `always_standby`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Keep the secondary in standby for all requests rather than only after the threshold condition.

### Behavior

- Provides controlled degradation instead of unconditional double-querying.
- Useful when one path is usually faster but another path is more complete or stable.

### Typical Uses

- Low-latency primary plus stable backup
- Tail-latency protection

### Notes

- A too-aggressive threshold can turn the secondary into a routine dependency.

---

## `hosts`

### Purpose

Returns local static answers using host-style entries.

### Parameters

```yaml
- tag: hosts_main
  type: hosts
  args:
    entries:
      - "full:router.local 192.168.1.1"
    files:
      - "/etc/forgedns/hosts.txt"
```

### Configuration Details

#### `entries`

- Type: `array`; Required: no
- Purpose: Inline host rules.

#### `files`

- Type: `array`; Required: no
- Purpose: External host files.

### Behavior

- Produces local answers directly.
- Commonly used before forwarding.

### Typical Uses

- Local service discovery
- Small fixed overrides

---

## `arbitrary`

### Purpose

Injects arbitrary DNS records from zone-style rule strings.

### Parameters

```yaml
- tag: arbitrary_main
  type: arbitrary
  args:
    rules:
      - "status.local. 60 IN TXT \"ok\""
```

### Configuration Details

#### `rules`

- Type: `array`; Required: no
- Purpose: Inline record rules.

#### `files`

- Type: `array`; Required: no
- Purpose: External rule files.

### Behavior

- Produces fully synthetic answers.
- Useful when `hosts` is too limited.

### Typical Uses

- TXT test records
- Local authority-style data

### Notes

- Keep rule files readable. Arbitrary records become hard to audit faster than `hosts` entries.

---

## `redirect`

### Purpose

Rewrites matching names toward different target names or answer destinations.

### Parameters

```yaml
- tag: redirect_main
  type: redirect
  args:
    rules:
      - "domain:ads.example sinkhole.local"
```

### Configuration Details

#### `rules`

- Type: `array`; Required: no
- Purpose: Inline redirect rules.

#### `files`

- Type: `array`; Required: no
- Purpose: External redirect rule files.

### Behavior

- Applies name-level redirection before or during answer generation depending on the rule form.

### Typical Uses

- Sinkholes
- Internal rewrites
- Controlled override of known domains

### Notes

- Be explicit about rule scope to avoid broad accidental rewrites.

---

## `reverse_lookup`

### Purpose

Maintains a reverse IP-to-name cache and optionally handles PTR requests.

### Parameters

```yaml
- tag: reverse_lookup_main
  type: reverse_lookup
  args:
    size: 8192
    handle_ptr: true
    ttl: 600
```

### Configuration Details

#### `size`

- Type: `integer`; Required: no
- Purpose: Reverse cache capacity.

#### `handle_ptr`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Answer PTR requests from the reverse cache.

#### `ttl`

- Type: `duration`; Required: no
- Purpose: Reverse cache retention TTL.

### Behavior

- Learns from successful responses.
- Can expose cached domain names for IP lookups and PTR handling.

### Plugin API

- `GET /plugins/<tag>?ip=<ip_addr>`

### Typical Uses

- Debugging resolved destinations
- Supporting PTR-like introspection for learned answers

### Notes

- This is an auxiliary index, not a replacement for authoritative PTR data.

---

## `ecs_handler`

### Purpose

Controls EDNS Client Subnet forwarding or injection.

### Parameters

```yaml
- tag: ecs_main
  type: ecs_handler
  args:
    forward: true
    send: true
    mask4: 24
    mask6: 56
```

### Configuration Details

#### `forward`

- Type: `boolean`; Required: no
- Purpose: Preserve ECS from the client side.

#### `send`

- Type: `boolean`; Required: no
- Purpose: Send ECS to upstreams.

#### `preset`

- Type: `string`; Required: no
- Purpose: Use a preset ECS source.

#### `mask4`

- Type: `integer`; Required: no
- Purpose: IPv4 ECS mask.

#### `mask6`

- Type: `integer`; Required: no
- Purpose: IPv6 ECS mask.

### quick setup

```yaml
- exec: "ecs_handler 24 56"
```

### Behavior

- Can preserve, synthesize, or normalize ECS before forwarding.
- Interacts with cache correctness if ECS is also part of the cache key.

### Typical Uses

- Geo-sensitive upstream policies
- Client-network-aware answers

### Notes

- Keep ECS handling and cache-key policy aligned.

---

## `forward_edns0opt`

### Purpose

Forwards selected EDNS0 options to upstreams.

### Parameters

```yaml
- tag: opt_forward
  type: forward_edns0opt
  args:
    codes: [8, 10]
```

### Configuration Details

#### `codes`

- Type: `array`; Required: yes
- Purpose: EDNS0 option codes to preserve and forward.

### quick setup

```yaml
- exec: "forward_edns0opt 8 10"
```

### Behavior

- Keeps only selected EDNS0 options instead of blindly forwarding everything.

### Typical Uses

- Preserve specific client-side EDNS signaling needed by upstreams.

---

## `ttl`

### Purpose

Rewrites response TTL values.

### Parameters

```yaml
- tag: ttl_main
  type: ttl
  args:
    min: 60
    max: 600
```

### Configuration Details

#### `fix`

- Type: `duration`; Required: no
- Purpose: Force all TTLs to one fixed value.

#### `min`

- Type: `duration`; Required: no
- Purpose: Lower bound for TTLs.

#### `max`

- Type: `duration`; Required: no
- Purpose: Upper bound for TTLs.

### quick setup

```yaml
- exec: "ttl 300"
```

### Behavior

- Adjusts TTLs on the response path.
- Can fix, clamp, or normalize TTLs.

### Typical Uses

- Stabilize answer retention
- Avoid extreme upstream TTL values

---

## `prefer_ipv4` / `prefer_ipv6` {#prefer_ipv4-prefer_ipv6}

### Purpose

Biases dual-stack results toward one address family.

### Parameters

```yaml
- tag: prefer_v4
  type: prefer_ipv4
  args:
    cache: true
    cache_ttl: 1800
```

### Configuration Details

#### `cache`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Cache preference decisions.

#### `cache_ttl`

- Type: `duration`; Required: no
- Purpose: Retention for the preference cache.

### Behavior

- Helps make A and AAAA selection more stable when both families exist.

### Typical Uses

- Prefer the family that works better on a given network
- Reduce dual-stack instability

### Notes

- Preference is not a substitute for fixing broken transport paths.

---

## `black_hole`

### Purpose

Returns sinkhole IPs directly.

### Parameters

```yaml
- tag: sinkhole
  type: black_hole
  args:
    ips:
      - "0.0.0.0"
      - "::"
```

### Configuration Details

#### `ips`

- Type: `array`; Required: yes
- Purpose: Sinkhole addresses to return.

### quick setup

```yaml
- exec: "black_hole 0.0.0.0 ::"
```

### Behavior

- Generates immediate answers that point to sinkhole addresses.

### Typical Uses

- Blocking domains
- Safe redirection away from real destinations

---

## `drop_resp`

### Purpose

Drops the current response.

### Parameters

No parameters.

### Configuration Details

No configuration fields.

### quick setup

```yaml
- exec: "drop_resp"
```

### Behavior

- Clears the existing response from context so later rules can continue.

### Typical Uses

- Discard unwanted intermediate results
- Force a later branch to rebuild the answer

---

## `sleep`

### Purpose

Sleeps for a bounded duration inside the chain.

### Parameters

```yaml
- tag: delay_main
  type: sleep
  args:
    duration: 100ms
```

### Configuration Details

#### `duration`

- Type: `duration`; Required: yes
- Purpose: Sleep duration.

### quick setup

```yaml
- exec: "sleep 100ms"
```

### Typical Uses

- Testing
- Timing experiments

---

## `debug_print`

### Purpose

Prints a debug message.

### Parameters

```yaml
- tag: dbg
  type: debug_print
  args:
    msg: "before forward"
```

### Configuration Details

#### `msg`

- Type: `string`; Required: yes
- Purpose: Message content.

### quick setup

```yaml
- exec: "debug_print before_forward"
```

### Typical Uses

- Temporary debugging
- Reading sequence flow during development

---

## `query_summary`

### Purpose

Records concise query summaries.

### Parameters

```yaml
- tag: summary_main
  type: query_summary
  args:
    msg: "main path"
```

### Configuration Details

#### `msg`

- Type: `string`; Required: no
- Purpose: Extra summary label.

### quick setup

```yaml
- exec: "query_summary main_path"
```

### Behavior

- Emits compact logs or summaries for operator visibility.

### Typical Uses

- Light observability on the main path
- Distinguish different branches

---

## `metrics_collector`

### Purpose

Collects Prometheus metrics for query handling.

### Parameters

```yaml
- tag: metrics_main
  type: metrics_collector
  args:
    name: "main"
```

### Configuration Details

#### `name`

- Type: `string`; Required: no
- Purpose: Metrics label namespace.

### quick setup

```yaml
- exec: "metrics_collector main"
```

### Behavior

- Exposes query counters, inflight counts, and latency metrics through the management API.

### API

- `GET /metrics`

### Typical Uses

- Prometheus integration
- Observe multiple policy entry points separately

---

## `ipset`

### Purpose

Writes response IPs into Linux `ipset`.

### Parameters

```yaml
- tag: ipset_main
  type: ipset
  args:
    set_name4: "policy_v4"
    set_name6: "policy_v6"
    mask4: 32
    mask6: 128
```

### Configuration Details

#### `set_name4`

- Type: `string`; Required: no
- Purpose: Target IPv4 ipset name.

#### `set_name6`

- Type: `string`; Required: no
- Purpose: Target IPv6 ipset name.

#### `mask4`

- Type: `integer`; Required: no
- Purpose: IPv4 network mask applied before insertion.

#### `mask6`

- Type: `integer`; Required: no
- Purpose: IPv6 network mask applied before insertion.

### quick setup

```yaml
- exec: "ipset policy_v4 policy_v6"
```

### Behavior

- Learns A and AAAA answers and writes them into system sets.

### Typical Uses

- Policy routing
- Firewall integration

### Notes

- This is Linux-specific and should stay off the most latency-sensitive path unless required.

---

## `nftset`

### Purpose

Writes response IPs into nftables sets.

### Parameters

```yaml
- tag: nftset_main
  type: nftset
  args:
    table_family4: "ip"
    table_name4: "filter"
    set_name4: "policy_v4"
```

### Configuration Details

#### `ipv4`

- Type: `boolean`; Required: no
- Purpose: Enable IPv4 writes.

#### `ipv6`

- Type: `boolean`; Required: no
- Purpose: Enable IPv6 writes.

#### `table_family4` / `table_family6`

- Type: `string`; Required: no
- Purpose: nft table family for IPv4 and IPv6.

#### `table_name4` / `table_name6`

- Type: `string`; Required: no
- Purpose: nft table name for IPv4 and IPv6.

#### `set_name4` / `set_name6`

- Type: `string`; Required: no
- Purpose: target nft set names.

#### `mask4` / `mask6`

- Type: `integer`; Required: no
- Purpose: network mask applied before insertion.

### quick setup

```yaml
- exec: "nftset filter policy_v4 policy_v6"
```

### Behavior

- Learns answer IPs and mirrors them into nftables sets.

### Typical Uses

- nftables-driven routing or firewall policies

### Notes

- Keep table family and set names consistent with system-side nft definitions.

---

## `ros_address_list`

### Purpose

Writes response IPs into MikroTik RouterOS address lists.

### Parameters

```yaml
- tag: ros_main
  type: ros_address_list
  args:
    address: "http://192.168.88.1"
    username: "admin"
    password: "password"
    address_list4: "policy_v4"
    address_list6: "policy_v6"
    async: true
```

### Configuration Details

#### `address`

- Type: `string`; Required: yes
- Purpose: RouterOS API endpoint.

#### `username`

- Type: `string`; Required: yes
- Purpose: RouterOS username.

#### `password`

- Type: `string`; Required: yes
- Purpose: RouterOS password.

#### `async`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Write updates asynchronously.

#### `address_list4`

- Type: `string`; Required: no
- Purpose: IPv4 address-list name.

#### `address_list6`

- Type: `string`; Required: no
- Purpose: IPv6 address-list name.

#### `comment_prefix`

- Type: `string`; Required: no
- Purpose: Prefix for generated RouterOS comments.

#### `persistent`

- Type: `object`; Required: no
- Purpose: Additional static or persistent entries merged with learned entries.

#### `persistent.ips`

- Type: `array`; Required: no
- Purpose: Inline persistent IPs.

#### `persistent.files`

- Type: `array`; Required: no
- Purpose: Files containing persistent IPs.

#### `min_ttl`

- Type: `duration`; Required: no
- Purpose: Lower TTL bound used for RouterOS entry timeout.

#### `max_ttl`

- Type: `duration`; Required: no
- Purpose: Upper TTL bound used for RouterOS entry timeout.

#### `fixed_ttl`

- Type: `duration`; Required: no
- Purpose: Force one fixed timeout value. Set it to `0` to create dynamic entries without a RouterOS `timeout`.

#### `cleanup_on_shutdown`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Remove learned entries during graceful shutdown.

### Behavior

- Learns A and AAAA answers and syncs them into RouterOS address lists.
- Can operate synchronously or asynchronously.
- Supports combining dynamic learned entries with persistent policy data.

### Typical Uses

- DNS-driven policy routing on RouterOS
- Maintaining dynamic destination groups from DNS answers

### Notes

- This plugin is primarily for control-plane integration. Keep side effects and response-path latency tradeoffs visible in your design.
