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

### Example Configuration

```yaml
- tag: seq_main
  type: sequence
  args:
    # Try cache first
    - exec: "$cache_main"
    # Stop immediately on cache hit
    - matches: "has_resp"
      exec: "accept"
    # Arrays of matches are AND-ed together
    # Examples prefer quick-setup matcher expressions directly
    - matches:
        - "client_ip $lan_ip_set"
        - "qname $local_domains"
      exec: "$hosts_main"
    # Rules may also execute unconditionally
    - exec: "$metrics_main"
    # Only forward when no response exists yet
    - matches: "!has_resp"
      exec: "$forward_main"
    # Normalize TTL after a response is available
    - matches: "has_resp"
      exec: "$ttl_main"
```

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

### Built-In Control Flow

Besides plugin calls, `sequence.args[].exec` can also use built-in control flow:

#### `accept`

- Ends the current `sequence` immediately.
- This is an explicit early stop, so outer callers do not continue with later rules.
- Does not build a response by itself; it is usually used after an earlier stage has already produced one.

#### `return`

- Ends the current `sequence` immediately and gives control back to the caller.
- Does not build a response.
- If the current `sequence` was entered by `jump`, the caller continues with the next rule.

#### `reject [rcode]`

- Builds a response immediately and ends the current `sequence`.
- The default `rcode` is `REFUSED`.
- Only decimal numeric rcodes are accepted, for example `reject 2` or `reject 3`.
- Stops later rules from running.

#### `mark ...`

- Inserts one or more integer marks, then continues to the next rule in the current `sequence`.
- Supports `mark 1`, `mark 1 2 3`, and `mark 1,2,3`.

#### `jump seq_tag`

- Calls another `sequence`; conceptually this is a subroutine call.
- The parameter must be the target `sequence` tag without `$`.
- If the target `sequence` reaches its tail or executes `return`, the current `sequence` resumes with the next rule.
- If the target `sequence` executes `accept`, `reject`, or another `Stop`, the current `sequence` stops too.

#### `goto seq_tag`

- Transfers control one-way to another `sequence`.
- The parameter must be the target `sequence` tag without `$`.
- Once `goto` runs, the current `sequence` never resumes at later rules.
- If the target `sequence` executes `return`, that `return` is propagated outward.

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

### Example Configuration

```yaml
- tag: forward_main
  type: forward
  args:
    # Effective fan-out in multi-upstream mode
    concurrent: 3
    upstreams:
      # Simplest UDP upstream
      - tag: "cf_udp"
        addr: "udp://1.1.1.1:53"
        timeout: 3s

      # Domain-based DoH upstream showing bootstrap, pooling, HTTP/3,
      # and Linux socket options
      - tag: "doh_main"
        addr: "https://resolver.example/dns-query"
        bootstrap: "8.8.8.8:53"
        bootstrap_version: 4
        port: 443
        idle_timeout: 30
        max_conns: 256
        timeout: 5s
        enable_pipeline: false
        enable_http3: true
        so_mark: 100
        bind_to_device: "eth0"

      # DoT upstream showing dial_addr, SOCKS5, TLS verification, and pipelining
      - tag: "dot_backup"
        addr: "tls://dns.example:853"
        dial_addr: "203.0.113.53"
        socks5: "user:pass@127.0.0.1:1080"
        idle_timeout: 60
        max_conns: 128
        insecure_skip_verify: false
        timeout: 4s
        enable_pipeline: true
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

#### `short_circuit`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Stop the executor chain after a successful upstream response.
- Notes:
  - When disabled, `forward` still populates `response`, but later executors can continue processing it.
  - When enabled, a successful upstream result immediately ends the remaining executor chain.

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
- exec: "forward 1.1.1.1 short_circuit=true"
```

Quick setup supports the trailing flag forms `short_circuit`, `short_circuit=true`, and `short_circuit=false`.
Use the full plugin form for bootstrap, proxy, HTTP/3, pool settings, and other advanced options.

### Behavior

- Single-upstream mode queries the configured upstream directly.
- Multi-upstream mode races queries from a randomized starting point and keeps the first successful answer.
- When combined with `prefer_ipv4` or `prefer_ipv6`, it can run preferred-family probes.
- With `short_circuit` enabled, a successful upstream response stops the remaining executor chain immediately.

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

### Example Configuration

```yaml
- tag: cache_main
  type: cache
  args:
    # Maximum number of cached entries
    size: 8192
    # Stop the chain immediately when cache returns a response
    short_circuit: true
    # Serve stale responses briefly after original TTL expiry and refresh lazily
    lazy_cache_ttl: 120
    # Cache NXDOMAIN / NODATA responses too
    cache_negative: true
    # Upper bound for negative-cache TTL
    max_negative_ttl: 300
    # Fallback TTL when a negative response has no SOA
    negative_ttl_without_soa: 60
    # Upper bound for positive TTL
    max_positive_ttl: 600
    # Exclude ECS from the cache key for a better hit ratio
    ecs_in_key: false
    # Persist cache contents to disk
    dump_file: "./dns_cache.dump"
    # Periodic dump interval in seconds
    dump_interval: 600
```

### Configuration Details

#### `size`

- Type: `integer`; Required: no; Default: implementation default
- Purpose: Cache capacity.

#### `lazy_cache_ttl`

- Type: `duration`; Required: no
- Purpose: Enable lazy cache for successful positive responses.
- Behavior:
  - The original response TTL still defines the fresh-hit window.
  - `lazy_cache_ttl` defines the stale reply TTL and keeps entries briefly available after freshness expires.
  - Stale hits trigger an asynchronous background refresh.
  - This setting does not shorten the original fresh TTL.

#### `dump_file`

- Type: `string`; Required: no
- Purpose: Persistence dump file path.

#### `dump_interval`

- Type: `duration`; Required: no
- Purpose: Periodic dump interval.

#### `short_circuit`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Stop the chain when the cache produces a response.
- Notes:
  - When set to `false`, later executors still run even if cache has already populated `response`.
  - If you want to skip later `forward` stages on cache hits, handle it explicitly in `sequence`, for example with `has_resp` or `accept`.

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

### quick setup

```yaml
- exec: "cache"
- exec: "cache short_circuit=true"
```

- With no arguments, quick setup uses the default cache configuration.
- It currently supports the trailing flag forms `short_circuit`, `short_circuit=true`, and `short_circuit=false`.
- Use the full plugin form for other advanced settings.

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

### Example Configuration

```yaml
- tag: fallback_main
  type: fallback
  args:
    # Preferred path
    primary: "forward_fast"
    # Backup path
    secondary: "forward_stable"
    # Let the backup take over after 200 ms
    threshold: 200
    # Keep the backup running in parallel for lower tail latency
    always_standby: true
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

#### `short_circuit`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Stop the executor chain after fallback selects the winning response.

### Behavior

- Provides controlled degradation instead of unconditional double-querying.
- Useful when one path is usually faster but another path is more complete or stable.
- With `short_circuit` enabled, the winning branch writes its response and then immediately stops the remaining executor chain.

### Typical Uses

- Low-latency primary plus stable backup
- Tail-latency protection

### Notes

- A too-aggressive threshold can turn the secondary into a routine dependency.

---

## `hosts`

### Purpose

Returns local static answers using host-style entries.

### Example Configuration

```yaml
- tag: hosts_main
  type: hosts
  args:
    entries:
      # Unprefixed rules default to full:
      - "router.local 192.168.1.1"
      # Exact-name rule
      - "full:gateway.local 192.168.1.2"
      # Suffix rule returning both IPv4 and IPv6
      - "domain:svc.local 10.0.0.10 fd00::10"
      # Keyword rule
      - "keyword:nas 192.168.1.20"
      # Regex rule
      - "regexp:^api[0-9]+\\.corp\\.local$ 10.10.0.5"
    files:
      # Merge more hosts rules from files
      - "/etc/forgedns/hosts.txt"
    short_circuit: true
```

### Configuration Details

#### `entries`

- Type: `array`; Required: no; Default: empty array
- Purpose: Defines inline hosts rules.
- Rule format:
  - `<domain_rule> <ip1> <ip2> ...`

#### `files`

- Type: `array`; Required: no; Default: empty array
- Purpose: Specifies the list of external hosts rule files.

#### `short_circuit`

- Type: `bool`; Required: no; Default: `false`
- Purpose: Stops the remaining executor chain after a local answer is generated.

Rule format:

```text
<domain_rule> <ip1> <ip2> ...
```

### Behavior

- Handles only `IN` class `A` / `AAAA` requests with exactly one question.
- Unprefixed rules default to `full:` to match mosdns `hosts`.
- Rule-family priority is fixed as `full -> domain -> regexp -> keyword`.
- `domain:` uses the longest matching suffix.
- Repeated patterns use last-write-wins semantics in load order: inline `entries` first, then each configured file line by line.
- Positive local answers return same-family addresses with a fixed TTL of `10`.
- If the domain matches but the requested address family is missing, the plugin returns `NoError + empty answer + fake SOA` instead of passing through.
- Non-matching queries pass through to subsequent execution.
- By default it keeps running the remaining chain after a local response; enable `short_circuit` to stop immediately for both positive and empty local replies.

### Typical Uses

- Local service discovery
- Small fixed overrides

---

## `arbitrary`

### Purpose

Injects arbitrary DNS records from zone-style rule strings.

### Example Configuration

```yaml
- tag: arbitrary_main
  type: arbitrary
  args:
    rules:
      # TXT record
      - "example.com. 60 IN TXT \"hello world\""
      # MX record
      - "mail.example.com. 300 IN MX 10 mx1.example.com."
      # A / AAAA / CNAME / PTR records are also supported
      - "www.example.com. 120 IN A 192.0.2.10"
      - "www.example.com. 120 IN AAAA 2001:db8::10"
      - "alias.example.com. 120 IN CNAME www.example.com."
      - "10.2.0.192.in-addr.arpa. 300 IN PTR host.example.com."
    files:
      # Load more static records from files
      - "/etc/forgedns/zone.txt"
    short_circuit: false
```

### Configuration Details

#### `rules`

- Type: `array`; Required: no
- Purpose: Inline record rules.
- Syntax:
  - Each list item is parsed as an independent zone snippet.
  - Supports `$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE`, owner inheritance, TTL units, comments, quoted strings, and multiline `(` `)` syntax.
  - Common record types are parsed directly, including `A`, `AAAA`, `CNAME`, `NS`, `PTR`, `DNAME`, `ANAME`, `MD`, `MF`, `MB`, `MG`, `MR`, `NSAPPTR`, `MX`, `RT`, `AFSDB`, `RP`, `MINFO`, `HINFO`, `TXT`, `SPF`, `AVC`, `RESINFO`, `SOA`, `SRV`, `NAPTR`, and `CAA`.
  - Other record types can be loaded through RFC3597 generic syntax: `TYPE#### \# <len> <hex>`.
  - Defaults TTL to `3600` when omitted.

#### `files`

- Type: `array`; Required: no
- Purpose: External rule files.
- Syntax: Uses the same zone parser as `rules`.

#### `short_circuit`

- Type: `bool`; Required: no; Default: `false`
- Purpose: Stop the remaining executor chain after setting a synthetic response.
- Notes: By default `arbitrary` only sets the response and lets the chain continue.

### Behavior

- Produces fully synthetic answers.
- Matches exactly on `qname + qtype + qclass`.
- When a request carries multiple questions, all matched records are accumulated into one response.
- By default the executor only sets the response and keeps the remaining chain running.
- When `short_circuit` is enabled it returns `Stop` after a match.
- Quick setup syntax is intentionally not supported.
- Useful when `hosts` is too limited.

### Typical Uses

- TXT test records
- Local authority-style data

### Notes

- Keep rule files readable. Arbitrary records become hard to audit faster than `hosts` entries.
- This is still a static answer generator, not a full authoritative server with transfer or dynamic update support.
- The parser is broader than the zone parser used by mosdns `arbitrary`, but matching remains an exact static lookup.

---

## `redirect`

### Purpose

Rewrites matching names toward different target names or answer destinations.

### Example Configuration

```yaml
- tag: redirect_main
  type: redirect
  args:
    rules:
      # Exact-name redirect
      - "full:old.example.com new.example.net"
      # Suffix redirect
      - "domain:legacy.example.com modern.example.net"
      # Keyword redirect
      - "keyword:staging staging-gateway.example.net"
    files:
      # Merge more redirect rules from files
      - "/etc/forgedns/redirect.txt"
```

### Configuration Details

#### `rules`

- Type: `array`; Required: no; Default: empty array
- Purpose: Defines inline redirect rules.
- Rule format:
  - `<domain_rule> <target_name>`

#### `files`

- Type: `array`; Required: no; Default: empty array
- Purpose: Specifies the list of external redirect rule files.

Rule format:

```text
<domain_rule> <target_name>
```

### Behavior

- Forward phase:
  - Rewrites the request QUESTION NAME.
- Return phase:
  - Restores the target name in the response question back to the original name.
  - Appends a `CNAME original -> target` record in the answers.

### Typical Uses

- Point a unified entry domain to another set of records.
- Perform alias redirection for specific domains without changing client configuration.

### Notes

- It is better suited for simple queries such as `A` / `AAAA` / `TXT`.
- Full semantic transparency is not guaranteed for complex records and some extension scenarios.

---

## `ecs_handler`

### Purpose

Controls EDNS Client Subnet forwarding or injection.

### Example Configuration

```yaml
- tag: ecs_main
  type: ecs_handler
  args:
    # Strip client-supplied ECS first
    forward: false
    # Add ECS when the request has none
    send: true
    # IPv4 ECS prefix length
    mask4: 24
    # IPv6 ECS prefix length
    mask6: 48

- tag: ecs_preset
  type: ecs_handler
  args:
    # Preset ECS source
    preset: "203.0.113.10"
    # Fixed-source mode usually keeps these switches explicit
    forward: false
    send: true
    mask4: 24
    mask6: 48
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
- exec: "ecs_handler 203.0.113.10/24"
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

### Example Configuration

```yaml
- tag: edns_forward
  type: forward_edns0opt
  args:
    # Preserve only the selected EDNS0 option codes
    codes: [10, 12]
```

### Configuration Details

#### `codes`

- Type: `array`; Required: yes
- Purpose: EDNS0 option codes to preserve and forward.

### quick setup

```yaml
- exec: "forward_edns0opt 10,12"
```

### Behavior

- Keeps only selected EDNS0 options instead of blindly forwarding everything.

### Typical Uses

- Preserve specific client-side EDNS signaling needed by upstreams.

---

## `ttl`

### Purpose

Rewrites response TTL values.

### Example Configuration

Full object form:

```yaml
- tag: ttl_main
  type: ttl
  args:
    # First force TTL to 300
    fix: 300
    # Then keep a lower bound
    min: 60
    # And cap the upper bound
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
- exec: "ttl 60-600"
```

### Behavior

- Adjusts TTLs on the response path.
- Can fix, clamp, or normalize TTLs.

### Typical Uses

- Stabilize answer retention
- Avoid extreme upstream TTL values

---

<span id="prefer_ipv4-prefer_ipv6"></span>

## `prefer_ipv4` / `prefer_ipv6`

### Purpose

Biases dual-stack results toward one address family.

### Example Configuration

```yaml
- tag: prefer_v4
  type: prefer_ipv4
  args:
    # Cache whether the preferred family exists
    cache: true
    # Keep the preference cache for one hour
    cache_ttl: 3600
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

### Example Configuration

```yaml
- tag: sinkhole
  type: black_hole
  args:
    ips:
      # Returned for A queries
      - "0.0.0.0"
      # Returned for AAAA queries
      - "::"
    short_circuit: true
```

### Configuration Details

#### `ips`

- Type: `array`; Required: yes
- Purpose: Sinkhole addresses to return.

#### `short_circuit`

- Type: `bool`; Required: no; Default: `false`
- Purpose: Stops the remaining executor chain after a local answer is generated.

### quick setup

```yaml
- exec: "black_hole 0.0.0.0 ::"
- exec: "black_hole 0.0.0.0 :: short_circuit=true"
```

### Behavior

- Generates immediate answers that point to sinkhole addresses.
- By default it keeps running the remaining chain after a match; enable `short_circuit` to stop immediately.

### Typical Uses

- Blocking domains
- Safe redirection away from real destinations

---

## `drop_resp`

### Purpose

Drops the current response.

### Example Configuration

```yaml
- tag: clear_response
  type: drop_resp
  # No standalone args; execution simply clears the current response
```

### Configuration Details

No standalone configuration fields.

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

## `reverse_lookup`

### Purpose

Maintains a reverse IP-to-name cache and optionally handles PTR requests.

### Example Configuration

```yaml
- tag: reverse_lookup_main
  type: reverse_lookup
  args:
    # Reverse-cache capacity
    size: 65535
    # Retention time for IP -> name mappings
    ttl: 7200
    # Answer PTR directly from the learned cache
    handle_ptr: true
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

## `query_summary`

### Purpose

Records concise query summaries.

### Example Configuration

```yaml
- tag: summary_main
  type: query_summary
  args:
    # Extra title so multiple summary points are easy to distinguish
    msg: "main pipeline"
```

### Configuration Details

#### `msg`

- Type: `string`; Required: no
- Purpose: Extra summary label.

### quick setup

```yaml
- exec: "query_summary main"
```

### Behavior

- Emits compact logs or summaries for operator visibility.

### Typical Uses

- Light observability on the main path
- Distinguish different branches

---

## `query_recorder`

### Purpose

Persists the entry request, the post-`next` response, and `sequence` execution-path events into a recorder-owned SQLite database, then exposes history, aggregate stats, and an SSE stream.

### Example Configuration

```yaml
- tag: query_recorder_main
  type: query_recorder
  args:
    # SQLite path for this recorder. Different recorders should use different paths.
    path: "./data/query-recorder-main.sqlite"
    # Hot-path enqueue buffer size
    queue_size: 8192
    # Batch size per SQLite flush
    batch_size: 256
    # Background flush interval in milliseconds
    flush_interval_ms: 200
    # Number of recent records kept in memory for SSE tail replay
    memory_tail: 1024
    # Retention window in days; minimum 1
    retention_days: 7
    # Cleanup interval in hours; minimum 1
    cleanup_interval_hours: 1
```

### Configuration Details

#### `path`

- Type: `string`; Required: yes
- Purpose: SQLite path for this recorder.

#### `queue_size`

- Type: `integer`; Required: no; Default: `8192`
- Purpose: Bounded queue size between the request path and the writer thread.

#### `batch_size`

- Type: `integer`; Required: no; Default: `256`
- Purpose: Number of records flushed per SQLite batch.

#### `flush_interval_ms`

- Type: `integer`; Required: no; Default: `200`
- Purpose: Maximum batch flush interval in milliseconds.

#### `memory_tail`

- Type: `integer`; Required: no; Default: `1024`
- Purpose: Size of the in-memory tail used by `stream?tail=n`.

#### `retention_days`

- Type: `integer`; Required: no; Default: `7`; Minimum: `1`
- Purpose: Record retention window. Expired rows are deleted by the cleanup task.

#### `cleanup_interval_hours`

- Type: `integer`; Required: no; Default: `1`; Minimum: `1`
- Purpose: Cleanup task cadence.

### Behavior

- This is a pure executor observer and does not change server finalization logic.
- It captures a structured snapshot of the entry request, enables `DnsContext.execution_path`, runs `next`, and commits immediately after `next` returns.
- Successful runs store the current response. Failed runs store `error` and an empty response shape.
- Request and response payloads are not stored as wire blobs. Question, RR, and EDNS fields are extracted into JSON text columns.
- Each recorder uses exactly two tables:
  - `qr_<safe_tag>_<fnv64hex>_v1_records`
  - `qr_<safe_tag>_<fnv64hex>_v1_steps`
- `records` contains only the fixed schema fields for structured snapshots. `steps` stores `sequence` path events for path analysis and hit-rate reporting.
- Every recorder owns its own bounded queue, SQLite connection, writer thread, tail buffer, and SSE broadcaster.
- v1 assumes different recorders use different `path` values. There is no cross-recorder writer sharing or path coordination.

### Data Shape

- `questions_json` is always a question array, for example:

```json
[
  { "name": "www.example.com.", "qtype": "A", "qclass": "IN" }
]
```

- `answers_json`, `authorities_json`, `additionals_json`, and `signature_json` are RR arrays, for example:

```json
[
  {
    "name": "www.example.com.",
    "class": "IN",
    "ttl": 300,
    "rr_type": "A",
    "payload_kind": "A",
    "payload_text": "192.0.2.1",
    "payload": { "ip": "192.0.2.1" }
  }
]
```

- `req_edns_json` and `resp_edns_json` are EDNS objects or `NULL`.
- The `v1` suffix in the table name is the schema version. Future upgrades add new versioned tables rather than altering the existing ones in place.

### API

- `GET /plugins/<tag>/records`
  - Returns record rows ordered by `created_at_ms` descending.
  - Query parameters:
    - `cursor=<created_at_ms>:<id>`
    - `limit=<n>`, default `100`, max `500`
    - `since_ms=<unix_ms>`
    - `until_ms=<unix_ms>`
- `GET /plugins/<tag>/records/<id>`
  - Returns one full record plus `steps`.
- `GET /plugins/<tag>/stats/overview`
  - Returns totals, error count, dropped count, and average latency.
  - Supports `since_ms` and `until_ms`.
- `GET /plugins/<tag>/stats/plugins`
  - Returns hit stats grouped by `matcher / executor / builtin`.
  - Supports `since_ms`, `until_ms`, and `kind=matcher|executor|builtin|all`.
- `GET /plugins/<tag>/stream`
  - Streams newly written records over SSE.
  - Supports `tail=<n>` to replay the in-memory tail.

### Typical Uses

- Persistent audit and troubleshooting trails
- `sequence` path analysis and plugin hit-rate reporting
- Real-time query log feeds for dashboards or control planes

### Notes

- Place the recorder close to the entry point if you want the full main-path trace.
- If an earlier branch short-circuits before the recorder, that request will not be recorded.
- If `next` fails and the server later emits a fallback response, the database still reflects the plugin's point of view: `error` plus an empty response.
- If the management API is disabled, the recorder still writes SQLite data but does not expose query or SSE routes.

---

## `metrics_collector`

### Purpose

Collects Prometheus metrics for query handling.

### Example Configuration

```yaml
- tag: metrics_main
  type: metrics_collector
  args:
    # Collector label exported through /metrics
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

## `debug_print`

### Purpose

Prints a debug message.

### Example Configuration

```yaml
- tag: debug_main
  type: debug_print
  args:
    # Log title; defaults to "debug print" when omitted
    msg: "before forward"
```

### Configuration Details

#### `msg`

- Type: `string`; Required: yes
- Purpose: Message content.

### quick setup

```yaml
- exec: "debug_print cache branch"
```

### Typical Uses

- Temporary debugging
- Reading sequence branches during development

---

## `sleep`

### Purpose

Sleeps for a bounded duration inside the chain.

### Example Configuration

```yaml
- tag: sleep_100ms
  type: sleep
  args:
    # Add 100 ms of async delay
    duration: 100
```

### Configuration Details

#### `duration`

- Type: `duration`; Required: yes
- Purpose: Sleep duration.

### quick setup

```yaml
- exec: "sleep 100"
```

### Typical Uses

- Testing
- Timing experiments

---

## `http_request`

### Purpose

Sends callback requests to external `http/https` services. It can trigger before the current DNS flow enters downstream executors or after downstream execution completes, which makes it suitable for webhooks, audit pipelines, alerts, and external integrations.

### Example Configuration

```yaml
- tag: webhook_notify_after
  type: http_request
  args:
    method: POST
    url: "https://hooks.example.com/dns"
    phase: after
    async: true
    timeout: 5s
    headers:
      X-Client-IP: "${client_ip}"
      X-Qname: "${qname}"
    query_params:
      source: "forgedns"
      qname: "${qname}"
    json:
      qname: "${qname}"
      client_ip: "${client_ip}"
      rcode: "${rcode_name}"
      resp_ip: "${resp_ip}"
```

### Config Fields

#### `args.method`

- Type: `string`; Required: yes
- Purpose: Selects the HTTP method such as `GET`, `POST`, `PUT`, `PATCH`, or `DELETE`.

#### `args.url`

- Type: `string`; Required: yes
- Purpose: The target URL.
- Notes: Supports `${key}` placeholder interpolation. The rendered URL must use either `http` or `https`.

#### `args.phase`

- Type: `string`; Required: no; Default: `after`
- Allowed values: `before`, `after`
- Purpose: Controls whether the request is sent before or after downstream executors run.

#### `args.async`

- Type: `boolean`; Required: no; Default: `true`
- Purpose: Chooses bounded background dispatch or inline synchronous dispatch.

#### `args.timeout`

- Type: `string`; Required: no; Default: `5s`
- Purpose: Caps the total time budget for one HTTP call.
- Supported units: `ms`, `s`, `m`, `h`, `d`

#### `args.error_mode`

- Type: `string`; Required: no; Default: `continue`
- Allowed values:
  - `continue`: only log the failure and keep running
  - `stop`: return `Stop` on failure
  - `fail`: return an executor error immediately

#### `args.headers`

- Type: `map<string,string>`; Required: no; Default: empty
- Purpose: Adds HTTP request headers.
- Notes: Header values support `${key}` placeholder interpolation.

#### `args.query_params`

- Type: `map<string,string>`; Required: no; Default: empty
- Purpose: Appends additional query parameters to the rendered URL.
- Notes: Values support `${key}` placeholder interpolation and are combined with any query already present in `args.url`.

#### `args.body`

- Type: `string`; Required: no
- Purpose: Sends a raw string body.
- Notes: Supports `${key}` placeholder interpolation and can be paired with `args.content_type`.

#### `args.json`

- Type: `object | array`; Required: no
- Purpose: Sends a JSON body.
- Notes: Automatically sets `Content-Type: application/json`. Every string leaf supports `${key}` interpolation while non-string values are preserved as-is.

#### `args.form`

- Type: `map<string,string>`; Required: no
- Purpose: Sends an `application/x-www-form-urlencoded` body.
- Notes: Values support `${key}` interpolation and the plugin automatically sets the matching `Content-Type`.

#### `args.content_type`

- Type: `string`; Required: no
- Purpose: Sets `Content-Type` for raw `args.body`.
- Notes: This helper can only be used with `args.body`, not with `args.json` or `args.form`.

#### `args.socks5`

- Type: `string`; Required: no
- Purpose: Routes requests through a SOCKS5 proxy.
- Notes: Uses the same format as `upstream[].socks5`, including `host:port`, `username:password@host:port`, and bracketed IPv6.

#### `args.insecure_skip_verify`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Skips HTTPS certificate validation.

#### `args.max_redirects`

- Type: `integer`; Required: no; Default: `5`
- Purpose: Limits how many redirects are followed.

#### `args.queue_size`

- Type: `integer`; Required: no; Default: `256`
- Purpose: Sets the bounded queue capacity used by async mode.

### Available Placeholders

- Same as `script`: `qname`, `qtype`, `qtype_name`, `qclass`, `qclass_name`
- Source fields: `client_ip`, `client_port`, `server_name`, `url_path`
- Runtime fields: `marks`, `has_resp`
- Response fields: `rcode`, `rcode_name`, `resp_ip`
- Cron metadata: `cron_plugin_tag`, `cron_job_name`, `cron_trigger_kind`, `cron_scheduled_at_unix_ms`

### Behavior

- With `phase: before`, the HTTP request is dispatched first and the downstream executor chain runs afterward.
- With `phase: after`, the downstream executor chain runs first and the HTTP request is dispatched against the resulting context.
- `async: true` uses a bounded background queue. Queue insertion failures are handled according to `error_mode`.
- `async: false` waits for the HTTP call on the current request path.
- Only terminal `2xx` responses are treated as success. `3xx` responses are followed up to `max_redirects`.
- The plugin drains and discards the HTTP response body so connections remain reusable, but it does not write that body back into `DnsContext`.
- If `Content-Type` is already set explicitly in `args.headers`, the plugin does not overwrite it.

### Notes

- `args.body`, `args.json`, and `args.form` are mutually exclusive.
- This is a side-effect executor. In v1 it cannot rewrite DNS requests, responses, marks, or attrs based on the HTTP result.
- v1 does not support multipart uploads or quick setup syntax.
- If you need both trigger moments, configure two separate `http_request` plugin instances.

---

## `script`

### Purpose

Runs an explicitly configured external command and injects a stable subset of the current `DnsContext` into command arguments or environment variables.

### Example

```yaml
- tag: script_notify
  type: script
  args:
    command: "bash"
    args:
      - "/opt/forgedns/notify.sh"
      - "${qname}"
      - "${client_ip}"
    env:
      FDNS_QNAME: "${qname}"
      FDNS_CLIENT_IP: "${client_ip}"
      FDNS_MARKS: "${marks}"
    timeout: "5s"
    error_mode: continue
    max_output_bytes: 4096
```

### Config Fields

#### `args.command`

- Type: `string`; Required: yes
- Purpose: Command path or program name to execute.
- Notes: This field is never templated.

#### `args.args`

- Type: `array<string>`; Required: no; Default: empty
- Purpose: Positional command arguments.
- Notes: Each item supports `${key}` interpolation.

#### `args.env`

- Type: `map<string,string>`; Required: no; Default: empty
- Purpose: Extra child-process environment variables.
- Notes: Values support `${key}` interpolation and overlay the inherited process environment.

#### `args.cwd`

- Type: `string`; Required: no; Default: none
- Purpose: Working directory for the child process.

#### `args.timeout`

- Type: `string`; Required: no; Default: `5s`
- Purpose: Maximum execution time for one script run.
- Supported units: `ms`, `s`, `m`, `h`, `d`

#### `args.error_mode`

- Type: `string`; Required: no; Default: `continue`
- Allowed values:
  - `continue`: log failure or timeout, then return `Next`
  - `stop`: log failure or timeout, then return `Stop`
  - `fail`: return an executor error immediately

#### `args.max_output_bytes`

- Type: `usize`; Required: no; Default: `4096`
- Purpose: Maximum captured stdout/stderr length before truncation.

### Available Placeholders

- Request fields: `qname`, `qtype`, `qtype_name`, `qclass`, `qclass_name`
- Source fields: `client_ip`, `client_port`, `server_name`, `url_path`
- Runtime fields: `marks`, `has_resp`
- Response fields: `rcode`, `rcode_name`, `resp_ip`
- Cron metadata: `cron_plugin_tag`, `cron_job_name`, `cron_trigger_kind`, `cron_scheduled_at_unix_ms`

### Behavior

- The plugin does not mutate DNS requests or responses.
- It runs only the explicit configured command and does not wrap it with `sh -c`, `cmd /c`, or similar shell shortcuts.
- Arguments and environment variables are rendered from the current `DnsContext` on each execution.
- On timeout the child process is terminated, then `error_mode` decides how the sequence continues.

### Notes

- v1 does not support quick setup syntax.
- `command` must not be empty.
- Only the documented built-in placeholders are accepted; unknown placeholders fail plugin initialization.
- This is a side-effect executor. It does not support writing attrs, marks, or DNS responses back through stdout.

---

## `ipset`

### Purpose

Writes response IPs into Linux `ipset` through the embedded Rust netlink backend, without requiring the runtime `ipset` command.

### Example Configuration

```yaml
- tag: ipset_main
  type: ipset
  args:
    # ipset used for A answers
    set_name4: "forgedns_v4"
    # ipset used for AAAA answers
    set_name6: "forgedns_v6"
    # Aggregate IPv4 writes to /24 prefixes
    mask4: 24
    # Aggregate IPv6 writes to /64 prefixes
    mask6: 64
```

### Configuration Details

#### `set_name4`

- Type: `string`; Required: no; Default: none
- Purpose: Specifies the ipset name used to write IPv4 addresses.

#### `set_name6`

- Type: `string`; Required: no; Default: none
- Purpose: Specifies the ipset name used to write IPv6 addresses.

#### `mask4`

- Type: `integer`; Required: no; Default: `24`
- Purpose: Specifies the prefix length used when writing IPv4 addresses into ipset.

#### `mask6`

- Type: `integer`; Required: no; Default: `32`
- Purpose: Specifies the prefix length used when writing IPv6 addresses into ipset.

### quick setup

```yaml
- exec: "ipset forgedns_v4,4,24 forgedns_v6,6,64"
```

Format:

```text
<set_name>,<family>,<mask>
```

Here, `family` is `4` or `6`.

### Behavior

- Extracts unique A/AAAA addresses from the answer section.
- Writes them into the corresponding set according to the address family.
- Delivers them to the background writer through a non-blocking queue.

### Typical Uses

- Policy routing
- Firewall integration

### Notes

- On non-Linux platforms it degrades to a no-op.
- When the queue is full, the side effect is dropped and does not block the DNS hot path.

---

## `nftset`

### Purpose

Writes response IPs into nftables sets through the embedded Rust netlink backend, without requiring the runtime `nft` command.

### Example Configuration

Structured form:

```yaml
- tag: nftset_main
  type: nftset
  args:
    ipv4:
      # IPv4 target uses the ip family
      table_family: "ip"
      table_name: "mangle"
      set_name: "dns_v4"
      mask: 24
    ipv6:
      # IPv6 target uses the ip6 family
      table_family: "ip6"
      table_name: "mangle"
      set_name: "dns_v6"
      mask: 64
```

Compatibility form:

```yaml
- tag: nftset_legacy
  type: nftset
  args:
    # Compatibility fields, useful when migrating old configs
    table_family4: "ip"
    table_name4: "mangle"
    set_name4: "dns_v4"
    mask4: 24
    table_family6: "ip6"
    table_name6: "mangle"
    set_name6: "dns_v6"
    mask6: 64
```

### Configuration Details

#### `ipv4`

- Type: `object`; Required: no; Default: none
- Purpose: Defines the target IPv4 nftables set.
- Child fields:
  - `table_family`
  - `table_name`
  - `set_name`
  - `mask`

#### `ipv6`

- Type: `object`; Required: no; Default: none
- Purpose: Defines the target IPv6 nftables set.
- Child fields:
  - `table_family`
  - `table_name`
  - `set_name`
  - `mask`

#### `table_family4` / `table_family6`

- Type: `string`; Required: no; Default: none
- Purpose: In the compatibility form, defines the nftables table family for IPv4 / IPv6 respectively.

#### `table_name4` / `table_name6`

- Type: `string`; Required: no; Default: none
- Purpose: In the compatibility form, defines the nftables table name for IPv4 / IPv6 respectively.

#### `set_name4` / `set_name6`

- Type: `string`; Required: no; Default: none
- Purpose: In the compatibility form, defines the set name for IPv4 / IPv6 respectively.

#### `mask4` / `mask6`

- Type: `integer`; Required: no; Default: implementation-defined
- Purpose: In the compatibility form, defines the prefix length for IPv4 / IPv6 respectively.

### quick setup

```yaml
- exec: "nftset ip,mangle,dns_v4,ipv4_addr,24 ip6,mangle,dns_v6,ipv6_addr,64"
```

Format:

```text
<family>,<table>,<set>,<type>,<mask>
```

### Behavior

- Extracts A/AAAA addresses.
- Writes nftables interval elements according to the prefix.
- Also uses the background writer so that the hot path remains non-blocking.

### Typical Uses

- nftables-driven routing or firewall policies

### Notes

- On non-Linux platforms it degrades to a no-op.

---

## `ros_address_list`

### Purpose

Writes response IPs into MikroTik RouterOS address lists, with dynamic entries, persistent entries, startup-time file loading, and shutdown cleanup.

### Example Configuration

```yaml
- tag: ros_address_list_main
  type: ros_address_list
  args:
    # RouterOS API endpoint
    address: "172.16.1.1:8728"
    # API username
    username: "api-user"
    # API password
    password: "secret"
    # Use asynchronous writes to avoid blocking the DNS hot path
    async: true
    # Address list used for A records
    address_list4: "forgedns_ipv4"
    # Address list used for AAAA records
    address_list6: "forgedns_ipv6"
    # Prefix for comments on ForgeDNS-managed entries
    comment_prefix: "forgedns"
    # Lower bound for dynamic-entry TTL
    min_ttl: 60
    # Upper bound for dynamic-entry TTL
    max_ttl: 3600
    # Force dynamic entries to 300 seconds; use 0 to omit RouterOS timeout
    fixed_ttl: 300
    # Remove owned entries when the plugin shuts down
    cleanup_on_shutdown: true
    persistent:
      ips:
        # Persistent single IP
        - "1.1.1.1"
        # Persistent IPv4 CIDR
        - "100.64.1.0/24"
        # Persistent IPv6 CIDR
        - "2001:db8::/64"
      files:
        # Load more persistent items from files
        - "/etc/forgedns/persistent_ips.txt"
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

- Type: `bool`; Required: no; Default: `true`
- Purpose: Controls whether address writes use asynchronous mode. When enabled, the DNS response path only submits tasks, and a background manager completes the RouterOS interaction.

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

- Type: `object`; Required: no; Default: none
- Purpose: Defines the static address set that should be kept for the long term. This part does not depend on DNS responses to trigger. After plugin startup it can be synchronized to RouterOS directly and then kept consistent by the reconcile loop.

#### `persistent.ips`

- Type: `array<string>`; Required: no; Default: empty
- Purpose: Declares persistent IPs or CIDR ranges inline.

#### `persistent.files`

- Type: `array<string>`; Required: no; Default: empty
- Purpose: Loads the persistent address set from external files at plugin startup.
- Notes: These files are read once during initialization. To apply later file changes, reload the plugin or the application.

#### `min_ttl`

- Type: `u64`; Required: no; Default: `60`
- Purpose: Defines the minimum TTL allowed for dynamic address entries.

#### `max_ttl`

- Type: `u64`; Required: no; Default: `3600`
- Purpose: Defines the maximum TTL allowed for dynamic address entries.

#### `fixed_ttl`

- Type: `u64`; Required: no; Default: none
- Purpose: Specifies one fixed TTL for all dynamically written entries. If it is set to `0`, dynamic entries will not set a RouterOS `timeout`.

#### `cleanup_on_shutdown`

- Type: `bool`; Required: no; Default: `true`
- Purpose: Controls whether entries managed by the plugin are removed when the plugin exits.

### Behavior

- The plugin itself does not modify DNS responses.
- It only passes through during the forward phase.
- During the return phase:
  - Extracts A/AAAA records from `NOERROR` responses.
  - Deduplicates them and keeps the largest TTL.
  - Submits them to the background manager according to async or sync mode.
- The manager is responsible for:
  - Initial connectivity verification
  - Dynamic entry refresh
  - Persistent entry consistency maintenance
  - Cleanup on shutdown

### Typical Uses

- DNS-driven policy routing on RouterOS
- Maintaining dynamic destination groups from DNS answers

### Notes

- At least one of `address_list4` or `address_list6` is required.
- `comment_prefix` and the plugin `tag` must not contain `;` or `=`.
- Synchronous mode does not change the DNS response itself. Even if the RouterOS write fails, the DNS result is still preserved.
## `download`

### Purpose

Downloads one or more `http/https` files into a local directory and overwrites the target files only after the new content is fully written.

### Example Configuration

```yaml
- tag: rules_download
  type: download
  args:
    timeout: 30s
    socks5: "127.0.0.1:1080"
    downloads:
      - url: "https://example.com/geosite.dat"
        dir: "/etc/forgedns"
      - url: "https://example.com/geoip.dat"
        dir: "/etc/forgedns"
        filename: "geoip.dat"
```

### Quick Setup

```yaml
- exec: "download https://example.com/rules.txt /etc/forgedns"
```

### Behavior

- `downloads` run sequentially in declaration order.
- A failed item only emits a warning log and does not stop later items.
- Missing target directories are created automatically.
- Files are written to a temporary path first and then moved into place.
- When `socks5` is set, all download connections are routed through that SOCKS5 proxy using the same format as `upstream[].socks5`.
- By default, ForgeDNS checks target files during startup and downloads any missing ones before other plugins initialize. A bootstrap failure aborts startup.
- Set `startup_if_missing: false` to disable that bootstrap behavior.

### Notes

- Only `http` and `https` are supported.
- `socks5` accepts `host:port` and `username:password@host:port`; bracket IPv6 addresses such as `"[::1]:1080"` are supported too.
- `startup_if_missing` only fills missing files; it does not overwrite existing targets on every startup.
- When used inside a normal `sequence`, the download time is paid directly by that request.
- Overwriting a local file does not apply automatically. If you only need file-backed providers to pick up the new data, prefer chaining `reload_provider`; if `config.yaml`, dependency topology, or the plugin list changed too, use `reload`.

### Recommended Pairing

```yaml
- tag: rules_refresh
  type: sequence
  args:
    - exec: "$rules_download"
    - exec: "$reload_rules"

- tag: rules_download
  type: download
  args:
    downloads:
      - url: "https://example.com/geosite.dat"
        dir: "/etc/forgedns"

- tag: provider_geosite
  type: geosite
  args:
    file: "/etc/forgedns/geosite.dat"

- tag: reload_rules
  type: reload_provider
  args:
    - "$provider_geosite"
```

### Subscription Refresh Example

This example fits the common flow of “remote subscription -> scheduled download -> targeted provider refresh”:

```yaml
plugins:
  # 1. Run the subscription refresh flow periodically
  - tag: subscription_cron
    type: cron
    args:
      timezone: "Asia/Shanghai"
      jobs:
        - name: refresh_rule_subscriptions
          interval: 6h
          executors:
            - "$subscription_refresh"

  # 2. Chain download and targeted provider reload with a sequence
  - tag: subscription_refresh
    type: sequence
    args:
      - exec: "$subscription_download"
      - exec: "$reload_rule_providers"

  # 3. Download remote subscription files
  - tag: subscription_download
    type: download
    args:
      timeout: 60s
      startup_if_missing: true
      downloads:
        - url: "https://example.com/geosite.dat"
          dir: "/etc/forgedns/rules"
          filename: "geosite.dat"
        - url: "https://example.com/geoip.dat"
          dir: "/etc/forgedns/rules"
          filename: "geoip.dat"

  # 4. Reload only the affected providers after download completes
  - tag: reload_rule_providers
    type: reload_provider
    args:
      - "$provider_geosite"
      - "$provider_geoip"

  # 5. These providers re-read the local files after reload
  - tag: provider_geosite
    type: geosite
    args:
      file: "/etc/forgedns/rules/geosite.dat"

  - tag: provider_geoip
    type: geoip
    args:
      file: "/etc/forgedns/rules/geoip.dat"
```

Notes:

- `download` writes the subscription content to local files.
- `reload_provider` refreshes only the affected provider snapshots without rebuilding unrelated plugins.
- `startup_if_missing: true` is useful for first-time deployment when files may not exist yet.
- If the subscription source requires a proxy, set a SOCKS5 proxy on `subscription_download.args.socks5`.
- If you do not want startup to overwrite existing files, keep the default behavior and only bootstrap missing files.
- If the update also changes `config.yaml`, provider topology, or the plugin list, use a full `reload` instead.

### Full Reload Still Fits Config Changes

```yaml
- tag: config_refresh
  type: sequence
  args:
    - exec: "$subscription_download"
    - exec: "$reload_all"

- tag: reload_all
  type: reload
```

---

## `reload_provider`

### Purpose

Reloads one or more providers in place by tag, rebuilding their internal snapshots with the same startup configuration without triggering a full application reload.

### Example Configuration

```yaml
- tag: reload_rule_providers
  type: reload_provider
  args:
    - "$geosite_cn"
    - "$geoip_cn"
```

### Quick Setup

```yaml
- exec: "reload_provider $geosite_cn"
```

### Behavior

- Providers are reloaded sequentially in the order declared in `args`.
- The semantics are the same as calling `POST /plugins/<provider_tag>/reload` for each referenced provider.
- Once every provider reload succeeds, the executor returns `Next`.
- Only provider-local data is refreshed; tags, dependencies, and other plugin configuration are unchanged.

### Typical Uses

- Refreshing only the affected `domain_set`, `ip_set`, `geosite`, `geoip`, or `adguard_rule` providers after `download`.
- Reducing the blast radius and cost of a full application reload in background maintenance flows.

### Notes

- `args` only accepts provider references such as `"$geoip_cn"`; inline rules and file references are rejected.
- If the update changes `config.yaml`, provider topology, the plugin list, or other non-provider structures, you still need `reload`.
- Running this on a live request path may trigger file reads and recompilation, so it is usually a better fit for background `cron` or maintenance `sequence` flows.

---

## `reload`

### Purpose

Triggers the same application-level full reload as the management API `POST /reload`, reloading the active configuration and rebuilding all plugins.

### Example Configuration

```yaml
- tag: reload_all
  type: reload
```

### Quick Setup

```yaml
- exec: "reload"
```

### Behavior

- Execution submits a reload request to the application control layer.
- The semantics are the same as the management API `POST /reload`.
- Once the reload request is accepted, the executor returns `Next`.
- This is a full application reload. Reloading selected plugin tags is not supported.

### Typical Uses

- Pairing with `download` in a `cron` job so refreshed rule files take effect immediately.
- Triggering a full configuration reload from a dedicated background `sequence`.

### Notes

- It must run inside a normal ForgeDNS process with application control context attached.
- Execution fails when another reload is already `pending` or `in_progress`.
- Using it in a live request `sequence` triggers a full application reload and is usually not appropriate for latency-sensitive request paths.

---

## `cron`

### Purpose

Schedules a list of executors in the background. It does not participate in the live DNS request path and starts running only after plugin initialization.

### Example Configuration

```yaml
- tag: cron_jobs
  type: cron
  args:
    timezone: "Asia/Shanghai"
    jobs:
      - name: refresh_sets
        interval: 5m
        executors:
          - "$seq_refresh"
          - "debug_print cron refresh"

      - name: nightly_cleanup
        schedule: "15 3 * * *"
        executors:
          - "sleep 2s"
          - "$seq_cleanup"
```

### Configuration Details

#### `args.jobs`

- Type: `array`; Required: yes
- Purpose: Defines one or more background jobs.
- Runtime impact:
  - The array cannot be empty.
  - Each job maintains its own trigger state and overlap protection.

#### `args.timezone`

- Type: `string`; Required: no
- Default: system local time zone
- Purpose: Overrides the time zone used by all `schedule` jobs in this `cron` plugin.
- Notes:
  - Only affects `schedule`.
  - When omitted, ForgeDNS uses the system local time zone and falls back to `UTC` if unavailable.
  - Use IANA names such as `Asia/Shanghai`, `UTC`, or `America/Los_Angeles`.

#### `args.jobs[].name`

- Type: `string`; Required: yes
- Purpose: Job name used in logs and runtime metadata.
- Runtime impact:
  - Must be unique within the same `cron` plugin.

#### `args.jobs[].schedule`

- Type: `string`; Required: exactly one of `schedule` or `interval`
- Purpose: Schedule a job with a standard 5-field cron expression.
- Notes:
  - Only `minute hour day month day-of-week` is supported.
  - Second-level cron expressions are not supported.
  - Next runs are computed in `args.timezone` or the system local time zone.

#### `args.jobs[].interval`

- Type: `string`; Required: exactly one of `schedule` or `interval`
- Purpose: Schedule a job with a fixed interval.
- Supports:
  - `5m`
  - `1h`
  - `1d`
- Runtime impact:
  - Minimum interval is `1m`.
  - The first run happens after one full interval elapses.

#### `args.jobs[].executors`

- Type: `array`; Required: yes
- Purpose: Ordered list of executors to run for the job.
- Supports:
  - `$tag` explicit executor references
  - bare `tag` references
  - quick-setup expressions such as `debug_print cron refresh`
- Runtime impact:
  - The array cannot be empty.
  - Later executors still run even if an earlier executor returns `Stop`, produces a response, or fails.

### Behavior

- `schedule` and `interval` are mutually exclusive.
- If a job is still running when the next trigger arrives, that trigger is skipped and not replayed later.
- Jobs run with an empty `DnsContext`, so this plugin is best suited for side-effect executors or dedicated background `sequence` chains.
- `cron` itself cannot be executed inside a normal request `sequence`.

### Typical Uses

- Periodic side-effect tasks.
- Scheduling a dedicated background `sequence`.
- Providing a common trigger surface for future executors such as `reload`.

### Notes

- A `cron` job cannot reference another `cron` executor.
- Executors that require a real DNS request usually do not make sense in an empty background context.

---
