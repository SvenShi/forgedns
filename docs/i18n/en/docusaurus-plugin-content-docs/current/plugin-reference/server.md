---
title: Server Plugins
sidebar_position: 2
---

Server plugins receive client requests and hand them off to an entry executor. They do not implement complex policy logic themselves. Their main concerns are the listening protocol, bind address, TLS parameters, and the `entry` executor.

## General Notes

Every server plugin depends on an `entry`. It must reference an existing executor plugin, usually a `sequence`:

```yaml
- tag: seq_main
  type: sequence
  args:
    # Try cache first
    - exec: "$cache_main"
    # Only forward when no response exists yet
    - matches: "!has_resp"
      exec: "$forward_main"

- tag: udp_in
  type: udp_server
  args:
    # Must reference an existing executor, usually a sequence
    entry: "seq_main"
    # Standard UDP DNS bind address
    listen: "0.0.0.0:53"
```

---

## `udp_server`

### Purpose

Listens for DNS over UDP and forwards requests to `entry`.

### Example Configuration

```yaml
- tag: udp_in
  type: udp_server
  args:
    # Entry executor for this listener
    entry: "seq_main"
    # Can be written as ip:port or :port
    listen: "0.0.0.0:53"
```

### Configuration Details

#### `entry`

- Type: `string`; Required: yes; Default: none
- Purpose: Selects the executor that handles every request arriving on this listener.
- Example: `entry: "seq_main"`
- Requirements:
  - Must reference an existing executor plugin.
  - In practice this is usually a `sequence` tag.
- Runtime impact:
  - All requests entering this `udp_server` continue through that executor.
  - Initialization fails if the reference is missing or of the wrong type.

#### `listen`

- Type: `string`; Required: yes; Default: none
- Purpose: Defines the UDP bind address.
- Examples:
  - `listen: "0.0.0.0:53"`
  - `listen: ":5353"`
- Supported forms:
  - `ip:port`
  - `:port`
- Runtime impact:
  - Determines the bound address and port.
  - Invalid addresses, port conflicts, or bind failures prevent startup.

### Behavior

- Receives requests through a UDP socket.
- Response encoding respects the client's advertised EDNS UDP payload size.
- Oversized responses are truncated according to DNS semantics rather than by blindly cutting raw bytes.

### Good Fits

- Standard low-overhead DNS ingress with high concurrency.
- The main listener for local networks.
- Multi-protocol setups alongside `tcp_server` or `http_server`.

### Notes

- UDP and QUIC both consume UDP ports. Avoid conflicts.
- Prefer a shared `sequence` entry instead of duplicating policy logic in multiple server instances.

---

## `tcp_server`

### Purpose

Listens for DNS over TCP. If `cert` and `key` are both configured, it can also serve as a DoT listener.

### Example Configuration

```yaml
- tag: tcp_in
  type: tcp_server
  args:
    # TCP requests enter the main policy chain
    entry: "seq_main"
    # Listen on the standard TCP DNS port
    listen: ":53"
    # Idle connection lifetime in seconds
    idle_timeout: 10

- tag: dot_in
  type: tcp_server
  args:
    # Reuse the same policy chain for DoT
    entry: "seq_main"
    # Typical DoT port
    listen: ":853"
    # PEM certificate chain
    cert: "/etc/forgedns/server.crt"
    # PEM private key
    key: "/etc/forgedns/server.key"
    # Keep DoT connections alive a bit longer for reuse
    idle_timeout: 30
```

### Configuration Details

#### `entry`

- Type: `string`; Required: yes; Default: none
- Purpose: Selects the executor used by TCP or DoT requests.
- Example: `entry: "seq_main"`
- Requirements:
  - Must reference an existing executor plugin.
- Runtime impact:
  - Every DNS message on accepted connections is processed by that executor.

#### `listen`

- Type: `string`; Required: yes; Default: none
- Purpose: Defines the TCP bind address.
- Examples:
  - `listen: ":53"`
  - `listen: "127.0.0.1:853"`
- Supported forms:
  - `ip:port`
  - `:port`
- Runtime impact:
  - Controls the bind address for plaintext TCP or DoT.

#### `cert`

- Type: `string`; Required: no; Default: none
- Purpose: Path to the TLS certificate file.
- Example: `cert: "/etc/forgedns/server.crt"`
- Usage:
  - Enables TLS when paired with `key`.
- Runtime impact:
  - Allows the same plugin type to act as a DoT listener.

#### `key`

- Type: `string`; Required: no; Default: none
- Purpose: Path to the TLS private key file.
- Example: `key: "/etc/forgedns/server.key"`
- Usage:
  - Enables TLS when paired with `cert`.
- Runtime impact:
  - TLS mode cannot start if the key is missing or invalid.

#### `idle_timeout`

- Type: `integer`; Required: no; Default: `10`
- Unit: seconds
- Purpose: Controls idle connection lifetime.
- Example: `idle_timeout: 30`
- Runtime impact:
  - Affects keepalive behavior and long-lived connection reuse.

### Behavior

- Without TLS it serves DNS over TCP.
- With both `cert` and `key` it serves DNS over TLS.
- The TLS ALPN is set to `dot`.
- A single connection can carry multiple DNS messages.

### Good Fits

- TCP fallback ingress.
- DoT deployments.
- Clients that benefit from long-lived connections.

### Notes

- `cert` and `key` must be configured together.
- If you need both plaintext TCP and DoT, define two separate plugin instances.

---

## `http_server`

### Purpose

Provides DNS over HTTPS and can serve HTTP/2 plus optional HTTP/3.

### Example Configuration

```yaml
- tag: doh_in
  type: http_server
  args:
    # HTTPS / DoH bind address
    listen: ":443"
    # Certificate required for HTTPS and HTTP/3
    cert: "/etc/forgedns/server.crt"
    # Private key required for HTTPS and HTTP/3
    key: "/etc/forgedns/server.key"
    # Also enable DoH over HTTP/3 when TLS is present
    enable_http3: true
    # Restore the real client IP from a reverse-proxy header
    src_ip_header: "X-Forwarded-For"
    # Idle timeout for HTTP/2 and HTTP/3 connections
    idle_timeout: 30
    entries:
      # Standard RFC 8484 endpoint
      - path: "/dns-query"
        exec: "seq_main"
      # Alternate path for a different policy chain
      - path: "/dns-alt"
        exec: "seq_alt"
```

### Configuration Details

#### `entries`

- Type: `array`; Required: yes; Default: none
- Purpose: Maps HTTP request paths to executors.
- Examples:
  - `path: "/dns-query", exec: "seq_main"`
  - `path: "/dns-alt", exec: "seq_alt"`
- Each item contains:
  - `path`
    - Type: `string`
    - Required: yes
    - Purpose: DoH request path.
    - Constraint: must start with `/`.
  - `exec`
    - Type: `string`
    - Required: yes
    - Purpose: Executor for requests hitting that path.
    - Constraint: must reference an existing executor plugin.
- Runtime impact:
  - Different paths can enter different policy chains.

#### `listen`

- Type: `string`; Required: yes; Default: none
- Purpose: Defines the HTTP or HTTPS bind address.
- Examples:
  - `listen: ":80"`
  - `listen: ":443"`

#### `src_ip_header`

- Type: `string`; Required: no; Default: none
- Purpose: Header name used to read the original client address.
- Example: `src_ip_header: "X-Forwarded-For"`
- Runtime impact:
  - Allows a reverse proxy to pass through the real source address.

#### `cert`

- Type: `string`; Required: no; Default: none
- Purpose: HTTPS certificate file path.
- Example: `cert: "/etc/forgedns/server.crt"`
- Runtime impact:
  - HTTPS is enabled only when `cert` and `key` are both present.

#### `key`

- Type: `string`; Required: no; Default: none
- Purpose: HTTPS private key file path.
- Example: `key: "/etc/forgedns/server.key"`
- Runtime impact:
  - HTTPS is enabled only when `cert` and `key` are both present.

#### `idle_timeout`

- Type: `integer`; Required: no; Default: `30`
- Unit: seconds
- Purpose: Controls idle HTTP connection lifetime.
- Example: `idle_timeout: 30`
- Runtime impact:
  - Affects HTTP/2 long-lived connection behavior.

#### `enable_http3`

- Type: `boolean`; Required: no; Default: `false`
- Purpose: Enables HTTP/3 in addition to HTTP/2.
- Example: `enable_http3: true`
- Requirements:
  - `cert` and `key` must both be configured.
- Runtime impact:
  - Starts an additional QUIC-based DoH listener task.

### Behavior

- Each `path` can route to a different `exec`, which is useful for multi-entry policies.
- Registers both GET and POST DoH access methods commonly used for RFC 8484.
- When HTTP/3 is enabled, an extra QUIC listener is started.

### Good Fits

- Standard DoH exposure.
- Multiple DNS policy entry points on one listener.
- Deployments behind a reverse proxy that preserve the original client IP with `src_ip_header`.

### Notes

- `enable_http3: true` requires both `cert` and `key`.
- If a reverse proxy is involved, define a trusted boundary for `src_ip_header` to avoid spoofed source IPs.
## `quic_server`

### Purpose

Provides DNS over QUIC.

### Example Configuration

```yaml
- tag: doq_in
  type: quic_server
  args:
    # Policy chain used by DoQ requests
    entry: "seq_main"
    # Common DoQ port
    listen: ":853"
    # TLS certificate is mandatory for DoQ
    cert: "/etc/forgedns/server.crt"
    # TLS private key is mandatory for DoQ
    key: "/etc/forgedns/server.key"
    # QUIC transport idle timeout in seconds
    idle_timeout: 30
```

### Configuration Details

#### `entry`

- Type: `string`; Required: yes; Default: none
- Purpose: Selects the executor used by DoQ requests.
- Example: `entry: "seq_main"`
- Requirements:
  - Must reference an existing executor plugin.

#### `listen`

- Type: `string`; Required: yes; Default: none
- Purpose: Defines the QUIC bind address.
- Example: `listen: ":853"`
- Runtime impact:
  - Occupies a UDP port.

#### `cert`

- Type: `string`; Required: yes; Default: none
- Purpose: Path to the TLS certificate required by DoQ.
- Example: `cert: "/etc/forgedns/server.crt"`
- Runtime impact:
  - The listener cannot start if the certificate is invalid.

#### `key`

- Type: `string`; Required: yes; Default: none
- Purpose: Path to the TLS private key required by DoQ.
- Example: `key: "/etc/forgedns/server.key"`
- Runtime impact:
  - The listener cannot start if the private key is invalid.

#### `idle_timeout`

- Type: `integer`; Required: no; Default: none
- Unit: seconds
- Purpose: Controls QUIC transport idle timeout.
- Example: `idle_timeout: 30`
- Runtime impact:
  - Affects when idle QUIC connections are reclaimed.

### Behavior

- DoQ always requires TLS, so `cert` and `key` are mandatory.
- ALPN is fixed to `doq`.
- Each bidirectional stream represents one independent DNS exchange.

### Good Fits

- Encrypted DNS ingress with low latency.
- Modern clients that benefit from QUIC transport behavior.

### Notes

- The listener still consumes a UDP port underneath.
- Do not bind the same address and port as `udp_server`.

---

