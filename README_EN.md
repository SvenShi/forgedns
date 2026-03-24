# ForgeDNS

[中文](README.md) | [English](README_EN.md)

**⚡ A programmable DNS server for modern networks, built with performance boundaries and policy orchestration in mind.**

ForgeDNS is a high-performance DNS project written in Rust.
It is not trying to be a "feature bucket" DNS utility. The goal is to become a DNS core that is genuinely suitable for long-term infrastructure use: fast, stable, controllable, and able to keep evolving cleanly.

Inspired by mosdns and built on Tokio plus a custom DNS message stack, ForgeDNS separates the owned message model from the wire codec layer and is designed around one idea:

**DNS should remain fast even when it becomes your policy engine.**

The project is under active development.

## ✦ ForgeDNS At A Glance

> **A faster DNS path, a cleaner policy model, and a more modern transport stack.**
>
> ForgeDNS is not only about forwarding queries. It is about keeping DNS efficient even when it also needs to handle cache, filtering, fallback, rewriting, local answers, and system-facing side effects.

| Dimension | What ForgeDNS Optimizes For |
| --- | --- |
| ⚡ Performance | Keep the hot path short and avoid letting features turn DNS into the bottleneck |
| 🧩 Orchestration | Express resolver behavior through one matcher / executor / provider pipeline |
| 🔐 Protocols | Cover both classic DNS and modern encrypted DNS transports |
| 🛰️ Integration | Let DNS participate in system and network control, not only resolution |

## Why ForgeDNS

Most DNS software starts simple, then gets slower and harder to reason about as policy, transports, integrations, and operational requirements accumulate.

ForgeDNS takes the opposite direction.
It is designed from the beginning to support:

- ⚡ low latency on the critical path
- 🧩 composable policy orchestration
- 🔐 modern encrypted DNS transports
- 🌐 system-level integration beyond packet forwarding
- 🧱 long-term extensibility without architectural drift

This is not just a resolver.
It is a performance-oriented DNS core for real networks.

## Why High-Performance DNS Matters

DNS is the first step of almost every connection.
If DNS is slow, the whole network feels slow.
If DNS becomes unstable under policy load, the rest of the stack pays for it.

For a serious DNS server, performance means:

- lower latency before every outbound connection
- better tail behavior under concurrency
- lower CPU and memory overhead on the hottest path in the network
- more room for cache, filtering, routing, and observability without turning DNS into the bottleneck
- keeping DNS itself from becoming the limiting factor in the stack

A DNS server that is only fast in trivial cases is not enough.
Modern deployments need performance under real policy complexity.

## What Makes ForgeDNS Different

### ⚡ Performance is part of the architecture

ForgeDNS is structured to reduce avoidable overhead:

- Rust for low runtime overhead and predictable memory behavior
- Tokio for concurrent, I/O-heavy workloads
- protocol-aware upstream connection pooling, reuse, and pipelining
- TTL-aware cache and negative-cache support for hot-path efficiency
- flattened provider lookups to avoid recursive policy overhead
- `post_execute` hooks to keep observability and side effects away from the tightest response path

Performance here is not a late optimization pass.
It is a design constraint.

### 🧠 Policy is a first-class capability

ForgeDNS does not bury behavior inside transport-specific code paths.
It separates concerns clearly:

- `server` accepts traffic
- `message` provides the custom DNS message model, RDATA model, and wire codec
- `network` handles upstream transports, pooling, bootstrap, and protocol-specific reuse
- `sequence` orchestrates policy
- `matcher` decides when rules apply
- `executor` performs actions
- `provider` supplies reusable domain and IP data

That separation makes the system easier to extend, reason about, and keep fast as features grow.

### 🌍 It is built for today's DNS reality

ForgeDNS already supports a modern transport stack on both ingress and egress:

- UDP
- TCP
- DoT
- DoQ
- DoH

It also supports:

- bootstrap resolution
- SOCKS5 upstream dialing
- multi-upstream concurrency
- transport-aware connection reuse and pipelining

A modern DNS system should not force users to choose between flexibility and protocol coverage.

### 🛰️ It treats DNS as infrastructure, not just resolution

ForgeDNS is already moving beyond pure packet forwarding.
Current system-facing capabilities include:

- Linux `ipset` integration
- Linux `nftables` set integration
- MikroTik RouterOS route synchronization
- reverse lookup cache generation from observed answers

This makes ForgeDNS relevant not only for resolution, but also for routing, segmentation, gateway control, and policy-driven networking.

### 🧱 It is designed to keep growing cleanly

ForgeDNS is still early, but the direction is already visible:

- keep listeners thin
- keep most behavior in composable policy layers
- hide upstream protocol complexity behind unified abstractions
- add capability through clean modules instead of core-loop sprawl

That gives ForgeDNS a stronger long-term shape than software that grows by accumulating special cases.

## Why The Custom Message Stack Matters

ForgeDNS does not build its entire DNS data path directly on top of a third-party message object model.
Instead, it maintains its own message stack.
That is not about reinventing DNS for its own sake. It is about letting the message model, wire codec, performance work, and policy pipeline evolve together.

At a high level, the current design has two layers:

- an owned model used by the policy pipeline, centered on `Message`, `Name`, `Record`, and `RData`
- a dedicated wire layer under `message/wire` for codec, compression, length calculation, truncation, and RR-specific wire rules

That separation gives ForgeDNS several concrete advantages.

### 1. It enables targeted hot-path optimization

Because the message stack is under project control, ForgeDNS can optimize around its own real bottlenecks instead of inheriting the object layout and abstraction boundaries of a general-purpose library.

That already shows up in areas such as:

- `Name` keeping a wire-oriented representation while lazily building presentation data
- targeted handling for `TXT`, `OPT`, compression maps, and length estimation
- controlled behavior around truncation, `EDNS`, and extended `rcode`

For a DNS server that cares about cache, fallback, rewriting, local answers, and system-facing side effects, that level of control matters a lot.

### 2. It fits the policy layer more naturally

ForgeDNS matchers and executors do more than just inspect packets.
They often need to:

- read qname, qtype, and qclass
- change `rcode`
- build local answers
- preserve or restore `EDNS`
- rewrite, truncate, or post-process responses

If the policy layer sits on top of an external abstraction that does not map cleanly to those needs, code becomes more indirect and conversions start to accumulate.
The current message stack lets policy code work directly with ForgeDNS's own semantics.

### 3. It keeps protocol correctness and server semantics in one place

For a DNS server, the hard part is rarely just "can this packet be parsed".
The harder questions are things like:

- whether truncation behavior is correct
- whether `OPT`, `TSIG`, and `SIG0` are ordered and preserved correctly
- whether complex structures such as `SVCB/HTTPS`, `NSEC/NSEC3`, and EDNS options follow strict wire rules
- whether compression, length prediction, and final encoding stay consistent

The custom message stack makes it easier to keep those concerns aligned:

- the model layer expresses service semantics
- the wire layer expresses protocol rules
- tests can cover both byte-level roundtrips and high-level message behavior

That is much easier to keep coherent over time than splitting policy behavior and wire behavior across unrelated object systems.

### 4. It can grow with ForgeDNS's plugin architecture

ForgeDNS is not just a resolver. It is a policy system built around:

`server -> context -> matcher/executor/provider -> upstream`

That means the message layer has to keep supporting:

- more executors that reshape responses
- more matchers that inspect query and answer content
- more integration plugins that observe or extract message results
- more complex RDATA and EDNS semantics over time

Owning the message layer makes that growth much easier to manage than constantly adapting around someone else's original abstraction boundaries.

### 5. It makes testing and benchmarking more direct

The current `message` package can be tested and benchmarked independently with:

- byte-level roundtrip tests for `Name`, `RData`, and `Message`
- focused protocol tests for `SVCB`, `NSEC`, `EDNS`, and truncation behavior
- the `message_codec` benchmark suite

That gives ForgeDNS a much tighter loop for validating both correctness and performance at the message-layer boundary.

From an engineering perspective, this is a long-term investment:
the message stack is not only there to work today, but to preserve control over correctness and performance as the DNS core keeps growing.

## 🚀 Performance Design Principles

ForgeDNS does not depend on a single magic optimization.
Its performance model comes from a set of consistent engineering rules.

### 1. Keep the hot path short

Once a request enters the system, listener layers should do as little as possible beyond accept, decode, and dispatch.
Policy logic is kept in the unified `sequence` pipeline instead of being duplicated across transport-specific paths.
That reduces repeated branching and keeps the critical path easier to control.

### 2. Do expensive work once, reuse it many times

Complexity should be prepared ahead of the request path whenever possible. Examples already present in the codebase include:

- providers flatten referenced rule sets before runtime matching
- domain and IP rules are organized into match-friendly structures
- `DnsContext` caches a normalized query view so qname processing is not repeated unnecessarily

The principle is simple: work that can be moved to initialization or low-frequency paths should not be paid for on every query.

### 3. Treat connections as reusable assets

For upstreams, handshake and connection setup are expensive.
ForgeDNS uses protocol-aware pooling, reuse, and pipelining to amortize that cost.
This is especially important for:

- DoT / DoQ / DoH upstreams
- high-concurrency forwarding workloads
- multi-upstream racing where aggregate latency matters

### 4. Keep side effects away from the most sensitive path

Logging, metrics, route sync, set writes, and other side effects matter, but they should not blindly block the response path.
ForgeDNS uses mechanisms such as `post_execute`, maintenance tasks, and async queues to decouple parts of that work from the hottest portion of request handling.

The goal is not to eliminate side effects.
The goal is to keep them controlled.

### 5. Make cache behavior consistent with DNS semantics

A useful DNS cache is not just a hash map with responses in it.
ForgeDNS emphasizes TTL-aware caching, negative caching, expiration handling, and persistence boundaries so cache behavior remains aligned with resolver expectations instead of becoming a hidden correctness risk.

### 6. Limit lock pressure and shared-state inflation

One common way DNS systems lose performance is by allowing global shared state to grow until locking and coordination dominate the hot path.
ForgeDNS consistently leans toward lighter shared-state patterns, atomics where appropriate, locally maintainable structures, and background maintenance rather than pushing all coordination into request handling.

### 7. Design for performance and extensibility together

Some systems are fast only while they remain simple.
Once policy, plugins, and transports accumulate, the architecture starts fighting itself.
ForgeDNS is being built to avoid that trap.

That is why it keeps insisting on:

- clear layering
- explicit plugin boundaries
- unified upstream abstractions
- a single policy orchestration model

Without those constraints, performance work tends to decay as the project grows.

## Architecture At A Glance

```mermaid
flowchart TB

A[👤 Client / App]

B[🌐 Server Plugins<br/>UDP / TCP / DoT / DoQ / DoH]

C[📦 DnsContext<br/>request / response / attrs]

subgraph D[🧠 Sequence Policy Pipeline]
    D1[🔎 Matcher<br/>decide when rules apply]
    D2[⚙️ Executor<br/>forward / cache / rewrite / fallback]
    D3[📚 Provider<br/>reusable domain/ip data]

    D1 --> D2
    D3 --> D2
end

E[🔁 Upstream Resolver<br/>UDP / TCP / DoT / DoQ / DoH]

F[🛰️ System Integrations<br/>ipset / nftset / MT]

G[✅ Final DNS Response]

A --> B
B --> C
C --> D
D --> E
D --> F
E --> G
F --> G
```

A request typically flows like this:

1. a `server` plugin accepts UDP, TCP, DoT, DoQ, or DoH traffic
2. the request enters `DnsContext`
3. `sequence` evaluates matchers and dispatches executors
4. providers supply reusable domain/IP data to the policy layer
5. the response is returned, while optional post-stage logic can still observe or trigger side effects

The result is a DNS pipeline that combines control and performance instead of trading one for the other.

## ✨ Current Capabilities

ForgeDNS already includes:

- 🌐 server-side UDP, TCP, DoT, DoQ, and DoH
- 🔁 upstream UDP, TCP, DoT, DoQ, and DoH
- ⚔️ multi-upstream forwarding and concurrent racing
- 🧠 in-memory DNS cache with TTL and negative-cache handling
- 🛟 fallback execution between primary and standby paths
- 🧩 local static answers and arbitrary resource-record responses
- 🔀 query rewriting and response rewriting
- 📍 EDNS Client Subnet handling
- ↔️ dual-stack preference helpers
- 📚 reusable domain/IP rule-set providers
- 🛰️ DNS-to-system integrations such as `ipset`, `nftset`, and MikroTik route sync

## 🧭 Use Cases

### Home network and parental control

When a home network needs centralized access control, DNS is often the most natural control point.
ForgeDNS fits this role well because it can handle baseline resolution while also serving as the place where filtering and device-specific policy evolve over time.

Good fits include:

- access control for different family members
- device-specific policy handling
- parental control workflows for child devices
- future integration with ad blocking and external rule sources

### Gateways, side routers, and policy routing

In gateway and side-router deployments, DNS is not only resolution. It is also a policy entry point.
ForgeDNS already has the foundations needed to push DNS results into surrounding system behavior, which makes it a good fit for DNS-driven traffic steering.

Good fits include:

- policy routing based on resolved domains
- kernel-side traffic steering with `ipset` / `nftset`
- RouterOS-side control through MikroTik route synchronization
- using DNS outcomes to influence egress path selection

### Multi-upstream and advanced resolution strategy

When an environment needs multiple upstreams, mixed transports, failover, and latency racing, a simple forwarder tends to run out of headroom quickly.
ForgeDNS is better aligned with cases where the resolution strategy itself is complex.

Good fits include:

- multi-upstream racing
- primary/standby upstream failover
- mixed classic DNS and encrypted DNS upstream usage
- different resolution pipelines for different request conditions

### Rule-driven filtering and rewriting

If your DNS layer is expected not only to answer queries but also to rewrite, intercept, or synthesize results based on policy, ForgeDNS's orchestration model becomes much more valuable.

Good fits include:

- static local answers and arbitrary record synthesis
- query rewriting and response rewriting
- rule decisions based on domain, client, or response content
- future integration with AdGuard rules, URL-delivered rule sets, and V2Ray `.dat` data files

### Long-lived self-hosted DNS infrastructure

Some users do not just want something that works today. They want something they can keep building on.
ForgeDNS fits scenarios where DNS is treated as long-term infrastructure rather than a disposable utility.

Those scenarios usually care about:

- whether the technical direction is clear
- whether capabilities can keep growing cleanly
- whether new features can be added without damaging the critical path
- whether performance boundaries can still hold as functionality expands

## Representative Building Blocks

README intentionally does not try to be the full plugin manual. Detailed configuration will move to the WikiBook.

The most representative components today are:

- `sequence`: policy orchestration core
- `forward`: unified upstream forwarding executor
- `forward_edns0opt`: policy-controlled EDNS0 option forwarding and response reinjection
- `cache`: hot-path response cache with TTL and negative-cache semantics
- `fallback`: primary/standby failover composition
- `hosts`, `arbitrary`, `redirect`, `black_hole`: local answer and rewrite primitives
- `dual_selector`, `ecs_handler`, `ttl`: response shaping and policy-enhancement helpers
- `domain_set`, `ip_set`: reusable rule-set providers
- `qname`, `client_ip`, `resp_ip`, `rcode`, `rate_limiter`: common policy matchers
- `ipset`, `nftset`, `mikrotik`, `reverse_lookup`: DNS-to-system integration plugins
- `metrics_collector`, `query_summary`, `debug_print`: lightweight observability helpers

## 🎯 Who ForgeDNS Is For

ForgeDNS is a strong fit if you want:

- ⚡ a self-hosted DNS core that is performance-conscious from the start
- 🔐 a resolver that can cover classic DNS, encrypted DNS, and policy DNS in one system
- 🌐 DNS-driven routing, filtering, or gateway behavior
- 🧩 an architecture that can grow through composition instead of becoming a monolith
- 🧭 a project with a clear long-term technical direction

## Build And Run

```bash
cargo build --release
cargo run -- -c config.yaml
cargo run -- -c config.yaml -l debug
```

The sample `config.yaml` is the best starting point for understanding how ForgeDNS is assembled today.

## 🛣️ Roadmap

The next major items on the roadmap are:

- management HTTP API
- Prometheus integration and exporter support
- family / parental control features
- ad blocking with AdGuard rule support
- loading domain and IP rule sets from URLs
- reading V2Ray `.dat` rule files

Note: ForgeDNS already includes `http_server` for DoH. The roadmap item above refers to a separate management HTTP interface.

## Acknowledgements

ForgeDNS is deeply influenced by:

- [mosdns](https://github.com/IrineSistiana/mosdns)
  - the original Go project that inspired much of the policy and plugin direction
- [hickory-dns](https://github.com/hickory-dns/hickory-dns)
  - an important Rust project that helped shape the protocol side of ForgeDNS

## License

GPL-3.0-or-later
