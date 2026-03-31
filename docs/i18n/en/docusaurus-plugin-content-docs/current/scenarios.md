---
title: Common Policy Scenarios
sidebar_position: 6
---

This chapter gives deployment patterns closer to real-world use. The examples are organized by policy goal rather than by geography.

## Scenario 1: Cache-First Basic Forwarding

Policy goals:

* Prefer cache hits to reduce latency
* Fall back to the primary upstream on misses
* Record query summaries and metrics

```yaml
plugins:
  - tag: metrics_main
    type: metrics_collector
    args:
      name: "main"

  - tag: summary_main
    type: query_summary
    args:
      msg: "main path"

  - tag: cache_main
    type: cache
    args:
      size: 8192
      short_circuit: true
      cache_negative: true

  - tag: forward_main
    type: forward
    args:
      upstreams:
        - addr: "udp://1.1.1.1:53"

  - tag: seq_main
    type: sequence
    args:
      - exec: "$metrics_main"
      - exec: "$summary_main"
      - exec: "$cache_main"
      - matches: "!$has_resp"
        exec: "$forward_main"

  - tag: udp_in
    type: udp_server
    args:
      entry: "seq_main"
      listen: ":53"
```

Good fits:

* A single primary upstream
* Latency-sensitive deployments
* Configurations that should stay explicit and easy to read

## Scenario 2: Dual-Upstream Fast Fallback

Policy goals:

* Prefer a lower-latency primary path
* Switch quickly when the primary is slow or failing
* Avoid turning the secondary into a hard dependency for every request

```yaml
plugins:
  - tag: forward_fast
    type: forward
    args:
      upstreams:
        - addr: "https://resolver-a.example/dns-query"
          bootstrap: "8.8.8.8:53"

  - tag: forward_stable
    type: forward
    args:
      upstreams:
        - addr: "tls://resolver-b.example:853"
          bootstrap: "8.8.4.4:53"

  - tag: fallback_main
    type: fallback
    args:
      primary: "forward_fast"
      secondary: "forward_stable"
      threshold: 200
      always_standby: false

  - tag: seq_main
    type: sequence
    args:
      - exec: "$fallback_main"
```

Good fits:

* One upstream optimized for speed and another for stability
* Tail-latency improvement

## Scenario 3: Prefer Local Static Answers, Then Forward

Policy goals:

* Return local overrides first for internal services and fixed names
* Query external upstreams only on misses

```yaml
plugins:
  - tag: local_hosts
    type: hosts
    args:
      entries:
        - "full:router.local 192.168.1.1"
        - "domain:svc.local 10.0.0.10 fd00::10"

  - tag: local_records
    type: arbitrary
    args:
      rules:
        - "status.local. 60 IN TXT \"ok\""

  - tag: forward_main
    type: forward
    args:
      upstreams:
        - addr: "udp://1.1.1.1:53"

  - tag: seq_main
    type: sequence
    args:
      - exec: "$local_hosts"
      - matches: "!has_resp"
        exec: "$local_records"
      - matches: "!has_resp"
        exec: "$forward_main"
```

Good fits:

* Local service discovery
* Fixed overrides
* Small-scale authoritative-style local data maintenance

## Scenario 4: Dual-Stack Preference

Policy goals:

* Prefer IPv4 or IPv6 depending on the network target
* Make dual-stack names resolve more consistently to the preferred address family

```yaml
plugins:
  - tag: prefer_v4
    type: prefer_ipv4
    args:
      cache: true
      cache_ttl: 1800

  - tag: forward_main
    type: forward
    args:
      upstreams:
        - addr: "udp://1.1.1.1:53"

  - tag: seq_main
    type: sequence
    args:
      - exec: "$prefer_v4"
      - matches: "!has_resp"
        exec: "$forward_main"
```

Good fits:

* Clients with inconsistent stack support
* Networks where one address family is less reliable

## Scenario 5: Tiered Policy by Client Subnet

Policy goals:

* Use different logic for different client sources
* Host several policy classes in one ForgeDNS instance

```yaml
plugins:
  - tag: forward_a
    type: forward
    args:
      upstreams:
        - addr: "udp://1.1.1.1:53"

  - tag: forward_b
    type: forward
    args:
      upstreams:
        - addr: "udp://8.8.8.8:53"

  - tag: seq_main
    type: sequence
    args:
      - matches: "client_ip 192.168.10.0/24"
        exec: "$forward_a"
      - matches: "!has_resp"
        exec: "$forward_b"
```

Good fits:

* Multi-tenant LANs
* Office and guest network splits
* A single process serving multiple policy groups

## Scenario 6: Drive Network Integration from DNS Results

Policy goals:

* Turn resolved target IPs into system-side effects
* Feed firewall, route, or address-list state from DNS answers

```yaml
plugins:
  - tag: target_domains
    type: domain_set
    args:
      exps:
        - "domain:stream.example"

  - tag: forward_main
    type: forward
    args:
      upstreams:
        - addr: "udp://1.1.1.1:53"

  - tag: route_sync
    type: ros_address_list
    args:
      address: "http://192.168.88.1"
      username: "admin"
      password: "password"
      address_list4: "policy_v4"
      address_list6: "policy_v6"

  - tag: seq_main
    type: sequence
    args:
      - exec: "$forward_main"
      - matches: "qname $target_domains"
        exec: "$route_sync"
```

Good fits:

* Policy routing
* Firewall address lists
* Systems that consume DNS-learned targets

## Scenario 7: AdGuard-Based Ad Blocking

Policy goals:

* Reuse existing AdGuard DNS rule files
* Return sinkhole answers immediately when rules match
* Forward unmatched traffic through the normal upstream path

```yaml
plugins:
  - tag: ad_rules
    type: adguard_rule
    args:
      files:
        - "/etc/forgedns/adguard.txt"

  - tag: blocked
    type: sequence
    args:
      - exec: "black_hole 0.0.0.0 ::"
      - exec: accept

  - tag: forward_main
    type: forward
    args:
      upstreams:
        - addr: "udp://1.1.1.1:53"

  - tag: seq_main
    type: sequence
    args:
      - matches: "question $ad_rules"
        exec: goto blocked
      - exec: "$forward_main"
```

Good fits:

* Home networks or gateways that want DNS-level ad blocking
* Deployments that prefer to reuse maintained AdGuard rule files
* Policy graphs that want a clear split between blocking and normal resolution

## Scenario 8: Separate the Control Plane and Observability Plane

Policy goals:

* Expose management APIs and metrics separately from client-facing DNS listeners
* Keep operational interfaces easy to secure and monitor

```yaml
api:
  http:
    listen: "127.0.0.1:9088"
    auth:
      type: basic
      username: "admin"
      password: "secret"

plugins:
  - tag: metrics_main
    type: metrics_collector
    args:
      name: "main"

  - tag: seq_main
    type: sequence
    args:
      - exec: "$metrics_main"
      - exec: "$forward_main"
```

Good fits:

* Hosts that expose DNS to clients but keep management local
* Integrations with Prometheus or operational platforms
* Environments that need explicit separation between serving traffic and operating the service

## Composition Principles

### Decide the Main Path First, Then Add Side Effects

Start by making the main resolution path correct and readable, then layer in metrics, route sync, reverse lookup, or other side effects. This keeps the latency-critical path understandable and avoids coupling correctness to observability.

### Move Shared Rules into Providers Instead of Repeating Them Across Matchers

If multiple matchers reference the same domain or IP list, move that data into `domain_set` or `ip_set`. Providers make large policy graphs easier to update, easier to review, and less likely to drift.
