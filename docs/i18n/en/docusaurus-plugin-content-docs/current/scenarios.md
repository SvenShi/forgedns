---
title: Common Policy Scenarios
sidebar_position: 6
---

This chapter provides configuration examples for common deployment needs. Start with the minimal runnable DNS gateway, then add home-gateway policy, domain routing, upstream fallback, encrypted upstreams, subscription refresh, auditing, or network integration as needed.

Each example can be used as either a complete configuration or a policy fragment. Examples without `udp_server` / `tcp_server` focus on the policy chain itself; for deployment, attach their `seq_main` to the listeners from the minimal runnable gateway scenario.

## Scenario 1: Minimal Runnable DNS Gateway

Policy goals:

* Expose both standard UDP and TCP DNS listeners
* Prefer local hosts, then cache, then the public upstream
* Use a non-privileged port so the config is easy to test locally or in a container

```yaml
api:
  http: "127.0.0.1:9088"

plugins:
  - tag: local_hosts
    type: hosts
    args:
      entries:
        - "full:router.lan 192.168.1.1"
        - "domain:svc.lan 192.168.10.10 fd00::10"
      short_circuit: true

  - tag: cache_main
    type: cache
    args:
      size: 4096
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
      - exec: "$local_hosts"
      - exec: "$cache_main"
      - matches: "!has_resp"
        exec: "$forward_main"

  - tag: udp_lan
    type: udp_server
    args:
      entry: "seq_main"
      listen: ":5353"

  - tag: tcp_lan
    type: tcp_server
    args:
      entry: "seq_main"
      listen: ":5353"
```

Good fits:

* First-time OxiDNS validation
* Home or lab networks starting from a small gateway config
* Avoiding `:53` permissions, port conflicts, and system resolver overlap during testing

## Scenario 2: Home or Small Office All-in-One Policy

Policy goals:

* Return local names first
* Sinkhole ad-rule hits
* Use cache and public upstreams for everything else
* Keep metrics ready for later observability

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
      name: "home"

  - tag: local_hosts
    type: hosts
    args:
      entries:
        - "full:router.lan 192.168.1.1"
        - "full:nas.lan 192.168.1.20"
        - "domain:svc.lan 192.168.10.10"
      short_circuit: true

  - tag: ad_rules
    type: adguard_rule
    args:
      rules:
        - "||ads.example.com^"
        - "||tracking.example.net^"
        - "@@||safe.ads.example.com^"

  - tag: blocked
    type: sequence
    args:
      - exec: "black_hole 0.0.0.0 ::"
      - exec: accept

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
        - addr: "udp://8.8.8.8:53"

  - tag: seq_main
    type: sequence
    args:
      - exec: "$metrics_main"
      - exec: "$local_hosts"
      - matches: "question $ad_rules"
        exec: goto blocked
      - exec: "$cache_main"
      - matches: "!has_resp"
        exec: "$forward_main"

  - tag: udp_lan
    type: udp_server
    args:
      entry: "seq_main"
      listen: ":5353"

  - tag: tcp_lan
    type: tcp_server
    args:
      entry: "seq_main"
      listen: ":5353"
```

Good fits:

* Home gateways, sidecar DNS, and small office DNS
* One config handling local names, ad blocking, cache, and default forwarding
* Starting with inline rules before moving to external rule files

## Scenario 3: Route Domains to Different Upstreams

Policy goals:

* Send internal domains to an internal DNS server
* Send selected domains to a dedicated upstream
* Send everything else to the default upstream

```yaml
plugins:
  - tag: internal_domains
    type: domain_set
    args:
      exps:
        - "domain:corp.lan"
        - "domain:internal.example"

  - tag: privacy_domains
    type: domain_set
    args:
      exps:
        - "domain:example.org"
        - "full:secure.example.net"

  - tag: forward_internal
    type: forward
    args:
      upstreams:
        - addr: "udp://192.168.1.1:53"

  - tag: forward_privacy
    type: forward
    args:
      upstreams:
        - addr: "tls://dns.quad9.net:853"
          bootstrap: "9.9.9.9:53"

  - tag: forward_default
    type: forward
    args:
      upstreams:
        - addr: "udp://1.1.1.1:53"

  - tag: seq_main
    type: sequence
    args:
      - matches: "qname $internal_domains"
        exec: "$forward_internal"
      - matches: "qname $privacy_domains"
        exec: "$forward_privacy"
      - matches: "!has_resp"
        exec: "$forward_default"
```

Good fits:

* Mixed internal and public DNS environments
* Sending only a small domain set through a specific egress or encrypted upstream
* Avoiding repeated domain lists across multiple `sequence` rules

## Scenario 4: Multi-Upstream Resilience and Fast Fallback

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
        - addr: "https://cloudflare-dns.com/dns-query"
          bootstrap: "1.1.1.1:53"

  - tag: forward_stable
    type: forward
    args:
      upstreams:
        - addr: "tls://dns.google:853"
          bootstrap: "8.8.8.8:53"

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
* Keeping fallback logic in one executor instead of repeating backup rules

## Scenario 5: Use Encrypted DNS Upstreams

Policy goals:

* Keep normal UDP / TCP DNS access for LAN clients
* Use DoH / DoT between OxiDNS and upstream resolvers
* Race multiple encrypted upstreams

```yaml
plugins:
  - tag: cache_main
    type: cache
    args:
      size: 8192
      short_circuit: true
      cache_negative: true

  - tag: forward_encrypted
    type: forward
    args:
      concurrent: 2
      upstreams:
        - tag: "cloudflare_doh"
          addr: "https://cloudflare-dns.com/dns-query"
          bootstrap: "1.1.1.1:53"
          timeout: 5s
        - tag: "google_dot"
          addr: "tls://dns.google:853"
          bootstrap: "8.8.8.8:53"
          timeout: 5s

  - tag: seq_main
    type: sequence
    args:
      - exec: "$cache_main"
      - matches: "!has_resp"
        exec: "$forward_encrypted"

  - tag: udp_lan
    type: udp_server
    args:
      entry: "seq_main"
      listen: ":5353"

  - tag: tcp_lan
    type: tcp_server
    args:
      entry: "seq_main"
      listen: ":5353"
```

Good fits:

* LAN clients should keep using ordinary DNS
* Outbound resolver traffic should be encrypted
* Domain-based upstreams need `bootstrap` to avoid a resolver bootstrap loop

To expose encrypted DNS to clients, add a TLS-enabled `tcp_server`, `http_server`, or `quic_server` on top of this policy and make sure the certificate and private key files already exist and are readable.

## Scenario 6: Automatically Refresh Ad-Blocking Subscriptions

Policy goals:

* Fill the local rule file automatically on first startup
* Download rule subscriptions in the background
* Reload only the affected provider after download, without a full process reload

```yaml
plugins:
  - tag: subscription_download
    type: download
    args:
      timeout: 60s
      startup_if_missing: true
      downloads:
        - url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
          dir: "./rules"
          filename: "adguard.txt"

  - tag: ad_rules
    type: adguard_rule
    args:
      files:
        - "./rules/adguard.txt"

  - tag: reload_ad_rules
    type: reload_provider
    args:
      - "$ad_rules"

  - tag: subscription_refresh
    type: sequence
    args:
      - exec: "$subscription_download"
      - exec: "$reload_ad_rules"

  - tag: subscription_cron
    type: cron
    args:
      timezone: "Asia/Shanghai"
      jobs:
        - name: refresh_ad_rules
          interval: 12h
          executors:
            - "$subscription_refresh"

  - tag: blocked
    type: sequence
    args:
      - exec: "black_hole 0.0.0.0 ::"
      - exec: accept

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
      - matches: "question $ad_rules"
        exec: goto blocked
      - exec: "$cache_main"
      - matches: "!has_resp"
        exec: "$forward_main"
```

Good fits:

* Rule files maintained by remote subscriptions
* Updating rule data independently from the main configuration
* Keeping full `reload` actions out of the real-time request path

## Scenario 7: Debugging, Auditing, and Path Analysis

Policy goals:

* Record query summaries and structured query history
* Preserve `sequence` execution paths for rule-hit analysis
* Expose metrics and management APIs at the same time

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
      name: "debug"

  - tag: recorder_main
    type: query_recorder
    args:
      path: "./query-recorder.sqlite"
      queue_size: 8192
      batch_size: 256
      flush_interval_ms: 200
      memory_tail: 1024
      retention_days: 7

  - tag: summary_main
    type: query_summary
    args:
      msg: "debug path"

  - tag: cache_main
    type: cache
    args:
      size: 4096
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
      - exec: "$recorder_main"
      - exec: "$summary_main"
      - exec: "$cache_main"
      - matches: "!has_resp"
        exec: "$forward_main"

  - tag: udp_debug
    type: udp_server
    args:
      entry: "seq_main"
      listen: ":5353"
```

Good fits:

* Observing rule hits before a new policy goes live
* Explaining why one domain reached a specific branch
* Feeding historical and live query data into the WebUI or external tools

## Scenario 8: Drive Network Integration from DNS Results

Policy goals:

* Turn resolved target IPs into system-side effects
* Feed firewall, route, or address-list state from DNS answers
* Sync only selected domains instead of writing every answer into the external system

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
      address: "172.16.1.1:8728"
      username: "api-user"
      password: "secret"
      async: true
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
* Deployments that need DNS-learned targets in network-device policy

## Composition Principles

### Decide the Main Path First, Then Add Side Effects

Start by making the main resolution path correct and readable, then layer in metrics, route sync, reverse lookup, or other side effects. This keeps the latency-critical path understandable and avoids coupling correctness to observability.

### Move Shared Rules into Providers Instead of Repeating Them Across Matchers

If multiple matchers reference the same domain or IP list, move that data into `domain_set` or `ip_set`. Providers make large policy graphs easier to update, easier to review, and less likely to drift.
