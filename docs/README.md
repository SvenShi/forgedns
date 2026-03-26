# ForgeDNS 文档

本文档采用 GitBook 目录结构，重点说明 ForgeDNS 的插件体系、配置结构、管理 API 与常见策略组合方式。

整体设计遵循同一条主链路：

```text
server -> DnsContext -> matcher/executor/provider pipeline -> upstream or side effects -> response
```

建议按照以下顺序阅读本文档：

1. 阅读《配置总览》，了解顶层 YAML 结构与 `sequence` 编排方式。
2. 阅读《插件总览》下的四类插件文档，建立 `server / executor / matcher / provider` 的结构认知。
3. 在接入运维平台、控制平面或观测系统时，阅读《管理 API》。
4. 在进行策略落地与组合设计时，阅读《常见策略场景》。

## 文档范围

当前内置插件如下：

- `server`
  - `udp_server`
  - `tcp_server`
  - `quic_server`
  - `http_server`
- `executor`
  - `sequence`
  - `forward`
  - `cache`
  - `fallback`
  - `hosts`
  - `arbitrary`
  - `redirect`
  - `reverse_lookup`
  - `ecs_handler`
  - `forward_edns0opt`
  - `ttl`
  - `prefer_ipv4`
  - `prefer_ipv6`
  - `black_hole`
  - `drop_resp`
  - `sleep`
  - `debug_print`
  - `query_summary`
  - `metrics_collector`
  - `ipset`
  - `nftset`
  - `mikrotik`
- `matcher`
  - `_true`
  - `_false`
  - `qname`
  - `qtype`
  - `qclass`
  - `client_ip`
  - `resp_ip`
  - `ptr_ip`
  - `cname`
  - `mark`
  - `env`
  - `random`
  - `rate_limiter`
  - `rcode`
  - `has_resp`
  - `has_wanted_ans`
  - `string_exp`
- `provider`
  - `domain_set`
  - `ip_set`
