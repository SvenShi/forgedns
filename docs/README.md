# ForgeDNS 文档

本文档重点说明 ForgeDNS 的配置结构、插件体系、管理 API、常见策略组合，以及架构与性能说明。

建议按照以下顺序阅读本文档：

1. 阅读《[配置总览](01-configuration.md)》，了解顶层 YAML 结构与 `sequence` 编排方式。
2. 阅读《[插件总览](02-plugin-reference/)》下的四类插件文档，建立 `server / executor / matcher / provider` 的结构认知。
3. 在接入运维平台、控制平面或观测系统时，阅读《[管理 API](03-api.md)》。
4. 在进行策略落地与组合设计时，阅读《[常见策略场景](05-scenarios.md)》。
5. 在理解内部设计与性能方向时，阅读《[架构与设计](06-architecture-and-design.md)》与《[性能与基准](07-benchmarks.md)》。

## 文档范围

当前内置插件如下：

* [`server`](02-plugin-reference/server.md)
  * [`udp_server`](02-plugin-reference/server.md#udp_server)
  * [`tcp_server`](02-plugin-reference/server.md#tcp_server)
  * [`quic_server`](02-plugin-reference/server.md#quic_server)
  * [`http_server`](02-plugin-reference/server.md#http_server)
* [`executor`](02-plugin-reference/executor.md)
  * [`sequence`](02-plugin-reference/executor.md#sequence)
  * [`forward`](02-plugin-reference/executor.md#forward)
  * [`cache`](02-plugin-reference/executor.md#cache)
  * [`fallback`](02-plugin-reference/executor.md#fallback)
  * [`hosts`](02-plugin-reference/executor.md#hosts)
  * [`arbitrary`](02-plugin-reference/executor.md#arbitrary)
  * [`redirect`](02-plugin-reference/executor.md#redirect)
  * [`reverse_lookup`](02-plugin-reference/executor.md#reverse_lookup)
  * [`ecs_handler`](02-plugin-reference/executor.md#ecs_handler)
  * [`forward_edns0opt`](02-plugin-reference/executor.md#forward_edns0opt)
  * [`ttl`](02-plugin-reference/executor.md#ttl-1)
  * [`prefer_ipv4`](02-plugin-reference/executor.md#prefer_ipv4-prefer_ipv6)
  * [`prefer_ipv6`](02-plugin-reference/executor.md#prefer_ipv4-prefer_ipv6)
  * [`black_hole`](02-plugin-reference/executor.md#black_hole)
  * [`drop_resp`](02-plugin-reference/executor.md#drop_resp)
  * [`sleep`](02-plugin-reference/executor.md#sleep)
  * [`debug_print`](02-plugin-reference/executor.md#debug_print)
  * [`query_summary`](02-plugin-reference/executor.md#query_summary)
  * [`metrics_collector`](02-plugin-reference/executor.md#metrics_collector)
  * [`ipset`](02-plugin-reference/executor.md#ipset)
  * [`nftset`](02-plugin-reference/executor.md#nftset)
  * [`mikrotik`](02-plugin-reference/executor.md#mikrotik)
* [`matcher`](02-plugin-reference/matcher.md)
  * [`_true`](02-plugin-reference/matcher.md#true)
  * [`_false`](02-plugin-reference/matcher.md#false)
  * [`qname`](02-plugin-reference/matcher.md#qname)
  * [`qtype`](02-plugin-reference/matcher.md#qtype)
  * [`qclass`](02-plugin-reference/matcher.md#qclass)
  * [`client_ip`](02-plugin-reference/matcher.md#client_ip)
  * [`resp_ip`](02-plugin-reference/matcher.md#resp_ip)
  * [`ptr_ip`](02-plugin-reference/matcher.md#ptr_ip)
  * [`cname`](02-plugin-reference/matcher.md#cname)
  * [`mark`](02-plugin-reference/matcher.md#mark)
  * [`env`](02-plugin-reference/matcher.md#env)
  * [`random`](02-plugin-reference/matcher.md#random)
  * [`rate_limiter`](02-plugin-reference/matcher.md#rate_limiter)
  * [`rcode`](02-plugin-reference/matcher.md#rcode)
  * [`has_resp`](02-plugin-reference/matcher.md#has_resp)
  * [`has_wanted_ans`](02-plugin-reference/matcher.md#has_wanted_ans)
  * [`string_exp`](02-plugin-reference/matcher.md#string_exp)
* [`provider`](02-plugin-reference/provider.md)
  * [`domain_set`](02-plugin-reference/provider.md#domain_set)
  * [`ip_set`](02-plugin-reference/provider.md#ip_set)
