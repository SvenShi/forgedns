---
title: 常见策略场景
sidebar_position: 6
---

本章提供常见部署需求对应的配置示例。可以先从“最小可运行 DNS 网关”启动服务，再按需要加入家庭网关、域名分流、上游容错、加密上游、规则订阅、审计排障或网络联动能力。

每个示例都可以作为一份独立配置或策略片段使用。没有写 `udp_server` / `tcp_server` 的示例，表示重点在策略链本身；实际部署时可把对应 `seq_main` 接入“最小可运行 DNS 网关”里的监听器。

## 场景一：最小可运行 DNS 网关

策略目标：

* 提供 UDP / TCP 两种标准 DNS 入口
* 本地 hosts 优先，未命中再走缓存和公共上游
* 使用非特权端口，方便先在本机或容器中验证

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

适用场景：

* 首次验证 OxiDNS 行为
* 家庭或实验网络的起步配置
* 需要先避开 `:53` 端口权限、端口占用和系统 DNS 冲突

## 场景二：家庭或小办公室一体化策略

策略目标：

* 本地域名优先返回
* 广告规则命中后返回黑洞应答
* 未命中流量走缓存和公共上游
* 提供指标入口，便于后续接入观测

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

适用场景：

* 家用网关、旁路 DNS 或小办公室 DNS
* 希望一份配置同时处理本地名称、广告过滤、缓存和默认转发
* 先用内联规则起步，再逐步切换到外部规则文件

## 场景三：按域名分流到不同上游

策略目标：

* 内部域名走内网 DNS
* 指定域名走专用上游
* 其它请求走默认上游

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

适用场景：

* 公司内网域名和公网域名混合解析
* 只让少量域名使用特定出口或特定加密上游
* 避免把域名列表重复写在多条 `sequence` 规则里

## 场景四：多上游容错与快速回退

策略目标：

* 优先走延迟更低的主链路
* 主链路慢或失败时快速切换
* 不让备用链路在所有请求上都变成强依赖

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

适用场景：

* 一条上游追求速度，一条上游追求稳定
* 希望改善尾延迟
* 将容错逻辑收敛在一个 executor 里，而不是在多条规则里重复兜底

## 场景五：出站使用加密 DNS 上游

策略目标：

* 客户端仍使用普通 UDP / TCP 访问 OxiDNS
* OxiDNS 到上游使用 DoH / DoT
* 多个加密上游之间做并发竞争

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

适用场景：

* 局域网内保持普通 DNS 接入
* 出站链路希望加密
* 希望用 `bootstrap` 避免域名型上游形成自举依赖

如需对客户端提供 DoT / DoH / DoQ 入口，请在此基础上增加 `tcp_server` TLS、`http_server` 或 `quic_server` 实例，并提前准备可读的证书和私钥文件。

## 场景六：广告规则订阅自动更新

策略目标：

* 首次启动时自动补齐本地规则文件
* 后台周期性下载规则订阅
* 下载完成后只刷新相关 provider，不全量重载进程

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

适用场景：

* 规则文件来自远程订阅
* 希望规则更新独立于主配置更新
* 不希望把 `reload` 这种全量重载动作放进实时请求路径

## 场景七：调试、审计与路径分析

策略目标：

* 记录查询摘要和结构化查询历史
* 保留 `sequence` 执行路径，方便排查规则命中
* 同时暴露指标和管理 API

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

适用场景：

* 新策略上线前观察命中路径
* 排查某个域名为什么走了特定分支
* 给 WebUI 或外部系统提供历史查询与实时查询流

## 场景八：DNS 结果驱动网络联动

策略目标：

* 把解析结果同步到系统或设备侧集合
* DNS 决策与后续流量策略联动
* 只对目标域名同步，避免把所有解析结果写入外部系统

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

适用场景：

* DNS 驱动的路由或防火墙控制
* 需要把解析结果同步到外部网络系统
* 需要把 DNS 学到的目标地址交给网络设备侧策略使用

## 组合原则

### 先决定主路径，再加副作用

推荐顺序如下：

1. 先确认主路径。
   * 本地应答？
   * 缓存？
   * 单上游还是多上游？
2. 再加补充能力。
   * ECS
   * TTL 改写
   * 双栈偏好
3. 最后加观测和联动。
   * `query_summary`
   * `metrics_collector`
   * `ipset` / `nftset` / `ros_address_list`

### 能放到 provider 的规则，不要重复写在多个 matcher 里

当规则开始在多个分支中重复出现时：

* 域名规则提取成 `domain_set`
* IP 规则提取成 `ip_set`

该方式可使策略层聚焦于规则集引用关系，而无需重复维护相同规则文本。
