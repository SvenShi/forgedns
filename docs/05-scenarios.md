# 常见策略场景

本章给出若干更接近实际部署的组合方式。示例以策略目标为组织方式，不使用地域划分。

## 场景一：缓存优先的基础转发策略

策略目标：

* 优先命中缓存降低延时
* 未命中时走主上游
* 记录查询摘要与指标

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

适用场景：

* 单一主上游
* 对时延敏感
* 配置要尽量清晰直接

## 场景二：双上游快速回退策略

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

适用场景：

* 一条上游追求速度，一条上游追求稳定
* 希望改善尾延迟

## 场景三：本地静态优先，未命中再转发

策略目标：

* 内部服务、固定名称、本地覆盖优先返回
* 未命中时再查外部上游

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

适用场景：

* 本地服务发现
* 固定覆盖
* 小规模本地权威式数据维护

## 场景四：双栈偏好策略

策略目标：

* 根据网络目标选择偏好 IPv4 或 IPv6
* 让双栈域名更稳定地落到偏好地址族

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

适用场景：

* 客户端栈能力不一致
* 希望降低某一地址族带来的不确定性

## 场景五：基于来源网段的分层策略

策略目标：

* 不同客户端来源使用不同处理逻辑
* 在同一实例中承载多类策略

```yaml
plugins:
  - tag: group_a
    type: client_ip
    args:
      - "192.168.10.0/24"

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
      - matches: "$group_a"
        exec: "$forward_a"
      - matches: "!has_resp"
        exec: "$forward_b"
```

适用场景：

* 多业务域入口
* 按来源网络进行分层解析策略

## 场景六：DNS 结果驱动网络联动策略

策略目标：

* 把解析结果同步到系统或设备侧集合
* DNS 决策与后续流量策略联动

```yaml
plugins:
  - tag: forward_main
    type: forward
    args:
      upstreams:
        - addr: "udp://1.1.1.1:53"

  - tag: nftset_main
    type: nftset
    args:
      ipv4:
        table_family: "ip"
        table_name: "mangle"
        set_name: "dns_v4"
        mask: 24

  - tag: mikrotik_main
    type: mikrotik
    args:
      address: "172.16.1.1:8728"
      username: "api-user"
      password: "secret"
      async: true
      address_list4: "forgedns_ipv4"

  - tag: seq_main
    type: sequence
    args:
      - exec: "$forward_main"
      - exec: "$mikrotik_main"
```

适用场景：

* DNS 驱动的路由或防火墙控制
* 需要把解析结果同步到外部网络系统

## 场景七：管理面与观测面独立开放

策略目标：

* DNS 监听与管理 API 分离
* 支持健康检查、重载、配置校验与指标抓取

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

  - tag: forward_main
    type: forward
    args:
      upstreams:
        - addr: "udp://1.1.1.1:53"

  - tag: seq_main
    type: sequence
    args:
      - exec: "$metrics_main"
      - exec: "$forward_main"
```

可配合接口：

* `GET /healthz`
* `GET /readyz`
* `GET /health`
* `GET /control`
* `POST /reload`
* `GET /metrics`

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
   * `ipset` / `nftset` / `mikrotik`

### 能放到 provider 的规则，不要重复写在多个 matcher 里

当规则开始在多个分支中重复出现时：

* 域名规则提取成 `domain_set`
* IP 规则提取成 `ip_set`

该方式可使策略层聚焦于规则集引用关系，而无需重复维护相同规则文本。
