---
title: 执行器插件
sidebar_position: 3
---

执行器是 ForgeDNS 的核心动作层。它们可以读写请求、设置响应、调用上游、缓存结果、做回退、记录日志，或触发系统联动。

阅读本章时，应重点关注以下两个问题：

1. 这个插件是在“正向阶段”生效，还是在“回程阶段”也会改写结果？
2. 它是主路径动作，还是观测/副作用动作？

---

## `cron`

### 作用

后台调度一组 executor。它不会参与实时 DNS 请求链，而是在插件初始化后按 cron 或固定间隔触发任务。

### 配置示例

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

### 配置项

#### `args.jobs`

- 类型：`array`；必填：是；默认值：无
- 作用：定义一个或多个后台任务。
- 运行影响：
  - 数组不能为空。
  - 每个任务独立维护自己的调度状态和重叠保护。

#### `args.timezone`

- 类型：`string`；必填：否；默认值：系统本地时区
- 作用：为当前 `cron` 插件下的所有 `schedule` 任务指定时区。
- 运行影响：
  - 仅对 `schedule` 生效。
  - 未配置时会使用系统本地时区；无法获取时退回 `UTC`。
  - 应填写 IANA 时区名称，例如 `Asia/Shanghai`、`UTC`、`America/Los_Angeles`。

#### `args.jobs[].name`

- 类型：`string`；必填：是；默认值：无
- 作用：任务名称，用于日志与运行时标识。
- 运行影响：
  - 在同一个 `cron` 插件内必须唯一。

#### `args.jobs[].schedule`

- 类型：`string`；必填：与 `interval` 二选一；默认值：无
- 作用：使用标准 5 字段 cron 表达式调度任务。
- 规则说明：
  - 仅支持 `minute hour day month day-of-week`。
  - 不支持秒级 cron。
  - 按 `args.timezone` 或系统本地时区计算下一次触发时间。

#### `args.jobs[].interval`

- 类型：`string`；必填：与 `schedule` 二选一；默认值：无
- 作用：用简单固定间隔调度任务。
- 支持格式：
  - `5m`
  - `1h`
  - `1d`
- 运行影响：
  - 最小粒度为 `1m`。
  - 启动后会等待一个完整间隔再首次触发。

#### `args.jobs[].executors`

- 类型：`array`；必填：是；默认值：无
- 作用：定义任务触发时顺序执行的 executor 列表。
- 支持形式：
  - `$tag`：显式引用已存在 executor
  - `tag`：裸 tag 引用
  - quick setup 表达式，例如 `debug_print cron refresh`
- 运行影响：
  - 数组不能为空。
  - 即使某个 executor 返回 `Stop`、设置了响应、或执行报错，后续 executor 仍会继续执行。

### 行为说明

- `schedule` 和 `interval` 必须二选一。
- 同一个 job 若上一轮仍在运行，本轮会被跳过，不补跑。
- 任务使用空的 `DnsContext`，适合副作用类 executor 或后台编排的 `sequence`。
- `cron` 本身不能放进普通请求 `sequence` 里执行。

### 典型用途

- 定时触发后台副作用逻辑。
- 定时执行一个专门的 `sequence` 编排。
- 为未来的 `reload` 之类后台动作提供统一调度入口。

### 注意事项

- 不允许引用另一个 `cron` executor。
- 依赖真实 DNS 请求内容的 executor 在空上下文任务中通常没有意义。

---

## `download`

### 作用

下载一个或多个 `http/https` 文件到本地目录，并在新内容完整写入后覆盖目标文件。

### 配置示例

```yaml
- tag: rules_download
  type: download
  args:
    timeout: 30s
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

### 行为说明

- `downloads` 按声明顺序串行执行。
- 单个下载失败只会写 warning 日志，不会阻止后续项继续下载。
- 目标目录不存在时会自动创建。
- 文件会先写入临时文件，再覆盖目标文件，避免半写入状态。

### 注意事项

- 只支持 `http` / `https`。
- 放进普通 `sequence` 时会直接占用该次请求的执行时间。
- 覆盖本地文件后不会自动触发配置 reload；如需让新文件立即生效，请显式串联一个 `reload` executor。

### 推荐搭配

```yaml
- tag: rules_refresh
  type: sequence
  args:
    - exec: "$rules_download"
    - exec: "$reload_all"

- tag: rules_download
  type: download
  args:
    downloads:
      - url: "https://example.com/geosite.dat"
        dir: "/etc/forgedns"

- tag: reload_all
  type: reload
```

---

## `reload`

### 作用

触发一次与管理 API `POST /reload` 相同的应用级全量 reload，重新加载当前配置并重建所有插件。

### 配置示例

```yaml
- tag: reload_all
  type: reload
```

### Quick Setup

```yaml
- exec: "reload"
```

### 行为说明

- 执行时会向应用控制层提交一次 reload 请求。
- 语义等同于调用管理 API 的 `POST /reload`。
- reload 请求被接受后当前 executor 返回 `Next`。
- 这是全量应用 reload，不支持按指定 tag 只重载部分插件。

### 典型用途

- 在 `cron` 任务中配合 `download`，周期性刷新本地规则文件后立即让新配置生效。
- 在后台维护 `sequence` 中统一触发一次全量配置重载。

### 注意事项

- 需要运行在带有应用控制上下文的正常 ForgeDNS 进程中。
- 如果已有 reload 处于 `pending` 或 `in_progress`，本次执行会返回错误。
- 放进普通请求 `sequence` 时会触发全量应用 reload，通常不建议在实时请求路径上使用。

---

## `sequence`

### 作用

把多个 matcher 和 executor 编排成一条流水线，是最常用的入口执行器。

### 配置示例

```yaml
- tag: seq_main
  type: sequence
  args:
    # 先尝试读取缓存
    - exec: "$cache_main"
    # 命中缓存后直接结束
    - matches: "has_resp"
      exec: "accept"
    # 多个 matches 写成数组时是逻辑与
    # 示例里尽量直接写 quick setup 表达式
    - matches:
        - "client_ip $lan_ip_set"
        - "qname $local_domains"
      exec: "$hosts_main"
    # 没有前置条件时也可以直接执行观测类插件
    - exec: "$metrics_main"
    # 还没有响应时再继续转发
    - matches: "!has_resp"
      exec: "$forward_main"
    # 响应回来后统一收敛 TTL
    - matches: "has_resp"
      exec: "$ttl_main"
```

### 配置项

`sequence` 的 `args` 为规则数组，数组中的每个元素代表一条顺序执行规则。

#### `args`

- 类型：`array`；必填：是；默认值：无
- 作用：定义 sequence 的规则链。
- 运行影响：
  - 规则按书写顺序依次执行。
  - `args` 为空时插件初始化失败。

#### `args[].matches`

- 类型：`string` 或 `array`
- 必填：否
- 默认值：无
- 作用：定义当前规则的匹配条件。
- 支持形式：
  - 单个 matcher 字符串
  - 多个 matcher 组成的列表
- 运行影响：
  - 多个条件之间为逻辑与关系。
  - 未配置时表示无前置匹配条件。

#### `args[].exec`

- 类型：`string`；必填：否；默认值：无
- 作用：定义规则命中后要执行的动作。
- 支持内容：
  - 插件引用
  - quick setup 表达式
  - 内建控制流
- 运行影响：
  - 直接决定当前规则的执行行为。

### 行为说明

- 按顺序执行规则。
- 一条规则里多个 `matches` 需要同时为真。
- 可以通过 `jump` / `goto` 调用其它 `sequence`。

### 典型用途

- 统一总入口。
- 把缓存、本地应答、转发、联动拆分成可读的策略层。
- 通过 marks、matchers 做复杂分支。

### 注意事项

- 被引用的插件必须已经定义。
- `sequence` 至少需要一条规则。

---

## `forward`

### 作用

向上游发起 DNS 查询。

### 配置示例

```yaml
- tag: forward_main
  type: forward
  args:
    # 多上游模式下实际并发扇出
    concurrent: 3
    upstreams:
      # 最简单的 UDP 上游
      - tag: "cf_udp"
        addr: "udp://1.1.1.1:53"
        timeout: 3s

      # 域名型 DoH 上游，演示 bootstrap / 连接池 / HTTP/3 / Linux socket 参数
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

      # DoT 上游，演示 dial_addr / SOCKS5 / TLS 校验开关 / pipeline
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

### 配置项

#### `concurrent`

- 类型：`integer`；必填：否；默认值：`1`
- 取值范围：实际运行时会限制在 `1..=3`
- 作用：定义多上游模式下的并发查询扇出数。
- 运行影响：
  - 值越大，多上游竞争越积极，但同时会增加上游请求量。

#### `upstreams`

- 类型：`array`；必填：是；默认值：无
- 作用：定义一个或多个上游目标。
- 运行影响：
  - 数组长度为 `1` 时使用单上游模式。
  - 数组长度大于 `1` 时使用竞争式查询模式。

#### `upstreams[].addr`

- 类型：`string`；必填：是；默认值：无
- 作用：定义上游地址、协议类型以及目标主机。
- 示例：
  - `addr: "8.8.8.8:53"`
  - `addr: "tls://dns.example:853"`
  - `addr: "https://resolver.example/dns-query"`
- 支持格式：
  - `udp://8.8.8.8:53` 或 `8.8.8.8:53`
  - `tcp://8.8.8.8:53`
  - `tcp+pipeline://8.8.8.8:53`
  - `tls://dns.example:853`
  - `tls+pipeline://dns.example:853`
  - `quic://dns.example:853` 或 `doq://dns.example:853`
  - `https://resolver.example/dns-query` 或 `doh://resolver.example/dns-query`
  - `h3://resolver.example/dns-query`
- 规则说明：
  - 未写协议时，按 `udp://` 处理。
  - `https://` / `doh://` 表示 DoH，`h3://` 表示强制 DoH over HTTP/3。
  - `tcp+pipeline://` 与 `tls+pipeline://` 会直接启用流水线模式。
  - DoH 地址应包含实际请求路径，例如 `/dns-query`。
- 配置建议：域名型上游建议同时配置 `bootstrap`，避免形成引导解析依赖。

#### `upstreams[].tag`

- 类型：`string`；必填：否；默认值：无
- 作用：为单个上游提供日志标识，便于排查多上游竞争结果。
- 示例：`tag: "upstream_google"`

#### `upstreams[].dial_addr`

- 类型：`ip`；必填：否；默认值：无
- 作用：指定实际连接 IP，同时保留 `addr` 中的主机名用于 SNI、Host 和证书校验。
- 示例：`dial_addr: "1.1.1.1"`
- 适用场景：固定拨号地址、绕过本机解析或配合自定义路由出口。

#### `upstreams[].port`

- 类型：`integer`；必填：否；默认值：协议默认端口
- 作用：覆盖协议默认端口。
- 示例：`port: 5353`

#### `upstreams[].bootstrap`

- 类型：`string`；必填：否；默认值：无
- 作用：为域名型上游提供引导解析服务器。
- 示例：
  - `bootstrap: "8.8.8.8:53"`
  - `bootstrap: "[2606:4700:4700::1111]:53"`
- 规则说明：
  - 仅在 `addr` 使用域名时有意义。
  - 应写为 `IP:port`，不能再写域名。
  - 典型用于 DoT、DoQ、DoH 域名上游的首次解析。

#### `upstreams[].bootstrap_version`

- 类型：`integer`；必填：否；默认值：无
- 作用：指定 bootstrap 优先使用 IPv4 或 IPv6。
- 示例：
  - `bootstrap_version: 4`
  - `bootstrap_version: 6`
- 取值：`4` 或 `6`。

#### `upstreams[].socks5`

- 类型：`string`；必填：否；默认值：无
- 作用：为上游连接指定 SOCKS5 代理。
- 示例：
  - `socks5: "127.0.0.1:1080"`
  - `socks5: "user:pass@127.0.0.1:1080"`
  - `socks5: "user:pass@[2001:db8::1]:1080"`
- 支持格式：
  - `host:port`
  - `username:password@host:port`
  - IPv6 需写成 `[addr]:port`
  - 带认证的 IPv6 需写成 `username:password@[addr]:port`
- 规则说明：
  - 代理主机可以是 IP，也可以是主机名；主机名会使用系统解析。
  - 认证部分只按第一个 `:` 分割用户名和密码，因此格式必须是 `username:password@...`。
  - 上游启用 `enable_http3` 时不应再配置 `socks5`，两者不属于同一连接模型。
- 注意事项：格式错误、端口非法或代理主机解析失败时，该上游不会被正常创建。

#### `upstreams[].idle_timeout`

- 类型：`integer`；必填：否；默认值：无
- 单位：秒
- 作用：定义连接池空闲连接保留时间。
- 示例：`idle_timeout: 30`

#### `upstreams[].max_conns`

- 类型：`integer`；必填：否；默认值：实现默认值
- 作用：定义连接池连接上限。
- 示例：`max_conns: 256`

#### `upstreams[].insecure_skip_verify`

- 类型：`boolean`；必填：否；默认值：`false`
- 作用：控制是否跳过 TLS 证书校验。
- 示例：`insecure_skip_verify: true`
- 注意事项：仅适用于测试、自签证书或受控环境。

#### `upstreams[].timeout`

- 类型：`duration`；必填：否；默认值：`5s`
- 作用：定义单次上游查询超时。
- 示例：`timeout: 3s`

#### `upstreams[].enable_pipeline`

- 类型：`boolean`；必填：否；默认值：协议默认行为
- 作用：控制 TCP 或 DoT 流水线。
- 示例：`enable_pipeline: true`
- 说明：也可直接通过 `tcp+pipeline://` 或 `tls+pipeline://` 在 `addr` 中启用。

#### `upstreams[].enable_http3`

- 类型：`boolean`；必填：否；默认值：`false`
- 作用：控制 DoH 是否使用 HTTP/3。
- 示例：`enable_http3: true`
- 说明：也可直接通过 `h3://` 在 `addr` 中启用。

#### `upstreams[].so_mark`

- 类型：`integer`；必填：否；默认值：无
- 作用：设置 Linux `SO_MARK`。
- 示例：`so_mark: 100`

#### `upstreams[].bind_to_device`

- 类型：`string`；必填：否；默认值：无
- 作用：设置 Linux `SO_BINDTODEVICE`。
- 示例：`bind_to_device: "eth1"`

### quick setup

```yaml
- exec: "forward 1.1.1.1"
- exec: "forward 1.1.1.1 8.8.8.8"
```

说明：

- 单个地址创建单上游转发。
- 多个地址创建并发竞争转发。
- quick setup 只接受地址列表，进阶参数需要完整插件形式。

### 行为说明

- 单上游模式：直接查询该上游。
- 多上游模式：从随机起点选择上游并发查询，先返回成功结果者胜出。
- 当与 `prefer_ipv4` / `prefer_ipv6` 联动时，支持额外 preferred qtype probe。

### 常见用途

- 标准转发。
- 多上游容错。
- 多协议混合上游。

### 注意事项

- 需要更细的并发、代理、引导解析、HTTP/3 参数时，使用完整 `upstreams` 配置。
- 多上游越多并不一定越好，先保证上游分组语义清晰。

---

## `cache`

### 作用

对响应做 TTL 感知缓存，支持负缓存与持久化。

### 配置示例

```yaml
- tag: cache_main
  type: cache
  args:
    # 最大缓存条目数
    size: 8192
    # 命中缓存后直接结束后续执行
    short_circuit: true
    # 允许在原始 TTL 过期后短时间返回 stale 响应，并异步刷新缓存
    lazy_cache_ttl: 120
    # 开启 NXDOMAIN / NODATA 负缓存
    cache_negative: true
    # 负缓存 TTL 上限
    max_negative_ttl: 300
    # 负响应没有 SOA 时使用的回退 TTL
    negative_ttl_without_soa: 60
    # 正响应 TTL 上限
    max_positive_ttl: 600
    # ECS 不参与缓存键，提升命中率
    ecs_in_key: false
    # 启用缓存持久化
    dump_file: "./dns_cache.dump"
    # 定期落盘周期，单位秒
    dump_interval: 600
```

### 配置项

#### `size`

- 类型：`integer`；必填：否；默认值：`1024`
- 作用：定义缓存最大条目数。

#### `lazy_cache_ttl`

- 类型：`integer`；必填：否；默认值：无
- 单位：秒
- 作用：为正向成功响应启用 lazy cache。
- 运行影响：
  - 原始 TTL 决定 fresh 命中窗口。
  - `lazy_cache_ttl` 决定 stale 回包 TTL，并允许在原始 TTL 过期后短时间返回 stale 响应。
  - stale 命中会在后台异步刷新缓存。
  - 该配置不会缩短原始 fresh TTL。

#### `dump_file`

- 类型：`string`；必填：否；默认值：无
- 作用：指定缓存持久化文件路径。

#### `dump_interval`

- 类型：`integer`；必填：否；默认值：`600`
- 单位：秒
- 作用：定义缓存定期落盘周期。

#### `short_circuit`

- 类型：`boolean`；必填：否；默认值：实现默认行为
- 作用：控制缓存命中后是否立即结束后续执行。
- 说明：
  - 设为 `false` 时，即使 cache 已经写入 response，后续执行链仍会继续。
  - 如需避免后续 `forward` 再次发起查询，应在 `sequence` 中配合 `has_resp`、`accept` 等控制流使用。

#### `cache_negative`

- 类型：`boolean`；必填：否；默认值：实现默认行为
- 作用：控制是否缓存 NXDOMAIN 与 NODATA。

#### `max_negative_ttl`

- 类型：`integer`；必填：否；默认值：`300`
- 单位：秒
- 作用：定义负缓存 TTL 上限。

#### `negative_ttl_without_soa`

- 类型：`integer`；必填：否；默认值：`60`
- 单位：秒
- 作用：定义无 SOA 负响应的回退 TTL。

#### `max_positive_ttl`

- 类型：`integer`；必填：否；默认值：无
- 单位：秒
- 作用：定义正响应 TTL 上限。

#### `ecs_in_key`

- 类型：`boolean`；必填：否；默认值：`false`
- 作用：控制 ECS scope 是否参与缓存键计算。

### 行为说明

- 既会读缓存，也会在后续拿到响应后写缓存。
- 命中缓存时，返回缓存副本并按剩余 TTL 输出。
- 内置过期清理和近似 LRU 回收。

### 插件 API

- `GET /plugins/<tag>/flush`
  - 清空缓存。
- `GET /plugins/<tag>/dump`
  - 导出缓存内容。
- `POST /plugins/<tag>/load_dump`
  - 导入缓存 dump。

### 典型用途

- 所有转发入口前置缓存。
- 构建高命中率低时延策略。
- 在可控场景中持久化缓存，加快重启后恢复。

### 注意事项

- 如果前面有会直接生成本地应答的插件，放置位置会决定这些结果是否进入缓存。
- `ecs_in_key` 开启后，缓存碎片会明显增加。

---

## `fallback`

### 作用

在主路径失败或过慢时，切换到备用路径。

### 配置示例

```yaml
- tag: fallback_main
  type: fallback
  args:
    # 首选路径
    primary: "forward_fast"
    # 兜底路径
    secondary: "forward_stable"
    # 主路径超过 200ms 后允许备用路径接管
    threshold: 200
    # 让备用路径始终并行待命，换取更低尾延迟
    always_standby: true
```

### 配置项

#### `primary`

- 类型：`string`；必填：是；默认值：无
- 作用：指定主执行器。

#### `secondary`

- 类型：`string`；必填：是；默认值：无
- 作用：指定备用执行器。

#### `threshold`

- 类型：`integer`；必填：否；默认值：`0`
- 单位：毫秒
- 作用：定义主路径超时或延迟判定阈值。

#### `always_standby`

- 类型：`boolean`；必填：否；默认值：`false`
- 作用：控制备用路径是否与主路径同时待命。

### 行为说明

- 正向启动主路径。
- 到达阈值或主路径失败后启动/释放备用路径。
- 谁先拿到有效响应，谁赢。
- 另一分支会被取消。

### 典型用途

- 快速上游 + 稳定上游的双层回退。
- 不同协议上游之间的故障兜底。

### 注意事项

- 这是“路径级”回退，不是“记录级”合并。
- `always_standby` 可以降低尾延迟，但会放大上游开销。

---

## `hosts`

### 作用

按域名规则直接返回静态 `A` / `AAAA`。

### 配置示例

```yaml
- tag: hosts_main
  type: hosts
  args:
    entries:
      # 精确匹配单个主机名
      - "full:router.local 192.168.1.1"
      # 后缀匹配，可同时返回 IPv4 / IPv6
      - "domain:svc.local 10.0.0.10 fd00::10"
      # 关键字匹配
      - "keyword:nas 192.168.1.20"
      # 正则匹配
      - "regexp:^api[0-9]+\\.corp\\.local$ 10.10.0.5"
    files:
      # 从文件合并更多 hosts 规则
      - "/etc/forgedns/hosts.txt"
```

### 配置项

#### `entries`

- 类型：`array`；必填：否；默认值：空数组
- 作用：定义内联 hosts 规则。
- 规则格式：
  - `<域名规则> <ip1> <ip2> ...`

#### `files`

- 类型：`array`；必填：否；默认值：空数组
- 作用：指定外部 hosts 规则文件列表。

规则格式：

```text
<域名规则> <ip1> <ip2> ...
```

### 行为说明

- 仅处理 `IN` 类的 `A` / `AAAA` 请求。
- 根据查询类型返回同族地址。
- 未命中时透传后续执行。
- TTL 固定为 `300`。

### 典型用途

- 本地服务名。
- 固定内部地址映射。
- 小规模静态域名覆盖。

---

## `arbitrary`

### 作用

加载任意静态 DNS 记录并在命中时直接构造应答。

### 配置示例

```yaml
- tag: arbitrary_main
  type: arbitrary
  args:
    rules:
      # TXT 记录
      - "example.com. 60 IN TXT \"hello world\""
      # MX 记录
      - "mail.example.com. 300 IN MX 10 mx1.example.com."
      # A / AAAA / CNAME / PTR 也都可以直接写
      - "www.example.com. 120 IN A 192.0.2.10"
      - "www.example.com. 120 IN AAAA 2001:db8::10"
      - "alias.example.com. 120 IN CNAME www.example.com."
      - "10.2.0.192.in-addr.arpa. 300 IN PTR host.example.com."
    files:
      # 从文件加载更多静态记录
      - "/etc/forgedns/zone.txt"
```

### 配置项

#### `rules`

- 类型：`array`；必填：否；默认值：空数组
- 作用：定义内联静态记录列表。

#### `files`

- 类型：`array`；必填：否；默认值：空数组
- 作用：指定静态记录文件列表。

### 行为说明

- 查询名与类型匹配时，直接生成本地应答。
- `ANY` 查询会返回该名称下全部已加载记录。
- 常见 `A` / `AAAA` 走了快路径优化。

### 典型用途

- 少量静态权威式记录。
- 本地 TXT / MX / PTR / CNAME 数据。
- 测试或实验环境的本地响应。

### 注意事项

- 这是“静态响应生成器”，不负责 zone 传送或权威服务器全语义。

---

## `redirect`

### 作用

把请求域名改写为另一个目标域名，并在返回阶段补回客户端可见的 CNAME。

### 配置示例

```yaml
- tag: redirect_main
  type: redirect
  args:
    rules:
      # 精确重定向
      - "full:old.example.com new.example.net"
      # 后缀重定向
      - "domain:legacy.example.com modern.example.net"
      # 关键字重定向
      - "keyword:staging staging-gateway.example.net"
    files:
      # 从文件合并更多重定向规则
      - "/etc/forgedns/redirect.txt"
```

### 配置项

#### `rules`

- 类型：`array`；必填：否；默认值：空数组
- 作用：定义内联重定向规则。
- 规则格式：
  - `<域名规则> <目标域名>`

#### `files`

- 类型：`array`；必填：否；默认值：空数组
- 作用：指定外部重定向规则文件列表。

规则格式：

```text
<域名规则> <目标域名>
```

### 行为说明

- 正向阶段：改写请求的 QUESTION NAME。
- 回程阶段：
  - 把 response question 中的目标名还原为原始名。
  - 在 answers 里追加一条 `CNAME original -> target`。

### 典型用途

- 统一入口域名指向另一套记录。
- 对特定域名做别名跳转而不改客户端配置。

### 注意事项

- 更适合 A/AAAA/TXT 这类简单请求。
- 对复杂记录和某些扩展场景不保证完全语义透明。

---

## `reverse_lookup`

### 作用

缓存应答中的 IP -> 域名关系，并可选地处理 PTR 查询。

### 配置示例

```yaml
- tag: reverse_lookup_main
  type: reverse_lookup
  args:
    # 反查缓存容量
    size: 65535
    # IP -> 域名映射保留时间
    ttl: 7200
    # 命中缓存时直接回答 PTR
    handle_ptr: true
```

### 配置项

#### `size`

- 类型：`integer`；必填：否；默认值：`65535`
- 作用：定义反查缓存容量上限。

#### `handle_ptr`

- 类型：`boolean`；必填：否；默认值：`false`
- 作用：控制是否直接用反查缓存响应 PTR 请求。

#### `ttl`

- 类型：`integer`；必填：否；默认值：`7200`
- 单位：秒
- 作用：定义 IP 到域名映射的缓存 TTL。

### 行为说明

- 若 `handle_ptr: true` 且 PTR 命中缓存，会直接返回 PTR 响应并停止后续链路。
- 正常回程阶段会扫描 `A` / `AAAA` answers，把 IP 与请求域名写入缓存。
- 会把记录 TTL 限制在插件配置 TTL 上限内。

### 插件 API

- `GET /plugins/<tag>?ip=<ip>`
  - 返回命中的完全限定域名。

### 典型用途

- 本地快速 IP 反查。
- 策略排障、日志联动、资产可视化。

### 注意事项

- 推荐放置在 `cache` 之前，否则缓存命中可能绕过该插件，导致反查表不更新。

---

## `ecs_handler`

### 作用

处理 EDNS Client Subnet。

### 配置示例

```yaml
- tag: ecs_main
  type: ecs_handler
  args:
    # 客户端自带 ECS 时先移除
    forward: false
    # 请求没有 ECS 时自动补发
    send: true
    # IPv4 ECS 前缀长度
    mask4: 24
    # IPv6 ECS 前缀长度
    mask6: 48

- tag: ecs_preset
  type: ecs_handler
  args:
    # 预设 ECS 地址
    preset: "203.0.113.10"
    # 固定来源模式下也建议显式写出策略开关
    forward: false
    send: true
    mask4: 24
    mask6: 48
```

### 配置项

#### `forward`

- 类型：`boolean`；必填：否；默认值：`false`
- 作用：控制是否保留客户端请求中已有的 ECS。

#### `send`

- 类型：`boolean`；必填：否；默认值：`false`
- 作用：控制在请求缺少 ECS 时，是否根据来源地址自动补充 ECS。

#### `preset`

- 类型：`string`；必填：否；默认值：无
- 作用：指定固定的 ECS 来源地址。

#### `mask4`

- 类型：`integer`；必填：否；默认值：`24`
- 作用：指定 IPv4 ECS 前缀长度。

#### `mask6`

- 类型：`integer`；必填：否；默认值：`48`
- 作用：指定 IPv6 ECS 前缀长度。

### quick setup

```yaml
- exec: "ecs_handler 203.0.113.10/24"
```

当前 quick setup 主要用于传入 preset IP。涉及高级开关时，应使用完整配置形式。

### 行为说明

- 正向阶段：
  - 可删掉已有 ECS。
  - 可保留已有 ECS。
  - 可根据客户端地址或 preset 注入 ECS。
- 回程阶段：
  - 如果 ECS 不是从客户端原样转发的，会把响应里的 ECS 去掉，避免泄露内部构造信息。

### 典型用途

- 面向策略上游携带客户端网段信息。
- 在网关场景下根据访问来源做更细粒度结果优化。

### 注意事项

- `mask4` 最大 `32`，`mask6` 最大 `128`。

---

## `forward_edns0opt`

### 作用

把指定 EDNS0 option code 从下游请求转发到最终响应中。

### 配置示例

```yaml
- tag: edns_forward
  type: forward_edns0opt
  args:
    # 只透传指定的 EDNS0 option code
    codes: [10, 12]
```

### 配置项

#### `codes`

- 类型：`array`；必填：否；默认值：空数组
- 作用：定义允许从请求复制到响应中的 EDNS0 option code 集合。
- 运行影响：
  - 未配置时插件基本退化为无操作。

### quick setup

```yaml
- exec: "forward_edns0opt 10,12"
```

### 行为说明

- 正向阶段从请求里收集目标 option。
- 回程阶段把这些 option 写回响应的 OPT 记录。
- 会做去重。

### 典型用途

- 透传特定 EDNS0 扩展。
- 在策略链中保留与下游会话有关的附加元数据。

---

## `ttl`

### 作用

改写响应 TTL。

### 配置示例

完整对象形式：

```yaml
- tag: ttl_main
  type: ttl
  args:
    # 先把 TTL 固定为 300
    fix: 300
    # 再做下限兜底
    min: 60
    # 再做上限约束
    max: 600
```


### 配置项

#### `fix`

- 类型：`integer`；必填：否；默认值：无
- 作用：将所有响应 TTL 固定为同一个值。

#### `min`

- 类型：`integer`；必填：否；默认值：无
- 作用：定义 TTL 下限。

#### `max`

- 类型：`integer`；必填：否；默认值：无
- 作用：定义 TTL 上限。

### quick setup

```yaml
- exec: "ttl 300"
- exec: "ttl 60-600"
```

### 行为说明

- 会改写 answers、authority、additionals 中的 TTL。
- 适合放在获得响应之后。

### 典型用途

- 缩短高波动域名的 TTL。
- 统一本地策略结果的缓存行为。

---

## `prefer_ipv4` / `prefer_ipv6` {#prefer_ipv4-prefer_ipv6}

### 作用

双栈优选器。对偏好类型做学习，对非偏好类型做抑制。

### 配置示例

```yaml
- tag: prefer_v4
  type: prefer_ipv4
  args:
    # 记录 preferred 类型是否存在
    cache: true
    # preferred 状态缓存时长
    cache_ttl: 3600
```

### 配置项

#### `cache`

- 类型：`boolean`；必填：否；默认值：`true`
- 作用：控制是否缓存 preferred 类型存在状态。

#### `cache_ttl`

- 类型：`integer`；必填：否；默认值：`3600`
- 单位：秒
- 作用：定义 preferred 状态缓存时长。

### 行为说明

- `prefer_ipv4`
  - 偏好 `A`。
- `prefer_ipv6`
  - 偏好 `AAAA`。
- 偏好类型请求正常放行，并记录“该域名存在 preferred answer”。
- 非偏好类型请求：
  - 若缓存已知 preferred answer 存在，则直接返回空成功响应抑制该类型。
  - 否则借助 `forward` 的 probe 机制进行一次 preferred 类型探测，再决定是否抑制。

### 典型用途

- 客户端双栈策略收敛。
- 某些网络环境下优先收敛到更稳定的一类地址。

### 注意事项

- 该插件与 `forward` 联动最为紧密，通常放置在 `forward` 之前并通过 continuation 生效。

---

## `black_hole`

### 作用

对命中的 `A` / `AAAA` 请求直接返回预设地址。

### 配置示例

```yaml
- tag: sinkhole
  type: black_hole
  args:
    ips:
      # A 查询时返回
      - "0.0.0.0"
      # AAAA 查询时返回
      - "::"
```

### 配置项

#### `ips`

- 类型：`array`；必填：否；默认值：空数组
- 作用：定义本地合成返回地址集合。
- 运行影响：
  - IPv4 地址仅用于 A 应答。
  - IPv6 地址仅用于 AAAA 应答。

### quick setup

```yaml
- exec: "black_hole 0.0.0.0 ::"
```

### 行为说明

- A 查询返回配置中的 IPv4 地址。
- AAAA 查询返回配置中的 IPv6 地址。
- 其它类型透传。

### 典型用途

- 拦截、黑洞、占位地址返回。

---

## `drop_resp`

### 作用

清空当前上下文中的响应。

### 配置示例

```yaml
- tag: clear_response
  type: drop_resp
  # 无独立 args；执行时会直接清掉当前 response
```

### 配置项

无独立配置字段。

### quick setup

```yaml
- exec: "drop_resp"
```

### 行为说明

- 仅清理 `context.response`。
- 不会清 marks 或请求元信息。

### 典型用途

- 覆盖前面错误或不满意的响应结果。
- 配合后续重新转发或重建响应。

---

## `sleep`

### 作用

异步延迟，用于测试和策略实验。

### 配置示例

```yaml
- tag: sleep_100ms
  type: sleep
  args:
    # 额外异步延迟 100ms
    duration: 100
```

### 配置项

#### `duration`

- 类型：`integer`；必填：否；默认值：`0`
- 单位：毫秒
- 作用：定义当前请求在该执行器上的额外异步等待时间。

### quick setup

```yaml
- exec: "sleep 100"
```

### 典型用途

- 测试 `fallback` 阈值。
- 人工制造慢路径验证观测链路。

---

## `debug_print`

### 作用

打印请求与响应对象，便于调试。

### 配置示例

```yaml
- tag: debug_main
  type: debug_print
  args:
    # 日志标题；未配置时默认是 "debug print"
    msg: "before forward"
```

- `msg`
  - 可选日志标题。
  - 默认 `"debug print"`。

### 配置项

#### `msg`

- 类型：`string`；必填：否；默认值：`"debug print"`
- 作用：定义日志输出标题。

### quick setup

```yaml
- exec: "debug_print cache branch"
```

### 典型用途

- 排查 sequence 分支。
- 验证请求和响应在插件前后是否被改写。

---

## `query_summary`

### 作用

在后续链路执行完后输出紧凑查询摘要。

### 配置示例

```yaml
- tag: summary_main
  type: query_summary
  args:
    # 日志标题；便于区分不同链路
    msg: "main pipeline"
```

### 配置项

#### `msg`

- 类型：`string`；必填：否；默认值：`"query summary"`
- 作用：定义摘要日志标题。

### quick setup

```yaml
- exec: "query_summary main"
```

### 行为说明

- 正向阶段记录开始时间。
- 回程阶段输出：
  - 来源地址
  - qname
  - qtype
  - rcode
  - elapsed_ms

### 典型用途

- 低成本链路追踪。
- 分支延时对比。

---

## `metrics_collector`

### 作用

收集轻量级请求计数与延时指标，并导出 Prometheus 格式。

### 配置示例

```yaml
- tag: metrics_main
  type: metrics_collector
  args:
    # 指标名称标签；导出到 /metrics 时会带上它
    name: "main"
```

### 配置项

#### `name`

- 类型：`string`；必填：否；默认值：`"default"`
- 作用：定义当前指标收集器的名称标签。

### quick setup

```yaml
- exec: "metrics_collector main"
```

### 行为说明

- 正向阶段：
  - `query_total +1`
  - `inflight +1`
  - 记录开始时间
- 回程阶段：
  - `inflight -1`
  - 若无响应则 `err_total +1`
  - 若有响应则累计延时

### API

- `GET /metrics`
  - Prometheus 文本格式。

### 典型用途

- 主链路观测。
- 多条策略入口延时对比。

---

## `ipset`

### 作用

把响应中的 IP 写入 Linux `ipset`。

### 配置示例

```yaml
- tag: ipset_main
  type: ipset
  args:
    # A 记录写入的 ipset
    set_name4: "forgedns_v4"
    # AAAA 记录写入的 ipset
    set_name6: "forgedns_v6"
    # IPv4 写入前先聚合成 /24
    mask4: 24
    # IPv6 写入前先聚合成 /64
    mask6: 64
```

### 配置项

#### `set_name4`

- 类型：`string`；必填：否；默认值：无
- 作用：指定写入 IPv4 地址的 ipset 名称。

#### `set_name6`

- 类型：`string`；必填：否；默认值：无
- 作用：指定写入 IPv6 地址的 ipset 名称。

#### `mask4`

- 类型：`integer`；必填：否；默认值：`24`
- 作用：指定 IPv4 地址写入 ipset 时使用的前缀长度。

#### `mask6`

- 类型：`integer`；必填：否；默认值：`32`
- 作用：指定 IPv6 地址写入 ipset 时使用的前缀长度。

### quick setup

```yaml
- exec: "ipset forgedns_v4,4,24 forgedns_v6,6,64"
```

格式：

```text
<set_name>,<family>,<mask>
```

其中 `family` 为 `4` 或 `6`。

### 行为说明

- 从 answer 中提取唯一 A/AAAA 地址。
- 根据地址族写入相应 set。
- 通过非阻塞队列投递到后台 writer。

### 典型用途

- 基于 DNS 结果驱动后续流量策略。
- DNS 到防火墙名单的联动。

### 注意事项

- Linux 以外平台会退化为 no-op。
- 队列满时会丢 side effect，不阻塞 DNS 主路径。

---

## `nftset`

### 作用

把响应 IP 写入 Linux `nftables set`。

### 配置示例

结构化写法：

```yaml
- tag: nftset_main
  type: nftset
  args:
    ipv4:
      # IPv4 使用 ip family
      table_family: "ip"
      table_name: "mangle"
      set_name: "dns_v4"
      mask: 24
    ipv6:
      # IPv6 使用 ip6 family
      table_family: "ip6"
      table_name: "mangle"
      set_name: "dns_v6"
      mask: 64
```

兼容写法：

```yaml
- tag: nftset_legacy
  type: nftset
  args:
    # 兼容字段，适合从旧配置迁移
    table_family4: "ip"
    table_name4: "mangle"
    set_name4: "dns_v4"
    mask4: 24
    table_family6: "ip6"
    table_name6: "mangle"
    set_name6: "dns_v6"
    mask6: 64
```

### 配置项

#### `ipv4`

- 类型：`object`；必填：否；默认值：无
- 作用：定义 IPv4 目标 nftables set。
- 子字段：
  - `table_family`
  - `table_name`
  - `set_name`
  - `mask`

#### `ipv6`

- 类型：`object`；必填：否；默认值：无
- 作用：定义 IPv6 目标 nftables set。
- 子字段：
  - `table_family`
  - `table_name`
  - `set_name`
  - `mask`

#### `table_family4` / `table_family6`

- 类型：`string`；必填：否；默认值：无
- 作用：兼容写法下分别定义 IPv4 / IPv6 的 nftables 表 family。

#### `table_name4` / `table_name6`

- 类型：`string`；必填：否；默认值：无
- 作用：兼容写法下分别定义 IPv4 / IPv6 的 nftables 表名。

#### `set_name4` / `set_name6`

- 类型：`string`；必填：否；默认值：无
- 作用：兼容写法下分别定义 IPv4 / IPv6 的 set 名称。

#### `mask4` / `mask6`

- 类型：`integer`；必填：否；默认值：由实现确定
- 作用：兼容写法下分别定义 IPv4 / IPv6 前缀长度。

### quick setup

```yaml
- exec: "nftset ip,mangle,dns_v4,ipv4_addr,24 ip6,mangle,dns_v6,ipv6_addr,64"
```

格式：

```text
<family>,<table>,<set>,<type>,<mask>
```

### 行为说明

- 提取 A/AAAA 地址。
- 根据前缀写入 nftables 区间元素。
- 同样走后台 writer，保持主路径非阻塞。

### 典型用途

- 与 `nftables` 集合联动的分类、路由或防火墙策略。

### 注意事项

- Linux 以外平台退化为 no-op。

---

## `ros_address_list`

### 作用

把应答 IP 同步到 RouterOS address-list，支持动态项、常驻项、启动时文件加载和关闭时清理。

### 配置示例

```yaml
- tag: ros_address_list_main
  type: ros_address_list
  args:
    # RouterOS API 地址
    address: "172.16.1.1:8728"
    # API 用户名
    username: "api-user"
    # API 密码
    password: "secret"
    # 异步提交，避免阻塞 DNS 主路径
    async: true
    # A 记录写入的 address-list
    address_list4: "forgedns_ipv4"
    # AAAA 记录写入的 address-list
    address_list6: "forgedns_ipv6"
    # 用于标记 ForgeDNS 管理条目的注释前缀
    comment_prefix: "forgedns"
    # 动态项 TTL 下限
    min_ttl: 60
    # 动态项 TTL 上限
    max_ttl: 3600
    # 强制把动态项 TTL 固定为 300 秒；填 0 表示不设置 timeout
    fixed_ttl: 300
    # 插件关闭时清理自己维护的条目
    cleanup_on_shutdown: true
    persistent:
      ips:
        # 常驻单 IP
        - "1.1.1.1"
        # 常驻 IPv4 网段
        - "100.64.1.0/24"
        # 常驻 IPv6 网段
        - "2001:db8::/64"
      files:
        # 从文件加载更多常驻项
        - "/etc/forgedns/persistent_ips.txt"
```

### 配置项

#### `address`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 RouterOS API 服务地址，通常写为 `host:port`。插件启动后将使用该地址建立管理连接，并在运行期间维持与设备的同步关系。
- 配置建议：使用 RouterOS API 明文端口时通常为 `8728`，如部署了加密 API，应按实际端口填写。

#### `username`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 RouterOS API 登录用户名。该账户需要具备读取和维护目标 `address-list` 的权限。
- 配置建议：建议为本插件单独创建专用账号，以便隔离权限范围和审计记录。

#### `password`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 RouterOS API 登录密码。插件初始化、重连和后台同步均依赖该凭据。
- 注意事项：应避免在公开仓库或共享示例中直接暴露真实口令。

#### `async`

- 类型：`bool`；必填：否；默认值：`true`
- 作用：控制地址写入行为是否采用异步方式。启用后，DNS 应答路径只负责投递任务，由后台管理器完成与 RouterOS 的交互。
- 影响：异步模式有助于降低请求路径阻塞风险；关闭后会改为同步提交，更适合需要立即确认提交结果的场景。

#### `address_list4`

- 类型：`string`；必填：否；默认值：无
- 作用：指定 IPv4 地址写入的目标 `address-list` 名称。插件从 DNS 应答中提取到 A 记录后，将写入该列表。
- 配置建议：如果策略仅处理 IPv4，应至少配置本项。

#### `address_list6`

- 类型：`string`；必填：否；默认值：无
- 作用：指定 IPv6 地址写入的目标 `address-list` 名称。插件从 DNS 应答中提取到 AAAA 记录后，将写入该列表。
- 配置建议：如果策略需要覆盖 IPv6，应同时配置本项，并在 RouterOS 侧建立对应的匹配与路由规则。

#### `comment_prefix`

- 类型：`string`；必填：否；默认值：`fdns`
- 作用：指定插件写入 RouterOS 条目时使用的注释前缀。该前缀用于区分 ForgeDNS 创建的动态项和常驻项，便于后续刷新、重载与清理。
- 注意事项：该值及插件 `tag` 不应包含 `;` 或 `=`，以避免影响内部标记格式。

#### `persistent`

- 类型：`object`；必填：否；默认值：无
- 作用：定义需要长期保留的静态地址集合。该部分不依赖 DNS 应答触发，可在插件启动后直接同步到 RouterOS，并由后台 reconcile 保持一致性。
- 子字段：
  - `ips`
  - `files`

#### `persistent.ips`

- 类型：`array<string>`；必填：否；默认值：空
- 作用：以内联方式声明常驻 IP 或 CIDR 网段。适用于数量较少且变更频率不高的固定策略对象。
- 支持格式：单个 IPv4、单个 IPv6、IPv4 CIDR、IPv6 CIDR。

#### `persistent.files`

- 类型：`array<string>`；必填：否；默认值：空
- 作用：从外部文件加载常驻地址集合。适用于需要由其他系统生成、集中维护或批量管理的地址列表。
- 行为说明：这些文件只在插件初始化时读取一次。文件变更后如需生效，需要 reload 插件或应用。

#### `min_ttl`

- 类型：`u64`；必填：否；默认值：`60`
- 作用：定义动态地址项允许使用的最小 TTL。当 DNS 应答中的 TTL 过小或为零时，插件会提升到该值后再写入 RouterOS。
- 适用场景：用于避免高频刷新造成的管理面抖动。

#### `max_ttl`

- 类型：`u64`；必填：否；默认值：`3600`
- 作用：定义动态地址项允许使用的最大 TTL。当 DNS 应答中的 TTL 过大时，插件会截断到该上限。
- 适用场景：用于限制策略项在网络设备中的滞留时间，降低地址陈旧风险。

#### `fixed_ttl`

- 类型：`u64`；必填：否；默认值：无
- 作用：为所有动态写入项指定固定 TTL。配置本项后，插件不再使用 DNS 记录中的原始 TTL，也不再受 `min_ttl` 与 `max_ttl` 的区间裁剪影响。若设为 `0`，则动态项不会设置 RouterOS `timeout`。
- 适用场景：适合需要统一刷新周期、便于运维预估和策略收敛的场景。

#### `cleanup_on_shutdown`

- 类型：`bool`；必填：否；默认值：`true`
- 作用：控制插件退出时是否清理由其管理的条目。启用后，插件在正常关闭阶段会删除自身写入并可识别归属的 RouterOS 地址项。
- 影响：关闭该选项后，已写入条目会继续保留在 RouterOS 中，适合要求策略状态跨进程重启保留的场景。

### 行为说明

- 插件本身不改 DNS 响应。
- 正向阶段只透传。
- 回程阶段：
  - 从 `NOERROR` 响应中提取 A/AAAA。
  - 去重并保留最大 TTL。
  - 根据异步或同步模式投递给后台 manager。
- manager 负责：
  - 初始连通性验证
  - 动态项刷新
  - 持久项一致性维护
  - 关闭清理

### 典型用途

- DNS 驱动路由地址集维护。
- DNS 驱动动态策略名单。
- 通过 RouterOS address-list 把域名解析结果外溢到网络设备策略层。

### 注意事项

- 至少需要 `address_list4` 或 `address_list6` 之一。
- `comment_prefix` 与插件 `tag` 不能包含 `;` 或 `=`。
- 同步模式不会改变 DNS 应答本身，即使 RouterOS 写入失败也会保留 DNS 结果。
