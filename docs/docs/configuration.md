---
title: 配置总览
sidebar_position: 2
---

## 写在最前

ForgeDNS 的配置文件是 YAML。当前顶层结构由四部分组成：

```yaml
runtime:
  worker_threads: 4

api:
  http: "127.0.0.1:9088"

log:
  level: info
  file: ./forgedns.log

plugins:
  - tag: seq_main
    type: sequence
    args:
      - exec: "forward 1.1.1.1"
```

其中：

- `runtime`
  - 运行时参数。
- `api`
  - 管理 API。
- `log`
  - 日志输出。
- `plugins`
  - 所有插件实例定义。ForgeDNS 通过插件组合完成完整 DNS 流程。

## 顶层字段

### `runtime`

```yaml
runtime:
  worker_threads: 4
```

字段说明：

- `worker_threads`
  - 含义：Tokio 多线程运行时的 worker 数。
  - 默认：未配置时自动取系统可用并行度。
  - 限制：不能为 `0`。

### `log`

```yaml
log:
  level: info
  file: ./forgedns.log
  rotation:
    type: daily
    max_files: 7
```

字段说明：

- `level`
  - 可选值：`off` `trace` `debug` `info` `warn` `error`
  - 默认：`info`
- `file`
  - 含义：可选日志文件路径。
  - 不配置时仅输出到标准输出。
  - 配置后，ForgeDNS 会同时输出到标准输出和日志文件。
  - 日志文件内容为 UTF-8 纯文本格式，不写入终端 ANSI 颜色控制码。
- `rotation`
  - 含义：日志文件轮转策略。
  - 默认：`never`

`rotation` 支持以下配置：

- `type: never`
  - 不轮转，始终写入同一个文件。
- `type: minutely`
  - 按分钟轮转。
- `type: hourly`
  - 按小时轮转。
- `type: daily`
  - 按天轮转。
- `type: weekly`
  - 按周轮转。
  - 可选配置 `max_files`，表示最多保留多少个历史文件；`0` 表示不自动删除。

### `api`

`api.http` 支持两种写法。

简写：

```yaml
api:
  http: "127.0.0.1:9088"
```

详写：

```yaml
api:
  http:
    listen: "127.0.0.1:9443"
    ssl:
      cert: "/etc/forgedns/api.crt"
      key: "/etc/forgedns/api.key"
      client_ca: "/etc/forgedns/client-ca.crt"
      require_client_cert: true
    auth:
      type: basic
      username: "admin"
      password: "secret"
```

字段说明：

- `http.listen`
  - API 监听地址。
- `http.ssl.cert`
  - API 证书文件。
- `http.ssl.key`
  - API 私钥文件。
- `http.ssl.client_ca`
  - 可选客户端证书 CA。
- `http.ssl.require_client_cert`
  - 是否要求双向 TLS。
- `http.auth`
  - 当前支持 `basic`。
  - Basic Auth 的请求头编码方式见《管理 API》章节。

校验规则：

- `listen` 不能为空。
- `cert` 和 `key` 必须成对出现。
- `require_client_cert: true` 时必须提供 `client_ca`。
- `basic.username` 和 `basic.password` 都不能为空。

### `plugins`

每个插件定义都采用统一结构：

```yaml
- tag: cache_main
  type: cache
  args:
    size: 4096
```

通用规则：

- `tag`
  - 插件实例唯一标识。
  - 不能为空。
  - 在整个配置中必须唯一。
- `type`
  - 插件类型名。
  - 必须与已注册插件工厂一致。
- `args`
  - 插件参数。
  - 不同插件的参数形态不同，可能是对象、字符串、数组或空值。

## 四类插件的职责

### `server`

作用：接收 DNS 请求并把请求送入某个执行器入口。

特点：

- 不负责复杂策略判断。
- 核心配置通常是监听地址、TLS 参数、入口执行器。

### `executor`

作用：执行动作。

典型动作包括：

- 查询上游
- 生成本地响应
- 缓存读写
- TTL 调整
- ECS 处理
- 回退和并发竞争
- 观测与系统联动

### `matcher`

作用：做条件判断，供 `sequence` 规则使用。

典型判断维度包括：

- 查询域名
- 查询类型
- 客户端 IP
- 应答 IP
- 应答码
- 环境变量
- 采样命中
- 限流状态

### `provider`

作用：提供可复用规则集，供 `matcher` 或其它插件引用。

当前主要有：

- `domain_set`
- `ip_set`
- `geoip`
- `geosite`
- `adguard_rule`

## sequence 编排模型

`sequence` 是 ForgeDNS 的策略中枢。绝大多数非平凡配置都会以它作为总入口。

示例：

```yaml
- tag: seq_main
  type: sequence
  args:
    - matches:
        - "$lan_clients"
        - "qtype A"
      exec: "$cache_main"
    - matches: "!$has_resp"
      exec: "$forward_main"
    - exec: "accept"
```

每条规则支持两个核心字段：

- `matches`
  - 一个 matcher 表达式或表达式数组。
  - 数组中的所有条件都成立时，本条规则才命中。
- `exec`
  - 命中后执行的动作。

## 引用插件与 quick setup

### 引用已有插件

使用 `$tag` 引用已定义插件：

```yaml
- exec: "$forward_main"
- matches:
    - "$is_internal"
    - "!$has_resp"
  exec: "$cache_main"
```

### quick setup

如果 `sequence` 中写的不是 `$tag`，而是 `type + 参数` 形式，ForgeDNS 会即时构造临时插件。

示例：

```yaml
- exec: "forward 1.1.1.1 8.8.8.8"
- matches: "qname domain:example.com"
  exec: "ttl 300"
```

当前常见 quick setup：

- matcher
  - `_true`
  - `_false`
  - `qname ...`
  - `qtype ...`
  - `qclass ...`
  - `client_ip ...`
  - `resp_ip ...`
  - `ptr_ip ...`
  - `cname ...`
  - `mark ...`
  - `env ...`
  - `random ...`
  - `rate_limiter ...`
  - `rcode ...`
  - `has_resp`
  - `has_wanted_ans`
  - `string_exp ...`
- executor
  - `forward ...`
  - `ttl ...`
  - `sleep ...`
  - `debug_print ...`
  - `query_summary ...`
  - `metrics_collector ...`
  - `black_hole ...`
  - `drop_resp`
  - `ecs_handler ...`
  - `forward_edns0opt ...`
  - `ipset ...`
  - `nftset ...`

## sequence 内建控制流

除了调用插件，`sequence` 还支持内建控制流：

- `accept`
  - 终止当前 sequence，标记处理完成。
- `return`
  - 结束当前 sequence，回到调用方。
- `reject [rcode]`
  - 直接生成应答。
  - 默认 `REFUSED`。
  - 当前参数是十进制数字。
- `mark 1,2,3`
  - 写入上下文 marks。
- `jump seq_tag`
  - 调用另一个 `sequence`，回来后继续当前规则的下一条。
- `goto seq_tag`
  - 调用另一个 `sequence`，结束后不再回到当前 sequence。

示例：

```yaml
- matches: "$rate_ok"
  exec: "mark 100"
- matches: "!$rate_ok"
  exec: "reject 2"
```

## 通用规则语法

### 域名规则

以下规则会出现在 `qname`、`cname`、`domain_set`、`hosts`、`redirect` 等插件中：

- `full:example.com`
  - 完整匹配。
- `domain:example.com`
  - 后缀匹配。
- `keyword:cdn`
  - 子串匹配。
- `regexp:^api[0-9]+\\.example\\.com$`
  - 正则匹配。
- `example.com`
  - 未写前缀时，通常等价于 `domain:example.com`。

### IP 规则

以下规则会出现在 `client_ip`、`resp_ip`、`ptr_ip`、`ip_set` 等插件中：

- 单个 IP：`1.1.1.1`
- 网段：`192.168.0.0/16`
- IPv6 网段：`2400:3200::/32`

### provider 引用

支持在 matcher 或 provider 参数中引用 provider：

- `$tag`
  - 引用已定义且具备对应匹配能力的 provider。
  - 例如域名场景可引用 `domain_set`、`geosite`。
  - 例如 IP 场景可引用 `ip_set`、`geoip`。
- `&/path/to/file`
  - 直接从文件加载规则。

示例：

```yaml
args:
  - "domain:example.com"
  - "$core_domains"
  - "&/etc/forgedns/domains.txt"
```

## 上游统一结构

`forward` 的 `upstreams` 使用统一的 `UpstreamConfig`。

示例：

```yaml
upstreams:
  - addr: "udp://1.1.1.1:53"
  - addr: "https://resolver.example/dns-query"
    bootstrap: "8.8.8.8:53"
    timeout: 5s
    enable_http3: true
```

常用字段：

- `addr`
  - 上游地址。
  - 未写协议时按 UDP 处理。
  - 支持 `udp://`、`tcp://`、`tcp+pipeline://`、`tls://`、`tls+pipeline://`、`quic://`、`doq://`、`https://`、`doh://`、`h3://`。
  - DoH 应写完整路径，例如 `https://resolver.example/dns-query`。
- `dial_addr`
  - 指定实际连接 IP，但仍保留 `addr` 中的主机名用于 SNI/校验。
- `port`
  - 覆盖端口。
- `bootstrap`
  - 当上游地址是域名时，用于解析上游域名的引导 DNS。
- `bootstrap_version`
  - `4` 或 `6`。
- `socks5`
  - SOCKS5 代理。
  - 支持 `host:port` 与 `user:pass@host:port`。
  - IPv6 需写成 `[addr]:port`。
- `idle_timeout`
  - 空闲连接超时，单位秒。
- `max_conns`
  - 连接池最大连接数。
- `insecure_skip_verify`
  - 跳过 TLS 证书校验，仅建议测试环境使用。
- `timeout`
  - 单次查询超时，默认 `5s`。
- `enable_pipeline`
  - TCP/DoT 请求流水线。
- `enable_http3`
  - DoH 使用 HTTP/3。
- `so_mark`
  - Linux `SO_MARK`。
- `bind_to_device`
  - Linux `SO_BINDTODEVICE`。
