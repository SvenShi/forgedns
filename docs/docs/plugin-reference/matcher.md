---
title: 匹配器插件
sidebar_position: 4
---

匹配器插件返回 `true` 或 `false`，主要供 `sequence` 的 `matches` 使用。

## 匹配表达式规则

在 `sequence` 中使用 matcher 时，推荐优先使用 quick setup 形式，配置会更直观：

```yaml
- matches:
    - "client_ip $lan_ip_set"
    - "qtype A"
  exec: "$forward_main"
```

也可以继续组合其它 quick setup matcher：

```yaml
- matches:
    - "qname domain:example.com"
    - "qclass IN"
  exec: "$forward_main"
```

取反：

```yaml
- matches: "!has_resp"
  exec: "$forward_main"
```

---

<span id="true"></span>

## `_true`

### 作用

恒为真。

### 配置示例

```yaml
- tag: always_true
  type: _true
```

### 配置项

无独立配置字段。

### 典型用途

- 作为保底命中条件。
- 测试 sequence 分支顺序。

---

<span id="false"></span>

## `_false`

### 作用

恒为假。

### 配置示例

```yaml
- tag: always_false
  type: _false
```

### 配置项

无独立配置字段。

### 典型用途

- 临时禁用某条规则。

---

## `qname`

### 作用

匹配请求中的查询域名。

### 配置示例

```yaml
- tag: match_domain
  type: qname
  args:
    # 域名表达式
    - "domain:example.com"
    # 复用已有 domain_set
    - "$core_domains"
    # 从文件加载规则
    - "&/etc/forgedns/domains.txt"
```

### 配置项

`qname` 的 `args` 采用规则列表形式，列表中的每个元素均独立生效。

- 类型：`array`；必填：是；默认值：无
- 作用：定义域名匹配规则来源。
- 支持元素：
  - 域名表达式
  - 具备域名匹配能力的 provider 引用，例如 `domain_set`、`geosite`
  - 文件引用
- 运行影响：
  - 当前请求中的任意问题域名命中任一规则时，matcher 返回 `true`。

### quick setup

```yaml
- matches: "qname domain:example.com"
```

### 典型用途

- 按域名后缀、关键字、正则做策略分支。

---

## `question`

### 作用

按 provider 的 `contains_question` 语义匹配请求中的 question。

这个插件会遍历当前请求里的所有 question，只要任意 question 被任意一个 provider 命中，就返回 `true`。

### 配置示例

```yaml
- tag: match_ad
  type: question
  args:
    - "$ad_rules"
    - "$shared_domains"
```

### 配置项

- `args`
  - 类型：`array[string]`；必填：是；默认值：无
  - 作用：使用 `"$provider_tag"` 形式引用实现了 `contains_question` 的 provider。

### 行为说明

- 会遍历请求中的所有 question。
- 任意 question 被任意 provider 命中时返回 `true`。
- quick setup 也支持同样的 `"$provider_tag"` 写法。

### 典型用途

- 让 `adguard_rule`、`domain_set`、`geosite` 这类 provider 直接参与请求 question 匹配。
- 在 `sequence` 中先做 question 级匹配，再交给 `black_hole`、`reject` 或其它动作执行。

---

## `qtype`

### 作用

匹配请求中的 qtype。

### 配置示例

```yaml
- tag: only_a_aaaa
  type: qtype
  args: 
    - "A"
    - "AAAA"
```

### 配置项

`qtype` 的 `args` 为类型列表。

- 类型：`array`；必填：是；默认值：无
- 作用：定义允许命中的查询类型集合。
- 支持取值：
  - 标准类型名，例如 `A`、`AAAA`、`PTR`
  - 对应的数值形式
- 运行影响：
  - 请求中的任意问题类型命中配置集合时返回 `true`。

### quick setup

```yaml
- matches: "qtype A"
```

### 典型用途

- 区分 A / AAAA / PTR / TXT 等。

---

## `qclass`

### 作用

匹配请求中的 qclass。

### 配置示例

```yaml
- tag: only_in
  type: qclass
  args: 
    - "IN"
```

### 配置项

`qclass` 的 `args` 为类别列表。

- 类型：`array`；必填：是；默认值：无
- 作用：定义允许命中的查询类别集合。
- 支持取值：
  - 标准类别名，例如 `IN`
  - 对应的数值形式
- 运行影响：
  - 请求中的任意问题类别命中配置集合时返回 `true`。

### quick setup

```yaml
- matches: "qclass IN"
```

### 典型用途

- 严格限制仅处理 IN 类查询。

---

## `client_ip`

### 作用

匹配客户端来源 IP。

### 配置示例

```yaml
- tag: lan_clients
  type: client_ip
  args:
    # 直接写 CIDR
    - "192.168.0.0/16"
    # 引用 ip_set
    - "$lan_ip_set"
```

### 配置项

`client_ip` 的 `args` 采用规则列表形式。

- 类型：`array`；必填：是；默认值：无
- 作用：定义客户端来源地址匹配条件。
- 支持元素：
  - 单个 IP
  - CIDR
  - `ip_set` 引用
- 运行影响：
  - 只要客户端来源地址命中任一规则，matcher 即返回 `true`。

### quick setup

```yaml
- matches: "client_ip 192.168.1.0/24"
```

### 典型用途

- 按来源网段划分策略。

---

## `resp_ip`

### 作用

匹配响应 answers 中的 A/AAAA IP。

### 配置示例

```yaml
- tag: matched_resp_ip
  type: resp_ip
  args:
    - "100.64.0.0/10"
    - "$special_targets"
```

### 配置项

`resp_ip` 的 `args` 采用规则列表形式。

- 类型：`array`；必填：是；默认值：无
- 作用：定义应答地址匹配条件。
- 支持元素：
  - 单个 IP
  - CIDR
  - `ip_set` 引用
- 运行影响：
  - 只检查 response answer 区中的 A/AAAA 地址。
  - 任一答案地址命中即返回 `true`。

### quick setup

```yaml
- matches: "resp_ip 10.0.0.0/8"
```

### 典型用途

- 根据上游返回地址继续做二次处置。
- 配合 `ipset` / `nftset` 前做更细粒度筛选。

---

## `ptr_ip`

### 作用

从 PTR 请求名中解析 IP 并做匹配。

### 配置示例

与 `client_ip` / `resp_ip` 类似，支持 IP 规则和 `ip_set`。

### 配置项

`ptr_ip` 的 `args` 采用规则列表形式。

- 类型：`array`；必填：是；默认值：无
- 作用：定义 PTR 请求名解析出的地址匹配条件。
- 支持元素：
  - 单个 IP
  - CIDR
  - `ip_set` 引用
- 运行影响：
  - 仅对 PTR 查询生效。
  - PTR 请求名解析出的地址命中任一规则时返回 `true`。

### quick setup

```yaml
- matches: "ptr_ip 192.168.0.0/16"
```

### 典型用途

- 只允许某些地址段走 PTR 反查。

---

## `cname`

### 作用

匹配响应中的 CNAME 目标域名。

### 配置示例

```yaml
- tag: cname_target
  type: cname
  args:
    - "domain:example.com"
    - "$core_domains"
    - "&/etc/forgedns/cnames.txt"
```

### 配置项

`cname` 的 `args` 采用规则列表形式。

- 类型：`array`；必填：是；默认值：无
- 作用：定义 CNAME 目标名称匹配条件。
- 支持元素：
  - 域名表达式
  - `domain_set` 引用
  - 文件引用
- 运行影响：
  - 只检查响应中的 CNAME 目标。
  - 任一 CNAME 目标命中时返回 `true`。

### quick setup

```yaml
- matches: "cname keyword:cdn"
```

### 典型用途

- 根据 CNAME 指向做后续策略。

---

## `mark`

### 作用

匹配上下文中的 mark 集合。

### 配置示例

```yaml
- tag: marked_100
  type: mark
  args:
    - "100"
    - "200"
```

说明：

- 参数会被解析为整数 mark。
- 只要上下文 marks 与配置 marks 有交集就算命中。

### 配置项

`mark` 的 `args` 为 mark 列表。

- 类型：`array`；必填：是；默认值：无
- 作用：定义可命中的上下文标记集合。
- 支持取值：
  - 无符号整数形式的 mark 值
- 运行影响：
  - 只要上下文 marks 与配置 marks 存在交集，即返回 `true`。

### quick setup

```yaml
- matches: "mark 100"
```

### 典型用途

- 在多个 sequence 间传递分支状态。

---

## `env`

### 作用

匹配进程环境变量。

### 配置示例

```yaml
- tag: env_profile_prod
  type: env
  args:
    - "PROFILE"
    - "prod"
```

或只校验存在：

```yaml
args:
  - "FEATURE_X"
```

### 配置项

`env` 的 `args` 为一到两个元素。

- 类型：`array`；必填：是；默认值：无
- 元素定义：
  - 第一个元素：环境变量名
  - 第二个元素：可选，期望值
- 运行影响：
  - 仅配置变量名时，环境变量存在即返回 `true`。
  - 同时配置变量名和值时，需完全匹配才返回 `true`。

### quick setup

```yaml
- matches: "env PROFILE prod"
```

### 行为说明

- 在 `init` 时缓存环境变量值。
- 运行中不会动态重新读取环境变量。

### 典型用途

- 同一配置在不同部署环境下启用不同分支。

---

## `random`

### 作用

按概率命中。

### 配置示例

```yaml
- tag: rollout_10p
  type: random
  args:
    - "0.1"
```

### 配置项

`random` 的 `args` 只接受一个概率值。

- 类型：`array`；必填：是；默认值：无
- 取值范围：`0.0` 到 `1.0`
- 作用：定义本次匹配返回 `true` 的概率。
- 运行影响：
  - `0.0` 表示始终不命中。
  - `1.0` 表示始终命中。

### quick setup

```yaml
- matches: "random 0.05"
```

### 典型用途

- 灰度放量。
- 抽样日志或观测。

---

## `rate_limiter`

### 作用

基于客户端 IP 的令牌桶限流。

### 配置示例

```yaml
- tag: qps_guard
  type: rate_limiter
  args:
    qps: 20
    burst: 40
    mask4: 32
    mask6: 48
```

### 配置项

#### `qps`

- 类型：`number`；必填：否；默认值：`20`
- 作用：定义每秒令牌补充速率。
- 运行影响：
  - 值越大，单位时间内允许通过的请求越多。

#### `burst`

- 类型：`integer`；必填：否；默认值：`40`
- 作用：定义令牌桶容量上限。
- 运行影响：
  - 值越大，短时间内允许的突发请求越多。

#### `mask4`

- 类型：`integer`；必填：否；默认值：`32`
- 作用：定义 IPv4 客户端聚合粒度。
- 运行影响：
  - 值越小，多个 IPv4 客户端越容易共享同一个限流桶。

#### `mask6`

- 类型：`integer`；必填：否；默认值：`48`
- 作用：定义 IPv6 客户端聚合粒度。
- 运行影响：
  - 值越小，多个 IPv6 客户端越容易共享同一个限流桶。

### quick setup

推荐使用完整配置，以便显式控制 `qps`、`burst` 和 `mask`。

### 行为说明

- 命中含义是“允许通过并消费一个令牌”。
- 返回 `false` 表示当前限流，不允许通过。

### 典型用途

- 源地址维度的入口保护。

---

## `rcode`

### 作用

匹配当前响应的 rcode。

### 配置示例

```yaml
- tag: only_noerror
  type: rcode
  args:
    - "0"
```

### 配置项

`rcode` 的 `args` 为 rcode 列表。

- 类型：`array`；必填：是；默认值：无
- 作用：定义可命中的响应码集合。
- 取值要求：
  - 当前使用十进制整数表示。
  - 例如：
    - `0` = `NOERROR`
    - `2` = `SERVFAIL`
    - `3` = `NXDOMAIN`
- 运行影响：
  - 仅当上下文中已有响应且 rcode 命中配置集合时返回 `true`。

### quick setup

```yaml
- matches: "rcode 2"
```

### 典型用途

- 根据失败类型做二次处置。

---

## `has_resp`

### 作用

只要上下文中已有响应就命中。

### 配置示例

```yaml
- tag: has_resp_flag
  type: has_resp
```

### 配置项

无独立配置字段。

### quick setup

```yaml
- matches: "has_resp"
```

### 典型用途

- 在 `cache`、`hosts`、`arbitrary` 后面判断是否已有结果。

---

## `has_wanted_ans`

### 作用

判断响应 answers 中是否包含与请求 qtype 对应的记录。

### 配置示例

```yaml
- tag: has_wanted_answer
  type: has_wanted_ans
```

### 配置项

无独立配置字段。

### quick setup

```yaml
- matches: "has_wanted_ans"
```

### 典型用途

- 判断是否真正拿到了所需类型答案，而不仅仅是有个响应包。

---

## `string_exp`

### 作用

通用字符串表达式匹配器，用于补足专用 matcher 不够灵活的场景。

### 配置示例

```yaml
- tag: match_http_path
  type: string_exp
  args: "url_path prefix /dns-"
```

也支持字符串数组：

```yaml
args:
  - "client_ip"
  - "prefix"
  - "192.168."
```

### 配置项

`string_exp` 的 `args` 可以为字符串或字符串数组。

- 类型：`string` 或 `array`
- 必填：是
- 默认值：无
- 作用：定义完整字符串表达式。
- 表达式组成：
  - 数据来源 `source`
  - 匹配操作 `op`
  - 一个或多个参数
- 运行影响：
  - 按表达式从上下文中取值并执行字符串匹配。

### 表达式格式

```text
<source> <op> <arg...>
```

支持的 `source`：

- `qname`
- `qtype`
- `qclass`
- `rcode`
- `resp_ip`
- `mark`
- `client_ip`
- `server_name`
- `url_path`
- `$ENV_KEY`

支持的 `op`：

- `eq`
- `prefix`
- `suffix`
- `contains`
- `regexp`
- `zl`

说明：

- `zl` 表示 zero length，用于判断字符串是否为空。
- `regexp` 支持一个或多个正则参数。

### quick setup

```yaml
- matches: "string_exp server_name suffix .example.net"
```

### 典型用途

- 按 DoH 路径、SNI、mark 集合、响应 IP 字符串做灵活判断。

### 注意事项

- 可使用专用 matcher 的场景，宜优先采用专用 matcher。
- `string_exp` 提供更高灵活性，但表达式的可读性与可维护性通常低于专用插件。
