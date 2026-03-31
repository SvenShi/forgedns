---
title: 数据提供器插件
sidebar_position: 5
---

provider 负责把规则集从“单条规则”提升为“可复用的数据资产”。在复杂配置里，provider 通常用于减少重复配置、沉淀共享规则、提升策略可维护性。

---

## `adguard_rule`

### 作用

提供 AdGuard Home DNS 规则子集的可复用 provider。

这个 provider 提供两种语义：

- `contains_question`：完整请求 question 求值，支持 `dnstype`
- `contains_name`：name-only 投影求值，会忽略所有 `dnstype` 规则

### 参数

```yaml
- tag: ad_rules
  type: adguard_rule
  args:
    rules:
      - "||ads.example.com^"
      - "@@||safe.ads.example.com^"
    files:
      - "/etc/forgedns/adguard.txt"
```

### 行为说明

- 支持：基础域名规则、`@@`、`important`、`badfilter`、`denyallow`、请求侧 `dnstype`
- 不支持但会 warning 并跳过：`/etc/hosts` 风格规则、`dnsrewrite`、`$client`、`$ctag`、未知 modifier
- 完整优先级顺序为：
  - `important` 例外
  - `important` 拦截
  - 普通例外
  - 普通拦截

### 典型用途

- 配合 `question` matcher 复用 AdGuard 规则文件。
- 在 provider 层统一管理复杂的 AdGuard 域名拦截语义。

---

## `domain_set`

### 作用

提供高性能域名规则集合，可被 `qname`、`cname` 等插件引用。

### 参数

```yaml
- tag: core_domains
  type: domain_set
  args:
    exps:
      - "domain:example.com"
      - "keyword:cdn"
      - "regexp:^api[0-9]+\\.example\\.net$"
    files:
      - "/etc/forgedns/domains.txt"
    sets:
      - "shared_domains"
```

- `exps`
  - 内联域名表达式列表。
- `files`
  - 外部规则文件。
- `sets`
  - 引用其它 `domain_set`。

### 配置项详解

#### `exps`

- 类型：`array`；必填：否；默认值：空数组
- 作用：定义内联域名表达式列表。
- 示例：
  - `- "full:example.com"`
  - `- "domain:example.com"`
  - `- "keyword:cdn"`
- 支持内容：
  - `full:`
  - `domain:`
  - `keyword:`
  - `regexp:`
  - 无前缀域名
- 运行影响：
  - 在初始化阶段编译为可直接匹配的规则集合。

#### `files`

- 类型：`array`；必填：否；默认值：空数组
- 作用：指定外部规则文件路径列表。
- 示例：`- "/etc/forgedns/domains.txt"`
- 文件要求：
  - 每行一条规则。
  - 空行与注释行会被忽略。
- 运行影响：
  - 文件内容会在初始化阶段加载并并入当前 provider。

#### `sets`

- 类型：`array`；必填：否；默认值：空数组
- 作用：引用其它 `domain_set` 实例。
- 示例：`- "shared_domain_set"`
- 约束：
  - 仅允许引用 `domain_set` 类型 provider。
- 运行影响：
  - 被引用的规则集会在初始化阶段被展平并并入当前 provider。

### 行为说明

- 初始化时会把 `exps`、`files` 和被引用 `sets` 展平。
- 运行时不做递归 provider 调用，直接基于编译好的 matcher 热路径匹配。

### 支持的规则格式

- `full:example.com`
- `domain:example.com`
- `keyword:cdn`
- `regexp:^api\\.example\\.com$`
- `example.com`

### 典型用途

- 共享核心域名列表。
- 把不同来源的规则文件聚合为一个 provider。

### 注意事项

- `sets` 只能引用 `domain_set` 类型 provider。

---

## `ip_set`

### 作用

提供 IP / CIDR 规则集合，可被 `client_ip`、`resp_ip`、`ptr_ip` 等 matcher 引用。

### 参数

```yaml
- tag: lan_ip_set
  type: ip_set
  args:
    ips:
      - "192.168.0.0/16"
      - "10.0.0.0/8"
      - "fd00::/8"
    files:
      - "/etc/forgedns/ips.txt"
    sets:
      - "shared_ip_set"
```

- `ips`
  - 内联 IP / CIDR。
- `files`
  - 外部规则文件。
- `sets`
  - 引用其它 `ip_set`。

### 配置项详解

#### `ips`

- 类型：`array`；必填：否；默认值：空数组
- 作用：定义内联 IP 或 CIDR 规则列表。
- 示例：
  - `- "1.1.1.1"`
  - `- "192.168.0.0/16"`
  - `- "2400:3200::/32"`
- 支持内容：
  - 单个 IPv4 地址
  - 单个 IPv6 地址
  - IPv4 CIDR
  - IPv6 CIDR
- 运行影响：
  - 规则会在初始化阶段编译为地址匹配结构。

#### `files`

- 类型：`array`；必填：否；默认值：空数组
- 作用：指定外部 IP 规则文件路径列表。
- 示例：`- "/etc/forgedns/ips.txt"`
- 文件要求：
  - 每行一条 IP 或 CIDR 规则。
  - 空行与注释行会被忽略。
- 运行影响：
  - 文件内容会在初始化阶段加载并并入当前 provider。

#### `sets`

- 类型：`array`；必填：否；默认值：空数组
- 作用：引用其它 `ip_set` 实例。
- 示例：`- "shared_ip_set"`
- 约束：
  - 仅允许引用 `ip_set` 类型 provider。
- 运行影响：
  - 被引用集合会在初始化阶段展平，并按地址族加入当前 provider。

### 行为说明

- 初始化时把所有来源加载并展平。
- 会分别维护 IPv4 / IPv6 规则索引。
- 运行时按地址族快速过滤。

### 规则格式

- `1.1.1.1`
- `192.168.0.0/16`
- `2400:3200::/32`

### 典型用途

- LAN / WAN / overlay 等网络边界集合。
- 安全名单、旁路名单、特定目标网段集。

### 注意事项

- `sets` 只能引用 `ip_set`。
