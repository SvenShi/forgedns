---
title: 数据提供器插件
sidebar_position: 5
---

provider 负责把规则集从“单条规则”提升为“可复用的数据资产”。在复杂配置里，provider 通常用于减少重复配置、沉淀共享规则、提升策略可维护性。

支持的数据 provider 既可以被 matcher 直接通过 `"$tag"` 引用，也可以继续被 `domain_set` / `ip_set` 组合，只要它们具备对应的域名或 IP 匹配能力。`domain_set` / `ip_set` 会只编译自己的本地规则，并在运行时继续查询被引用的 provider，不再复制下游 provider 的规则副本。

运行中的 provider 都会注册一个管理接口 `POST /plugins/<provider_tag>/reload`，并可通过 `reload_provider` executor 使用启动时同一份配置刷新自身快照，而不会重建其它插件。

运行时只会初始化真正被消费到的 provider。如果某个 provider 没有被任何 `server`、`executor`、`matcher` 直接或间接引用，它会在启动阶段被跳过，不会出现在 runtime registry 中，并会输出一条 warning 日志提示该 provider 未被使用。

---

## `adguard_rule`

### 作用

提供 AdGuard Home DNS 规则子集的可复用 provider。

这个 provider 提供两种语义：

- `contains_question`：完整请求 question 求值，支持 `dnstype`
- `contains_name`：name-only 投影求值，会忽略所有 `dnstype` 规则

### 配置示例

```yaml
- tag: ad_rules
  type: adguard_rule
  args:
    rules:
      # 基础拦截规则
      - "||ads.example.com^"
      # 例外规则
      - "@@||safe.ads.example.com^"
      # 带 dnstype / important / denyallow 的复杂规则也可以直接内联
      - "||cdn.example.com^$dnstype=A|AAAA,important,denyallow=cdn-safe.example.com"
    files:
      # 也可以从外部规则文件加载
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

- 配合 `qname` matcher 做 name-only 域名投影匹配。
- 配合 `question` matcher 复用 AdGuard 规则文件。
- 在 provider 层统一管理复杂的 AdGuard 域名拦截语义。

### 注意事项

- `qname` / `cname` 这类 name-only matcher 会走 `contains_name` 语义，因此会忽略带 `dnstype` 的规则。
- `adguard_rule` 可以被 `domain_set.sets` 继续组合；由于命中逻辑保留在运行时求值，`@@`、`important`、`denyallow` 和 `dnstype` 的优先级不会在组合后丢失。

---

## `domain_set`

### 作用

提供高性能域名规则集合，可被 `qname`、`cname` 等插件引用。

### 配置示例

```yaml
- tag: core_domains
  type: domain_set
  args:
    exps:
      # 精确匹配
      - "full:login.example.com"
      # 后缀域名匹配
      - "domain:example.com"
      # 关键字匹配
      - "keyword:cdn"
      # 正则匹配
      - "regexp:^api[0-9]+\\.example\\.net$"
      # 不带前缀时按域名规则解析
      - "static.example.org"
    files:
      # 从文件合并更多规则
      - "/etc/forgedns/domains.txt"
    sets:
      # 复用其它具备域名匹配能力的 provider
      - "shared_domains"
      - "shared_geosite"
```

### 配置项

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
  - 文件内容会在初始化或 `reload_provider` 时重新读取，并编译进当前 provider 的本地 matcher。

#### `sets`

- 类型：`array`；必填：否；默认值：空数组
- 作用：引用其它 `domain_set` 实例。
- 示例：`- "shared_domain_set"`
- 约束：
  - 允许引用任意具备域名匹配能力的 provider，例如 `domain_set`、`geosite`、`adguard_rule`。
- 运行影响：
  - 当前 provider 只保存被引用 provider 的稳定句柄，不复制其规则。
  - 下游 provider 单独 reload 后，当前 `domain_set` 无需 reload 即可看到新结果。

### 行为说明

- 初始化或 reload 时只编译本地 `exps` / `files`。
- 运行时按“本地 matcher -> `sets` 中声明顺序的 provider”依次判断。
- 不再把被引用 provider 的规则文本或编译结果复制进当前 provider。

### 支持的规则格式

- `full:example.com`
- `domain:example.com`
- `keyword:cdn`
- `regexp:^api\\.example\\.com$`
- `example.com`

### 典型用途

- 共享核心域名列表。
- 把本地手写规则和共享 provider 组合成一个统一入口。

### 注意事项

- `sets` 只能引用具备域名匹配能力的 provider。
- 若修改了 `sets` 拓扑、tag 或 provider 配置结构，仍需要应用级 `reload`；`reload_provider` 只刷新当前 provider 的既有配置和外部数据文件。

---

## `geosite`

### 作用

从 v2ray-rules-dat 的 `geosite.dat` 中提取一个或多个 code，并编译成可复用域名规则集合。

### 配置示例

```yaml
- tag: geosite_cn
  type: geosite
  args:
    file: "/etc/forgedns/geosite.dat"
    selectors:
      - "cn"
      - "geolocation-!cn"
```

### 配置项

#### `file`

- 类型：`string`；必填：是
- 作用：指定 `geosite.dat` 文件路径。

#### `selectors`

- 类型：`array`；必填：否；默认值：空数组
- 作用：按 code 提取部分规则，也支持 `code@attribute` 语法按 attribute 进一步过滤。
- 行为：
  - 大小写不敏感精确匹配。
  - 多个 selector 取并集。
  - 未设置或空数组时，加载整个 dat 文件的全部规则并集。
  - 例如 `category-games@cn` 表示只提取 `category-games` 中带 `cn` attribute 的规则。

### 行为说明

- `Plain` 会映射为 `keyword:` 规则。
- `Regex` 会映射为 `regexp:` 规则。
- `RootDomain` 会映射为 `domain:` 规则。
- `Full` 会映射为 `full:` 规则。
- 可被 `qname`、`cname`、`question` 直接引用，也可被 `domain_set.sets` 继续聚合。
- 可通过 `reload_provider` 或 `POST /plugins/<tag>/reload` 独立刷新 dat 文件内容。
- 如需在运行前把部分 selector 预导出成文本规则文件，可使用 `forgedns export-dat --kind geosite`。

---

## `ip_set`

### 作用

提供 IP / CIDR 规则集合，可被 `client_ip`、`resp_ip`、`ptr_ip` 等 matcher 引用。

### 配置示例

```yaml
- tag: lan_ip_set
  type: ip_set
  args:
    ips:
      # 单个 IPv4
      - "192.168.1.1"
      # IPv4 CIDR
      - "192.168.0.0/16"
      - "10.0.0.0/8"
      # 单个 IPv6
      - "2001:db8::1"
      # IPv6 CIDR
      - "fd00::/8"
    files:
      # 从文件合并更多 IP / CIDR
      - "/etc/forgedns/ips.txt"
    sets:
      # 复用其它具备 IP 匹配能力的 provider
      - "shared_ip_set"
      - "shared_geoip"
```

### 配置项

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
  - 文件内容会在初始化或 `reload_provider` 时重新读取，并编译进当前 provider 的本地 matcher。

#### `sets`

- 类型：`array`；必填：否；默认值：空数组
- 作用：引用其它 `ip_set` 实例。
- 示例：`- "shared_ip_set"`
- 约束：
  - 允许引用任意具备 IP 匹配能力的 provider，例如 `ip_set`、`geoip`。
- 运行影响：
  - 当前 provider 只保存被引用 provider 的稳定句柄，不复制其规则。
  - 下游 provider 单独 reload 后，当前 `ip_set` 无需 reload 即可看到新结果。

### 行为说明

- 初始化或 reload 时只编译本地 `ips` / `files`。
- 会分别维护 IPv4 / IPv6 规则索引。
- 运行时按“本地 matcher -> `sets` 中声明顺序的 provider”判断。

### 规则格式

- `1.1.1.1`
- `192.168.0.0/16`
- `2400:3200::/32`

### 典型用途

- LAN / WAN / overlay 等网络边界集合。
- 安全名单、旁路名单、特定目标网段集。
- 把本地 CIDR 和共享 `geoip` / `ip_set` provider 组合为统一入口。

### 注意事项

- `sets` 只能引用具备 IP 匹配能力的 provider。
- 若修改了 `sets` 拓扑、tag 或 provider 配置结构，仍需要应用级 `reload`；`reload_provider` 只刷新当前 provider 的既有配置和外部数据文件。

---

## `geoip`

### 作用

从 v2ray-rules-dat 的 `geoip.dat` 中提取一个或多个 code，并编译成可复用 IP / CIDR 集合。

### 配置示例

```yaml
- tag: geoip_cn
  type: geoip
  args:
    file: "/etc/forgedns/geoip.dat"
    selectors:
      - "cn"
```

### 配置项

#### `file`

- 类型：`string`；必填：是
- 作用：指定 `geoip.dat` 文件路径。

#### `selectors`

- 类型：`array`；必填：否；默认值：空数组
- 作用：按 code 提取部分规则。
- 行为：
  - 大小写不敏感精确匹配。
  - 多个 selector 取并集。
  - 未设置或空数组时，加载整个 dat 文件的全部 CIDR 并集。

### 行为说明

- 仅提供 IP 命中能力，可被 `client_ip`、`resp_ip`、`ptr_ip` 直接引用。
- 也可被 `ip_set.sets` 组合，并在上层 provider 运行时继续参与匹配。
- 可通过 `reload_provider` 或 `POST /plugins/<tag>/reload` 独立刷新 dat 文件内容。
- 如需在运行前把部分 selector 预导出成文本规则文件，可使用 `forgedns export-dat --kind geoip`。
