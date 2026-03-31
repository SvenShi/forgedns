---
title: 服务端插件
sidebar_position: 2
---

服务端插件负责接收客户端请求，并把请求交给某个入口执行器。它们本身不承担复杂策略逻辑，核心关注点是监听协议、监听地址、TLS 参数和入口 `entry`。

## 通用说明

所有服务端插件都依赖一个 `entry`，该字段必须引用一个已定义的执行器插件，通常是 `sequence`：

```yaml
- tag: seq_main
  type: sequence
  args:
    - exec: "$cache_main"
    - matches: "!$has_resp"
      exec: "$forward_main"

- tag: udp_in
  type: udp_server
  args:
    entry: "seq_main"
    listen: "0.0.0.0:53"
```

---

## `udp_server`

### 作用

监听 UDP DNS 请求，并把请求转交给 `entry`。

### 配置示例

```yaml
- tag: udp_in
  type: udp_server
  args:
    entry: "seq_main"
    listen: "0.0.0.0:53"
```

### 配置项

#### `entry`

- 类型：`string`；必填：是；默认值：无
- 作用：指定处理该监听器全部请求的入口执行器。
- 示例：`entry: "seq_main"`
- 配置要求：
  - 必须引用已定义的执行器插件。
  - 常见取值为某个 `sequence` 的 `tag`。
- 运行影响：
  - 所有进入当前 `udp_server` 的请求都会交由该执行器继续处理。
  - 若引用不存在或类型错误，插件初始化将失败。

#### `listen`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 UDP 监听地址。
- 示例：
  - `listen: "0.0.0.0:53"`
  - `listen: ":5353"`
- 支持格式：
  - `ip:port`
  - `:port`
- 运行影响：
  - 决定监听器绑定的地址与端口。
  - 地址无效、端口冲突或绑定失败时，监听器无法启动。

### 行为说明

- 使用 UDP socket 接收请求。
- 响应编码时会参考客户端宣告的 EDNS UDP payload。
- 超长响应会按 DNS 语义截断，而不是简单裁切原始字节流。

### 适用策略

- 高并发、低开销的标准 DNS 入口。
- 本地网络的主监听器。
- 与 `tcp_server` / `http_server` 并存，构成多协议接入。

### 注意事项

- UDP 与 QUIC 都基于 UDP 端口，避免端口冲突。
- 推荐将入口统一交给 `sequence`，避免在不同 server 实例中重复维护策略。

---

## `tcp_server`

### 作用

监听 TCP DNS 请求；当同时配置 `cert` 和 `key` 时，也可作为 DoT 入口。

### 配置示例

```yaml
- tag: tcp_in
  type: tcp_server
  args:
    entry: "seq_main"
    listen: ":53"
    idle_timeout: 10

- tag: dot_in
  type: tcp_server
  args:
    entry: "seq_main"
    listen: ":853"
    cert: "/etc/forgedns/server.crt"
    key: "/etc/forgedns/server.key"
    idle_timeout: 30
```

### 配置项

#### `entry`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 TCP 或 DoT 请求进入策略链时使用的入口执行器。
- 示例：`entry: "seq_main"`
- 配置要求：
  - 必须引用已定义的执行器插件。
- 运行影响：
  - 所有连接上的 DNS 消息都会交由该执行器处理。

#### `listen`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 TCP 监听地址。
- 示例：
  - `listen: ":53"`
  - `listen: "127.0.0.1:853"`
- 支持格式：
  - `ip:port`
  - `:port`
- 运行影响：
  - 影响明文 TCP 或 DoT 服务的绑定地址。

#### `cert`

- 类型：`string`；必填：否；默认值：无
- 作用：指定 TLS 证书文件路径。
- 示例：`cert: "/etc/forgedns/server.crt"`
- 使用条件：
  - 与 `key` 配合使用时启用 TLS。
- 运行影响：
  - 配置后可将 `tcp_server` 用作 DoT 入口。

#### `key`

- 类型：`string`；必填：否；默认值：无
- 作用：指定 TLS 私钥文件路径。
- 示例：`key: "/etc/forgedns/server.key"`
- 使用条件：
  - 与 `cert` 配合使用时启用 TLS。
- 运行影响：
  - 缺失或无效时，TLS 模式无法建立。

#### `idle_timeout`

- 类型：`integer`；必填：否；默认值：`10`
- 单位：秒
- 作用：指定连接空闲超时设置。
- 示例：`idle_timeout: 30`
- 运行影响：
  - 影响长连接保活与空闲连接生命周期。
  - 值越大，空闲连接保留时间越长。

### 行为说明

- 不配置 TLS 时，提供 DNS over TCP。
- 同时配置 `cert` + `key` 时，提供 DNS over TLS。
- TLS 场景会把 ALPN 设置为 `dot`。
- 每个连接可以承载多个 DNS 消息。

### 适用策略

- 提供 TCP 回退入口。
- 提供加密 DNS 的 DoT 接入。
- 需要长连接复用的客户端场景。

### 注意事项

- `cert` 和 `key` 需要一起配置。
- 如需同时提供明文 TCP 与 DoT，推荐定义两个独立的插件实例。

---

## `quic_server`

### 作用

提供 DNS over QUIC 服务。

### 配置示例

```yaml
- tag: doq_in
  type: quic_server
  args:
    entry: "seq_main"
    listen: ":853"
    cert: "/etc/forgedns/server.crt"
    key: "/etc/forgedns/server.key"
    idle_timeout: 30
```

### 配置项

#### `entry`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 DoQ 请求进入策略链时使用的入口执行器。
- 示例：`entry: "seq_main"`
- 配置要求：
  - 必须引用已定义的执行器插件。

#### `listen`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 QUIC 监听地址。
- 示例：`listen: ":853"`
- 运行影响：
  - 实际占用 UDP 端口。

#### `cert`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 DoQ 所需 TLS 证书文件。
- 示例：`cert: "/etc/forgedns/server.crt"`
- 运行影响：
  - 证书无效时监听器无法启动。

#### `key`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 DoQ 所需 TLS 私钥文件。
- 示例：`key: "/etc/forgedns/server.key"`
- 运行影响：
  - 私钥无效时监听器无法启动。

#### `idle_timeout`

- 类型：`integer`；必填：否；默认值：无
- 单位：秒
- 作用：指定 QUIC transport 的空闲超时。
- 示例：`idle_timeout: 30`
- 运行影响：
  - 影响空闲 QUIC 连接的回收时机。

### 行为说明

- DoQ 强制要求 TLS，所以 `cert` 和 `key` 是必填项。
- ALPN 固定为 `doq`。
- 每个双向流代表一次独立 DNS 交换。

### 适用策略

- 低时延加密 DNS 入口。
- 需要结合 QUIC 优势的现代客户端接入。

### 注意事项

- 监听端口底层仍然占用 UDP。
- 与 `udp_server` 不应绑定同一地址端口。

---

## `http_server`

### 作用

提供 DNS over HTTPS 服务，可同时支持 HTTP/2 与可选 HTTP/3。

### 配置示例

```yaml
- tag: doh_in
  type: http_server
  args:
    listen: ":443"
    cert: "/etc/forgedns/server.crt"
    key: "/etc/forgedns/server.key"
    enable_http3: true
    src_ip_header: "X-Forwarded-For"
    idle_timeout: 30
    entries:
      - path: "/dns-query"
        exec: "seq_main"
      - path: "/dns-alt"
        exec: "seq_alt"
```

### 配置项

#### `entries`

- 类型：`array`；必填：是；默认值：无
- 作用：定义 HTTP 路径到执行器的映射关系。
- 示例：
  - `path: "/dns-query", exec: "seq_main"`
  - `path: "/dns-alt", exec: "seq_alt"`
- 每个元素包含以下字段：
  - `path`
    - 类型：`string`
    - 必填：是
    - 作用：指定 DoH 请求路径。
    - 约束：必须以 `/` 开头。
  - `exec`
    - 类型：`string`
    - 必填：是
    - 作用：指定处理该路径请求的执行器。
    - 约束：必须引用已定义的执行器插件。
- 运行影响：
  - 不同路径可进入不同策略链。

#### `listen`

- 类型：`string`；必填：是；默认值：无
- 作用：指定 HTTP/HTTPS 监听地址。
- 示例：
  - `listen: ":80"`
  - `listen: ":443"`

#### `src_ip_header`

- 类型：`string`；必填：否；默认值：无
- 作用：指定从请求头中读取真实客户端来源地址的字段名。
- 示例：`src_ip_header: "X-Forwarded-For"`
- 运行影响：
  - 配置后，请求来源地址可由反向代理透传。

#### `cert`

- 类型：`string`；必填：否；默认值：无
- 作用：指定 HTTPS 证书文件路径。
- 示例：`cert: "/etc/forgedns/server.crt"`
- 运行影响：
  - 与 `key` 同时配置时启用 HTTPS。

#### `key`

- 类型：`string`；必填：否；默认值：无
- 作用：指定 HTTPS 私钥文件路径。
- 示例：`key: "/etc/forgedns/server.key"`
- 运行影响：
  - 与 `cert` 同时配置时启用 HTTPS。

#### `idle_timeout`

- 类型：`integer`；必填：否；默认值：`30`
- 单位：秒
- 作用：指定 HTTP 连接空闲超时。
- 示例：`idle_timeout: 30`
- 运行影响：
  - 影响 HTTP/2 长连接生命周期。

#### `enable_http3`

- 类型：`boolean`；必填：否；默认值：`false`
- 作用：指定是否同时启用 HTTP/3。
- 示例：`enable_http3: true`
- 使用条件：
  - 需要同时配置 `cert` 与 `key`。
- 运行影响：
  - 启用后会额外启动基于 QUIC 的 DoH 监听任务。

### 行为说明

- 每个 `path` 可以路由到不同 `exec`，适合做多入口策略。
- 自动注册 GET 与 POST 两种 RFC 8484 常见 DoH 访问方式。
- 开启 HTTP/3 时，会额外启动基于 QUIC 的监听任务。

### 适用策略

- 暴露标准 DoH 接口。
- 在同一个监听地址下提供多条 DNS 策略入口。
- 部署在反向代理后，使用 `src_ip_header` 保留真实来源地址。

### 注意事项

- `enable_http3: true` 时必须提供 `cert` 和 `key`。
- 若后面有反代，请确认 `src_ip_header` 的可信边界，避免伪造来源 IP。
