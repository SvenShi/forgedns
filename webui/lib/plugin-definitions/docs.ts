export const pluginFieldDocs = {
  udp_server: {
    entry:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定处理该监听器全部请求的入口执行器，通常为sequence插件。\n- 配置要求：\n  - 必须引用已定义的执行器插件。\n  - 常见取值为某个 `sequence` 的 `tag`。\n- 运行影响：\n  - 所有进入当前 `udp_server` 的请求都会交由该执行器继续处理。\n  - 若引用不存在或类型错误，插件初始化将失败。",
    listen:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 UDP 监听地址。\n- 支持格式：\n  - `ip:port`\n  - `:port`\n- 运行影响：\n  - 决定监听器绑定的地址与端口。\n  - 地址无效、端口冲突或绑定失败时，监听器无法启动。",
  },
  tcp_server: {
    entry:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 TCP 或 DoT 请求进入策略链时使用的入口执行器。\n- 配置要求：\n  - 必须引用已定义的执行器插件。\n- 运行影响：\n  - 所有连接上的 DNS 消息都会交由该执行器处理。",
    listen:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 TCP 监听地址。\n- 支持格式：\n  - `ip:port`\n  - `:port`\n- 运行影响：\n  - 影响明文 TCP 或 DoT 服务的绑定地址。",
    cert: "- 类型：`string`；必填：否；默认值：无\n- 作用：指定 TLS 证书文件路径。\n- 使用条件：\n  - 与 `key` 配合使用时启用 TLS。\n- 运行影响：\n  - 配置后可将 `tcp_server` 用作 DoT 入口。",
    key: "- 类型：`string`；必填：否；默认值：无\n- 作用：指定 TLS 私钥文件路径。\n- 使用条件：\n  - 与 `cert` 配合使用时启用 TLS。\n- 运行影响：\n  - 缺失或无效时，TLS 模式无法建立。",
    idle_timeout:
      "- 类型：`integer`；必填：否；默认值：`10`\n- 单位：秒\n- 作用：指定连接空闲超时设置。\n- 运行影响：\n  - 影响长连接保活与空闲连接生命周期。\n  - 值越大，空闲连接保留时间越长。",
  },
  http_server: {
    entries:
      "- 类型：`array`；必填：是；默认值：无\n- 作用：定义 HTTP 路径到执行器的映射关系。\n- 每个元素包含以下字段：\n  - `path`\n    - 类型：`string`\n    - 必填：是\n    - 作用：指定 DoH 请求路径。\n    - 约束：必须以 `/` 开头。\n  - `exec`\n    - 类型：`string`\n    - 必填：是\n    - 作用：指定处理该路径请求的执行器。\n    - 约束：必须引用已定义的执行器插件。\n- 运行影响：\n  - 不同路径可进入不同策略链。",
    listen:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 HTTP/HTTPS 监听地址。",
    src_ip_header:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：指定从请求头中读取真实客户端来源地址的字段名。\n- 运行影响：\n  - 配置后，请求来源地址可由反向代理透传。",
    cert: "- 类型：`string`；必填：否；默认值：无\n- 作用：指定 HTTPS 证书文件路径。\n- 运行影响：\n  - 与 `key` 同时配置时启用 HTTPS。",
    key: "- 类型：`string`；必填：否；默认值：无\n- 作用：指定 HTTPS 私钥文件路径。\n- 运行影响：\n  - 与 `cert` 同时配置时启用 HTTPS。",
    idle_timeout:
      "- 类型：`integer`；必填：否；默认值：`30`\n- 单位：秒\n- 作用：指定 HTTP 连接空闲超时。\n- 运行影响：\n  - 影响 HTTP/2 长连接生命周期。",
    enable_http3:
      '- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：指定是否同时启用 HTTP/3。\n- 使用条件：\n  - 需要同时配置 `cert` 与 `key`。\n- 运行影响：\n  - 启用后会额外启动基于 QUIC 的 DoH 监听任务。\n  - HTTP/2 响应会返回 `Alt-Svc: h3=":<listen-port>"; ma=86400`，提示客户端可升级到同端口 HTTP/3。',
  },
  quic_server: {
    entry:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 DoQ 请求进入策略链时使用的入口执行器。\n- 配置要求：\n  - 必须引用已定义的执行器插件。",
    listen:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 QUIC 监听地址。\n- 运行影响：\n  - 实际占用 UDP 端口。",
    cert: "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 DoQ 所需 TLS 证书文件。\n- 运行影响：\n  - 证书无效时监听器无法启动。",
    key: "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 DoQ 所需 TLS 私钥文件。\n- 运行影响：\n  - 私钥无效时监听器无法启动。",
    idle_timeout:
      "- 类型：`integer`；必填：否；默认值：无\n- 单位：秒\n- 作用：指定 QUIC transport 的空闲超时。\n- 运行影响：\n  - 影响空闲 QUIC 连接的回收时机。",
  },
  sequence: {
    args: "- 类型：`array`；必填：是；默认值：无\n- 作用：定义 sequence 的规则链。\n- 运行影响：\n  - 规则按书写顺序依次执行。\n  - `args` 为空时插件初始化失败。",
    "args[].matches":
      "- 类型：`string` 或 `array`\n- 必填：否\n- 默认值：无\n- 作用：定义当前规则的匹配条件。\n- 支持形式：\n  - 单个 matcher 字符串\n  - 多个 matcher 组成的列表\n- 运行影响：\n  - 多个条件之间为逻辑与关系。\n  - 未配置时表示无前置匹配条件。",
    "args[].exec":
      "- 类型：`string`；必填：否；默认值：无\n- 作用：定义规则命中后要执行的动作。\n- 支持内容：\n  - 插件引用\n  - quick setup 表达式\n  - 内建控制流\n- 运行影响：\n  - 直接决定当前规则的执行行为。",
  },
  forward: {
    concurrent:
      "- 类型：`integer`；必填：否；默认值：`1`\n- 取值范围：实际运行时会限制在 `1..=3`\n- 作用：定义多上游模式下的并发查询扇出数。\n- 运行影响：\n  - 值越大，多上游竞争越积极，但同时会增加上游请求量。",
    upstreams:
      "- 类型：`array`；必填：是；默认值：无\n- 作用：定义一个或多个上游目标。\n- 运行影响：\n  - 数组长度为 `1` 时使用单上游模式。\n  - 数组长度大于 `1` 时使用竞争式查询模式。",
    short_circuit:
      "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：控制在拿到成功上游响应后，是否立即停止后续 executor 链。\n- 说明：\n  - 关闭时，`forward` 仍会写入 `response`，但后续 executor 还能继续处理这份响应。\n  - 开启时，成功返回后会直接结束后续 executor 链。",
    "upstreams[].addr":
      "- 类型：`string`；必填：是；默认值：无\n- 作用：定义上游地址、协议类型以及目标主机。\n- 支持格式：\n  - `udp://8.8.8.8:53` 或 `8.8.8.8:53`\n  - `tcp://8.8.8.8:53`\n  - `tcp+pipeline://8.8.8.8:53`\n  - `tls://dns.example:853`\n  - `tls+pipeline://dns.example:853`\n  - `quic://dns.example:853` 或 `doq://dns.example:853`\n  - `https://resolver.example/dns-query` 或 `doh://resolver.example/dns-query`\n  - `h3://resolver.example/dns-query`\n- 规则说明：\n  - 未写协议时，按 `udp://` 处理。\n  - `https://` / `doh://` 表示 DoH，`h3://` 表示强制 DoH over HTTP/3。\n  - `tcp+pipeline://` 与 `tls+pipeline://` 会直接启用流水线模式。\n  - DoH 地址应包含实际请求路径，例如 `/dns-query`。\n- 配置建议：域名型上游建议同时配置 `bootstrap`，避免形成引导解析依赖。",
    "upstreams[].tag":
      "- 类型：`string`；必填：否；默认值：无\n- 作用：为单个上游提供日志标识，便于排查多上游竞争结果。",
    "upstreams[].dial_addr":
      "- 类型：`ip`；必填：否；默认值：无\n- 作用：指定实际连接 IP，同时保留 `addr` 中的主机名用于 SNI、Host 和证书校验。\n- 适用场景：固定拨号地址、绕过本机解析或配合自定义路由出口。",
    "upstreams[].port":
      "- 类型：`integer`；必填：否；默认值：协议默认端口\n- 作用：覆盖协议默认端口。",
    "upstreams[].bootstrap":
      "- 类型：`string`；必填：否；默认值：无\n- 作用：为域名型上游提供引导解析服务器。\n- 规则说明：\n  - 仅在 `addr` 使用域名时有意义。\n  - 应写为 `IP:port`，不能再写域名。\n  - 典型用于 DoT、DoQ、DoH 域名上游的首次解析。",
    "upstreams[].bootstrap_version":
      "- 类型：`integer`；必填：否；默认值：无\n- 作用：指定 bootstrap 优先使用 IPv4 或 IPv6。\n- 取值：`4` 或 `6`。",
    "upstreams[].socks5":
      "- 类型：`string`；必填：否；默认值：无\n- 作用：为上游连接指定 SOCKS5 代理。\n- 支持格式：\n  - `host:port`\n  - `username:password@host:port`\n  - IPv6 需写成 `[addr]:port`\n  - 带认证的 IPv6 需写成 `username:password@[addr]:port`\n- 规则说明：\n  - 代理主机可以是 IP，也可以是主机名；主机名会使用系统解析。\n  - 认证部分只按第一个 `:` 分割用户名和密码，因此格式必须是 `username:password@...`。\n  - 上游启用 `enable_http3` 时不应再配置 `socks5`，两者不属于同一连接模型。\n- 注意事项：格式错误、端口非法或代理主机解析失败时，该上游不会被正常创建。",
    "upstreams[].idle_timeout":
      "- 类型：`integer`；必填：否；默认值：无\n- 单位：秒\n- 作用：定义连接池空闲连接保留时间。",
    "upstreams[].max_conns":
      "- 类型：`integer`；必填：否；默认值：实现默认值\n- 作用：定义连接池连接上限。",
    "upstreams[].insecure_skip_verify":
      "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：控制是否跳过 TLS 证书校验。\n- 注意事项：仅适用于测试、自签证书或受控环境。",
    "upstreams[].timeout":
      "- 类型：`duration`；必填：否；默认值：`5s`\n- 作用：定义单次上游查询超时。",
    "upstreams[].enable_pipeline":
      "- 类型：`boolean`；必填：否；默认值：协议默认行为\n- 作用：控制 TCP 或 DoT 流水线。\n- 说明：也可直接通过 `tcp+pipeline://` 或 `tls+pipeline://` 在 `addr` 中启用。",
    "upstreams[].enable_http3":
      "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：控制 DoH 是否使用 HTTP/3。\n- 说明：也可直接通过 `h3://` 在 `addr` 中启用。",
    "upstreams[].so_mark":
      "- 类型：`integer`；必填：否；默认值：无\n- 作用：设置 Linux `SO_MARK`。",
    "upstreams[].bind_to_device":
      "- 类型：`string`；必填：否；默认值：无\n- 作用：设置 Linux `SO_BINDTODEVICE`。",
  },
  cache: {
    size: "- 类型：`integer`；必填：否；默认值：`1024`\n- 作用：定义缓存最大条目数。",
    lazy_cache_ttl:
      "- 类型：`integer`；必填：否；默认值：无\n- 单位：秒\n- 作用：为正向成功响应启用 lazy cache。\n- 运行影响：\n  - 原始 TTL 决定 fresh 命中窗口。\n  - `lazy_cache_ttl` 决定 stale 回包 TTL，并允许在原始 TTL 过期后短时间返回 stale 响应。\n  - stale 命中会在后台异步刷新缓存。\n  - 该配置不会缩短原始 fresh TTL。",
    dump_file:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：指定缓存持久化文件路径。",
    dump_interval:
      "- 类型：`integer`；必填：否；默认值：`600`\n- 单位：秒\n- 作用：定义缓存定期落盘周期。",
    short_circuit:
      "- 类型：`boolean`；必填：否；默认值：实现默认行为\n- 作用：控制缓存命中后是否立即结束后续执行。\n- 说明：\n  - 设为 `false` 时，即使 cache 已经写入 response，后续执行链仍会继续。\n  - 如需避免后续 `forward` 再次发起查询，应在 `sequence` 中配合 `has_resp`、`accept` 等控制流使用。",
    cache_negative:
      "- 类型：`boolean`；必填：否；默认值：实现默认行为\n- 作用：控制是否缓存 NXDOMAIN 与 NODATA。",
    max_negative_ttl:
      "- 类型：`integer`；必填：否；默认值：`300`\n- 单位：秒\n- 作用：定义负缓存 TTL 上限。",
    negative_ttl_without_soa:
      "- 类型：`integer`；必填：否；默认值：`60`\n- 单位：秒\n- 作用：定义无 SOA 负响应的回退 TTL。",
    max_positive_ttl:
      "- 类型：`integer`；必填：否；默认值：无\n- 单位：秒\n- 作用：定义正响应 TTL 上限。",
    ecs_in_key:
      "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：控制 ECS scope 是否参与缓存键计算。",
  },
  fallback: {
    primary: "- 类型：`string`；必填：是；默认值：无\n- 作用：指定主执行器。",
    secondary:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定备用执行器。",
    threshold:
      "- 类型：`integer`；必填：否；默认值：`0`\n- 单位：毫秒\n- 作用：定义主路径超时或延迟判定阈值。",
    always_standby:
      "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：控制备用路径是否与主路径同时待命。",
    short_circuit:
      "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：控制在主/备路径选出最终响应后，是否立即停止后续 executor 链。",
  },
  hosts: {
    entries:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：定义内联 hosts 规则。\n- 规则格式：\n  - `<域名规则> <ip1> <ip2> ...`",
    files:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：指定外部 hosts 规则文件列表。",
    short_circuit:
      "- 类型：`bool`；必填：否；默认值：`false`\n- 作用：命中并生成本地应答后，是否立即停止后续 executor 链。",
  },
  arbitrary: {
    rules:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：定义内联静态记录列表。\n- 语法：\n  - 每个数组项会作为独立 zone 片段解析。\n  - 支持 `$ORIGIN`、`$TTL`、`$INCLUDE`、`$GENERATE`、owner 继承、TTL 单位写法、注释、quoted string、多行 `(` `)` 语法。\n  - 常见记录类型支持直接文本解析，包括 `A`、`AAAA`、`CNAME`、`NS`、`PTR`、`DNAME`、`ANAME`、`MD`、`MF`、`MB`、`MG`、`MR`、`NSAPPTR`、`MX`、`RT`、`AFSDB`、`RP`、`MINFO`、`HINFO`、`TXT`、`SPF`、`AVC`、`RESINFO`、`SOA`、`SRV`、`NAPTR`、`CAA`。\n  - 其他记录类型可通过 RFC3597 通用语法 `TYPE#### \\# <len> <hex>` 导入。\n  - 省略 TTL 时默认使用 `3600`。",
    files:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：指定静态记录文件列表。\n- 语法：使用同一套 zone parser，支持与 `rules` 一致的语法能力。",
    short_circuit:
      "- 类型：`bool`；必填：否；默认值：`false`\n- 作用：命中并生成本地响应后，是否立即停止后续 executor 链。\n- 说明：默认只设置 response 并继续执行；显式开启时返回 `Stop`。",
  },
  redirect: {
    rules:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：定义内联重定向规则。\n- 规则格式：\n  - `<域名规则> <目标域名>`",
    files:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：指定外部重定向规则文件列表。\n\n规则格式：",
  },
  ecs_handler: {
    forward:
      "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：控制是否保留客户端请求中已有的 ECS。",
    send: "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：控制在请求缺少 ECS 时，是否根据来源地址自动补充 ECS。",
    preset:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：指定固定的 ECS 来源地址。",
    mask4:
      "- 类型：`integer`；必填：否；默认值：`24`\n- 作用：指定 IPv4 ECS 前缀长度。",
    mask6:
      "- 类型：`integer`；必填：否；默认值：`48`\n- 作用：指定 IPv6 ECS 前缀长度。",
  },
  forward_edns0opt: {
    codes:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：定义允许从请求复制到响应中的 EDNS0 option code 集合。\n- 运行影响：\n  - 未配置时插件基本退化为无操作。",
  },
  ttl: {
    fix: "- 类型：`integer`；必填：否；默认值：无\n- 作用：将所有响应 TTL 固定为同一个值。",
    min: "- 类型：`integer`；必填：否；默认值：无\n- 作用：定义 TTL 下限。",
    max: "- 类型：`integer`；必填：否；默认值：无\n- 作用：定义 TTL 上限。",
  },
  prefer_ipv4: {
    cache:
      "- 类型：`boolean`；必填：否；默认值：`true`\n- 作用：控制是否缓存 preferred 类型存在状态。",
    cache_ttl:
      "- 类型：`integer`；必填：否；默认值：`3600`\n- 单位：秒\n- 作用：定义 preferred 状态缓存时长。",
  },
  prefer_ipv6: {
    cache:
      "- 类型：`boolean`；必填：否；默认值：`true`\n- 作用：控制是否缓存 preferred 类型存在状态。",
    cache_ttl:
      "- 类型：`integer`；必填：否；默认值：`3600`\n- 单位：秒\n- 作用：定义 preferred 状态缓存时长。",
  },
  black_hole: {
    ips: "- 类型：`array`；必填：否；默认值：空数组\n- 作用：定义本地合成返回地址集合。\n- 运行影响：\n  - IPv4 地址仅用于 A 应答。\n  - IPv6 地址仅用于 AAAA 应答。",
    short_circuit:
      "- 类型：`bool`；必填：否；默认值：`false`\n- 作用：命中并生成本地应答后，是否立即停止后续 executor 链。",
  },
  drop_resp: {
    args: "无独立配置字段。",
  },
  reverse_lookup: {
    size: "- 类型：`integer`；必填：否；默认值：`65535`\n- 作用：定义反查缓存容量上限。",
    handle_ptr:
      "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：控制是否直接用反查缓存响应 PTR 请求。",
    ttl: "- 类型：`integer`；必填：否；默认值：`7200`\n- 单位：秒\n- 作用：定义 IP 到域名映射的缓存 TTL。",
  },
  query_summary: {
    msg: '- 类型：`string`；必填：否；默认值：`"query summary"`\n- 作用：定义摘要日志标题。',
  },
  query_recorder: {
    path: "- 类型：`string`；必填：是\n- 作用：指定当前 recorder 的 SQLite 文件路径。",
    queue_size:
      "- 类型：`integer`；必填：否；默认值：`8192`\n- 作用：定义热路径到后台写线程的有界队列大小。",
    batch_size:
      "- 类型：`integer`；必填：否；默认值：`256`\n- 作用：定义后台批量写入 SQLite 的单批记录数。",
    flush_interval_ms:
      "- 类型：`integer`；必填：否；默认值：`200`\n- 作用：定义后台写线程的批量 flush 间隔。",
    memory_tail:
      "- 类型：`integer`；必填：否；默认值：`1024`\n- 作用：定义最近记录的内存 tail 长度，用于 `stream?tail=n` 回放。",
    retention_days:
      "- 类型：`integer`；必填：否；默认值：`7`\n- 最小值：`1`\n- 作用：定义日志保留天数；过期数据会被定时实际删除。",
    cleanup_interval_hours:
      "- 类型：`integer`；必填：否；默认值：`1`\n- 最小值：`1`\n- 作用：定义过期清理任务的执行周期。",
  },
  metrics_collector: {
    name: '- 类型：`string`；必填：否；默认值：`"default"`\n- 作用：定义当前指标收集器的名称标签。',
  },
  debug_print: {
    msg: '- 类型：`string`；必填：否；默认值：`"debug print"`\n- 作用：定义日志输出标题。',
  },
  sleep: {
    duration:
      "- 类型：`integer`；必填：否；默认值：`0`\n- 单位：毫秒\n- 作用：定义当前请求在该执行器上的额外异步等待时间。",
  },
  http_request: {
    method:
      "- 类型：`string`；必填：是\n- 作用：指定 HTTP 方法，例如 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`。",
    url: "- 类型：`string`；必填：是\n- 作用：目标 URL。\n- 说明：支持 `${key}` 占位符插值；渲染后的 URL 只允许使用 `http` 或 `https`。",
    phase:
      "- 类型：`string`；必填：否；默认值：`after`\n- 可选值：`before`、`after`\n- 作用：控制请求在下游 executor 之前发送，还是在下游执行完成后发送。",
    async:
      "- 类型：`boolean`；必填：否；默认值：`true`\n- 作用：控制使用异步后台队列发送，还是在当前请求路径同步等待 HTTP 完成。",
    timeout:
      "- 类型：`string`；必填：否；默认值：`5s`\n- 作用：限制单次 HTTP 调用的总超时时间。\n- 支持单位：`ms`、`s`、`m`、`h`、`d`",
    error_mode:
      "- 类型：`string`；必填：否；默认值：`continue`\n- 可选值：\n  - `continue`：失败仅记录日志，然后继续后续链路\n  - `stop`：失败后返回 `Stop`\n  - `fail`：失败后直接返回 executor 错误",
    headers:
      "- 类型：`map<string,string>`；必填：否；默认值：空\n- 作用：附加 HTTP 请求头。\n- 说明：header value 支持 `${key}` 占位符插值。",
    query_params:
      "- 类型：`map<string,string>`；必填：否；默认值：空\n- 作用：把额外参数追加到 URL query 上。\n- 说明：value 支持 `${key}` 占位符插值；会与 URL 自带 query 一起发送。",
    body: "- 类型：`string`；必填：否\n- 作用：原始字符串请求体。\n- 说明：支持 `${key}` 占位符插值；可选配 `args.content_type`。",
    json: "- 类型：`object | array`；必填：否\n- 作用：以 JSON 方式发送请求体。\n- 说明：会自动设置 `Content-Type: application/json`；其中所有字符串叶子节点支持 `${key}` 占位符插值，非字符串值原样保留。",
    form: "- 类型：`map<string,string>`；必填：否\n- 作用：以 `application/x-www-form-urlencoded` 方式发送表单。\n- 说明：value 支持 `${key}` 占位符插值；会自动设置对应的 `Content-Type`。",
    content_type:
      "- 类型：`string`；必填：否\n- 作用：为原始 `args.body` 指定 `Content-Type`。\n- 说明：只能和 `args.body` 搭配，不能与 `args.json` 或 `args.form` 同时使用。",
    socks5:
      "- 类型：`string`；必填：否\n- 作用：指定 SOCKS5 代理。\n- 说明：格式与 `upstream[].socks5` 一致，支持 `host:port`、`username:password@host:port` 和带中括号的 IPv6。",
    insecure_skip_verify:
      "- 类型：`boolean`；必填：否；默认值：`false`\n- 作用：是否跳过 HTTPS 证书校验。",
    max_redirects:
      "- 类型：`integer`；必填：否；默认值：`5`\n- 作用：限制最多跟随多少次重定向。",
    queue_size:
      "- 类型：`integer`；必填：否；默认值：`256`\n- 作用：异步模式下后台发送队列的容量。",
  },
  script: {
    command:
      "- 类型：`string`；必填：是\n- 作用：要执行的命令路径或命令名。\n- 说明：该字段不支持模板替换，避免命令本身在运行期漂移。",
    args: "- 类型：`array<string>`；必填：否；默认值：空\n- 作用：传给命令的参数数组。\n- 说明：每一项支持 `${key}` 占位符插值。",
    env: "- 类型：`map<string,string>`；必填：否；默认值：空\n- 作用：追加到子进程环境变量中的键值对。\n- 说明：value 支持 `${key}` 占位符插值；不会清空父进程已有环境变量。",
    cwd: "- 类型：`string`；必填：否；默认值：无\n- 作用：指定脚本运行时的工作目录。",
    timeout:
      "- 类型：`string`；必填：否；默认值：`5s`\n- 作用：限制单次脚本执行时长。\n- 支持单位：`ms`、`s`、`m`、`h`、`d`",
    error_mode:
      "- 类型：`string`；必填：否；默认值：`continue`\n- 可选值：\n  - `continue`：失败或超时仅记录日志，然后返回 `Next`\n  - `stop`：失败或超时后返回 `Stop`\n  - `fail`：失败或超时直接返回错误",
    max_output_bytes:
      "- 类型：`usize`；必填：否；默认值：`4096`\n- 作用：限制 stdout / stderr 的捕获长度，超过部分只做截断标记。",
  },
  ipset: {
    set_name4:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：指定写入 IPv4 地址的 ipset 名称。",
    set_name6:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：指定写入 IPv6 地址的 ipset 名称。",
    mask4:
      "- 类型：`integer`；必填：否；默认值：`24`\n- 作用：指定 IPv4 地址写入 ipset 时使用的前缀长度。",
    mask6:
      "- 类型：`integer`；必填：否；默认值：`32`\n- 作用：指定 IPv6 地址写入 ipset 时使用的前缀长度。",
  },
  nftset: {
    ipv4: "- 类型：`object`；必填：否；默认值：无\n- 作用：定义 IPv4 目标 nftables set。\n- 子字段：\n  - `table_family`\n  - `table_name`\n  - `set_name`\n  - `mask`",
    ipv6: "- 类型：`object`；必填：否；默认值：无\n- 作用：定义 IPv6 目标 nftables set。\n- 子字段：\n  - `table_family`\n  - `table_name`\n  - `set_name`\n  - `mask`",
    table_family4:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：兼容写法下分别定义 IPv4 / IPv6 的 nftables 表 family。",
    table_family6:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：兼容写法下分别定义 IPv4 / IPv6 的 nftables 表 family。",
    table_name4:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：兼容写法下分别定义 IPv4 / IPv6 的 nftables 表名。",
    table_name6:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：兼容写法下分别定义 IPv4 / IPv6 的 nftables 表名。",
    set_name4:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：兼容写法下分别定义 IPv4 / IPv6 的 set 名称。",
    set_name6:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：兼容写法下分别定义 IPv4 / IPv6 的 set 名称。",
    mask4:
      "- 类型：`integer`；必填：否；默认值：由实现确定\n- 作用：兼容写法下分别定义 IPv4 / IPv6 前缀长度。",
    mask6:
      "- 类型：`integer`；必填：否；默认值：由实现确定\n- 作用：兼容写法下分别定义 IPv4 / IPv6 前缀长度。",
  },
  ros_address_list: {
    address:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 RouterOS API 服务地址，通常写为 `host:port`。插件启动后将使用该地址建立管理连接，并在运行期间维持与设备的同步关系。\n- 配置建议：使用 RouterOS API 明文端口时通常为 `8728`，如部署了加密 API，应按实际端口填写。",
    username:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 RouterOS API 登录用户名。该账户需要具备读取和维护目标 `address-list` 的权限。\n- 配置建议：建议为本插件单独创建专用账号，以便隔离权限范围和审计记录。",
    password:
      "- 类型：`string`；必填：是；默认值：无\n- 作用：指定 RouterOS API 登录密码。插件初始化、重连和后台同步均依赖该凭据。\n- 注意事项：应避免在公开仓库或共享示例中直接暴露真实口令。",
    async:
      "- 类型：`bool`；必填：否；默认值：`true`\n- 作用：控制地址写入行为是否采用异步方式。启用后，DNS 应答路径只负责投递任务，由后台管理器完成与 RouterOS 的交互。\n- 影响：异步模式有助于降低请求路径阻塞风险；关闭后会改为同步提交，更适合需要立即确认提交结果的场景。",
    address_list4:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：指定 IPv4 地址写入的目标 `address-list` 名称。插件从 DNS 应答中提取到 A 记录后，将写入该列表。\n- 配置建议：如果策略仅处理 IPv4，应至少配置本项。",
    address_list6:
      "- 类型：`string`；必填：否；默认值：无\n- 作用：指定 IPv6 地址写入的目标 `address-list` 名称。插件从 DNS 应答中提取到 AAAA 记录后，将写入该列表。\n- 配置建议：如果策略需要覆盖 IPv6，应同时配置本项，并在 RouterOS 侧建立对应的匹配与路由规则。",
    comment_prefix:
      "- 类型：`string`；必填：否；默认值：`fdns`\n- 作用：指定插件写入 RouterOS 条目时使用的注释前缀。该前缀用于区分 ForgeDNS 创建的动态项和常驻项，便于后续刷新、重载与清理。\n- 注意事项：该值及插件 `tag` 不应包含 `;` 或 `=`，以避免影响内部标记格式。",
    persistent:
      "- 类型：`object`；必填：否；默认值：无\n- 作用：定义需要长期保留的静态地址集合。该部分不依赖 DNS 应答触发，可在插件启动后直接同步到 RouterOS，并由后台 reconcile 保持一致性。\n- 子字段：\n  - `ips`\n  - `files`",
    "persistent.ips":
      "- 类型：`array<string>`；必填：否；默认值：空\n- 作用：以内联方式声明常驻 IP 或 CIDR 网段。适用于数量较少且变更频率不高的固定策略对象。\n- 支持格式：单个 IPv4、单个 IPv6、IPv4 CIDR、IPv6 CIDR。",
    "persistent.files":
      "- 类型：`array<string>`；必填：否；默认值：空\n- 作用：从外部文件加载常驻地址集合。适用于需要由其他系统生成、集中维护或批量管理的地址列表。\n- 行为说明：这些文件只在插件初始化时读取一次。文件变更后如需生效，需要 reload 插件或应用。",
    min_ttl:
      "- 类型：`u64`；必填：否；默认值：`60`\n- 作用：定义动态地址项允许使用的最小 TTL。当 DNS 应答中的 TTL 过小或为零时，插件会提升到该值后再写入 RouterOS。\n- 适用场景：用于避免高频刷新造成的管理面抖动。",
    max_ttl:
      "- 类型：`u64`；必填：否；默认值：`3600`\n- 作用：定义动态地址项允许使用的最大 TTL。当 DNS 应答中的 TTL 过大时，插件会截断到该上限。\n- 适用场景：用于限制策略项在网络设备中的滞留时间，降低地址陈旧风险。",
    fixed_ttl:
      "- 类型：`u64`；必填：否；默认值：无\n- 作用：为所有动态写入项指定固定 TTL。配置本项后，插件不再使用 DNS 记录中的原始 TTL，也不再受 `min_ttl` 与 `max_ttl` 的区间裁剪影响。若设为 `0`，则动态项不会设置 RouterOS `timeout`。\n- 适用场景：适合需要统一刷新周期、便于运维预估和策略收敛的场景。",
    cleanup_on_shutdown:
      "- 类型：`bool`；必填：否；默认值：`true`\n- 作用：控制插件退出时是否清理由其管理的条目。启用后，插件在正常关闭阶段会删除自身写入并可识别归属的 RouterOS 地址项。\n- 影响：关闭该选项后，已写入条目会继续保留在 RouterOS 中，适合要求策略状态跨进程重启保留的场景。",
  },
  upgrade: {
    args: "- `force`\n    - 类型：`bool`\n    - 默认值：`false`\n    - 即使目标 release 不比当前版本更新，也继续下载、校验并替换。\n- `cleanup`\n    - 类型：`bool`\n    - 默认值：`true`\n    - 升级成功后清理 `cache_dir` 和 `backup_dir`。\n- `repository`\n    - GitHub 仓库，默认 `SvenShi/forgedns`。\n- `asset`\n    - Release asset 名称；`auto` 会按当前平台选择 archive。\n- `cache_dir` / `backup_dir`\n    - 下载缓存目录和替换前备份目录。\n- `restart`\n    - 可选值为 `none` 或 `service`。设置为 `service` 时，升级成功替换二进制文件后，应用会主动退出并返回错误码，以便 systemd 自动重启。因此，对应的 service 必须将 `Restart` 设置为 `always` 或 `on-failure`。\n- `timeout`、`socks5`、`insecure_skip_verify`\n    - 与 CLI `upgrade` 参数含义一致。",
  },
  cron: {
    jobs: "- 类型：`array`；必填：是；默认值：无\n- 作用：定义一个或多个后台任务。\n- 运行影响：\n  - 数组不能为空。\n  - 每个任务独立维护自己的调度状态和重叠保护。",
    timezone:
      "- 类型：`string`；必填：否；默认值：系统本地时区\n- 作用：为当前 `cron` 插件下的所有 `schedule` 任务指定时区。\n- 运行影响：\n  - 仅对 `schedule` 生效。\n  - 未配置时会使用系统本地时区；无法获取时退回 `UTC`。\n  - 应填写 IANA 时区名称，例如 `Asia/Shanghai`、`UTC`、`America/Los_Angeles`。",
    "jobs[].name":
      "- 类型：`string`；必填：是；默认值：无\n- 作用：任务名称，用于日志与运行时标识。\n- 运行影响：\n  - 在同一个 `cron` 插件内必须唯一。",
    "jobs[].schedule":
      "- 类型：`string`；必填：与 `interval` 二选一；默认值：无\n- 作用：使用标准 5 字段 cron 表达式调度任务。\n- 规则说明：\n  - 仅支持 `minute hour day month day-of-week`。\n  - 不支持秒级 cron。\n  - 按 `args.timezone` 或系统本地时区计算下一次触发时间。",
    "jobs[].interval":
      "- 类型：`string`；必填：与 `schedule` 二选一；默认值：无\n- 作用：用简单固定间隔调度任务。\n- 支持格式：\n  - `5m`\n  - `1h`\n  - `1d`\n- 运行影响：\n  - 最小粒度为 `1m`。\n  - 启动后会等待一个完整间隔再首次触发。",
    "jobs[].executors":
      "- 类型：`array`；必填：是；默认值：无\n- 作用：定义任务触发时顺序执行的 executor 列表。\n- 支持形式：\n  - `$tag`：显式引用已存在 executor\n  - `tag`：裸 tag 引用\n  - quick setup 表达式，例如 `debug_print cron refresh`\n- 运行影响：\n  - 数组不能为空。\n  - 即使某个 executor 返回 `Stop`、设置了响应、或执行报错，后续 executor 仍会继续执行。",
  },
  any_match: {
    args: '`any_match` 的 `args` 为 matcher 表达式列表。\n\n- 类型：`array[string]`；必填：是；默认值：无\n- 支持元素：\n  - matcher tag 引用（如 `"$match_tag"`）\n  - quick setup matcher 表达式（如 `"qname domain:example.com"`）\n  - 取反 matcher 表达式（如 `"!$has_resp"`）\n- 运行影响：\n  - 按配置顺序依次判断，命中任意一个后立即短路返回 `true`。\n  - 全部不命中时返回 `false`。',
  },
  qname: {
    args: "`qname` 的 `args` 采用规则列表形式，列表中的每个元素均独立生效。\n\n- 类型：`array`；必填：是；默认值：无\n- 作用：定义域名匹配规则来源。\n- 支持元素：\n  - 域名表达式\n  - 具备域名匹配能力的 provider 引用，例如 `domain_set`、`geosite`\n  - 文件引用\n- 运行影响：\n  - 当前请求中的任意问题域名命中任一规则时，matcher 返回 `true`。",
  },
  question: {
    args: '- `args`\n  - 类型：`array[string]`；必填：是；默认值：无\n  - 作用：使用 `"$provider_tag"` 形式引用实现了 `contains_question` 的 provider。',
  },
  qtype: {
    args: "`qtype` 的 `args` 为类型列表。\n\n- 类型：`array`；必填：是；默认值：无\n- 作用：定义允许命中的查询类型集合。\n- 常见映射：`1` = `A`、`28` = `AAAA`、`12` = `PTR`\n- 运行影响：\n  - 请求中的任意问题类型命中配置集合时返回 `true`。",
  },
  qclass: {
    args: "`qclass` 的 `args` 为类别列表。\n\n- 类型：`array`；必填：是；默认值：无\n- 作用：定义允许命中的查询类别集合。\n- 常见映射：`1` = `IN`、`3` = `CH`、`4` = `HS`\n- 运行影响：\n  - 请求中的任意问题类别命中配置集合时返回 `true`。",
  },
  client_ip: {
    args: "`client_ip` 的 `args` 采用规则列表形式。\n\n- 类型：`array`；必填：是；默认值：无\n- 作用：定义客户端来源地址匹配条件。\n- 支持元素：\n  - 单个 IP\n  - CIDR\n  - `ip_set` 引用\n- 运行影响：\n  - 只要客户端来源地址命中任一规则，matcher 即返回 `true`。",
  },
  resp_ip: {
    args: "`resp_ip` 的 `args` 采用规则列表形式。\n\n- 类型：`array`；必填：是；默认值：无\n- 作用：定义应答地址匹配条件。\n- 支持元素：\n  - 单个 IP\n  - CIDR\n  - `ip_set` 引用\n- 运行影响：\n  - 只检查 response answer 区中的 A/AAAA 地址。\n  - 任一答案地址命中即返回 `true`。",
  },
  ptr_ip: {
    args: "`ptr_ip` 的 `args` 采用规则列表形式。\n\n- 类型：`array`；必填：是；默认值：无\n- 作用：定义 PTR 请求名解析出的地址匹配条件。\n- 支持元素：\n  - 单个 IP\n  - CIDR\n  - `ip_set` 引用\n- 运行影响：\n  - 仅对 PTR 查询生效。\n  - PTR 请求名解析出的地址命中任一规则时返回 `true`。",
  },
  cname: {
    args: "`cname` 的 `args` 采用规则列表形式。\n\n- 类型：`array`；必填：是；默认值：无\n- 作用：定义 CNAME 目标名称匹配条件。\n- 支持元素：\n  - 域名表达式\n  - `domain_set` 引用\n  - 文件引用\n- 运行影响：\n  - 只检查响应中的 CNAME 目标。\n  - 任一 CNAME 目标命中时返回 `true`。",
  },
  rcode: {
    args: "`rcode` 的 `args` 为 rcode 列表。\n\n- 类型：`array`；必填：是；默认值：无\n- 作用：定义可命中的响应码集合。\n- 取值要求：\n  - 当前使用十进制整数表示。\n  - 例如：\n    - `0` = `NOERROR`\n    - `2` = `SERVFAIL`\n    - `3` = `NXDOMAIN`\n- 运行影响：\n  - 仅当上下文中已有响应且 rcode 命中配置集合时返回 `true`。",
  },
  has_resp: {
    args: "无独立配置字段。",
  },
  has_wanted_ans: {
    args: "无独立配置字段。",
  },
  mark: {
    args: "`mark` 的 `args` 为 mark 列表。\n\n- 类型：`array`；必填：是；默认值：无\n- 作用：定义可命中的上下文标记集合。\n- 支持取值：\n  - 无符号整数形式的 mark 值\n- 运行影响：\n  - 只要上下文 marks 与配置 marks 存在交集，即返回 `true`。",
  },
  env: {
    args: "`env` 的 `args` 为一到两个元素。\n\n- 类型：`array`；必填：是；默认值：无\n- 元素定义：\n  - 第一个元素：环境变量名\n  - 第二个元素：可选，期望值\n- 运行影响：\n  - 仅配置变量名时，环境变量存在即返回 `true`。\n  - 同时配置变量名和值时，需完全匹配才返回 `true`。",
  },
  random: {
    args: "`random` 的 `args` 只接受一个概率值。\n\n- 类型：`array`；必填：是；默认值：无\n- 取值范围：`0.0` 到 `1.0`\n- 作用：定义本次匹配返回 `true` 的概率。\n- 运行影响：\n  - `0.0` 表示始终不命中。\n  - `1.0` 表示始终命中。",
  },
  rate_limiter: {
    qps: "- 类型：`number`；必填：否；默认值：`20`\n- 作用：定义每秒令牌补充速率。\n- 运行影响：\n  - 值越大，单位时间内允许通过的请求越多。",
    burst:
      "- 类型：`integer`；必填：否；默认值：`40`\n- 作用：定义令牌桶容量上限。\n- 运行影响：\n  - 值越大，短时间内允许的突发请求越多。",
    mask4:
      "- 类型：`integer`；必填：否；默认值：`32`\n- 作用：定义 IPv4 客户端聚合粒度。\n- 运行影响：\n  - 值越小，多个 IPv4 客户端越容易共享同一个限流桶。",
    mask6:
      "- 类型：`integer`；必填：否；默认值：`48`\n- 作用：定义 IPv6 客户端聚合粒度。\n- 运行影响：\n  - 值越小，多个 IPv6 客户端越容易共享同一个限流桶。",
  },
  string_exp: {
    args: "`string_exp` 的 `args` 可以为字符串或字符串数组。\n\n- 类型：`string` 或 `array`\n- 必填：是\n- 默认值：无\n- 作用：定义完整字符串表达式。\n- 表达式组成：\n  - 数据来源 `source`\n  - 匹配操作 `op`\n  - 一个或多个参数\n- 运行影响：\n  - 按表达式从上下文中取值并执行字符串匹配。",
  },
  _true: {
    args: "无独立配置字段。",
  },
  _false: {
    args: "无独立配置字段。",
  },
  domain_set: {
    exps: "- 类型：`array`；必填：否；默认值：空数组\n- 作用：定义内联域名表达式列表。\n- 支持内容：\n  - `full:`\n  - `domain:`\n  - `keyword:`\n  - `regexp:`\n  - 无前缀域名\n- 运行影响：\n  - 在初始化阶段编译为可直接匹配的规则集合。",
    files:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：指定外部规则文件路径列表。\n- 文件要求：\n  - 每行一条规则。\n  - 空行与注释行会被忽略。\n- 运行影响：\n  - 文件内容会在初始化或 `reload_provider` 时重新读取，并编译进当前 provider 的本地 matcher。",
    sets: "- 类型：`array`；必填：否；默认值：空数组\n- 作用：引用其它 `domain_set` 实例。\n- 约束：\n  - 允许引用任意具备域名匹配能力的 provider，例如 `domain_set`、`geosite`、`adguard_rule`。\n- 运行影响：\n  - 当前 provider 只保存被引用 provider 的稳定句柄，不复制其规则。\n  - 下游 provider 单独 reload 后，当前 `domain_set` 无需 reload 即可看到新结果。",
  },
  geosite: {
    file: "- 类型：`string`；必填：是\n- 作用：指定 `geosite.dat` 文件路径。",
    selectors:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：按 code 提取部分规则，也支持 `code@attribute` 语法按 attribute 进一步过滤。\n- 行为：\n  - 大小写不敏感精确匹配。\n  - 多个 selector 取并集。\n  - 未设置或空数组时，加载整个 dat 文件的全部规则并集。\n  - 例如 `category-games@cn` 表示只提取 `category-games` 中带 `cn` attribute 的规则。",
  },
  ip_set: {
    ips: "- 类型：`array`；必填：否；默认值：空数组\n- 作用：定义内联 IP 或 CIDR 规则列表。\n- 支持内容：\n  - 单个 IPv4 地址\n  - 单个 IPv6 地址\n  - IPv4 CIDR\n  - IPv6 CIDR\n- 运行影响：\n  - 规则会在初始化阶段编译为地址匹配结构。",
    files:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：指定外部 IP 规则文件路径列表。\n- 文件要求：\n  - 每行一条 IP 或 CIDR 规则。\n  - 空行与注释行会被忽略。\n- 运行影响：\n  - 文件内容会在初始化或 `reload_provider` 时重新读取，并编译进当前 provider 的本地 matcher。",
    sets: "- 类型：`array`；必填：否；默认值：空数组\n- 作用：引用其它 `ip_set` 实例。\n- 约束：\n  - 允许引用任意具备 IP 匹配能力的 provider，例如 `ip_set`、`geoip`。\n- 运行影响：\n  - 当前 provider 只保存被引用 provider 的稳定句柄，不复制其规则。\n  - 下游 provider 单独 reload 后，当前 `ip_set` 无需 reload 即可看到新结果。",
  },
  geoip: {
    file: "- 类型：`string`；必填：是\n- 作用：指定 `geoip.dat` 文件路径。",
    selectors:
      "- 类型：`array`；必填：否；默认值：空数组\n- 作用：按 code 提取部分规则。\n- 行为：\n  - 大小写不敏感精确匹配。\n  - 多个 selector 取并集。\n  - 未设置或空数组时，加载整个 dat 文件的全部 CIDR 并集。",
  },
} as const satisfies Record<string, Record<string, string>>;
