---
title: 管理 API
sidebar_position: 4
---

OxiDNS 的管理 API 是独立控制平面，负责：

* 进程与启动健康检查
* 配置检查与配置文本校验
* 重载与关闭控制
* 插件扩展 API
* Prometheus 指标导出

本章说明管理 API 的启用方式、认证传输、核心接口和指标导出。

## 启用方式

### 简写

```yaml
api:
  http: "127.0.0.1:9088"
```

监听地址支持 `ip:port`、`[ipv6]:port` 和 `:port`。`http: ":9088"` 会绑定为双栈 `[::]:9088`；仅监听 IPv4 时请显式写 `0.0.0.0:9088`。

### 详写

```yaml
api:
  http:
    listen: "127.0.0.1:9443"
    ssl:
      cert: "/etc/oxidns/api.crt"
      key: "/etc/oxidns/api.key"
      client_ca: "/etc/oxidns/client-ca.crt"
      require_client_cert: true
    auth:
      type: basic
      username: "admin"
      password: "secret"
    webui:
      root: "/opt/oxidns/webui"
      index: "index.html"
```

## 认证与传输

### TLS

当 `ssl.cert` 与 `ssl.key` 同时配置时，API 使用 HTTPS。

可选增强：

* `client_ca`
  * 配置客户端 CA。
* `require_client_cert`
  * 强制双向认证。

### Basic Auth

```yaml
auth:
  type: basic
  username: "admin"
  password: "secret"
```

开启后，所有 API 请求都需要通过 Basic Auth。

请求头格式如下：

```http
Authorization: Basic YWRtaW46c2VjcmV0
```

编码规则如下：

* 先按 `username:password` 拼接原始字符串。
* 再对整个字符串做 Base64 编码。
* 请求头前缀必须为 `Basic `。

以上示例中，`admin:secret` 对应的 Base64 结果为 `YWRtaW46c2VjcmV0`。

注意事项：

* 这里使用的是标准 Base64，不是 URL-safe Base64。
* 不需要分别对 `username` 和 `password` 单独编码。
* 不使用百分号编码，也不应先做 URL encode。
* 服务端按解码后的完整结果与 `username:password` 做直接比较。

示例：

```bash
curl -u admin:secret http://127.0.0.1:9088/api/healthz
```

或：

```bash
curl -H 'Authorization: Basic YWRtaW46c2VjcmV0' \
  http://127.0.0.1:9088/api/healthz
```

### WebUI 静态文件

管理 API 可以直接服务外部 WebUI 静态目录。WebUI 挂载在根路径 `/`，管理 API 统一位于 `/api/*`：

```yaml
api:
  http:
    listen: "0.0.0.0:9199"
    webui:
      root: "/opt/oxidns/webui"
      index: "index.html"
```

启用后，访问 `http://服务器:9199/` 加载 WebUI，WebUI 使用同源 `/api` 访问后端。静态文件不受 Basic Auth 保护，但 `/api/*` 仍按管理 API 的认证与 CORS 规则处理。完整配置、构建步骤和 nginx 独立部署示例见《[WebUI 部署](webui.md)》。

### CORS / WebUI 跨域

默认情况下，管理 API 会根据 `api.http.listen` 自动处理 WebUI 跨域：

* 监听 `0.0.0.0` 或 `[::]` 时，自动返回 `Access-Control-Allow-Origin: *`。
* 监听具体 IP 时，自动允许同一 host 的 WebUI 访问，且不限制 WebUI 端口。例如 API 监听 `192.168.1.10:8080`，则 `http://192.168.1.10:3000`、`http://192.168.1.10:5173` 都可访问。
* 监听 `127.0.0.1` 或 `[::1]` 时，也会允许 `localhost`。

如需收紧或覆盖自动策略，可显式配置 `cors.allowed_origins`：

```yaml
api:
  http:
    listen: "0.0.0.0:8080"
    cors:
      allowed_origins:
        - "http://localhost:3000"
        - "http://192.168.1.100:3000"
```

显式配置后，`allowed_origins` 按浏览器发送的 `Origin` 精确匹配。可使用 `"*"` 允许任意 origin，但此时浏览器不会接受带凭据的跨域请求。

## 路由组织

API 路由分成三类：

* 全局路由
  * 例如 `/api/healthz`、`/api/control`
* 插件路由
  * 统一格式：`/api/plugins/<plugin_tag>/<subpath>`
* 观测路由
  * 例如 `/api/metrics`

## 内置健康检查接口

### `GET /api/healthz`

作用：

* 只检查 API 监听是否已建立。

返回：

* `200 OK`：`ok`
* `503 Service Unavailable`：`not_listening`

### `GET /api/readyz`

作用：

* 检查插件初始化和 server 启动是否已完成。

返回：

* `200 OK`：`ready`
* `503 Service Unavailable`：`not_ready`

### `GET /api/health`

作用：

* 返回 JSON 形式的健康详情。

示例结构：

```json
{
  "status": "ok",
  "version": "x.y.z",
  "uptime_ms": 12345,
  "checks": {
    "api": "ok",
    "plugin_init": "ok",
    "server_startup": "ok"
  },
  "plugins": {
    "total": 12,
    "servers": 4
  }
}
```

## 内置控制接口

### `GET /api/control`

作用：

* 返回当前进程控制面状态。

返回内容包括：

* 运行状态
* 运行时长
* 当前配置路径
* 是否请求过 shutdown
* reload 状态快照

### `POST /api/shutdown`

作用：

* 请求优雅关闭。

返回：

* `202 Accepted`

### `POST /api/reload`

作用：

* 请求重载配置，重新加载所有插件。

返回：

* `202 Accepted`
  * 已受理。
* `409 Conflict`
  * 已有 reload 在 pending / in\_progress。

### `GET /api/reload/status`

作用：

* 查询最近一次重载状态。

返回字段包括：

* `status`
  * `idle`
  * `pending`
  * `in_progress`
  * `ok`
  * `failed`
* `pending`
* `in_progress`
* `last_started_ms`
* `last_completed_ms`
* `last_success_ms`
* `last_error`

## 配置检查接口

### `GET /api/config`

作用：

* 读取当前启动参数指向的配置文件原文。
* 返回 YAML 文本、配置路径、内容版本和文件更新时间。

返回示例：

```json
{
  "ok": true,
  "path": "/etc/oxidns/config.yaml",
  "format": "yaml",
  "content": "plugins:\n  - tag: forward\n    type: forward\n",
  "version": "sha256-hex",
  "updated_at_ms": 1760000000000
}
```

### `PUT /api/config`

作用：

* 保存完整 YAML 配置文件。
* 保存前默认执行与 `POST /api/config/validate` 相同的校验。
* 可在保存成功后触发一次应用级 reload。

请求体：

```json
{
  "format": "yaml",
  "content": "plugins:\n  - tag: debug_main\n    type: debug_print\n",
  "base_version": "sha256-hex",
  "validate": true,
  "reload": false
}
```

返回：

* `200 OK`
  * 配置已保存，返回新版本、插件数量和初始化顺序。
* `400 Bad Request`
  * YAML 无法解析、配置校验失败，或 `format` 不是 `yaml`。
* `409 Conflict`
  * `base_version` 与当前文件版本不一致，或保存后请求 reload 时已有 reload 正在进行。

### `GET /api/config/check`

作用：

* 校验当前配置文件路径对应的配置文件。

适用场景：

* 检查磁盘上现有配置是否能成功解析与通过插件依赖校验。

### `POST /api/config/validate`

作用：

* 直接校验请求体中的 YAML 配置文本。
* 同时支持 `PUT /api/config` 使用的 JSON 包装格式。

请求体要求：

* UTF-8 YAML 文本且非空；或
* JSON：`{"format":"yaml","content":"...yaml..."}`

适用场景：

* 控制平面先验校验配置，再决定是否落盘。

## 插件扩展 API

### 统一格式

```
/api/plugins/<plugin_tag>/<route>
```

说明：

* 也有少量插件会把主资源绑定到前缀路由下，例如 `query_recorder` 的 `/api/plugins/<tag>/records/<id>`。

### cache

#### `GET /api/plugins/<cache_tag>/flush`

清空缓存。

### provider

#### `POST /api/plugins/<provider_tag>/reload`

作用：

* 使用 provider 启动时的同一份配置，定向刷新该 provider 的内部数据快照。
* 不会重建其它插件，也不会修改 provider tag、依赖关系或配置拓扑。

返回：

* `200 OK`
  * provider 已成功 reload。
* `400 Bad Request`
  * provider 不存在、不是运行中的 provider，或 reload 过程中返回错误。

适用场景：

* 规则文件下载完成后，只刷新受影响的 `domain_set`、`ip_set`、`geosite`、`geoip`、`adguard_rule` provider。
* 需要避免应用级全量 `POST /api/reload` 对其它插件造成重建影响。

注意：

* 如果变更涉及 `config.yaml`、provider 依赖拓扑、插件列表或其它非 provider 结构，仍然需要使用 `POST /api/reload`。

#### `GET /api/plugins/<cache_tag>/dump`

导出缓存 dump。

#### `POST /api/plugins/<cache_tag>/load_dump`

导入缓存 dump。

### reverse\_lookup

#### `GET /api/plugins/<tag>?ip=<ip_addr>`

按 IP 查询缓存中的域名。

示例：

```
GET /api/plugins/reverse_lookup_main?ip=8.8.8.8
```

返回：

* 命中：域名文本，通常为 fully-qualified domain name。
* 未命中：空响应体。
* 参数错误：`400 Bad Request`。

### query\_recorder

#### `GET /api/plugins/<tag>/records`

按 `created_at_ms` 倒序返回 recorder 主表中的记录列表，不包含 `steps`。

查询参数：

* `cursor=<created_at_ms>:<id>`
  * 用于继续向后翻页。
* `limit=<n>`
  * 默认 `100`，最大 `500`。
* `since_ms=<unix_ms>`
  * 仅返回大于等于该时间的记录。
* `until_ms=<unix_ms>`
  * 仅返回小于等于该时间的记录。

返回：

* `200 OK`
  * JSON，形如：

```json
{
  "ok": true,
  "next_cursor": "1713510000123:42",
  "records": [
    {
      "id": 42,
      "created_at_ms": 1713510000123,
      "elapsed_ms": 12,
      "request_id": 1234,
      "client_ip": "192.0.2.10",
      "questions_json": [
        { "name": "www.example.com.", "qtype": "A", "qclass": "IN" }
      ],
      "req_rd": true,
      "req_cd": false,
      "req_ad": false,
      "req_opcode": "Query",
      "req_edns_json": null,
      "error": null,
      "has_response": true,
      "rcode": "NoError",
      "resp_aa": false,
      "resp_tc": false,
      "resp_ra": true,
      "resp_ad": false,
      "resp_cd": false,
      "answer_count": 1,
      "authority_count": 0,
      "additional_count": 0,
      "answers_json": [
        {
          "name": "www.example.com.",
          "class": "IN",
          "ttl": 300,
          "rr_type": "A",
          "payload_kind": "A",
          "payload_text": "192.0.2.1",
          "payload": { "ip": "192.0.2.1" }
        }
      ],
      "authorities_json": [],
      "additionals_json": [],
      "signature_json": [],
      "resp_edns_json": null
    }
  ]
}
```

#### `GET /api/plugins/<tag>/records/<id>`

返回单条完整记录，并附带 `steps` 路径事件数组。

返回：

* `200 OK`
  * JSON，包含 `record` 对象；其中 `record.record` 为主表字段，`record.steps` 为路径事件。
* `404 Not Found`
  * 记录不存在。

#### `GET /api/plugins/<tag>/stats/overview`

返回 recorder 概览统计。

查询参数：

* `since_ms=<unix_ms>`
* `until_ms=<unix_ms>`

返回字段：

* `query_total`
* `error_total`
* `dropped_total`
* `avg_elapsed_ms`

#### `GET /api/plugins/<tag>/stats/plugins`

按路径事件聚合插件命中情况。

查询参数：

* `since_ms=<unix_ms>`
* `until_ms=<unix_ms>`
* `kind=matcher|executor|builtin|all`

返回字段：

* `kind`
* `tag`
* `evaluated`
* `matched`
* `executed`
* `query_total`
* `query_share`

#### `GET /api/plugins/<tag>/stream`

通过 SSE 推送新写入的完整记录。

查询参数：

* `tail=<n>`
  * 先回放最近 `n` 条内存 tail，再持续推送新记录。

说明：

* `event: record` 的 `data` 为完整 `RecordDetail` JSON。
* 会定期发送 heartbeat 注释帧以保持长连接。

## Prometheus 指标

### `GET /api/metrics`

当 API 启用时会注册该接口。该接口是唯一的 Prometheus 文本入口；插件不会额外暴露独立的 stats/metrics HTTP 接口。

当前导出的指标包括：

* `query_total`
* `query_error_total`
* `query_inflight`
* `query_latency_count`
* `query_latency_sum_ms`
* `cache_lookup_total`
* `cache_hit_total`
* `cache_miss_total`
* `cache_expired_total`
* `cache_insert_total`
* `cache_skip_total`
* `cache_lazy_refresh_total`
* `cache_entry_count`
* `forward_query_total`
* `forward_success_total`
* `forward_error_total`
* `forward_timeout_total`
* `forward_latency_count`
* `forward_latency_sum_ms`
* `forward_upstream_query_total`
* `forward_upstream_success_total`
* `forward_upstream_error_total`
* `forward_upstream_timeout_total`
* `forward_upstream_latency_count`
* `forward_upstream_latency_sum_ms`
* `fallback_primary_total`
* `fallback_primary_error_total`
* `fallback_secondary_total`
* `blackhole_block_total`
* `hosts_hit_total`
* `hosts_miss_total`
* `ratelimit_allowed_total`
* `ratelimit_rejected_total`
* `server_request_total`
* `server_completed_total`
* `server_controlled_total`
* `server_failed_total`
* `server_inflight`
* `server_latency_count`
* `server_latency_sum_ms`
* `ipset_entries_total`
* `ipset_dropped_total`
* `ipset_write_total`
* `ipset_write_error_total`
* `nftset_entries_total`
* `nftset_dropped_total`
* `nftset_write_total`
* `nftset_write_error_total`
* `ros_address_list_observe_total`
* `ros_address_list_dropped_total`
* `ros_address_list_sync_error_total`
* `ros_address_list_sync_timeout_total`
* `reverse_lookup_ptr_hit_total`
* `reverse_lookup_ptr_miss_total`
* `reverse_lookup_cache_insert_total`
* `reverse_lookup_cache_entries`
* `download_success_total`
* `download_failure_total`
* `download_timeout_total`
* `http_request_dispatch_total`
* `http_request_error_total`
* `http_request_dropped_total`
* `script_run_total`
* `script_success_total`
* `script_error_total`
* `script_timeout_total`
* `reload_trigger_total`
* `reload_error_total`
* `reload_provider_reload_total`
* `reload_provider_reload_error_total`
* `cron_job_run_total`
* `cron_job_skipped_total`
* `cron_executor_error_total`

这些指标带有低基数插件级标签，例如 `plugin_tag`、`name`、`kind`、`reason`、`result`、`protocol`。`server_*` 额外带有 `protocol`（`udp`/`tcp`/`dot`/`quic`/`doh`）标签。`forward_upstream_*` 带有 `upstream` 标签，其取值为上游 tag（未配置时为解析后的地址）；由于上游集合在启动时固定且数量有限，属于低基数维度。域名、客户端 IP 等高基数字段不会进入通用指标层；需要逐条查询明细时请使用 `query_recorder`。

## 配置参考

### 最小可用管理面

```yaml
api:
  http: "127.0.0.1:9088"
```

适用场景：

* 本机运维
* 进程自检
* 指标抓取

### 受保护控制面

```yaml
api:
  http:
    listen: "0.0.0.0:9443"
    ssl:
      cert: "/etc/oxidns/api.crt"
      key: "/etc/oxidns/api.key"
    auth:
      type: basic
      username: "admin"
      password: "secret"
```

适用场景：

* 远程控制
* 与上层运维平台集成

### 双向认证控制面

```yaml
api:
  http:
    listen: "0.0.0.0:9443"
    ssl:
      cert: "/etc/oxidns/api.crt"
      key: "/etc/oxidns/api.key"
      client_ca: "/etc/oxidns/client-ca.crt"
      require_client_cert: true
```

适用场景：

* 严格受控的自动化系统
* 多租户或高敏感运维环境
