---
title: 管理 API
sidebar_position: 4
---

ForgeDNS 的管理 API 是独立控制平面，负责：

* 进程与启动健康检查
* 配置检查与配置文本校验
* 重载与关闭控制
* 插件扩展 API
* Prometheus 指标导出

本章介绍当前提供的管理 API。

## 启用方式

### 简写

```yaml
api:
  http: "127.0.0.1:9088"
```

### 详写

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
curl -u admin:secret http://127.0.0.1:9088/healthz
```

或：

```bash
curl -H 'Authorization: Basic YWRtaW46c2VjcmV0' \
  http://127.0.0.1:9088/healthz
```

## 路由组织

API 路由分成三类：

* 全局路由
  * 例如 `/healthz`、`/control`
* 插件路由
  * 统一格式：`/plugins/<plugin_tag>/<subpath>`
* 观测路由
  * 例如 `/metrics`

## 内置健康检查接口

### `GET /healthz`

作用：

* 只检查 API 监听是否已建立。

返回：

* `200 OK`：`ok`
* `503 Service Unavailable`：`not_listening`

### `GET /readyz`

作用：

* 检查插件初始化和 server 启动是否已完成。

返回：

* `200 OK`：`ready`
* `503 Service Unavailable`：`not_ready`

### `GET /health`

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

### `GET /control`

作用：

* 返回当前进程控制面状态。

返回内容包括：

* 运行状态
* 运行时长
* 当前配置路径
* 是否请求过 shutdown
* reload 状态快照

### `POST /shutdown`

作用：

* 请求优雅关闭。

返回：

* `202 Accepted`

### `POST /reload`

作用：

* 请求重载配置，重新加载所有插件。

返回：

* `202 Accepted`
  * 已受理。
* `409 Conflict`
  * 已有 reload 在 pending / in\_progress。

### `GET /reload/status`

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

### `GET /config/check`

作用：

* 校验当前配置文件路径对应的配置文件。

适用场景：

* 检查磁盘上现有配置是否能成功解析与通过插件依赖校验。

### `POST /config/validate`

作用：

* 直接校验请求体中的 YAML 配置文本。

请求体要求：

* UTF-8 文本
* 非空

适用场景：

* 控制平面先验校验配置，再决定是否落盘。

## 插件扩展 API

### 统一格式

```
/plugins/<plugin_tag>/<route>
```

### cache

#### `GET /plugins/<cache_tag>/flush`

清空缓存。

### provider

#### `POST /plugins/<provider_tag>/reload`

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
* 需要避免应用级全量 `POST /reload` 对其它插件造成重建影响。

注意：

* 如果变更涉及 `config.yaml`、provider 依赖拓扑、插件列表或其它非 provider 结构，仍然需要使用 `POST /reload`。

#### `GET /plugins/<cache_tag>/dump`

导出缓存 dump。

#### `POST /plugins/<cache_tag>/load_dump`

导入缓存 dump。

### reverse\_lookup

#### `GET /plugins/<tag>?ip=<ip_addr>`

按 IP 查询缓存中的域名。

示例：

```
GET /plugins/reverse_lookup_main?ip=8.8.8.8
```

返回：

* 命中：域名文本，通常为 fully-qualified domain name。
* 未命中：空响应体。
* 参数错误：`400 Bad Request`。

## Prometheus 指标

### `GET /metrics`

当配置了至少一个 `metrics_collector` 且 API 已启用时，会注册该接口。

当前导出的指标包括：

* `forgedns_query_total`
* `forgedns_query_error_total`
* `forgedns_query_inflight`
* `forgedns_query_latency_count`
* `forgedns_query_latency_sum_ms`

这些指标带有插件级标签信息，可用于区分不同流水线观测点。

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
      cert: "/etc/forgedns/api.crt"
      key: "/etc/forgedns/api.key"
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
      cert: "/etc/forgedns/api.crt"
      key: "/etc/forgedns/api.key"
      client_ca: "/etc/forgedns/client-ca.crt"
      require_client_cert: true
```

适用场景：

* 严格受控的自动化系统
* 多租户或高敏感运维环境
