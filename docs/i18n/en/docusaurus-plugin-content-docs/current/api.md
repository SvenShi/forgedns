---
title: Management API
sidebar_position: 4
---

ForgeDNS exposes a standalone control plane for:

* Process and startup health checks
* Config checks and raw config text validation
* Reload and shutdown control
* Plugin extension APIs
* Prometheus metrics export

This chapter documents the current management API surface.

## How to Enable It

### Shorthand

```yaml
api:
  http: "127.0.0.1:9088"
```

### Expanded Form

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

## Authentication and Transport

### TLS

When both `ssl.cert` and `ssl.key` are configured, the API is served over HTTPS.

Optional hardening:

* `client_ca`
  * Configures the client CA.
* `require_client_cert`
  * Enforces mutual TLS.

### Basic Auth

```yaml
auth:
  type: basic
  username: "admin"
  password: "secret"
```

When enabled, all API requests require Basic Auth.

The request header looks like this:

```http
Authorization: Basic YWRtaW46c2VjcmV0
```

Encoding rules:

* Concatenate the raw string as `username:password`
* Base64-encode the whole string
* Prefix the header value with `Basic `

In the example above, the Base64 value for `admin:secret` is `YWRtaW46c2VjcmV0`.

Notes:

* This uses standard Base64, not URL-safe Base64.
* Do not encode `username` and `password` separately.
* Do not percent-encode or URL-encode first.
* The server compares the fully decoded value directly against `username:password`.

Examples:

```bash
curl -u admin:secret http://127.0.0.1:9088/healthz
```

Or:

```bash
curl -H 'Authorization: Basic YWRtaW46c2VjcmV0' \
  http://127.0.0.1:9088/healthz
```

## Route Layout

API routes fall into three groups:

* Global routes
  * For example `/healthz` and `/control`
* Plugin routes
  * Uniform format: `/plugins/<plugin_tag>/<subpath>`
* Observability routes
  * For example `/metrics`

## Built-In Health Endpoints

### `GET /healthz`

Purpose:

* Checks only whether the API listener has been established.

Responses:

* `200 OK`: `ok`
* `503 Service Unavailable`: `not_listening`

### `GET /readyz`

Purpose:

* Checks whether plugin initialization and server startup are complete.

Responses:

* `200 OK`: `ready`
* `503 Service Unavailable`: `not_ready`

### `GET /health`

Purpose:

* Returns JSON health details.

Example shape:

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

## Built-In Control Endpoints

### `GET /control`

Purpose:

* Returns the current process control-plane state.

The payload includes:

* Running state
* Uptime
* Active config path
* Whether shutdown has been requested
* Reload status snapshots

### `POST /shutdown`

Purpose:

* Requests graceful shutdown.

Response:

* `202 Accepted`

### `POST /reload`

Purpose:

* Requests a config reload and reinitializes all plugins.

Responses:

* `202 Accepted`
  * The request has been accepted.
* `409 Conflict`
  * A reload is already `pending` or `in_progress`.

### `GET /reload/status`

Purpose:

* Returns the status of the most recent reload attempt.

Fields include:

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

## Config Check Endpoints

### `GET /config/check`

Purpose:

* Validates the config file at the current config path.

Good fit:

* Check whether the on-disk config parses correctly and passes plugin dependency validation.

### `POST /config/validate`

Purpose:

* Validates YAML config text sent directly in the request body.

Request body requirements:

* UTF-8 text
* Non-empty

Good fit:

* Validate a config in the control plane before writing it to disk.

## Plugin Extension APIs

### Unified Format

```
/plugins/<plugin_tag>/<route>
```

Notes:

* A few plugins also expose prefix routes. For example, `query_recorder` uses `/plugins/<tag>/records/<id>`.

### cache

#### `GET /plugins/<cache_tag>/flush`

Clears the cache.

### provider

#### `POST /plugins/<provider_tag>/reload`

Purpose:

* Reloads that provider's internal snapshot with the same configuration it used at startup.
* Does not rebuild unrelated plugins and does not change provider tags, dependency topology, or config structure.

Responses:

* `200 OK`
  * The provider reload succeeded.
* `400 Bad Request`
  * The provider does not exist, is not a live provider, or returned an error while reloading.

Good fit:

* Refreshing only the affected `domain_set`, `ip_set`, `geosite`, `geoip`, or `adguard_rule` provider after downloading new rule files.
* Avoiding the blast radius of an application-wide `POST /reload`.

Notes:

* If the change also updates `config.yaml`, provider topology, the plugin list, or other non-provider structures, you still need `POST /reload`.

#### `GET /plugins/<cache_tag>/dump`

Exports a cache dump.

#### `POST /plugins/<cache_tag>/load_dump`

Imports a cache dump.

### reverse_lookup

#### `GET /plugins/<tag>?ip=<ip_addr>`

Looks up the domain cached for an IP address.

Example:

```
GET /plugins/reverse_lookup_main?ip=8.8.8.8
```

Responses:

* Hit: domain text, usually a fully-qualified domain name
* Miss: empty response body
* Invalid parameter: `400 Bad Request`

### query_recorder

#### `GET /plugins/<tag>/records`

Returns recorder rows ordered by `created_at_ms` descending and does not include `steps`.

Query parameters:

* `cursor=<created_at_ms>:<id>`
  * Continue pagination after the last row from the previous page.
* `limit=<n>`
  * Default `100`, maximum `500`.
* `since_ms=<unix_ms>`
  * Only return rows at or after this timestamp.
* `until_ms=<unix_ms>`
  * Only return rows at or before this timestamp.

Responses:

* `200 OK`
  * JSON shaped like:

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

#### `GET /plugins/<tag>/records/<id>`

Returns one full record plus its `steps` array.

Responses:

* `200 OK`
  * JSON containing a `record` object. `record.record` holds the fixed main-table fields and `record.steps` holds path events.
* `404 Not Found`
  * The record does not exist.

#### `GET /plugins/<tag>/stats/overview`

Returns recorder overview statistics.

Query parameters:

* `since_ms=<unix_ms>`
* `until_ms=<unix_ms>`

Response fields:

* `query_total`
* `error_total`
* `dropped_total`
* `avg_elapsed_ms`

#### `GET /plugins/<tag>/stats/plugins`

Aggregates plugin hit information from recorded path events.

Query parameters:

* `since_ms=<unix_ms>`
* `until_ms=<unix_ms>`
* `kind=matcher|executor|builtin|all`

Response fields:

* `kind`
* `tag`
* `evaluated`
* `matched`
* `executed`
* `query_total`
* `query_share`

#### `GET /plugins/<tag>/stream`

Streams newly written records over SSE.

Query parameters:

* `tail=<n>`
  * Replay the most recent `n` records from the in-memory tail first, then continue streaming.

Notes:

* `event: record` uses the full `RecordDetail` JSON as `data`.
* Heartbeat comment frames are sent periodically to keep the connection alive.

## Prometheus Metrics

### `GET /metrics`

This endpoint is registered when the API is enabled and at least one `metrics_collector` is configured.

Current exported metrics include:

* `forgedns_query_total`
* `forgedns_query_error_total`
* `forgedns_query_inflight`
* `forgedns_query_latency_count`
* `forgedns_query_latency_sum_ms`

These metrics carry plugin-level labels so you can distinguish different observation points in the policy graph.

## Config Reference

### Minimal Management Plane

```yaml
api:
  http: "127.0.0.1:9088"
```

Good fit:

* Local operations
* Process self-checks
* Metrics scraping

### Protected Control Plane

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

Good fit:

* Remote control
* Integration with external operations platforms

### Mutual-TLS Control Plane

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

Good fit:

* Strictly controlled automation systems
* Multi-tenant or high-sensitivity operational environments
