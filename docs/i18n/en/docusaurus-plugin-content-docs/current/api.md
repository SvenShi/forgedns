---
title: Management API
sidebar_position: 4
---

ForgeDNS exposes a built-in management API for runtime status, health checks, reload operations, and config validation.

## Listener Forms

Shorthand:

```yaml
api:
  http: "127.0.0.1:9088"
```

Expanded:

```yaml
api:
  http:
    listen: "127.0.0.1:9443"
    ssl:
      cert: "/etc/forgedns/api.crt"
      key: "/etc/forgedns/api.key"
    auth:
      type: basic
      username: admin
      password: secret
```

## Authentication

ForgeDNS currently supports Basic Auth.

```http
Authorization: Basic base64(username:password)
```

When TLS is enabled, you can additionally require client certificates.

## Core Endpoints

### `GET /health`

Simple liveness endpoint.

### `GET /healthz`

Extended health endpoint for service discovery, probes, and dashboards.

### `GET /readyz`

Readiness check for orchestrated deployments.

### `GET /control`

Returns current process control state, including:

- Running state
- Uptime
- Active config path
- Whether shutdown was requested
- Reload snapshots

### `POST /shutdown`

Requests graceful shutdown.

Typical response:

```json
{
  "status": "accepted"
}
```

### `POST /reload`

Reloads the active configuration and reinitializes plugin wiring.

### `GET /reload/status`

Returns recent reload results and the latest status snapshot.

### `GET /config/check`

Checks the current or provided config for parse and validation errors.

### `POST /config/validate`

Validates posted configuration content before rollout.

## Plugin HTTP APIs

Some plugins expose their own management routes. These routes live under the same management server and are intended for diagnostics or operator tooling.

Examples:

- `cache`
- `reverse_lookup`
- Prometheus metrics exporters

## Operational Notes

- Bind the API to loopback or a dedicated management network.
- Put TLS and Basic Auth in front of all non-local deployments.
- Use `reload` for routine policy updates instead of process restarts.
- Use `config/check` or `config/validate` in CI/CD before shipping changes.

