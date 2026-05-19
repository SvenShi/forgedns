---
title: WebUI Deployment
sidebar_position: 5
---

The OxiDNS WebUI is a separately built static frontend. It is not compiled into the Rust backend binary. There are two recommended deployment modes:

- Backend-hosted WebUI: the OxiDNS management HTTP service serves the WebUI static directory directly. This is the simplest path for bare-metal hosts, NAS boxes, and small servers without nginx.
- Standalone nginx deployment: nginx serves the WebUI static files and reverse-proxies `/api/*` to the OxiDNS backend. This is better for environments that already use a domain, HTTPS, a gateway, or a shared service entry point.

In both modes, the WebUI defaults to the relative backend URL `/api`. When the WebUI page and `/api/*` share the same browser origin, no CORS setup is needed.

## Use The WebUI Included In Release Packages

Official release archives include a prebuilt `webui/` directory:

```text
oxidns
config.yaml
LICENSE
webui/
```

When OxiDNS runs from the extracted release directory, the default `webui.root: "./webui"` config works directly. Docker images also place the same WebUI static files under `/etc/oxidns/webui`.

Manual WebUI builds are only needed when building from source, developing the WebUI, or publishing static files separately through nginx or caddy.

## Build The WebUI Manually

The WebUI lives in the repository's `webui/` directory. Production builds are exported to `webui/out`:

```bash
cd webui
pnpm install --frozen-lockfile
pnpm build
```

After building, publish `out/` to a server directory, for example:

```bash
sudo mkdir -p /etc/oxidns/webui
sudo rsync -a --delete out/ /etc/oxidns/webui/
```

The examples below use `/etc/oxidns/webui` as the static directory.

## Mode 1: Backend-Hosted WebUI

This mode only needs the OxiDNS management HTTP port. The WebUI is mounted at `/`, and the management API is mounted under `/api/*`.

```yaml
api:
  http:
    listen: "0.0.0.0:9199"
    auth:
      type: basic
      username: "admin"
      password: "secret"
    webui:
      root: "/etc/oxidns/webui"
      index: "index.html"
```

Then open:

```text
http://server-ip:9199/
```

The WebUI calls same-origin endpoints such as `/api/health`, `/api/config`, and `/api/plugins/...`. Static files are not protected by Basic Auth; all `/api/*` requests still use the management API authentication, CORS, and TLS rules.

Field notes:

- `api.http.webui.root`
  - WebUI static file directory. This requires the expanded `api.http` form.
  - The shorthand `api.http: "ip:port"` only configures the listen address and cannot mount WebUI files.
- `api.http.webui.index`
  - Index file name. Defaults to `index.html`.
  - `/`, directory paths, and unmatched frontend deep links fall back to this file.

Static serving behavior:

- `/api` and `/api/*` always go to the management API and never fall back to the WebUI.
- Non-API `GET`/`HEAD` requests look up static files.
- Unmatched non-API paths return `index.html`, so refreshing frontend routes such as `/settings` works.
- The backend rejects path traversal attempts such as `..`, absolute paths, and invalid percent-decoded paths.

## Mode 2: Standalone nginx Deployment

In this mode, OxiDNS listens only on a local management API address, and nginx exposes the WebUI plus `/api` proxy externally.

OxiDNS can use a simple API-only config:

```yaml
api:
  http:
    listen: "127.0.0.1:9199"
    auth:
      type: basic
      username: "admin"
      password: "secret"
```

nginx example:

```nginx
server {
    listen 80;
    server_name oxidns.example.com;

    root /etc/oxidns/webui;
    index index.html;

    location = /api {
        proxy_pass http://127.0.0.1:9199;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:9199;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

Here `proxy_pass http://127.0.0.1:9199;` forwards browser requests such as `/api/health` to the backend unchanged. Do not use a form that strips the `/api` prefix. The OxiDNS backend only accepts API routes under `/api/*`.

If nginx terminates HTTPS, add `listen 443 ssl`, certificates, and the HTTP-to-HTTPS redirect in nginx. The OxiDNS backend can keep listening on plain `127.0.0.1:9199` because it is not exposed publicly.

## WebUI Backend URL

Keep the WebUI backend URL at the default value:

```text
/api
```

This works for:

- Backend-hosted WebUI.
- nginx, caddy, or another gateway proxying `/api/*` to OxiDNS.
- Docker Compose setups with a single entry container for WebUI and API.

Only use an absolute URL for development or temporary debugging, for example:

```text
http://192.168.1.10:9199/api
```

Absolute URLs trigger browser CORS rules, so the backend must allow the WebUI origin. The default CORS inference is:

- `listen: "0.0.0.0:9199"` or `listen: "[::]:9199"` allows any origin.
- Listening on a specific IP allows any WebUI port on the same host.
- When `api.http.cors.allowed_origins` is configured explicitly, entries are matched exactly against the browser `Origin`.

## Use The Online Console With A Local Service

You can also open `https://console.oxidns.org` and set the backend URL in the WebUI settings page to the OxiDNS management API on your machine or LAN:

```text
http://127.0.0.1:9199/api
```

If the browser and OxiDNS are not on the same machine, use the reachable address instead, for example:

```text
http://192.168.1.10:9199/api
```

This is not the recommended deployment mode. The online Console page and the local API are different origins, so the browser enforces CORS; the management API must also be reachable from the browser. Prefer backend-hosted WebUI or an nginx/caddy reverse proxy so the WebUI and `/api/*` stay same-origin.

If you still need the online Console for temporary use, explicitly allow the Console origin:

```yaml
api:
  http:
    listen: "127.0.0.1:9199"
    cors:
      allowed_origins:
        - "https://console.oxidns.org"
```

When accessing the OxiDNS management API from another device, also change `listen` to a LAN IP or `0.0.0.0:9199`, and restrict access with a firewall, reverse-proxy authentication, or network policy. Do not expose an unprotected management API directly to the public internet.

## Common Checks

- Opening `http://server:9199/` or the nginx domain shows the WebUI.
- Browser Network shows `/api/health` returning `200`, not a static file.
- If Basic Auth is enabled, configure the same username and password in the WebUI settings page.
- If refreshing `/settings` or `/plugins` returns 404, the static server is missing the `index.html` fallback. For nginx, check `try_files $uri $uri/ /index.html;`.
- If `/api/health` returns 404 through nginx, check whether `proxy_pass` accidentally strips the `/api` prefix.
