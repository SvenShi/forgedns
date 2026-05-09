---
title: WebUI 部署
sidebar_position: 5
---

OxiDNS WebUI 是独立构建的前端静态产物，不会编译进 Rust 后端二进制。部署时有两种推荐方式：

- 后端同端口托管：由 OxiDNS 管理 HTTP 服务直接托管 WebUI 静态目录，适合裸机、NAS、小型服务器等不想额外配置 nginx 的环境。
- nginx 独立部署：nginx 服务 WebUI 静态文件，并把 `/api/*` 反向代理到 OxiDNS 后端，适合已有域名、HTTPS、网关或多服务统一入口的环境。

无论哪种方式，WebUI 默认使用相对后端地址 `/api`。只要 WebUI 页面和 `/api/*` 位于同一个站点 origin 下，浏览器就不需要跨域配置。

## 使用 Release 包内置 WebUI

官方 release 压缩包会包含已经构建好的 `webui/` 目录：

```text
oxidns
config.yaml
LICENSE
webui/
```

如果直接在解压目录运行 OxiDNS，默认配置中的 `webui.root: "./webui"` 就可以直接使用。Docker 镜像也会把同一份 WebUI 静态文件放到 `/etc/oxidns/webui`。

只有从源码构建、二次开发 WebUI，或需要自行发布静态文件到 nginx/caddy 时，才需要手动构建 WebUI。

## 手动构建 WebUI

WebUI 位于仓库的 `webui/` 目录。生产构建输出为静态目录 `webui/out`：

```bash
cd webui
pnpm install --frozen-lockfile
pnpm build
```

构建完成后，将 `out/` 目录发布到服务器上的某个目录，例如：

```bash
sudo mkdir -p /opt/oxidns/webui
sudo rsync -a --delete out/ /opt/oxidns/webui/
```

后续文档都以 `/opt/oxidns/webui` 作为示例静态目录。

## 方式一：后端同端口托管

这种方式只需要 OxiDNS 自己启动一个管理 HTTP 端口。WebUI 挂载在 `/`，管理 API 统一挂载在 `/api/*`。

```yaml
api:
  http:
    listen: "0.0.0.0:9199"
    auth:
      type: basic
      username: "admin"
      password: "secret"
    webui:
      root: "/opt/oxidns/webui"
      index: "index.html"
```

启用后访问：

```text
http://服务器IP:9199/
```

WebUI 会请求同源的 `/api/health`、`/api/config`、`/api/plugins/...` 等接口。静态文件本身不受 Basic Auth 保护；所有 `/api/*` 请求仍按管理 API 的认证、CORS、TLS 规则处理。

字段说明：

- `api.http.webui.root`
  - WebUI 静态文件目录，必须使用 `api.http` 详写形式配置。
  - `api.http: "ip:port"` 简写只表示监听地址，不能挂载 WebUI。
- `api.http.webui.index`
  - 首页文件名，默认 `index.html`。
  - `/`、目录路径、以及前端路由深链未命中时都会回退到这个文件。

静态服务行为：

- `/api` 和 `/api/*` 永远进入管理 API，不会回退到 WebUI。
- 非 `/api` 的 `GET`/`HEAD` 请求会查找静态文件。
- 未命中的非 `/api` 路径会返回 `index.html`，因此刷新 `/settings` 这类前端路由可以正常工作。
- 后端会拒绝 `..`、绝对路径、非法 percent decode 等路径穿越请求。

## 方式二：nginx 独立部署

这种方式中，OxiDNS 只在本机监听管理 API，nginx 对外提供 WebUI 和 `/api` 反代。

OxiDNS 配置可以保持简单：

```yaml
api:
  http:
    listen: "127.0.0.1:9199"
    auth:
      type: basic
      username: "admin"
      password: "secret"
```

nginx 示例：

```nginx
server {
    listen 80;
    server_name oxidns.example.com;

    root /opt/oxidns/webui;
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

这里 `proxy_pass http://127.0.0.1:9199;` 会把浏览器请求的 `/api/health` 原样转发给后端，因此不要把它写成会剥离 `/api` 前缀的形式。OxiDNS 后端只接受 `/api/*` API 路由。

如果 nginx 负责 HTTPS，只需要把 `listen 443 ssl`、证书和 80 到 443 跳转加在 nginx 上即可；OxiDNS 后端仍可只监听 `127.0.0.1:9199` 明文端口，因为它不直接暴露到公网。

## WebUI 后端地址

WebUI 设置页里的后端地址推荐保持默认：

```text
/api
```

适用场景：

- 后端同端口托管 WebUI。
- nginx/caddy/网关把 `/api/*` 反代到 OxiDNS。
- Docker Compose 中通过统一入口容器暴露 WebUI 和 API。

只有在开发环境或临时调试时，才需要填写绝对地址，例如：

```text
http://192.168.1.10:9199/api
```

使用绝对地址时浏览器会进入跨域访问，需要后端 CORS 允许该 WebUI origin。默认 CORS 推导规则如下：

- `listen: "0.0.0.0:9199"` 或 `listen: "[::]:9199"` 会允许任意 origin。
- 监听具体 IP 时，会允许同一 host 的任意 WebUI 端口。
- 显式配置 `api.http.cors.allowed_origins` 后，按浏览器 `Origin` 精确匹配。

## 常见检查

- 打开 `http://服务器:9199/` 或 nginx 域名能看到 WebUI。
- 浏览器 Network 中 `/api/health` 返回 `200`，而不是请求到静态文件。
- 如果启用了 Basic Auth，WebUI 设置页中需要填写对应用户名和密码。
- 如果刷新 `/settings`、`/plugins` 后出现 404，说明静态服务缺少 `index.html` fallback；nginx 部署时确认 `try_files $uri $uri/ /index.html;` 已配置。
- 如果 nginx 反代后 `/api/health` 返回 404，检查 `proxy_pass` 是否错误剥离了 `/api` 前缀。
