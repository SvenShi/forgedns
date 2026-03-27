---
title: Server Plugins
sidebar_position: 2
---

Server plugins are the ingress layer. They accept traffic and pass it into an executor entrypoint, usually `sequence`.

Common fields:

- `listen`
  - Bind address.
- `entry`
  - Executor entrypoint.
- `ssl` / `tls`
  - Certificate and key settings where applicable.

## `udp_server`

Listens for classic DNS over UDP.

Use when:

- low-latency LAN or gateway deployments matter
- clients are standard stub resolvers

## `tcp_server`

Listens for DNS over TCP.

Use when:

- handling truncated UDP fallbacks
- serving clients or networks that prefer TCP

## `quic_server`

Listens for DNS over QUIC.

Use when:

- you need modern encrypted transport
- you want reduced handshake latency for repeated clients

## `http_server`

Serves HTTP-based DNS APIs such as DoH.

Use when:

- integrating with modern browsers or mobile clients
- exposing DNS through HTTP infrastructure

## Design Notes

- Keep server plugins thin.
- Avoid embedding policy directly in listeners.
- Route real decisions into executors, especially `sequence`.

