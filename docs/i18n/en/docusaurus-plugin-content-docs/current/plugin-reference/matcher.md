---
title: Matcher Plugins
sidebar_position: 4
---

Matchers provide branching conditions for `sequence`.

## Basic Matchers

### `_true`

Always matches.

### `_false`

Never matches.

## Query Matchers

### `qname`

Matches the query name.

### `qtype`

Matches the DNS record type.

### `qclass`

Matches the DNS class.

## Network Matchers

### `client_ip`

Matches the source client IP.

### `resp_ip`

Matches IPs present in the response.

### `ptr_ip`

Matches reverse lookup style IP-derived names.

## Response-State Matchers

### `rcode`

Matches the response code.

### `has_resp`

Checks whether a response has already been produced.

### `has_wanted_ans`

Checks whether the current response contains the desired answer shape.

## Metadata Matchers

### `cname`

Matches canonical name chains.

### `mark`

Matches internal policy marks.

### `env`

Matches environment variables.

### `random`

Supports sampling, rollout, or probabilistic branches.

### `rate_limiter`

Matches limiter state.

### `string_exp`

Evaluates string expressions against request metadata and variables.

## Guidance

- Keep individual matcher expressions readable.
- Move large domain/IP datasets into providers.
- Use `sequence` ordering to keep fast positive or negative paths near the top.

