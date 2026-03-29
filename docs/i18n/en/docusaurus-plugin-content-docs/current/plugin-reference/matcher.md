---
title: Matcher Plugins
sidebar_position: 4
---

Matcher plugins return `true` or `false`. They are mainly used by `sequence.matches`.

## Matcher Expression Rules

There are two common ways to use matchers inside `sequence`.

Reference an existing matcher:

```yaml
- matches:
    - "$is_lan"
    - "$only_a"
  exec: "$forward_main"
```

Quick setup:

```yaml
- matches:
    - "qname domain:example.com"
    - "qtype A"
  exec: "$forward_main"
```

Negation:

```yaml
- matches: "!$has_resp"
  exec: "$forward_main"
```

---

## `_true` {#true}

### Purpose

Always returns true.

### Parameters

No parameters.

### Configuration Details

No configuration fields.

### Typical Uses

- Fallback match condition.
- Testing rule order in a `sequence`.

---

## `_false` {#false}

### Purpose

Always returns false.

### Parameters

No parameters.

### Configuration Details

No configuration fields.

### Typical Uses

- Temporarily disable a branch.

---

## `qname`

### Purpose

Matches the query name in the request.

### Parameters

```yaml
- tag: match_domain
  type: qname
  args:
    - "domain:example.com"
    - "$core_domains"
    - "&/etc/forgedns/domains.txt"
```

Supports domain expressions, `domain_set` references, and file references.

### Configuration Details

`args` is a rule list.

- Type: `array`; Required: yes; Default: none
- Supported items:
  - domain expressions
  - `domain_set` references
  - file references
- Runtime impact:
  - Returns `true` when any question name matches any configured rule.

### quick setup

```yaml
- matches: "qname domain:example.com"
```

### Typical Uses

- Route by suffix, keyword, or regex.

---

## `qtype`

### Purpose

Matches request qtypes.

### Parameters

```yaml
- tag: only_a_aaaa
  type: qtype
  args: ["A", "AAAA"]
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supports:
  - standard type names such as `A`, `AAAA`, `PTR`
  - numeric values
- Runtime impact:
  - Returns `true` if any question type matches the configured set.

### quick setup

```yaml
- matches: "qtype A"
```

### Typical Uses

- Split A, AAAA, PTR, TXT, and other query classes of traffic.

---

## `qclass`

### Purpose

Matches request qclasses.

### Parameters

```yaml
- tag: only_in
  type: qclass
  args: ["IN"]
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supports standard class names or numeric values.
- Runtime impact:
  - Returns `true` if any question class matches the configured set.

### quick setup

```yaml
- matches: "qclass IN"
```

### Typical Uses

- Restrict handling to `IN` queries.

---

## `client_ip`

### Purpose

Matches the client source IP.

### Parameters

```yaml
- tag: lan_clients
  type: client_ip
  args:
    - "192.168.0.0/16"
    - "$lan_ip_set"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supported items:
  - single IPs
  - CIDRs
  - `ip_set` references
- Runtime impact:
  - Returns `true` when the client source address matches any rule.

### quick setup

```yaml
- matches: "client_ip 192.168.1.0/24"
```

### Typical Uses

- Split policies by source subnet.

---

## `resp_ip`

### Purpose

Matches A and AAAA addresses in the response answers.

### Parameters

```yaml
- tag: target_resp
  type: resp_ip
  args:
    - "10.0.0.0/8"
    - "$target_ip_set"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supported items:
  - single IPs
  - CIDRs
  - `ip_set` references
- Runtime impact:
  - Returns `true` when any A or AAAA answer IP matches any rule.

### quick setup

```yaml
- matches: "resp_ip 1.1.1.1"
```

### Typical Uses

- Trigger side effects based on returned answer addresses.

---

## `ptr_ip`

### Purpose

Matches the IP encoded in a PTR query name.

### Parameters

```yaml
- tag: ptr_lan
  type: ptr_ip
  args:
    - "192.168.0.0/16"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supported items:
  - single IPs
  - CIDRs
  - `ip_set` references
- Runtime impact:
  - Extracts the reverse-mapped IP from the PTR name and matches it against the configured rules.

### quick setup

```yaml
- matches: "ptr_ip 192.168.0.0/16"
```

### Typical Uses

- Separate handling for reverse-lookups of specific address spaces.

---

## `cname`

### Purpose

Matches CNAME targets in the response.

### Parameters

```yaml
- tag: cname_target
  type: cname
  args:
    - "domain:example.com"
    - "$core_domains"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supported items:
  - domain expressions
  - `domain_set` references
  - file references
- Runtime impact:
  - Returns `true` when any CNAME target in the response matches.

### quick setup

```yaml
- matches: "cname domain:example.com"
```

### Typical Uses

- Branch on canonical names returned by upstreams.

---

## `mark`

### Purpose

Matches marks already written into the DNS context.

### Parameters

```yaml
- tag: mark_internal
  type: mark
  args: [100, 200]
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supports integer mark values.
- Runtime impact:
  - Returns `true` if any configured mark exists in the context.

### quick setup

```yaml
- matches: "mark 100"
```

### Typical Uses

- Branch across phases after earlier decisions set marks.

---

## `env`

### Purpose

Matches environment variables.

### Parameters

```yaml
- tag: prod_only
  type: env
  args:
    - "ENV=prod"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Each item is an environment expression.
- Typical forms:
  - `KEY=value`
  - `KEY`
- Runtime impact:
  - Lets one config behave differently across environments without editing the policy graph itself.

### quick setup

```yaml
- matches: "env ENV=prod"
```

### Behavior

- `KEY=value` requires an exact match.
- `KEY` checks only for existence.

### Typical Uses

- Toggle policy branches by deployment environment.

---

## `random`

### Purpose

Matches probabilistically for rollout or sampling.

### Parameters

```yaml
- tag: sample_10
  type: random
  args: 0.1
```

### Configuration Details

- Type: `number`; Required: yes; Default: none
- Meaning: Probability between `0` and `1`.
- Runtime impact:
  - Returns `true` according to the configured sampling ratio.

### quick setup

```yaml
- matches: "random 0.2"
```

### Typical Uses

- Gradual rollout.
- Sampling for observability or experiments.

---

## `rate_limiter`

### Purpose

Matches based on per-source rate-limit state.

### Parameters

```yaml
- tag: rate_ok
  type: rate_limiter
  args:
    qps: 100
    burst: 50
    mask4: 24
    mask6: 64
```

### Configuration Details

#### `qps`

- Type: `integer`; Required: yes
- Meaning: Steady-state queries per second.

#### `burst`

- Type: `integer`; Required: no
- Meaning: Burst allowance above steady-state rate.

#### `mask4`

- Type: `integer`; Required: no
- Meaning: IPv4 aggregation mask for clients.

#### `mask6`

- Type: `integer`; Required: no
- Meaning: IPv6 aggregation mask for clients.

### quick setup

```yaml
- matches: "rate_limiter 100"
```

### Behavior

- Applies rate limiting per source prefix rather than only per exact IP.
- Useful for protecting upstreams or constraining abusive traffic.

### Typical Uses

- Query throttling.
- Split normal traffic and over-limit traffic into different branches.

---

## `rcode`

### Purpose

Matches the current response code.

### Parameters

```yaml
- tag: is_nxdomain
  type: rcode
  args: ["NXDOMAIN"]
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supports standard rcode names or numeric values.
- Runtime impact:
  - Returns `true` when the response rcode matches the configured set.

### quick setup

```yaml
- matches: "rcode NOERROR"
```

### Typical Uses

- Follow-up handling for upstream failures or negative responses.

---

## `has_resp`

### Purpose

Matches whether a response already exists in the context.

### Parameters

No parameters.

### Configuration Details

No configuration fields.

### quick setup

```yaml
- matches: "has_resp"
```

### Typical Uses

- Guard forwarding so it only runs when no earlier plugin has answered.

---

## `has_wanted_ans`

### Purpose

Matches whether the response already contains wanted answers.

### Parameters

No parameters.

### Configuration Details

No configuration fields.

### quick setup

```yaml
- matches: "has_wanted_ans"
```

### Typical Uses

- Build follow-up logic only when a meaningful answer is already present.

---

## `string_exp`

### Purpose

Matches using a string expression over request and response context.

### Parameters

```yaml
- tag: expr_match
  type: string_exp
  args: "has_resp && qname =~ 'example.com'"
```

### Configuration Details

- Type: `string`; Required: yes; Default: none
- Purpose: Defines an expression evaluated against the current DNS context.

### Expression Format

- The exact syntax follows ForgeDNS string-expression support.
- Use it when built-in matchers are not enough or when a compact composite condition is more readable than several nested rules.

### quick setup

```yaml
- matches: "string_exp has_resp"
```

### Typical Uses

- Compact composite predicates.
- Advanced matching without creating several separate helper matchers.

### Notes

- Prefer dedicated matchers when they are already sufficient. `string_exp` is more flexible but also harder to audit at a glance.
