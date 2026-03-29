---
title: Provider Plugins
sidebar_position: 5
---

Providers turn rule sets from one-off literals into reusable data assets. In larger configurations they reduce duplication, centralize shared datasets, and keep policies maintainable.

---

## `domain_set`

### Purpose

Provides a high-performance domain rule set that can be referenced by plugins such as `qname` and `cname`.

### Parameters

```yaml
- tag: core_domains
  type: domain_set
  args:
    exps:
      - "domain:example.com"
      - "keyword:cdn"
      - "regexp:^api[0-9]+\\.example\\.net$"
    files:
      - "/etc/forgedns/domains.txt"
    sets:
      - "shared_domains"
```

- `exps`
  - Inline domain expressions.
- `files`
  - External rule files.
- `sets`
  - References to other `domain_set` providers.

### Configuration Details

#### `exps`

- Type: `array`; Required: no; Default: empty array
- Purpose: Defines inline domain expressions.
- Examples:
  - `- "full:example.com"`
  - `- "domain:example.com"`
  - `- "keyword:cdn"`
- Supported forms:
  - `full:`
  - `domain:`
  - `keyword:`
  - `regexp:`
  - Bare domains without a prefix
- Runtime impact:
  - Compiled into directly matchable rules during initialization.

#### `files`

- Type: `array`; Required: no; Default: empty array
- Purpose: Lists external rule files.
- Example: `- "/etc/forgedns/domains.txt"`
- File requirements:
  - One rule per line.
  - Empty lines and comment lines are ignored.
- Runtime impact:
  - File contents are loaded during initialization and merged into the current provider.

#### `sets`

- Type: `array`; Required: no; Default: empty array
- Purpose: References other `domain_set` instances.
- Example: `- "shared_domain_set"`
- Constraints:
  - Only `domain_set` providers can be referenced.
- Runtime impact:
  - Referenced sets are flattened during initialization and merged into the current provider.

### Behavior

- `exps`, `files`, and referenced `sets` are flattened at initialization time.
- No recursive provider calls happen on the hot path; runtime matching uses precompiled match structures.

### Supported Rule Formats

- `full:example.com`
- `domain:example.com`
- `keyword:cdn`
- `regexp:^api\\.example\\.com$`
- `example.com`

### Typical Uses

- Share a core domain list across multiple policies.
- Aggregate rules from several files into one reusable provider.

### Notes

- `sets` may only reference other `domain_set` providers.

---

## `ip_set`

### Purpose

Provides IP and CIDR rule sets that can be referenced by matchers such as `client_ip`, `resp_ip`, and `ptr_ip`.

### Parameters

```yaml
- tag: lan_ip_set
  type: ip_set
  args:
    ips:
      - "192.168.0.0/16"
      - "10.0.0.0/8"
      - "fd00::/8"
    files:
      - "/etc/forgedns/ips.txt"
    sets:
      - "shared_ip_set"
```

- `ips`
  - Inline IP or CIDR entries.
- `files`
  - External rule files.
- `sets`
  - References to other `ip_set` providers.

### Configuration Details

#### `ips`

- Type: `array`; Required: no; Default: empty array
- Purpose: Defines inline IP or CIDR rules.
- Examples:
  - `- "1.1.1.1"`
  - `- "192.168.0.0/16"`
  - `- "2400:3200::/32"`
- Supported forms:
  - Individual IPv4 addresses
  - Individual IPv6 addresses
  - IPv4 CIDRs
  - IPv6 CIDRs
- Runtime impact:
  - Compiled into address matching structures during initialization.

#### `files`

- Type: `array`; Required: no; Default: empty array
- Purpose: Lists external IP rule files.
- Example: `- "/etc/forgedns/ips.txt"`
- File requirements:
  - One IP or CIDR rule per line.
  - Empty lines and comment lines are ignored.
- Runtime impact:
  - File contents are loaded during initialization and merged into the current provider.

#### `sets`

- Type: `array`; Required: no; Default: empty array
- Purpose: References other `ip_set` instances.
- Example: `- "shared_ip_set"`
- Constraints:
  - Only `ip_set` providers can be referenced.
- Runtime impact:
  - Referenced sets are flattened during initialization and merged into the current provider by address family.

### Behavior

- All sources are loaded and flattened during initialization.
- IPv4 and IPv6 rule indexes are maintained separately.
- Runtime matching filters quickly by address family.

### Rule Formats

- `1.1.1.1`
- `192.168.0.0/16`
- `2400:3200::/32`

### Typical Uses

- Define LAN, WAN, overlay, or infrastructure address groups.
- Build allowlists, bypass lists, or target network sets.

### Notes

- `sets` may only reference other `ip_set` providers.
