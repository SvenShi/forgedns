---
title: Provider Plugins
sidebar_position: 5
---

Providers turn rule sets from one-off literals into reusable data assets. In larger configurations they reduce duplication, centralize shared datasets, and keep policies maintainable.

Providers with domain or IP match capability can be referenced directly by matchers through `"$tag"` and can also be aggregated by `domain_set` or `ip_set`.

---

## `adguard_rule`

### Purpose

Provides a reusable subset of AdGuard Home DNS rule evaluation as a provider.

This provider exposes two semantics:

- `contains_question`: full request-question evaluation, including `dnstype`
- `contains_name`: a name-only projection that ignores all `dnstype` rules

### Example Configuration

```yaml
- tag: ad_rules
  type: adguard_rule
  args:
    rules:
      # Basic blocking rule
      - "||ads.example.com^"
      # Exception rule
      - "@@||safe.ads.example.com^"
      # Complex inline rule with dnstype / important / denyallow
      - "||cdn.example.com^$dnstype=A|AAAA,important,denyallow=cdn-safe.example.com"
    files:
      # External AdGuard-format rule files
      - "/etc/forgedns/adguard.txt"
```

### Behavior

- Supports: basic domain rules, `@@`, `important`, `badfilter`, `denyallow`,
  and request-side `dnstype`
- Unsupported but skipped with warnings: `/etc/hosts` style rules,
  `dnsrewrite`, `$client`, `$ctag`, and unknown modifiers
- Full precedence order:
  - `important` exceptions
  - `important` blocks
  - normal exceptions
  - normal blocks

### Typical Uses

- Reuse AdGuard rule files through the `question` matcher.
- Centralize complex AdGuard-style blocking semantics at the provider layer.

---

## `domain_set`

### Purpose

Provides a high-performance domain rule set that can be referenced by plugins such as `qname` and `cname`.

### Example Configuration

```yaml
- tag: core_domains
  type: domain_set
  args:
    exps:
      # Exact-name match
      - "full:login.example.com"
      # Suffix-domain match
      - "domain:example.com"
      # Keyword match
      - "keyword:cdn"
      # Regex match
      - "regexp:^api[0-9]+\\.example\\.net$"
      # Bare domain syntax is also allowed
      - "static.example.org"
    files:
      # Merge additional rules from files
      - "/etc/forgedns/domains.txt"
    sets:
      # Reuse another domain_set provider
      - "shared_domains"
```

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
- Purpose: References other providers with domain match capability.
- Example: `- "shared_domain_set"`
- Constraints:
  - `domain_set`, `geosite`, and other domain-capable providers are allowed.
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

- `sets` may reference any provider with domain match capability.

---

## `geosite`

### Purpose

Loads reusable domain rules from v2ray-rules-dat `geosite.dat`.

### Example Configuration

```yaml
- tag: geosite_cn
  type: geosite
  args:
    file: "/etc/forgedns/geosite.dat"
    selectors:
      - "cn"
      - "geolocation-!cn"
```

### Configuration Details

- `file`
  - Type: `string`; Required: yes
  - Path to `geosite.dat`.
- `selectors`
  - Type: `array`; Required: no; Default: empty array
  - Case-insensitive exact code filter. Also supports `code@attribute` selectors.
  - Multiple selectors are merged as a union.
  - Omit it or pass `[]` to load the full union of every entry in the dat file.
  - Example: `category-games@cn` keeps only rules under `category-games` that carry the `cn` attribute.

### Behavior

- `Plain` becomes `keyword:`.
- `Regex` becomes `regexp:`.
- `RootDomain` becomes `domain:`.
- `Full` becomes `full:`.
- Can be referenced directly by `qname`, `cname`, and `question`, or aggregated by `domain_set`.

---

## `ip_set`

### Purpose

Provides IP and CIDR rule sets that can be referenced by matchers such as `client_ip`, `resp_ip`, and `ptr_ip`.

### Example Configuration

```yaml
- tag: lan_ip_set
  type: ip_set
  args:
    ips:
      # Single IPv4
      - "192.168.1.1"
      # IPv4 CIDR
      - "192.168.0.0/16"
      - "10.0.0.0/8"
      # Single IPv6
      - "2001:db8::1"
      # IPv6 CIDR
      - "fd00::/8"
    files:
      # Merge more IP / CIDR entries from files
      - "/etc/forgedns/ips.txt"
    sets:
      # Reuse another ip_set provider
      - "shared_ip_set"
```

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
- Purpose: References other providers with IP match capability.
- Example: `- "shared_ip_set"`
- Constraints:
  - `ip_set`, `geoip`, and other IP-capable providers are allowed.
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

- `sets` may reference any provider with IP match capability.

---

## `geoip`

### Purpose

Loads reusable IP and CIDR rules from v2ray-rules-dat `geoip.dat`.

### Example Configuration

```yaml
- tag: geoip_cn
  type: geoip
  args:
    file: "/etc/forgedns/geoip.dat"
    selectors:
      - "cn"
```

### Configuration Details

- `file`
  - Type: `string`; Required: yes
  - Path to `geoip.dat`.
- `selectors`
  - Type: `array`; Required: no; Default: empty array
  - Case-insensitive exact code filter.
  - Multiple selectors are merged as a union.
  - Omit it or pass `[]` to load the full union of every entry in the dat file.

### Behavior

- Exposes IP-only membership checks.
- Can be referenced directly by `client_ip`, `resp_ip`, and `ptr_ip`, or aggregated by `ip_set`.
