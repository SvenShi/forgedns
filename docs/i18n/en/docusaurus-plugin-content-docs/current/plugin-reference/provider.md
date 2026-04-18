---
title: Provider Plugins
sidebar_position: 5
---

Providers turn rule sets from one-off literals into reusable data assets. In larger configurations they reduce duplication, centralize shared datasets, and keep policies maintainable.

Providers with domain or IP match capability can be referenced directly by matchers through `"$tag"` and can also be composed by `domain_set` or `ip_set`. Those composite providers compile only their own local rules and then consult referenced providers at runtime instead of copying downstream rule data into a merged matcher.

Every live provider also registers `POST /plugins/<provider_tag>/reload`, and the `reload_provider` executor can refresh that provider's snapshot in place with the same startup configuration without rebuilding unrelated plugins.

At runtime, ForgeDNS only initializes providers that are actually consumed. If a provider is not referenced directly or indirectly by any `server`, `executor`, or `matcher`, it is skipped during startup, does not appear in the runtime registry, and emits a warning log so the unused configuration is visible.

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

- Use AdGuard rules through the `qname` matcher with name-only projection semantics.
- Reuse AdGuard rule files through the `question` matcher.
- Centralize complex AdGuard-style blocking semantics at the provider layer.

### Notes

- Name-only matchers such as `qname` and `cname` use `contains_name`, so `dnstype`-only rules are ignored there.
- `adguard_rule` can be referenced from `domain_set.sets`; because evaluation stays dynamic, exception precedence and request-scoped modifiers such as `dnstype` remain intact.

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
      # Reuse another domain-capable provider
      - "shared_domains"
      - "shared_geosite"
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
  - File contents are re-read during initialization or `reload_provider` and compiled into the current provider's local matcher.

#### `sets`

- Type: `array`; Required: no; Default: empty array
- Purpose: References other providers with domain match capability.
- Example: `- "shared_domain_set"`
- Constraints:
  - `domain_set`, `geosite`, `adguard_rule`, and other domain-capable providers are allowed.
- Runtime impact:
  - The current provider keeps stable handles to referenced providers instead of copying their rules.
  - After a downstream provider reloads, the current `domain_set` sees the new result without reloading itself.

### Behavior

- Initialization and reload only compile local `exps` and `files`.
- Runtime matching checks the local matcher first and then evaluates referenced providers in `sets` declaration order.
- Referenced providers are no longer flattened into copied rule text or copied compiled state.

### Supported Rule Formats

- `full:example.com`
- `domain:example.com`
- `keyword:cdn`
- `regexp:^api\\.example\\.com$`
- `example.com`

### Typical Uses

- Share a core domain list across multiple policies.
- Combine local rules with shared providers behind one reusable entrypoint.

### Notes

- `sets` may reference any provider with domain match capability.
- Changing provider topology, tags, or config structure still requires a full `reload`; `reload_provider` only refreshes the current provider's existing config and external data files.

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
- Supports independent refresh through `reload_provider` or `POST /plugins/<tag>/reload`.
- If you want to pre-export selected rules into text files before runtime, use `forgedns export-dat --kind geosite`.

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
      # Reuse another IP-capable provider
      - "shared_ip_set"
      - "shared_geoip"
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
  - File contents are re-read during initialization or `reload_provider` and compiled into the current provider's local matcher.

#### `sets`

- Type: `array`; Required: no; Default: empty array
- Purpose: References other providers with IP match capability.
- Example: `- "shared_ip_set"`
- Constraints:
  - `ip_set`, `geoip`, and other IP-capable providers are allowed.
- Runtime impact:
  - The current provider keeps stable handles to referenced providers instead of copying their rules.
  - After a downstream provider reloads, the current `ip_set` sees the new result without reloading itself.

### Behavior

- Initialization and reload only compile local `ips` and `files`.
- IPv4 and IPv6 rule indexes are maintained separately.
- Runtime matching checks the local matcher first and then evaluates referenced providers in `sets` declaration order.

### Rule Formats

- `1.1.1.1`
- `192.168.0.0/16`
- `2400:3200::/32`

### Typical Uses

- Define LAN, WAN, overlay, or infrastructure address groups.
- Build allowlists, bypass lists, or target network sets.
- Combine local CIDRs with shared `geoip` or `ip_set` providers behind one reusable entrypoint.

### Notes

- `sets` may reference any provider with IP match capability.
- Changing provider topology, tags, or config structure still requires a full `reload`; `reload_provider` only refreshes the current provider's existing config and external data files.

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
- Can be referenced directly by `client_ip`, `resp_ip`, and `ptr_ip`, or composed by `ip_set`.
- Supports independent refresh through `reload_provider` or `POST /plugins/<tag>/reload`.
- If you want to pre-export selected rules into text files before runtime, use `forgedns export-dat --kind geoip`.
