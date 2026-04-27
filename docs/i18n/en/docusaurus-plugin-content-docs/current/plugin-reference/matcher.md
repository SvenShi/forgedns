---
title: Matcher Plugins
sidebar_position: 4
---

Matcher plugins return `true` or `false`. They are mainly used by `sequence.matches`.

## Matcher Expression Rules

Inside `sequence`, quick-setup matcher expressions are usually the clearest form to start with:

```yaml
- matches:
    - "client_ip $lan_ip_set"
    - "qtype 1"
  exec: "$forward_main"
```

You can combine other quick-setup matchers in the same way:

```yaml
- matches:
    - "qname domain:example.com"
    - "qclass 1"
  exec: "$forward_main"
```

Negation:

```yaml
- matches: "!has_resp"
  exec: "$forward_main"
```

---

## `any_match`

### Purpose

Composes multiple matcher expressions and returns `true` when any one of them matches.

### Example Configuration

```yaml
- tag: any_policy_hit
  type: any_match
  args:
    - "$lan_clients"
    - "qtype 28"
    - "!$blocked_qname"
```

### Configuration Details

`any_match` uses an `array[string]` `args` list.

- Type: `array[string]`; Required: yes; Default: none
- Supported entries:
  - matcher tag references (for example `"$match_tag"`)
  - quick-setup matcher expressions (for example `"qname domain:example.com"`)
  - negated matcher expressions (for example `"!$has_resp"`)
- Runtime impact:
  - Evaluates entries in order and short-circuits on the first matched entry.
  - Returns `false` only when all entries fail.

### Typical Uses

- Reuse one logical OR matcher across multiple sequence rules.
- Keep complex branching readable by moving OR conditions into one matcher.

---

## `qname`

### Purpose

Matches the query name in the request.

### Example Configuration

```yaml
- tag: match_domain
  type: qname
  args:
    # Domain expression
    - "domain:example.com"
    # Reuse an existing domain-capable provider
    - "$core_domains"
    # Load rules from file
    - "&/etc/forgedns/domains.txt"
```

### Configuration Details

`args` is a rule list.

- Type: `array`; Required: yes; Default: none
- Supported items:
  - domain expressions
  - provider references with domain match capability, such as `domain_set` or `geosite`
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

## `question`

### Purpose

Matches request questions using provider implementations of `contains_question`.

The matcher scans every question in the current request. It returns `true` as
soon as any question is matched by any referenced provider.

### Example Configuration

```yaml
- tag: match_ad
  type: question
  args:
    - "$ad_rules"
    - "$shared_domains"
```

### Configuration Details

- `args`
  - Type: `array[string]`; Required: yes; Default: none
  - Purpose: References providers that implement `contains_question` using `"$provider_tag"` entries.

### Behavior

- Scans all questions in the request.
- Returns `true` when any question is matched by any referenced provider.
- quick setup supports the same `"$provider_tag"` entries.

### Typical Uses

- Let providers such as `adguard_rule`, `domain_set`, or `geosite` participate directly in
  question-level matching.
- Branch in `sequence`, then hand off to `black_hole`, `reject`, or another
  executor.

---

## `qtype`

### Purpose

Matches request qtypes.

### Example Configuration

```yaml
- tag: only_a_aaaa
  type: qtype
  args:
    - "1"
    - "28"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- The examples below use numeric qtype codes.
- Common mappings:
  - `1` = `A`
  - `28` = `AAAA`
  - `12` = `PTR`
- Runtime impact:
  - Returns `true` if any question type matches the configured set.

### quick setup

```yaml
- matches: "qtype 1"
```

### Typical Uses

- Split A, AAAA, PTR, TXT, and other query classes of traffic.

---

## `qclass`

### Purpose

Matches request qclasses.

### Example Configuration

```yaml
- tag: only_in
  type: qclass
  args:
    - "1"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- The examples below use numeric qclass codes.
- Common mappings:
  - `1` = `IN`
  - `3` = `CH`
  - `4` = `HS`
- Runtime impact:
  - Returns `true` if any question class matches the configured set.

### quick setup

```yaml
- matches: "qclass 1"
```

### Typical Uses

- Restrict handling to `IN` queries.

---

## `client_ip`

### Purpose

Matches the client source IP.

### Example Configuration

```yaml
- tag: lan_clients
  type: client_ip
  args:
    # Inline CIDR
    - "192.168.0.0/16"
    # Reference an IP-capable provider
    - "$lan_ip_set"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supported items:
  - single IPs
  - CIDRs
  - provider references with IP match capability, such as `ip_set` or `geoip`
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

### Example Configuration

```yaml
- tag: matched_resp_ip
  type: resp_ip
  args:
    - "100.64.0.0/10"
    - "$special_targets"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supported items:
  - single IPs
  - CIDRs
  - provider references with IP match capability, such as `ip_set` or `geoip`
- Runtime impact:
  - Returns `true` when any A or AAAA answer IP matches any rule.

### quick setup

```yaml
- matches: "resp_ip 10.0.0.0/8"
```

### Typical Uses

- Trigger side effects based on returned answer addresses.

---

## `ptr_ip`

### Purpose

Matches the IP encoded in a PTR query name.

### Example Configuration

Similar to `client_ip` and `resp_ip`, it supports IP rules and IP-capable providers such as `ip_set` and `geoip`.

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supported items:
  - single IPs
  - CIDRs
  - provider references with IP match capability, such as `ip_set` or `geoip`
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

### Example Configuration

```yaml
- tag: cname_target
  type: cname
  args:
    - "domain:example.com"
    - "$core_domains"
    - "&/etc/forgedns/cnames.txt"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supported items:
  - domain expressions
  - provider references with domain match capability, such as `domain_set` or `geosite`
  - file references
- Runtime impact:
  - Returns `true` when any CNAME target in the response matches.

### quick setup

```yaml
- matches: "cname keyword:cdn"
```

### Typical Uses

- Branch on canonical names returned by upstreams.

---

## `rcode`

### Purpose

Matches the current response code.

### Example Configuration

```yaml
- tag: only_noerror
  type: rcode
  args:
    - "2"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supports decimal numeric rcodes only.
- Common examples:
  - `0` = `NOERROR`
  - `2` = `SERVFAIL`
  - `3` = `NXDOMAIN`
- Runtime impact:
  - Returns `true` when the response rcode matches the configured set.

### quick setup

```yaml
- matches: "rcode 2"
```

### Typical Uses

- Follow-up handling for upstream failures or negative responses.

---

## `has_resp`

### Purpose

Matches whether a response already exists in the context.

### Example Configuration

```yaml
- tag: has_resp_flag
  type: has_resp
```

### Configuration Details

No standalone configuration fields.

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

### Example Configuration

```yaml
- tag: has_wanted_answer
  type: has_wanted_ans
```

### Configuration Details

No standalone configuration fields.

### quick setup

```yaml
- matches: "has_wanted_ans"
```

### Typical Uses

- Build follow-up logic only when a meaningful answer is already present.

---

## `mark`

### Purpose

Matches marks already written into the DNS context.

### Example Configuration

```yaml
- tag: marked_100
  type: mark
  args:
    - "100"
    - "200"
```

### Configuration Details

- Type: `array`; Required: yes; Default: none
- Supports integer mark values.
- Multiple marks can be separated by commas or whitespace.
- Runtime impact:
  - Returns `true` if any configured mark exists in the context.

### quick setup

```yaml
- matches: "mark 100 200"
```

### Typical Uses

- Branch across phases after earlier decisions set marks.

---

## `env`

### Purpose

Matches environment variables.

### Example Configuration

```yaml
- tag: env_profile_prod
  type: env
  args:
    - "PROFILE"
    - "prod"
```

Or check only existence:

```yaml
args:
  - "FEATURE_X"
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
- matches: "env PROFILE prod"
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

### Example Configuration

```yaml
- tag: rollout_10p
  type: random
  args:
    - "0.1"
```

### Configuration Details

- Type: `number`; Required: yes; Default: none
- Meaning: Probability between `0` and `1`.
- Runtime impact:
  - Returns `true` according to the configured sampling ratio.

### quick setup

```yaml
- matches: "random 0.05"
```

### Typical Uses

- Gradual rollout.
- Sampling for observability or experiments.

---

## `rate_limiter`

### Purpose

Matches based on per-source rate-limit state.

### Example Configuration

```yaml
- tag: qps_guard
  type: rate_limiter
  args:
    qps: 20
    burst: 40
    mask4: 32
    mask6: 48
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

Prefer the full configuration so `qps`, `burst`, and `mask` stay explicit.

### Behavior

- Applies rate limiting per source prefix rather than only per exact IP.
- Useful for protecting upstreams or constraining abusive traffic.

### Typical Uses

- Query throttling.
- Split normal traffic and over-limit traffic into different branches.

---

## `string_exp`

### Purpose

Matches using a string expression over request and response context.

### Example Configuration

```yaml
- tag: match_http_path
  type: string_exp
  args: "url_path prefix /dns-"
```

It also supports a string array:

```yaml
args:
  - "client_ip"
  - "prefix"
  - "192.168."
```

### Configuration Details

- `string_exp` `args` can be a string or a string array.

- Type: `string` or `array`
- Required: yes
- Default: none
- Purpose: Defines the complete string expression.
- Expression parts:
  - data source `source`
  - matching operator `op`
  - one or more arguments
- Runtime impact:
  - Reads values from the context according to the expression and performs string matching.

### Expression Format

```text
<source> <op> <arg...>
```

Supported `source` values:

- `qname`
- `qtype`
- `qclass`
- `rcode`
- `resp_ip`
- `mark`
- `client_ip`
- `server_name`
- `url_path`
- `$ENV_KEY`

Supported `op` values:

- `eq`
- `prefix`
- `suffix`
- `contains`
- `regexp`
- `zl`

Notes:

- `zl` means zero length and is used to determine whether a string is empty.
- `regexp` supports one or more regex arguments.

### quick setup

```yaml
- matches: "string_exp server_name suffix .example.net"
```

### Typical Uses

- Perform flexible matching on DoH paths, SNI, mark sets, and response IP strings.

### Notes

- In scenarios where a dedicated matcher can be used, prefer the dedicated matcher.
- `string_exp` provides greater flexibility, but the readability and maintainability of the expression are usually lower than those of dedicated plugins.
<span id="true"></span>

## `_true`

### Purpose

Always returns true.

### Example Configuration

```yaml
- tag: always_true
  type: _true
```

### Configuration Details

No standalone configuration fields.

### Typical Uses

- Fallback match condition.
- Testing rule order in a `sequence`.

---

<span id="false"></span>

## `_false`

### Purpose

Always returns false.

### Example Configuration

```yaml
- tag: always_false
  type: _false
```

### Configuration Details

No standalone configuration fields.

### Typical Uses

- Temporarily disable a branch.

---
