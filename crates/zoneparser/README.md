# forgedns-zoneparser

This crate is a vendored and locally maintained zone file parser for ForgeDNS.

The crates.io package name is `forgedns-zoneparser` to avoid name conflicts,
while the library crate name remains `zoneparser`.

It started from the upstream `zoneparser` project, but the public API and the
parsing pipeline are now adapted for ForgeDNS:

- input is parsed from `&str` or file paths
- output is `forgedns_proto::Record`
- `ParseOptions` exposes parser defaults such as `initial_origin`,
  `default_ttl`, `base_dir`, and `max_include_depth`
- the parser supports a zonefile superset intended for ForgeDNS `arbitrary`

## Public API

```rust
use zoneparser::{ParseOptions, parse_file, parse_str};

let options = ParseOptions::default();
let inline_records = parse_str("$ORIGIN example.com.\nwww 60 IN A 192.0.2.1\n", &options)?;
let file_records = parse_file("/etc/forgedns/zone.txt", &options)?;
# Ok::<(), zoneparser::ZoneParseError>(())
```

```toml
[dependencies]
zoneparser = { package = "forgedns-zoneparser", version = "0.1" }
```

## Syntax Coverage

- `$ORIGIN`
- `$TTL`
- `$INCLUDE`
- `$GENERATE`
- owner inheritance
- TTL unit suffixes such as `1h`, `2d`, `1w2d3h`
- quoted strings and escapes
- multiline records with `(` `)`
- comments starting with `;` or `#`
- RFC3597 generic RDATA syntax: `TYPE#### \# <len> <hex>`

Common RR presentation formats are parsed directly. For types without a
dedicated text parser, RFC3597 generic syntax can still be used as long as the
wire format is supported by `forgedns-proto`.

## Notes

- This crate is not trying to preserve the original upstream iterator API.
- The parser is broader than what ForgeDNS `arbitrary` currently needs, but it
  is still focused on loading static zonefile content into ForgeDNS records.
