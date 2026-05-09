# oxidns-zoneparser

This crate is a vendored and locally maintained zone file parser for OxiDNS.

The crates.io package name is `oxidns-zoneparser` to avoid name conflicts,
while the library crate name remains `zoneparser`.

It started from the upstream `zoneparser` project, but the public API and the
parsing pipeline are now adapted for OxiDNS:

- input is parsed from `&str` or file paths
- output is `oxidns_proto::Record`
- `ParseOptions` exposes parser defaults such as `initial_origin`,
  `default_ttl`, `base_dir`, and `max_include_depth`
- the parser supports a zonefile superset intended for OxiDNS `arbitrary`

## Role in OxiDNS

OxiDNS uses this crate to load static DNS records into plugins that synthesize
answers, especially the `arbitrary` executor. Keeping the parser outside the
main server crate lets zonefile syntax support evolve without coupling it to
listeners, upstream transports, cache state, or runtime configuration.

## Public API

```rust
use zoneparser::{ParseOptions, parse_file, parse_str};

let options = ParseOptions::default();
let inline_records = parse_str("$ORIGIN example.com.\nwww 60 IN A 192.0.2.1\n", &options)?;
let file_records = parse_file("/etc/oxidns/zone.txt", &options)?;
# Ok::<(), zoneparser::ZoneParseError>(())
```

```toml
[dependencies]
zoneparser = { package = "oxidns-zoneparser", version = "0.1" }
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
wire format is supported by `oxidns-proto`.

## Options

`ParseOptions` controls the parser's initial state:

- `initial_origin` sets the origin used for relative owner names
- `default_ttl` sets the starting TTL before any `$TTL` directive is seen
- `base_dir` resolves relative `$INCLUDE` paths for inline sources
- `max_include_depth` bounds recursive include expansion

When parsing a file, `base_dir` defaults to the file's parent directory if it
is not set explicitly.

## Error Reporting

Parser errors include a source label, line number, and message when possible.
I/O errors and include-depth failures are reported as structured
`ZoneParseError` variants so callers can distinguish syntax problems from
environment or configuration issues.

## Notes

- This crate is not trying to preserve the original upstream iterator API.
- The parser is broader than what OxiDNS `arbitrary` currently needs, but it
  is still focused on loading static zonefile content into OxiDNS records.
- Parser output is already normalized to `oxidns_proto::Record`, so callers do
  not need a second conversion step before inserting records into OxiDNS
  response logic.
