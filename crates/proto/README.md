# oxidns-proto

`oxidns-proto` contains the DNS message model and wire codec primitives used
by OxiDNS.

It is split out as a standalone crate so the DNS protocol layer can evolve
independently from the full server runtime.

## Scope

This crate owns the protocol-facing types that OxiDNS uses before requests
enter the plugin pipeline and after executors produce responses:

- `Message`, `Header`, `Question`, and `Record`
- domain name parsing and formatting through `Name`
- DNS class, opcode, RCODE, and record type enums
- typed RDATA structs for common DNS records
- DNS wire-format encoding and decoding, including name compression support
- RFC3597-style generic RDATA decoding helpers for parser integrations

The crate deliberately avoids server runtime concerns such as sockets,
upstream pools, caching, configuration, logging, and plugin orchestration.

## Usage

```toml
[dependencies]
oxidns-proto = "0.1"
```

```rust
use oxidns_proto::{Message, Question, RecordType, DNSClass, Name};

let name: Name = "www.example.com.".parse()?;
let question = Question::new(name, RecordType::A, DNSClass::IN);

let mut message = Message::new();
message.set_id(0x1234);
message.add_question(question);

let bytes = message.to_bytes()?;
let decoded = Message::from_bytes(&bytes)?;

assert_eq!(decoded.id(), 0x1234);
# Ok::<(), oxidns_proto::ProtoError>(())
```

## Design Notes

- Types are owned values so they can move cleanly through async request
  handling and plugin boundaries.
- The codec is intended for DNS server and resolver workloads, where avoiding
  unnecessary allocation on the hot path matters.
- Feature flags `hotpath` and `hotpath-alloc` forward to the `hotpath` crate
  for optional instrumentation in performance-sensitive builds.
- Compatibility shims under `oxidns_proto::core` and `oxidns_proto::proto`
  exist for OxiDNS internals while the message layer is being split out.

## Relationship to OxiDNS

OxiDNS uses this crate as the shared DNS protocol substrate for listeners,
upstream clients, matchers, executors, tests, and the `oxidns-zoneparser`
crate. Changes here can affect parsing, rewriting, caching, and transport
behavior across the full server, so semantic changes should be covered by
codec and integration tests.
