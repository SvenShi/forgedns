# oxidns-macros

`oxidns-macros` contains procedural macros used by OxiDNS internals.

The crate is intentionally small. Its current job is to reduce boilerplate
when registering stateless plugin factories with the OxiDNS plugin inventory.

## Provided Macros

### `#[plugin_factory("type")]`

Registers a unit struct or empty braced struct as a plugin factory:

```rust
use oxidns_macros::plugin_factory;

#[plugin_factory("cache")]
pub struct CacheFactory;

#[plugin_factory("sequence")]
pub struct SequenceFactory {}
```

The generated code submits a `crate::plugin::FactoryRegistration` entry to the
`inventory` registry and constructs the factory as `Box<dyn
crate::plugin::PluginFactory>`.

## When to Use It

Use this macro for simple plugin factories that:

- have no fields
- do not need custom construction
- can be registered only by plugin type and module path

For factories that carry state, need dependency setup, or require a custom
constructor, use OxiDNS's explicit `register_plugin_factory!` path instead.

## Repository Notes

This crate is built for the OxiDNS workspace and assumes the consuming crate
has the expected `crate::plugin` types available. It is not meant to be a
general-purpose plugin framework.
