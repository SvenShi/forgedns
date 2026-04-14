# forgedns-ripset

Pure Rust library for managing Linux `ipset` and nftables sets through netlink.

This package is published to crates.io as `forgedns-ripset` to avoid the
upstream name conflict. The library crate name remains `ripset`.

## Features

- No shelling out to `ipset` or `nft`
- Supports ipset and nftables backends
- Supports IPv4, IPv6, and CIDR entries
- Optional entry timeout support
- Non-Linux targets compile with stub implementations that return `UnsupportedPlatform`

## Install

```toml
[dependencies]
ripset = { package = "forgedns-ripset", version = "0.1" }
```

## Library Usage

### ipset

```rust
use std::net::IpAddr;
use ripset::{
    ipset_add, ipset_create, ipset_del, ipset_destroy, ipset_flush, ipset_list, ipset_test,
    IpSetCreateOptions, IpSetFamily, IpSetType,
};

let opts = IpSetCreateOptions {
    set_type: IpSetType::HashIp,
    family: IpSetFamily::Inet,
    ..Default::default()
};

ipset_create("myset", &opts)?;

let addr: IpAddr = "192.168.1.1".parse()?;
ipset_add("myset", addr)?;
let exists = ipset_test("myset", addr)?;
let entries = ipset_list("myset")?;
ipset_del("myset", addr)?;
ipset_flush("myset")?;
ipset_destroy("myset")?;
```

### nftables

```rust
use std::net::IpAddr;
use ripset::{
    nftset_add, nftset_create_set, nftset_create_table, nftset_del, nftset_delete_set,
    nftset_delete_table, nftset_list, nftset_test, NftSetCreateOptions, NftSetType,
};

nftset_create_table("inet", "mytable")?;

let opts = NftSetCreateOptions {
    set_type: NftSetType::Ipv4Addr,
    ..Default::default()
};

nftset_create_set("inet", "mytable", "myset", &opts)?;

let addr: IpAddr = "10.0.0.1".parse()?;
nftset_add("inet", "mytable", "myset", addr)?;
let exists = nftset_test("inet", "mytable", "myset", addr)?;
let entries = nftset_list("inet", "mytable", "myset")?;
nftset_del("inet", "mytable", "myset", addr)?;
nftset_delete_set("inet", "mytable", "myset")?;
nftset_delete_table("inet", "mytable")?;
```

## Requirements

- Linux with netfilter support
- `CAP_NET_ADMIN` or root privileges
- `ip_set` kernel module for ipset
- `nf_tables` kernel module for nftables

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license
