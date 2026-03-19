/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Common high-frequency RDATA payload types.
//!
//! `Name` semantics are owned entirely by `crate::message::name`.
//! The name-like RDATA types in this module are only thin wrappers around that
//! canonical owned DNS name model.

use crate::core::error::DnsError;
use crate::message::Name;
use std::net::IpAddr;
use std::net::IpAddr::{V4, V6};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Owned IPv4 address payload.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct A(pub Ipv4Addr);

impl A {
    /// Construct an `A` payload from octets.
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(Ipv4Addr::new(a, b, c, d))
    }
}

/// Owned IPv6 address payload.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AAAA(pub Ipv6Addr);

impl AAAA {
    /// Construct an `AAAA` payload from an IPv6 address.
    pub fn new(addr: Ipv6Addr) -> Self {
        Self(addr)
    }
}

/// Canonical name payload used by CNAME-like records.
///
/// The wrapped [`Name`] value follows the canonical semantics implemented in
/// `crate::message::name`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CNAME(pub Name);

/// Authoritative name server target payload.
///
/// The wrapped [`Name`] value follows the canonical semantics implemented in
/// `crate::message::name`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NS(pub Name);

/// Reverse lookup target payload.
///
/// The wrapped [`Name`] value follows the canonical semantics implemented in
/// `crate::message::name`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PTR(pub Name);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum EdnsCode {
    Subnet,
    Unknown(u16),
}

impl From<u16> for EdnsCode {
    fn from(value: u16) -> Self {
        match value {
            8 => Self::Subnet,
            other => Self::Unknown(other),
        }
    }
}

impl From<EdnsCode> for u16 {
    fn from(value: EdnsCode) -> Self {
        match value {
            EdnsCode::Subnet => 8,
            EdnsCode::Unknown(other) => other,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientSubnet {
    addr: IpAddr,
    source_prefix: u8,
    scope_prefix: u8,
}

impl ClientSubnet {
    /// Construct an ECS payload as described by RFC 7871 section 6.
    ///
    /// `addr` is the original client address, while `source_prefix` and `scope_prefix`
    /// are stored as-is. Wire encoding later masks the address down to the advertised
    /// source prefix.
    pub fn new(addr: IpAddr, source_prefix: u8, scope_prefix: u8) -> Self {
        Self {
            addr,
            source_prefix,
            scope_prefix,
        }
    }

    /// Return the unmasked address value carried by the ECS option model.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Return the number of significant source bits announced to upstreams.
    pub fn source_prefix(&self) -> u8 {
        self.source_prefix
    }

    /// Return the intended cache scope prefix from RFC 7871.
    pub fn scope_prefix(&self) -> u8 {
        self.scope_prefix
    }
}

impl FromStr for ClientSubnet {
    type Err = DnsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_part, prefix_part) = s
            .split_once('/')
            .ok_or_else(|| DnsError::protocol("invalid client subnet string"))?;
        let addr: IpAddr = addr_part
            .parse()
            .map_err(|_| DnsError::protocol("invalid client subnet address"))?;
        let source_prefix: u8 = prefix_part
            .parse()
            .map_err(|_| DnsError::protocol("invalid client subnet prefix"))?;

        let max_prefix = match addr {
            V4(_) => 32,
            V6(_) => 128,
        };

        if source_prefix > max_prefix {
            return Err(DnsError::protocol(
                "client subnet prefix exceeds address width",
            ));
        }

        Ok(Self {
            addr,
            source_prefix,
            scope_prefix: 0,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EdnsOption {
    /// EDNS Client Subnet option (code 8, RFC 7871).
    Subnet(ClientSubnet),
    /// Unknown or currently unmodeled EDNS option stored as raw bytes.
    Unknown(u16, Vec<u8>),
}

impl From<&EdnsOption> for EdnsCode {
    fn from(value: &EdnsOption) -> Self {
        match value {
            EdnsOption::Subnet(_) => EdnsCode::Subnet,
            EdnsOption::Unknown(code, _) => EdnsCode::Unknown(*code),
        }
    }
}

impl From<EdnsOption> for EdnsCode {
    fn from(value: EdnsOption) -> Self {
        EdnsCode::from(&value)
    }
}

pub struct OptIter<'a> {
    pub(crate) inner: std::slice::Iter<'a, EdnsOption>,
}

impl<'a> Iterator for OptIter<'a> {
    type Item = &'a EdnsOption;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

/// Decoded EDNS flag bits carried in the OPT TTL field.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct EdnsFlags {
    pub dnssec_ok: bool,
    pub z: u16,
}

impl From<u16> for EdnsFlags {
    fn from(flags: u16) -> Self {
        Self {
            dnssec_ok: flags & 0x8000 == 0x8000,
            z: flags & 0x7FFF,
        }
    }
}

impl From<EdnsFlags> for u16 {
    fn from(flags: EdnsFlags) -> Self {
        match flags.dnssec_ok {
            true => 0x8000 | flags.z,
            false => 0x7FFF & flags.z,
        }
    }
}

/// Owned EDNS state attached to an OPT pseudo-record in the message model.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Edns {
    udp_payload_size: u16,
    ext_rcode: u8,
    version: u8,
    flags: EdnsFlags,
    options: Vec<EdnsOption>,
}

impl Default for Edns {
    fn default() -> Self {
        Self::new()
    }
}

impl Edns {
    /// Construct a default EDNS pseudo-record model.
    ///
    /// The default UDP payload size is ForgeDNS's preferred 1232 bytes, which is a
    /// common safe DNS-over-UDP payload on the modern Internet.
    pub fn new() -> Self {
        Self {
            udp_payload_size: 1232,
            ext_rcode: 0,
            version: 0,
            flags: EdnsFlags::default(),
            options: Vec::new(),
        }
    }

    pub fn udp_payload_size(&self) -> u16 {
        self.udp_payload_size
    }

    /// Set the CLASS field value used by the OPT pseudo-RR on the wire.
    pub fn set_udp_payload_size(&mut self, value: u16) {
        self.udp_payload_size = value;
    }

    pub fn ext_rcode(&self) -> u8 {
        self.ext_rcode
    }

    /// Set the high 8 bits of the extended response code carried in the OPT TTL field.
    pub fn set_ext_rcode(&mut self, value: u8) {
        self.ext_rcode = value;
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    /// Set the EDNS version carried in the OPT TTL field.
    pub fn set_version(&mut self, value: u8) {
        self.version = value;
    }

    /// Borrow the decoded EDNS flag bitfield.
    pub fn flags(&self) -> &EdnsFlags {
        &self.flags
    }

    /// Mutably borrow the decoded EDNS flag bitfield.
    pub fn flags_mut(&mut self) -> &mut EdnsFlags {
        &mut self.flags
    }

    /// Toggle the DNSSEC OK (DO) bit in the OPT TTL field.
    pub fn set_dnssec_ok(&mut self, enabled: bool) {
        self.flags.dnssec_ok = enabled;
    }

    /// Look up an EDNS option by code.
    pub fn option(&self, code: EdnsCode) -> Option<&EdnsOption> {
        self.options
            .iter()
            .find(|option| EdnsCode::from(*option) == code)
    }

    /// Borrow all EDNS options in insertion order.
    pub fn options(&self) -> &[EdnsOption] {
        &self.options
    }

    /// Insert or replace an EDNS option with the same code.
    ///
    /// This mirrors the common DNS library behavior that an OPT RR should not contain
    /// duplicate instances of the same structured option in the owned model.
    pub fn insert(&mut self, option: EdnsOption) {
        let code = EdnsCode::from(&option);
        self.remove(code);
        self.options.push(option);
    }

    /// Remove all EDNS options matching `code`.
    pub fn remove(&mut self, code: EdnsCode) {
        self.options.retain(|option| EdnsCode::from(option) != code);
    }

    /// Rebuild the 32-bit OPT TTL value from the structured EDNS fields.
    ///
    /// Layout: `[extended rcode:8][version:8][flags+z:16]`.
    pub fn raw_ttl(&self) -> u32 {
        (u32::from(self.ext_rcode) << 24)
            | (u32::from(self.version) << 16)
            | u32::from(u16::from(self.flags))
    }
}

/// Wrapper type used when an RR stores owned EDNS state.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OPT(pub Edns);

impl Default for OPT {
    fn default() -> Self {
        Self(Edns::new())
    }
}

impl OPT {
    pub fn insert(&mut self, option: EdnsOption) {
        self.0.insert(option);
    }

    pub fn remove(&mut self, code: EdnsCode) {
        self.0.remove(code);
    }

    pub fn get(&self, code: EdnsCode) -> Option<&EdnsOption> {
        self.0.option(code)
    }

    pub fn as_ref(&self) -> OptIter<'_> {
        OptIter {
            inner: self.0.options.iter(),
        }
    }
}

impl std::ops::Deref for OPT {
    type Target = Edns;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for OPT {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Owned mail exchanger payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MX {
    preference: u16,
    exchange: Name,
}

impl MX {
    /// Construct an `MX` payload.
    pub fn new(preference: u16, exchange: Name) -> Self {
        Self {
            preference,
            exchange,
        }
    }

    pub fn preference(&self) -> u16 {
        self.preference
    }

    pub fn exchange(&self) -> &Name {
        &self.exchange
    }
}

/// Owned service locator payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SRV {
    priority: u16,
    weight: u16,
    port: u16,
    target: Name,
}

impl SRV {
    /// Construct an `SRV` payload.
    pub fn new(priority: u16, weight: u16, port: u16, target: Name) -> Self {
        Self {
            priority,
            weight,
            port,
            target,
        }
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn target(&self) -> &Name {
        &self.target
    }
}

/// Owned naming authority pointer payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NAPTR {
    order: u16,
    preference: u16,
    flags: Box<[u8]>,
    services: Box<[u8]>,
    regexp: Box<[u8]>,
    replacement: Name,
}

impl NAPTR {
    /// Construct a `NAPTR` payload.
    pub fn new(
        order: u16,
        preference: u16,
        flags: Box<[u8]>,
        services: Box<[u8]>,
        regexp: Box<[u8]>,
        replacement: Name,
    ) -> Self {
        Self {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        }
    }

    pub fn order(&self) -> u16 {
        self.order
    }

    pub fn preference(&self) -> u16 {
        self.preference
    }

    pub fn flags(&self) -> &[u8] {
        &self.flags
    }

    pub fn services(&self) -> &[u8] {
        &self.services
    }

    pub fn regexp(&self) -> &[u8] {
        &self.regexp
    }

    pub fn replacement(&self) -> &Name {
        &self.replacement
    }
}

/// Owned certification authority authorization payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CAA {
    flag: u8,
    tag: Box<[u8]>,
    value: Box<[u8]>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DOA(pub Box<[u8]>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RESINFO(pub TXT);

impl CAA {
    /// Construct a `CAA` payload.
    pub fn new(flag: u8, tag: Box<[u8]>, value: Box<[u8]>) -> Self {
        Self { flag, tag, value }
    }

    pub fn flag(&self) -> u8 {
        self.flag
    }

    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Owned TXT payload stored as raw TXT RDATA wire:
/// [len][bytes][len][bytes]...
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TXT {
    wire: Box<[u8]>,
}

impl TXT {
    pub fn new(wire: Box<[u8]>) -> Self {
        Self { wire }
    }

    /// Borrow raw TXT RDATA wire payload.
    pub fn wire_data(&self) -> &[u8] {
        &self.wire
    }

    /// Iterate TXT chunks as raw bytes.
    pub fn txt_data(&self) -> TxtIter<'_> {
        TxtIter {
            wire: &self.wire,
            cursor: 0,
        }
    }

    /// Iterate TXT chunks as utf8 when valid.
    pub fn txt_data_utf8(&self) -> impl Iterator<Item = Option<&str>> {
        self.txt_data().map(|part| std::str::from_utf8(part).ok())
    }
}

pub struct TxtIter<'a> {
    wire: &'a [u8],
    cursor: usize,
}

impl<'a> Iterator for TxtIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.wire.len() {
            return None;
        }

        let len = self.wire[self.cursor] as usize;
        let start = self.cursor + 1;
        let end = start + len;
        if end > self.wire.len() {
            self.cursor = self.wire.len();
            return None;
        }

        self.cursor = end;
        Some(&self.wire[start..end])
    }
}

/// Owned start-of-authority payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SOA {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

impl SOA {
    pub fn new(
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    ) -> Self {
        Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }

    pub fn mname(&self) -> &Name {
        &self.mname
    }

    pub fn rname(&self) -> &Name {
        &self.rname
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn refresh(&self) -> i32 {
        self.refresh
    }

    pub fn retry(&self) -> i32 {
        self.retry
    }

    pub fn expire(&self) -> i32 {
        self.expire
    }

    pub fn minimum(&self) -> u32 {
        self.minimum
    }
}
