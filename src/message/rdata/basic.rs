/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Common high-frequency RDATA payload types.
//!
//! `Name` semantics are owned entirely by `crate::message::name`.
//! The name-like RDATA types in this module are only thin wrappers around that
//! canonical owned DNS name model.

use std::sync::Arc;

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

/// Named EDNS option codes carried inside an OPT pseudo-record.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum EdnsCode {
    /// Option code 0, reserved by RFC 6891.
    Reserved,
    /// Long-Lived Queries option (code 1).
    Llq,
    /// Update Lease option (code 2).
    UpdateLease,
    /// Name Server Identifier option (code 3).
    Nsid,
    /// ENUM Source-URI option (code 4).
    Esu,
    /// DNSSEC Algorithm Understood option (code 5).
    Dau,
    /// DS Hash Understood option (code 6).
    Dhu,
    /// NSEC3 Hash Understood option (code 7).
    N3u,
    /// EDNS Client Subnet option (code 8).
    Subnet,
    /// EDNS EXPIRE option (code 9).
    Expire,
    /// DNS COOKIE option (code 10).
    Cookie,
    /// edns-tcp-keepalive option (code 11).
    TcpKeepalive,
    /// Padding option (code 12).
    Padding,
    /// CHAIN option (code 13).
    Chain,
    /// edns-key-tag option (code 14).
    KeyTag,
    /// Extended DNS Error option (code 15).
    ExtendedDnsError,
    /// Client Tag option (code 16).
    ClientTag,
    /// Server Tag option (code 17).
    ServerTag,
    /// Report Channel option (code 18).
    ReportChannel,
    /// Zone Version option (code 19).
    ZoneVersion,
    /// Any unmodeled or currently unknown option code.
    Unknown(u16),
}

impl From<u16> for EdnsCode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::Reserved,
            1 => Self::Llq,
            2 => Self::UpdateLease,
            3 => Self::Nsid,
            4 => Self::Esu,
            5 => Self::Dau,
            6 => Self::Dhu,
            7 => Self::N3u,
            8 => Self::Subnet,
            9 => Self::Expire,
            10 => Self::Cookie,
            11 => Self::TcpKeepalive,
            12 => Self::Padding,
            13 => Self::Chain,
            14 => Self::KeyTag,
            15 => Self::ExtendedDnsError,
            16 => Self::ClientTag,
            17 => Self::ServerTag,
            18 => Self::ReportChannel,
            19 => Self::ZoneVersion,
            other => Self::Unknown(other),
        }
    }
}

impl From<EdnsCode> for u16 {
    fn from(value: EdnsCode) -> Self {
        match value {
            EdnsCode::Reserved => 0,
            EdnsCode::Llq => 1,
            EdnsCode::UpdateLease => 2,
            EdnsCode::Nsid => 3,
            EdnsCode::Esu => 4,
            EdnsCode::Dau => 5,
            EdnsCode::Dhu => 6,
            EdnsCode::N3u => 7,
            EdnsCode::Subnet => 8,
            EdnsCode::Expire => 9,
            EdnsCode::Cookie => 10,
            EdnsCode::TcpKeepalive => 11,
            EdnsCode::Padding => 12,
            EdnsCode::Chain => 13,
            EdnsCode::KeyTag => 14,
            EdnsCode::ExtendedDnsError => 15,
            EdnsCode::ClientTag => 16,
            EdnsCode::ServerTag => 17,
            EdnsCode::ReportChannel => 18,
            EdnsCode::ZoneVersion => 19,
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

/// Structured EDNS Name Server Identifier payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsNsid {
    nsid: Vec<u8>,
}

impl EdnsNsid {
    pub fn new(nsid: Vec<u8>) -> Self {
        Self { nsid }
    }

    pub fn nsid(&self) -> &[u8] {
        &self.nsid
    }
}

/// Structured EDNS COOKIE payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsCookie {
    cookie: Vec<u8>,
}

impl EdnsCookie {
    pub fn new(cookie: Vec<u8>) -> Self {
        Self { cookie }
    }

    pub fn cookie(&self) -> &[u8] {
        &self.cookie
    }
}

/// Structured Update Lease payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsUpdateLease {
    lease: u32,
    key_lease: Option<u32>,
}

impl EdnsUpdateLease {
    pub fn new(lease: u32, key_lease: Option<u32>) -> Self {
        Self { lease, key_lease }
    }

    pub fn lease(&self) -> u32 {
        self.lease
    }

    pub fn key_lease(&self) -> Option<u32> {
        self.key_lease
    }
}

/// Structured Long-Lived Queries payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsLlq {
    version: u16,
    opcode: u16,
    error: u16,
    id: u64,
    lease_life: u32,
}

impl EdnsLlq {
    pub fn new(version: u16, opcode: u16, error: u16, id: u64, lease_life: u32) -> Self {
        Self {
            version,
            opcode,
            error,
            id,
            lease_life,
        }
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn opcode(&self) -> u16 {
        self.opcode
    }

    pub fn error(&self) -> u16 {
        self.error
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn lease_life(&self) -> u32 {
        self.lease_life
    }
}

/// Shared algorithm-list model used by DAU/DHU/N3U.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsAlgorithmList {
    algorithms: Vec<u8>,
}

impl EdnsAlgorithmList {
    pub fn new(algorithms: Vec<u8>) -> Self {
        Self { algorithms }
    }

    pub fn algorithms(&self) -> &[u8] {
        &self.algorithms
    }
}

/// Structured EXPIRE payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsExpire {
    expire: u32,
    empty: bool,
}

impl EdnsExpire {
    pub fn new(expire: u32) -> Self {
        Self {
            expire,
            empty: false,
        }
    }

    pub fn empty() -> Self {
        Self {
            expire: 0,
            empty: true,
        }
    }

    pub fn expire(&self) -> u32 {
        self.expire
    }

    pub fn is_empty(&self) -> bool {
        self.empty
    }
}

/// Structured TCP keepalive payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsTcpKeepalive {
    timeout: Option<u16>,
}

impl EdnsTcpKeepalive {
    pub fn new(timeout: Option<u16>) -> Self {
        Self { timeout }
    }

    pub fn timeout(&self) -> Option<u16> {
        self.timeout
    }
}

/// Structured Padding payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsPadding {
    padding: Vec<u8>,
}

impl EdnsPadding {
    pub fn new(padding: Vec<u8>) -> Self {
        Self { padding }
    }

    pub fn padding(&self) -> &[u8] {
        &self.padding
    }
}

/// Structured Extended DNS Error payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsExtendedDnsError {
    info_code: u16,
    extra_text: Vec<u8>,
}

impl EdnsExtendedDnsError {
    pub fn new(info_code: u16, extra_text: Vec<u8>) -> Self {
        Self {
            info_code,
            extra_text,
        }
    }

    pub fn info_code(&self) -> u16 {
        self.info_code
    }

    pub fn extra_text(&self) -> &[u8] {
        &self.extra_text
    }
}

/// Structured ENUM Source-URI payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsEsu {
    uri: Vec<u8>,
}

impl EdnsEsu {
    pub fn new(uri: Vec<u8>) -> Self {
        Self { uri }
    }

    pub fn uri(&self) -> &[u8] {
        &self.uri
    }
}

/// Structured Report Channel payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsReportChannel {
    agent_domain: Name,
}

impl EdnsReportChannel {
    pub fn new(agent_domain: Name) -> Self {
        Self { agent_domain }
    }

    pub fn agent_domain(&self) -> &Name {
        &self.agent_domain
    }
}

/// Structured Zone Version payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsZoneVersion {
    label_count: u8,
    version_type: u8,
    version: Vec<u8>,
}

impl EdnsZoneVersion {
    pub fn new(label_count: u8, version_type: u8, version: Vec<u8>) -> Self {
        Self {
            label_count,
            version_type,
            version,
        }
    }

    pub fn label_count(&self) -> u8 {
        self.label_count
    }

    pub fn version_type(&self) -> u8 {
        self.version_type
    }

    pub fn version(&self) -> &[u8] {
        &self.version
    }
}

/// Structured local/experimental EDNS payload mirroring miekg/dns's `EDNS0_LOCAL`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EdnsLocal {
    code: u16,
    data: Vec<u8>,
}

impl EdnsLocal {
    pub fn new(code: u16, data: Vec<u8>) -> Self {
        Self { code, data }
    }

    pub fn code(&self) -> u16 {
        self.code
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Structured EDNS options modeled one-for-one after miekg/dns's EDNS0 option types.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EdnsOption {
    /// Long-Lived Queries option (code 1).
    Llq(EdnsLlq),
    /// Update Lease option (code 2).
    UpdateLease(EdnsUpdateLease),
    /// Name Server Identifier option (code 3).
    Nsid(EdnsNsid),
    /// ENUM Source-URI option (code 4).
    Esu(EdnsEsu),
    /// DNSSEC Algorithm Understood option (code 5).
    Dau(EdnsAlgorithmList),
    /// DS Hash Understood option (code 6).
    Dhu(EdnsAlgorithmList),
    /// NSEC3 Hash Understood option (code 7).
    N3u(EdnsAlgorithmList),
    /// EDNS Client Subnet option (code 8, RFC 7871).
    Subnet(ClientSubnet),
    /// EDNS EXPIRE option (code 9).
    Expire(EdnsExpire),
    /// DNS COOKIE option (code 10).
    Cookie(EdnsCookie),
    /// edns-tcp-keepalive option (code 11).
    TcpKeepalive(EdnsTcpKeepalive),
    /// Padding option (code 12).
    Padding(EdnsPadding),
    /// Extended DNS Error option (code 15).
    ExtendedDnsError(EdnsExtendedDnsError),
    /// Report Channel option (code 18).
    ReportChannel(EdnsReportChannel),
    /// Zone Version option (code 19).
    ZoneVersion(EdnsZoneVersion),
    /// Local/experimental or otherwise unmodeled option payload.
    Local(EdnsLocal),
}

impl From<&EdnsOption> for EdnsCode {
    fn from(value: &EdnsOption) -> Self {
        match value {
            EdnsOption::Llq(_) => EdnsCode::Llq,
            EdnsOption::UpdateLease(_) => EdnsCode::UpdateLease,
            EdnsOption::Nsid(_) => EdnsCode::Nsid,
            EdnsOption::Esu(_) => EdnsCode::Esu,
            EdnsOption::Dau(_) => EdnsCode::Dau,
            EdnsOption::Dhu(_) => EdnsCode::Dhu,
            EdnsOption::N3u(_) => EdnsCode::N3u,
            EdnsOption::Subnet(_) => EdnsCode::Subnet,
            EdnsOption::Expire(_) => EdnsCode::Expire,
            EdnsOption::Cookie(_) => EdnsCode::Cookie,
            EdnsOption::TcpKeepalive(_) => EdnsCode::TcpKeepalive,
            EdnsOption::Padding(_) => EdnsCode::Padding,
            EdnsOption::ExtendedDnsError(_) => EdnsCode::ExtendedDnsError,
            EdnsOption::ReportChannel(_) => EdnsCode::ReportChannel,
            EdnsOption::ZoneVersion(_) => EdnsCode::ZoneVersion,
            EdnsOption::Local(local) => EdnsCode::from(local.code()),
        }
    }
}

impl From<EdnsOption> for EdnsCode {
    fn from(value: EdnsOption) -> Self {
        EdnsCode::from(&value)
    }
}

impl EdnsOption {
    /// Return the encoded payload length of this option, excluding the 4-byte TL header.
    pub fn payload_len(&self) -> usize {
        match self {
            EdnsOption::Llq(_) => 18,
            EdnsOption::UpdateLease(value) => {
                if value.key_lease().is_some() {
                    8
                } else {
                    4
                }
            }
            EdnsOption::Nsid(value) => value.nsid().len(),
            EdnsOption::Esu(value) => value.uri().len(),
            EdnsOption::Dau(value) | EdnsOption::Dhu(value) | EdnsOption::N3u(value) => {
                value.algorithms().len()
            }
            EdnsOption::Subnet(value) => {
                let max_prefix = match value.addr() {
                    V4(_) => 32u8,
                    V6(_) => 128u8,
                };
                4 + usize::from(value.source_prefix().min(max_prefix)).div_ceil(8)
            }
            EdnsOption::Expire(value) => {
                if value.is_empty() {
                    0
                } else {
                    4
                }
            }
            EdnsOption::Cookie(value) => value.cookie().len(),
            EdnsOption::TcpKeepalive(value) => value.timeout().map(|_| 2).unwrap_or(0),
            EdnsOption::Padding(value) => value.padding().len(),
            EdnsOption::ExtendedDnsError(value) => 2 + value.extra_text().len(),
            EdnsOption::ReportChannel(value) => value.agent_domain().bytes_len(),
            EdnsOption::ZoneVersion(value) => 2 + value.version().len(),
            EdnsOption::Local(local) => local.data().len(),
        }
    }

    /// Return the raw payload bytes for options whose model is still byte-oriented.
    pub fn data(&self) -> &[u8] {
        match self {
            EdnsOption::Nsid(value) => value.nsid(),
            EdnsOption::Esu(value) => value.uri(),
            EdnsOption::Dau(value) | EdnsOption::Dhu(value) | EdnsOption::N3u(value) => {
                value.algorithms()
            }
            EdnsOption::Cookie(value) => value.cookie(),
            EdnsOption::Padding(value) => value.padding(),
            EdnsOption::ExtendedDnsError(value) => value.extra_text(),
            EdnsOption::ZoneVersion(value) => value.version(),
            EdnsOption::Local(local) => local.data(),
            EdnsOption::Llq(_)
            | EdnsOption::UpdateLease(_)
            | EdnsOption::Subnet(_)
            | EdnsOption::Expire(_)
            | EdnsOption::TcpKeepalive(_)
            | EdnsOption::ReportChannel(_) => &[],
        }
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
    inner: Arc<EdnsInner>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct EdnsInner {
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
            inner: Arc::new(EdnsInner {
                udp_payload_size: 1232,
                ext_rcode: 0,
                version: 0,
                flags: EdnsFlags::default(),
                options: Vec::new(),
            }),
        }
    }

    pub fn new_with_param(
        udp_payload_size: u16,
        ext_rcode: u8,
        version: u8,
        flags: EdnsFlags,
        options: Vec<EdnsOption>,
    ) -> Self {
        Self {
            inner: Arc::new(EdnsInner {
                udp_payload_size,
                ext_rcode,
                version,
                flags,
                options,
            }),
        }
    }

    pub fn udp_payload_size(&self) -> u16 {
        self.inner.udp_payload_size
    }

    /// Set the CLASS field value used by the OPT pseudo-RR on the wire.
    pub fn set_udp_payload_size(&mut self, value: u16) {
        Arc::make_mut(&mut self.inner).udp_payload_size = value;
    }

    pub fn ext_rcode(&self) -> u8 {
        self.inner.ext_rcode
    }

    /// Set the high 8 bits of the extended response code carried in the OPT TTL field.
    pub fn set_ext_rcode(&mut self, value: u8) {
        Arc::make_mut(&mut self.inner).ext_rcode = value;
    }

    pub fn version(&self) -> u8 {
        self.inner.version
    }

    /// Set the EDNS version carried in the OPT TTL field.
    pub fn set_version(&mut self, value: u8) {
        Arc::make_mut(&mut self.inner).version = value;
    }

    /// Borrow the decoded EDNS flag bitfield.
    pub fn flags(&self) -> &EdnsFlags {
        &self.inner.flags
    }

    /// Mutably borrow the decoded EDNS flag bitfield.
    pub fn flags_mut(&mut self) -> &mut EdnsFlags {
        &mut Arc::make_mut(&mut self.inner).flags
    }

    /// Toggle the DNSSEC OK (DO) bit in the OPT TTL field.
    pub fn set_dnssec_ok(&mut self, enabled: bool) {
        Arc::make_mut(&mut self.inner).flags.dnssec_ok = enabled;
    }

    /// Look up an EDNS option by code.
    pub fn option(&self, code: EdnsCode) -> Option<&EdnsOption> {
        self.inner
            .options
            .iter()
            .find(|option| EdnsCode::from(*option) == code)
    }

    /// Borrow all EDNS options in insertion order.
    pub fn options(&self) -> &[EdnsOption] {
        &self.inner.options
    }

    /// Insert or replace an EDNS option with the same code.
    ///
    /// This mirrors the common DNS library behavior that an OPT RR should not contain
    /// duplicate instances of the same structured option in the owned model.
    pub fn insert(&mut self, option: EdnsOption) {
        let code = EdnsCode::from(&option);
        self.remove(code);
        Arc::make_mut(&mut self.inner).options.push(option);
    }

    /// Remove all EDNS options matching `code`.
    pub fn remove(&mut self, code: EdnsCode) {
        Arc::make_mut(&mut self.inner)
            .options
            .retain(|option| EdnsCode::from(option) != code);
    }

    /// Rebuild the 32-bit OPT TTL value from the structured EDNS fields.
    ///
    /// Layout: `[extended rcode:8][version:8][flags+z:16]`.
    pub fn raw_ttl(&self) -> u32 {
        (u32::from(self.ext_rcode()) << 24)
            | (u32::from(self.version()) << 16)
            | u32::from(u16::from(*self.flags()))
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
            inner: self.0.options().iter(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::EdnsLocal;

    #[test]
    fn edns_code_roundtrip_covers_named_registry_values() {
        let cases = [
            (0u16, EdnsCode::Reserved),
            (1, EdnsCode::Llq),
            (2, EdnsCode::UpdateLease),
            (3, EdnsCode::Nsid),
            (4, EdnsCode::Esu),
            (5, EdnsCode::Dau),
            (6, EdnsCode::Dhu),
            (7, EdnsCode::N3u),
            (8, EdnsCode::Subnet),
            (9, EdnsCode::Expire),
            (10, EdnsCode::Cookie),
            (11, EdnsCode::TcpKeepalive),
            (12, EdnsCode::Padding),
            (13, EdnsCode::Chain),
            (14, EdnsCode::KeyTag),
            (15, EdnsCode::ExtendedDnsError),
            (16, EdnsCode::ClientTag),
            (17, EdnsCode::ServerTag),
            (18, EdnsCode::ReportChannel),
            (19, EdnsCode::ZoneVersion),
        ];

        for (wire, named) in cases {
            assert_eq!(EdnsCode::from(wire), named);
            assert_eq!(u16::from(named), wire);
        }

        assert_eq!(EdnsCode::from(65001), EdnsCode::Unknown(65001));
        assert_eq!(u16::from(EdnsCode::Unknown(65001)), 65001);
    }

    #[test]
    fn edns_clone_then_mutate_does_not_change_original() {
        let mut original = Edns::new();
        original.set_udp_payload_size(1232);
        original.set_dnssec_ok(true);
        original.insert(EdnsOption::Local(EdnsLocal::new(65001, vec![1, 2, 3])));

        let mut cloned = original.clone();
        cloned.set_udp_payload_size(4096);
        cloned.set_ext_rcode(2);
        cloned.flags_mut().z = 7;
        cloned.insert(EdnsOption::Local(EdnsLocal::new(65001, vec![9, 9, 9])));

        assert_eq!(original.udp_payload_size(), 1232);
        assert_eq!(original.ext_rcode(), 0);
        assert_eq!(original.flags().z, 0);
        let Some(EdnsOption::Local(local)) = original.option(EdnsCode::Unknown(65001)) else {
            panic!("expected original local edns option");
        };
        assert_eq!(local.data(), &[1, 2, 3]);

        assert_eq!(cloned.udp_payload_size(), 4096);
        assert_eq!(cloned.ext_rcode(), 2);
        assert_eq!(cloned.flags().z, 7);
        let Some(EdnsOption::Local(local)) = cloned.option(EdnsCode::Unknown(65001)) else {
            panic!("expected cloned local edns option");
        };
        assert_eq!(local.data(), &[9, 9, 9]);
    }
}
