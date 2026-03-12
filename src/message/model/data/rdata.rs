/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned RDATA payloads and EDNS helpers.

use crate::message::model::data::{Name, RecordType};
use std::net::{IpAddr, Ipv4Addr};

/// Supported owned RDATA payloads.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RData {
    /// IPv4 address payload.
    A(rdata::A),
    /// IPv6 address payload.
    AAAA(rdata::AAAA),
    /// Canonical name target payload.
    CNAME(rdata::name::CNAME),
    /// Authoritative name server target payload.
    NS(rdata::name::NS),
    /// Reverse lookup target payload.
    PTR(rdata::name::PTR),
    /// Mail exchanger payload.
    MX(rdata::MX),
    /// Text string payload.
    TXT(rdata::TXT),
    /// Start of authority payload.
    SOA(rdata::SOA),
    /// EDNS OPT pseudo-record payload.
    OPT(rdata::OPT),
    /// Opaque payload for unsupported record types.
    Unknown { record_type: u16, data: Vec<u8> },
}

impl RData {
    /// Return the owned RR type for this payload.
    pub fn record_type(&self) -> RecordType {
        match self {
            RData::A(_) => RecordType::A,
            RData::AAAA(_) => RecordType::AAAA,
            RData::CNAME(_) => RecordType::CNAME,
            RData::NS(_) => RecordType::NS,
            RData::PTR(_) => RecordType::PTR,
            RData::MX(_) => RecordType::MX,
            RData::TXT(_) => RecordType::TXT,
            RData::SOA(_) => RecordType::SOA,
            RData::OPT(_) => RecordType::OPT,
            RData::Unknown { record_type, .. } => RecordType::Unknown(*record_type),
        }
    }

    /// Extract an IP address from `A` and `AAAA` payloads.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        match self {
            RData::A(value) => Some(IpAddr::V4(value.0)),
            RData::AAAA(value) => Some(IpAddr::V6(value.0)),
            _ => None,
        }
    }
}

/// Owned RDATA helper types grouped by record family.
pub mod rdata {
    use super::Name;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    /// Owned mail exchanger payload.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct MX {
        /// MX preference value.
        preference: u16,
        /// Exchange hostname.
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

        /// Return the MX preference value.
        pub fn preference(&self) -> u16 {
            self.preference
        }

        /// Return the exchange hostname.
        pub fn exchange(&self) -> &Name {
            &self.exchange
        }
    }

    /// Owned text payload made of one or more character strings.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct TXT(Vec<String>);

    impl TXT {
        /// Construct a `TXT` payload from already split character strings.
        pub fn new(parts: Vec<String>) -> Self {
            Self(parts)
        }

        /// Return the text chunks carried by this record.
        pub fn txt_data(&self) -> &[String] {
            &self.0
        }
    }

    /// Owned start-of-authority payload.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct SOA {
        /// Primary master name server.
        mname: Name,
        /// Responsible mailbox encoded as a DNS name.
        rname: Name,
        /// Zone serial number.
        serial: u32,
        /// Refresh interval in seconds.
        refresh: i32,
        /// Retry interval in seconds.
        retry: i32,
        /// Expire interval in seconds.
        expire: i32,
        /// Minimum negative caching TTL.
        minimum: u32,
    }

    impl SOA {
        /// Construct an `SOA` payload.
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

        /// Return the primary master name server.
        pub fn mname(&self) -> &Name {
            &self.mname
        }

        /// Return the responsible mailbox name.
        pub fn rname(&self) -> &Name {
            &self.rname
        }

        /// Return the zone serial number.
        pub fn serial(&self) -> u32 {
            self.serial
        }

        /// Return the refresh interval.
        pub fn refresh(&self) -> i32 {
            self.refresh
        }

        /// Return the retry interval.
        pub fn retry(&self) -> i32 {
            self.retry
        }

        /// Return the expire interval.
        pub fn expire(&self) -> i32 {
            self.expire
        }

        /// Return the minimum / negative-cache TTL.
        pub fn minimum(&self) -> u32 {
            self.minimum
        }
    }

    /// Decoded EDNS flag bits used by the owned message model.
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct EdnsFlags {
        /// Whether the `DO` bit is set.
        pub dnssec_ok: bool,
    }

    impl Default for EdnsFlags {
        /// Construct EDNS flags with all bits cleared.
        fn default() -> Self {
            Self { dnssec_ok: false }
        }
    }

    /// Owned EDNS state attached to an OPT pseudo-record.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct Edns {
        /// Advertised UDP payload size.
        udp_payload_size: u16,
        /// Extended response code high bits.
        ext_rcode: u8,
        /// EDNS version.
        version: u8,
        /// Decoded EDNS flag bits.
        flags: EdnsFlags,
        /// Owned EDNS option list.
        options: Vec<opt::EdnsOption>,
    }

    impl Default for Edns {
        /// Construct EDNS with ForgeDNS defaults.
        fn default() -> Self {
            Self::new()
        }
    }

    impl Edns {
        /// Construct an empty EDNS state with the default UDP payload size.
        pub fn new() -> Self {
            Self {
                udp_payload_size: 1232,
                ext_rcode: 0,
                version: 0,
                flags: EdnsFlags::default(),
                options: Vec::new(),
            }
        }

        /// Return the advertised UDP payload size.
        pub fn udp_payload_size(&self) -> u16 {
            self.udp_payload_size
        }

        /// Update the advertised UDP payload size.
        pub fn set_udp_payload_size(&mut self, value: u16) {
            self.udp_payload_size = value;
        }

        /// Return the extended response code high bits.
        pub fn ext_rcode(&self) -> u8 {
            self.ext_rcode
        }

        /// Update the extended response code high bits.
        pub fn set_ext_rcode(&mut self, value: u8) {
            self.ext_rcode = value;
        }

        /// Return the EDNS version.
        pub fn version(&self) -> u8 {
            self.version
        }

        /// Update the EDNS version.
        pub fn set_version(&mut self, value: u8) {
            self.version = value;
        }

        /// Borrow the decoded EDNS flags.
        pub fn flags(&self) -> &EdnsFlags {
            &self.flags
        }

        /// Mutably borrow the decoded EDNS flags.
        pub fn flags_mut(&mut self) -> &mut EdnsFlags {
            &mut self.flags
        }

        /// Convenience helper for toggling the `DO` flag.
        pub fn set_dnssec_ok(&mut self, enabled: bool) {
            self.flags.dnssec_ok = enabled;
        }

        /// Return the first option matching `code`.
        pub fn option(&self, code: opt::EdnsCode) -> Option<&opt::EdnsOption> {
            self.options
                .iter()
                .find(|option| opt::EdnsCode::from(*option) == code)
        }

        /// Borrow the owned EDNS option list.
        pub fn options(&self) -> &[opt::EdnsOption] {
            &self.options
        }

        /// Insert or replace an EDNS option by code.
        pub fn insert(&mut self, option: opt::EdnsOption) {
            let code = opt::EdnsCode::from(&option);
            self.remove(code);
            self.options.push(option);
        }

        /// Remove all EDNS options with the requested code.
        pub fn remove(&mut self, code: opt::EdnsCode) {
            self.options
                .retain(|option| opt::EdnsCode::from(option) != code);
        }

        /// Reconstruct the raw 32-bit OPT TTL field from the decoded state.
        pub fn raw_ttl(&self) -> u32 {
            let mut value = (u32::from(self.ext_rcode) << 24) | (u32::from(self.version) << 16);
            if self.flags.dnssec_ok {
                value |= 0x8000;
            }
            value
        }

        /// Build owned EDNS state from a borrowed packet-backed view.
        pub fn from_ref(edns: &crate::message::wire::edns::EdnsRef<'_>) -> Self {
            edns.to_owned()
        }
    }

    /// Wrapper type used when an RR stores owned EDNS state.
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct OPT(pub Edns);

    impl Default for OPT {
        /// Construct an empty OPT payload.
        fn default() -> Self {
            Self(Edns::new())
        }
    }

    impl OPT {
        /// Insert or replace an EDNS option.
        pub fn insert(&mut self, option: opt::EdnsOption) {
            self.0.insert(option);
        }

        /// Remove all EDNS options with the requested code.
        pub fn remove(&mut self, code: opt::EdnsCode) {
            self.0.remove(code);
        }

        /// Return the first EDNS option matching `code`.
        pub fn get(&self, code: opt::EdnsCode) -> Option<&opt::EdnsOption> {
            self.0.option(code)
        }

        /// Iterate all EDNS options with their decoded codes.
        pub fn as_ref(&self) -> opt::OptIter<'_> {
            opt::OptIter {
                inner: self.0.options.iter(),
            }
        }
    }

    impl std::ops::Deref for OPT {
        type Target = Edns;

        /// Borrow the underlying owned EDNS state.
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl std::ops::DerefMut for OPT {
        /// Mutably borrow the underlying owned EDNS state.
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    /// Simple wrapper types for name-based RDATA payloads.
    pub mod name {
        use super::Name;

        /// Owned CNAME target.
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct CNAME(pub Name);

        /// Owned NS target.
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct NS(pub Name);

        /// Owned PTR target.
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct PTR(pub Name);
    }

    pub use name::{CNAME, NS, PTR};

    /// EDNS option types and iterators for the owned message model.
    pub mod opt {
        use super::IpAddr;
        use crate::core::error::DnsError;
        use std::net::IpAddr::{V4, V6};
        use std::str::FromStr;

        /// EDNS option codes recognized by ForgeDNS.
        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
        pub enum EdnsCode {
            /// EDNS Client Subnet.
            Subnet,
            /// Any other option code preserved numerically.
            Unknown(u16),
        }

        impl From<u16> for EdnsCode {
            /// Convert a numeric EDNS option code into the owned enum.
            fn from(value: u16) -> Self {
                match value {
                    8 => Self::Subnet,
                    other => Self::Unknown(other),
                }
            }
        }

        impl From<EdnsCode> for u16 {
            /// Convert an owned EDNS code back into its numeric value.
            fn from(value: EdnsCode) -> Self {
                match value {
                    EdnsCode::Subnet => 8,
                    EdnsCode::Unknown(other) => other,
                }
            }
        }

        /// Owned ECS option payload.
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct ClientSubnet {
            /// Original client or preset subnet address.
            addr: IpAddr,
            /// Source prefix length in bits.
            source_prefix: u8,
            /// Scope prefix length in bits.
            scope_prefix: u8,
        }

        impl ClientSubnet {
            /// Construct a new owned ECS payload.
            pub fn new(addr: IpAddr, source_prefix: u8, scope_prefix: u8) -> Self {
                Self {
                    addr,
                    source_prefix,
                    scope_prefix,
                }
            }

            /// Return the subnet address.
            pub fn addr(&self) -> IpAddr {
                self.addr
            }

            /// Return the source prefix length.
            pub fn source_prefix(&self) -> u8 {
                self.source_prefix
            }

            /// Return the scope prefix length.
            pub fn scope_prefix(&self) -> u8 {
                self.scope_prefix
            }
        }

        impl FromStr for ClientSubnet {
            type Err = DnsError;

            /// Parse ECS presentation format such as `192.0.2.0/24`.
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let (addr_raw, prefix_raw) = s
                    .split_once('/')
                    .ok_or_else(|| DnsError::protocol("ecs subnet must use ip/prefix syntax"))?;
                let addr = addr_raw.parse::<IpAddr>().map_err(|e| {
                    DnsError::protocol(format!("invalid ecs ip '{}': {}", addr_raw, e))
                })?;
                let prefix = prefix_raw.parse::<u8>().map_err(|e| {
                    DnsError::protocol(format!("invalid ecs prefix '{}': {}", prefix_raw, e))
                })?;
                let max = match addr {
                    V4(_) => 32,
                    V6(_) => 128,
                };
                Ok(Self::new(addr, prefix.min(max), 0))
            }
        }

        /// Owned EDNS option payloads.
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub enum EdnsOption {
            /// Owned ECS option payload.
            Subnet(ClientSubnet),
            /// Opaque payload for unsupported option codes.
            Unknown(u16, Vec<u8>),
        }

        impl From<&EdnsOption> for EdnsCode {
            /// Derive the EDNS option code from an owned payload.
            fn from(value: &EdnsOption) -> Self {
                match value {
                    EdnsOption::Subnet(_) => EdnsCode::Subnet,
                    EdnsOption::Unknown(code, _) => EdnsCode::Unknown(*code),
                }
            }
        }

        impl From<EdnsOption> for EdnsCode {
            /// Derive the EDNS option code from an owned payload by value.
            fn from(value: EdnsOption) -> Self {
                Self::from(&value)
            }
        }

        /// Iterator over owned EDNS options with decoded codes.
        pub struct OptIter<'a> {
            /// Underlying slice iterator over stored options.
            pub(crate) inner: std::slice::Iter<'a, EdnsOption>,
        }

        impl<'a> Iterator for OptIter<'a> {
            type Item = (EdnsCode, &'a EdnsOption);

            /// Return the next option together with its decoded code.
            fn next(&mut self) -> Option<Self::Item> {
                let option = self.inner.next()?;
                Some((EdnsCode::from(option), option))
            }
        }
    }
}

pub use self::rdata::{A, AAAA, CNAME, Edns, MX, NS, OPT, PTR, SOA, TXT};
pub use self::rdata::{name, opt};

impl From<Ipv4Addr> for rdata::A {
    /// Convert an IPv4 address into an owned `A` payload.
    fn from(value: Ipv4Addr) -> Self {
        Self(value)
    }
}
