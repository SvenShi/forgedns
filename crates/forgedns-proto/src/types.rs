// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS enums used by the owned message model.

use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::core::error::{DnsError, Result as DnsResult};

/// DNS message direction.
#[derive(Debug, Eq, PartialEq, PartialOrd, Copy, Clone, Hash)]
pub enum MessageType {
    /// Query message sent by a client or intermediate resolver.
    Query,
    /// Response message sent back to the requester.
    Response,
}

/// DNS operation code.
#[derive(Debug, PartialEq, Eq, PartialOrd, Copy, Clone, Hash)]
#[allow(dead_code)]
pub enum Opcode {
    /// Query request [RFC 1035](https://tools.ietf.org/html/rfc1035)
    Query,

    /// Inverse query (obsolete) [RFC 3425]
    IQuery,

    /// Status message [RFC 1035](https://tools.ietf.org/html/rfc1035)
    Status,

    /// Notify of change [RFC 1996](https://tools.ietf.org/html/rfc1996)
    Notify,

    /// Update message [RFC 2136](https://tools.ietf.org/html/rfc2136)
    Update,

    /// Any other opcode
    Unknown(u8),
}

impl Display for Opcode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Query => f.write_str("QUERY"),
            Self::IQuery => f.write_str("IQUERY"),
            Self::Status => f.write_str("STATUS"),
            Self::Notify => f.write_str("NOTIFY"),
            Self::Update => f.write_str("UPDATE"),
            Self::Unknown(opcode) => write!(f, "Unknown opcode ({opcode})"),
        }
    }
}

/// Convert from `OpCode` to `u8`
impl From<Opcode> for u8 {
    fn from(rt: Opcode) -> Self {
        match rt {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            // 1	IQuery (Inverse Query, OBSOLETE)	[RFC3425]
            Opcode::Status => 2,
            // 3	Unassigned
            Opcode::Notify => 4,
            Opcode::Update => 5,
            // 6-15	Unassigned
            Opcode::Unknown(opcode) => opcode,
        }
    }
}

/// Convert from `u8` to `OpCode`
impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Eq, PartialEq, PartialOrd, Copy, Clone, Hash, Default)]
#[allow(dead_code)]
pub enum Rcode {
    /// No Error [RFC 1035](https://tools.ietf.org/html/rfc1035)
    #[default]
    NoError,

    /// Format Error [RFC 1035](https://tools.ietf.org/html/rfc1035)
    FormErr,

    /// Server Failure [RFC 1035](https://tools.ietf.org/html/rfc1035)
    ServFail,

    /// Non-Existent Domain [RFC 1035](https://tools.ietf.org/html/rfc1035)
    NXDomain,

    /// Not Implemented [RFC 1035](https://tools.ietf.org/html/rfc1035)
    NotImp,

    /// Query Refused [RFC 1035](https://tools.ietf.org/html/rfc1035)
    Refused,

    /// Name Exists when it should not [RFC 2136](https://tools.ietf.org/html/rfc2136)
    YXDomain,

    /// RR Set Exists when it should not [RFC 2136](https://tools.ietf.org/html/rfc2136)
    YXRRSet,

    /// RR Set that should exist does not [RFC 2136](https://tools.ietf.org/html/rfc2136)
    NXRRSet,

    /// Server Not Authoritative for zone [RFC 2136](https://tools.ietf.org/html/rfc2136)
    /// or Not Authorized [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    NotAuth,

    /// Name not contained in zone [RFC 2136](https://tools.ietf.org/html/rfc2136)
    NotZone,

    /// Bad OPT Version [RFC 6891](https://tools.ietf.org/html/rfc6891#section-9)
    BADVERS,

    /// TSIG Signature Failure [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    BADSIG,

    /// Key not recognized [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    BADKEY,

    /// Signature out of time window [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945)
    BADTIME,

    /// Bad TKEY Mode [RFC 2930](https://tools.ietf.org/html/rfc2930#section-2.6)
    BADMODE,

    /// Duplicate key name [RFC 2930](https://tools.ietf.org/html/rfc2930#section-2.6)
    BADNAME,

    /// Algorithm not supported [RFC 2930](https://tools.ietf.org/html/rfc2930#section-2.6)
    BADALG,

    /// Bad Truncation [RFC 4635](https://tools.ietf.org/html/rfc4635#section-4)
    BADTRUNC,

    /// Bad/missing Server Cookie [RFC 7873](https://datatracker.ietf.org/doc/html/rfc7873)
    BADCOOKIE,
    // 24-3840      Unassigned
    // 3841-4095    Reserved for Private Use                        [RFC6895]
    // 4096-65534   Unassigned
    // 65535        Reserved, can be allocated by Standards Action  [RFC6895]
    /// An unknown or unregistered response code was received.
    Unknown(u16),
}

impl Rcode {
    #[inline]
    pub fn value(self) -> u16 {
        u16::from(self)
    }

    #[inline]
    pub fn low(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NXDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::YXDomain => 6,
            Self::YXRRSet => 7,
            Self::NXRRSet => 8,
            Self::NotAuth => 9,
            Self::NotZone => 10,
            Self::BADVERS | Self::BADSIG => 0,
            Self::BADKEY => 1,
            Self::BADTIME => 2,
            Self::BADMODE => 3,
            Self::BADNAME => 4,
            Self::BADALG => 5,
            Self::BADTRUNC => 6,
            Self::BADCOOKIE => 7,
            Self::Unknown(code) => (code & 0x000F) as u8,
        }
    }

    #[inline]
    pub fn high(self) -> u8 {
        match self {
            Self::NoError
            | Self::FormErr
            | Self::ServFail
            | Self::NXDomain
            | Self::NotImp
            | Self::Refused
            | Self::YXDomain
            | Self::YXRRSet
            | Self::NXRRSet
            | Self::NotAuth
            | Self::NotZone => 0,
            Self::BADVERS | Self::BADSIG => 1,
            Self::BADKEY => 1,
            Self::BADTIME => 1,
            Self::BADMODE => 1,
            Self::BADNAME => 1,
            Self::BADALG => 1,
            Self::BADTRUNC => 1,
            Self::BADCOOKIE => 1,
            Self::Unknown(code) => ((code >> 4) & 0x00FF) as u8,
        }
    }

    #[inline]
    pub fn has_extended_bits(self) -> bool {
        self.high() != 0
    }

    #[inline]
    pub fn from_parts(high: u8, low: u8) -> Self {
        Self::from((u16::from(high) << 4) | u16::from(low & 0x0F))
    }

    /// Transforms the response code into the human message
    pub fn to_str(self) -> &'static str {
        match self {
            Self::NoError => "No Error",
            Self::FormErr => "Form Error", // 1     FormErr       Format Error
            // [RFC1035]
            Self::ServFail => "Server Failure", // 2     ServFail      Server Failure
            // [RFC1035]
            Self::NXDomain => "Non-Existent Domain", // 3     NXDomain      Non-Existent Domain
            // [RFC1035]
            Self::NotImp => "Not Implemented", // 4     NotImp        Not Implemented
            // [RFC1035]
            Self::Refused => "Query Refused", // 5     Refused       Query Refused
            // [RFC1035]
            Self::YXDomain => "Name should not exist", /* 6     YXDomain      Name Exists when it should not      [RFC2136][RFC6672] */
            Self::YXRRSet => "RR Set should not exist", // 7     YXRRSet       RR Set Exists when
            // it should not    [RFC2136]
            Self::NXRRSet => "RR Set does not exist", // 8     NXRRSet       RR Set that should
            // exist does not   [RFC2136]
            Self::NotAuth => "Not authorized", // 9     NotAuth       Server Not Authoritative
            // for zone   [RFC2136]
            Self::NotZone => "Name not in zone", // 10    NotZone       Name not contained in
            // zone          [RFC2136]
            Self::BADVERS => "Bad OPT Version",
            Self::BADSIG => "TSIG Signature Failure",
            Self::BADKEY => "Key not recognized", // 17    BADKEY        Key not recognized
            // [RFC2845]
            Self::BADTIME => "Signature out of time window", // 18    BADTIME       Signature
            // out of time window
            // [RFC2845]
            Self::BADMODE => "Bad TKEY mode", // 19    BADMODE       Bad TKEY Mode
            // [RFC2930]
            Self::BADNAME => "Duplicate key name", // 20    BADNAME       Duplicate key name
            // [RFC2930]
            Self::BADALG => "Algorithm not supported", // 21    BADALG        Algorithm not
            // supported             [RFC2930]
            Self::BADTRUNC => "Bad truncation", // 22    BADTRUNC      Bad Truncation
            // [RFC4635]
            Self::BADCOOKIE => "Bad server cookie", // 23    BADCOOKIE     Bad/missing Server
            // Cookie           [RFC7873]
            Self::Unknown(_) => "Unknown response code",
        }
    }
}

impl Display for Rcode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(self.to_str())
    }
}

impl From<u16> for Rcode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::NoError, // 0    NoError    No Error                             [RFC1035]
            1 => Self::FormErr, // 1    FormErr    Format Error                         [RFC1035]
            2 => Self::ServFail, // 2    ServFail   Server Failure                       [RFC1035]
            3 => Self::NXDomain, // 3    NXDomain   Non-Existent Domain                  [RFC1035]
            4 => Self::NotImp,  // 4    NotImp     Not Implemented                      [RFC1035]
            5 => Self::Refused, // 5    Refused    Query Refused                        [RFC1035]
            6 => Self::YXDomain, // 6    YXDomain   Name Exists when it should not
            // [RFC2136][RFC6672]
            7 => Self::YXRRSet, // 7    YXRRSet    RR Set Exists when it should not     [RFC2136]
            8 => Self::NXRRSet, // 8    NXRRSet    RR Set that should exist does not    [RFC2136]
            9 => Self::NotAuth, // 9    NotAuth    Server Not Authoritative for zone    [RFC2136]
            10 => Self::NotZone, // 10   NotZone    Name not contained in zone           [RFC2136]
            16 => Self::BADVERS, // 16    BADVERS/BADSIG context-dependent; default to EDNS BADVERS
            17 => Self::BADKEY, // 17    BADKEY    Key not recognized                   [RFC2845]
            18 => Self::BADTIME, // 18    BADTIME   Signature out of time window         [RFC2845]
            19 => Self::BADMODE, // 19    BADMODE   Bad TKEY Mode                        [RFC2930]
            20 => Self::BADNAME, // 20    BADNAME   Duplicate key name                   [RFC2930]
            21 => Self::BADALG, // 21    BADALG    Algorithm not supported              [RFC2930]
            22 => Self::BADTRUNC, // 22    BADTRUNC  Bad Truncation                       [RFC4635]
            23 => Self::BADCOOKIE, // 23    BADCOOKIE Bad/missing Server Cookie            [RFC7873]
            code => Self::Unknown(code),
        }
    }
}

impl From<Rcode> for u16 {
    fn from(rt: Rcode) -> Self {
        match rt {
            Rcode::NoError => 0, // 0   NoError    No Error                              [RFC1035]
            Rcode::FormErr => 1, // 1   FormErr    Format Error                          [RFC1035]
            Rcode::ServFail => 2, // 2   ServFail   Server Failure                        [RFC1035]
            Rcode::NXDomain => 3, // 3   NXDomain   Non-Existent Domain                   [RFC1035]
            Rcode::NotImp => 4,  // 4   NotImp     Not Implemented                       [RFC1035]
            Rcode::Refused => 5, // 5   Refused    Query Refused                         [RFC1035]
            Rcode::YXDomain => 6, // 6   YXDomain   Name Exists when it should not
            // [RFC2136][RFC6672]
            Rcode::YXRRSet => 7, // 7   YXRRSet    RR Set Exists when it should not      [RFC2136]
            Rcode::NXRRSet => 8, // 8   NXRRSet    RR Set that should exist does not     [RFC2136]
            Rcode::NotAuth => 9, // 9   NotAuth    Server Not Authoritative for zone     [RFC2136]
            Rcode::NotZone => 10, // 10  NotZone    Name not contained in zone            [RFC2136]
            // 11-15    Unassigned
            //
            // 16  BADVERS  Bad OPT Version         [RFC6891]
            // 16  BADSIG   TSIG Signature Failure  [RFC2845]
            Rcode::BADVERS | Rcode::BADSIG => 16,
            Rcode::BADKEY => 17, // 17  BADKEY    Key not recognized                     [RFC2845]
            Rcode::BADTIME => 18, // 18  BADTIME   Signature out of time window           [RFC2845]
            Rcode::BADMODE => 19, // 19  BADMODE   Bad TKEY Mode                          [RFC2930]
            Rcode::BADNAME => 20, // 20  BADNAME   Duplicate key name                     [RFC2930]
            Rcode::BADALG => 21, // 21  BADALG    Algorithm not supported                [RFC2930]
            Rcode::BADTRUNC => 22, // 22  BADTRUNC  Bad Truncation                         [RFC4635]
            Rcode::BADCOOKIE => 23, // 23  BADCOOKIE Bad/missing Server Cookie
            // [RFC7873]
            Rcode::Unknown(code) => code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rcode;

    #[test]
    fn rcode_parts_roundtrip_matches_known_layout() {
        assert_eq!(Rcode::NoError.low(), 0);
        assert_eq!(Rcode::NoError.high(), 0);
        assert!(!Rcode::NoError.has_extended_bits());

        assert_eq!(Rcode::BADVERS.low(), 0);
        assert_eq!(Rcode::BADVERS.high(), 1);
        assert!(Rcode::BADVERS.has_extended_bits());

        assert_eq!(Rcode::Unknown(0x03AF).low(), 0x0F);
        assert_eq!(Rcode::Unknown(0x03AF).high(), 0x3A);
        assert_eq!(Rcode::from_parts(0x3A, 0x0F), Rcode::Unknown(0x03AF));
        assert_eq!(Rcode::from_parts(1, 0), Rcode::BADVERS);
    }
}

/// DNS class values supported by ForgeDNS.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[allow(dead_code)]
pub enum DNSClass {
    /// Internet
    IN,
    /// CSNET
    CS,
    /// Chaos
    CH,
    /// Hesiod
    HS,
    /// QCLASS NONE
    NONE,
    /// QCLASS * (ANY)
    ANY,
    /// Special class for OPT Version, it was overloaded for EDNS - RFC 6891
    /// From the RFC: `Values lower than 512 MUST be treated as equal to 512`
    OPT(u16),
    /// Unknown DNSClass was parsed
    Unknown(u16),
}

impl FromStr for DNSClass {
    type Err = DnsError;

    fn from_str(str: &str) -> DnsResult<Self> {
        debug_assert!(str.chars().all(|x| !char::is_ascii_lowercase(&x)));
        match str {
            "IN" => Ok(Self::IN),
            "CS" => Ok(Self::CS),
            "CH" => Ok(Self::CH),
            "HS" => Ok(Self::HS),
            "NONE" => Ok(Self::NONE),
            "ANY" | "*" => Ok(Self::ANY),
            _ => Err(DnsError::UnknownDnsClassStr(str.to_string())),
        }
    }
}
impl From<u16> for DNSClass {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            254 => Self::NONE,
            255 => Self::ANY,
            _ => Self::Unknown(value),
        }
    }
}

impl From<DNSClass> for u16 {
    fn from(rt: DNSClass) -> Self {
        match rt {
            DNSClass::IN => 1,
            DNSClass::CS => 2,
            DNSClass::CH => 3,
            DNSClass::HS => 4,
            DNSClass::NONE => 254,
            DNSClass::ANY => 255,
            // see https://tools.ietf.org/html/rfc6891#section-6.1.2
            DNSClass::OPT(max_payload_len) => max_payload_len.max(512),
            DNSClass::Unknown(unknown) => unknown,
        }
    }
}

impl DNSClass {
    /// Return the OPT version from value
    pub fn for_opt(value: u16) -> Self {
        // From RFC 6891: `Values lower than 512 MUST be treated as equal to 512`
        let value = value.max(512);
        Self::OPT(value)
    }
}

/// Convert from `DNSClass` to `&str`
impl From<DNSClass> for &'static str {
    fn from(rt: DNSClass) -> &'static str {
        match rt {
            DNSClass::IN => "IN",
            DNSClass::CS => "CS",
            DNSClass::CH => "CH",
            DNSClass::HS => "HS",
            DNSClass::NONE => "NONE",
            DNSClass::ANY => "ANY",
            DNSClass::OPT(_) => "OPT",
            DNSClass::Unknown(..) => "UNKNOWN",
        }
    }
}
impl Display for DNSClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(Into::<&str>::into(*self))
    }
}

/// The type of the resource record.
///
/// This specifies the type of data in the RData field of the Resource Record
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[allow(dead_code)]
pub enum RecordType {
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) IPv4 Address record
    A,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Name server record
    NS,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mail destination record (obsolete)
    MD,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mail forwarder record (obsolete)
    MF,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Canonical name record
    CNAME,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) and [RFC 2308](https://tools.ietf.org/html/rfc2308) Start of [a zone of] authority record
    SOA,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mailbox domain name (experimental)
    MB,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mail group member (experimental)
    MG,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mail rename domain name (experimental)
    MR,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Null server record, for testing
    NULL,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Well-known services
    WKS,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Pointer record
    PTR,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) host information
    HINFO,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mailbox or mail list information
    MINFO,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mail exchange record
    MX,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Text record
    TXT,
    /// [RFC 1183](https://tools.ietf.org/html/rfc1183) Responsible person
    RP,
    /// [RFC 1183](https://tools.ietf.org/html/rfc1183) AFS database server
    AFSDB,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) X.25 PSDN address
    X25,
    /// [RFC 1706](https://tools.ietf.org/html/rfc1706) NSAP address
    NSAP,
    /// [RFC 1183](https://tools.ietf.org/html/rfc1183) ISDN address
    ISDN,
    /// [RFC 1183](https://tools.ietf.org/html/rfc1183) Route through record
    RT,
    /// [RFC 2673](https://tools.ietf.org/html/rfc2673) Endpoint identifier
    EID,
    /// [RFC 2673](https://tools.ietf.org/html/rfc2673) Nimrod locator
    NIMLOC,
    /// [RFC 1706](https://tools.ietf.org/html/rfc1706) NSAP-PTR record
    NSAPPTR,
    /// [RFC 2535](https://tools.ietf.org/html/rfc2535) (and [RFC 2931](https://tools.ietf.org/html/rfc2931)) Signature, to support [RFC 2137](https://tools.ietf.org/html/rfc2137) Update
    SIG,
    /// [RFC 2535](https://tools.ietf.org/html/rfc2535) and [RFC 2930](https://tools.ietf.org/html/rfc2930) Key record
    KEY,
    /// [RFC 2163](https://tools.ietf.org/html/rfc2163) X.400 mail mapping
    PX,
    /// [RFC 1712](https://tools.ietf.org/html/rfc1712) Geographical position
    GPOS,
    /// [RFC 3596](https://tools.ietf.org/html/rfc3596) IPv6 address record
    AAAA,
    /// [RFC 1876](https://tools.ietf.org/html/rfc1876) Location record
    LOC,
    /// [RFC 2535](https://tools.ietf.org/html/rfc2535) Next domain record (obsolete)
    NXT,
    /// [RFC 2672](https://tools.ietf.org/html/rfc2672) Service locator
    SRV,
    /// [RFC 3403](https://tools.ietf.org/html/rfc3403) Naming Authority Pointer
    NAPTR,
    /// [RFC 2230](https://tools.ietf.org/html/rfc2230) Key exchanger
    KX,
    /// [RFC 4398](https://tools.ietf.org/html/rfc4398) Storing Certificates in the Domain Name System (DNS)
    CERT,
    /// [RFC 2648](https://tools.ietf.org/html/rfc2648) ATM address
    ATMA,
    /// [RFC 2874](https://tools.ietf.org/html/rfc2874) A6 IPv6 address (historic)
    A6,
    /// [RFC 2535](https://tools.ietf.org/html/rfc2535) Kitchen sink (obsolete)
    SINK,
    /// [RFC 6672](https://tools.ietf.org/html/rfc6672) Delegation name
    DNAME,
    /// [RFC 6891](https://tools.ietf.org/html/rfc6891) Option
    OPT,
    /// [RFC 3123](https://tools.ietf.org/html/rfc3123) Address Prefix List
    APL,
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) Delegation signer
    DS,
    /// [RFC 4255](https://tools.ietf.org/html/rfc4255) SSH Public Key Fingerprint
    SSHFP,
    /// [RFC 4025](https://tools.ietf.org/html/rfc4025) IPsec Key
    IPSECKEY,
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) DNSSEC signature
    RRSIG,
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) Next-Secure record
    NSEC,
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) DNS Key record
    DNSKEY,
    /// [RFC 4701](https://tools.ietf.org/html/rfc4701) DHCP identifier
    DHCID,
    /// [RFC 5155](https://tools.ietf.org/html/rfc5155) NSEC record version 3
    NSEC3,
    /// [RFC 5155](https://tools.ietf.org/html/rfc5155) NSEC3 parameters
    NSEC3PARAM,
    /// [RFC 6698](https://tools.ietf.org/html/rfc6698) TLSA certificate association
    TLSA,
    /// [RFC 8162](https://tools.ietf.org/html/rfc8162) S/MIME cert association
    SMIMEA,
    /// [RFC 5205](https://tools.ietf.org/html/rfc5205) Host Identity Protocol
    HIP,
    /// [RFC 3755](https://tools.ietf.org/html/rfc3755) no implementation
    NINFO,
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) reserved key record
    RKEY,
    /// [RFC 4034](https://tools.ietf.org/html/rfc4034) trust anchor linkage
    TALINK,
    /// [RFC 7344](https://tools.ietf.org/html/rfc7344) Child DS
    CDS,
    /// [RFC 7344](https://tools.ietf.org/html/rfc7344) Child DNSKEY
    CDNSKEY,
    /// [RFC 7929](https://tools.ietf.org/html/rfc7929) OpenPGP public key
    OPENPGPKEY,
    /// [RFC 7477](https://tools.ietf.org/html/rfc7477) Child-to-parent synchronization record
    CSYNC,
    /// [RFC 8976](https://tools.ietf.org/html/rfc8976) Message digest for DNS zones
    ZONEMD,
    /// [RFC 9460](https://tools.ietf.org/html/rfc9460) DNS SVCB and HTTPS RRs
    SVCB,
    /// [RFC 9460](https://tools.ietf.org/html/rfc9460) DNS SVCB and HTTPS RRs
    HTTPS,
    /// [RFC 7208](https://tools.ietf.org/html/rfc7208) Sender Policy Framework
    SPF,
    /// [RFC 1712](https://tools.ietf.org/html/rfc1712) User information
    UINFO,
    /// [RFC 1712](https://tools.ietf.org/html/rfc1712) User ID
    UID,
    /// [RFC 1712](https://tools.ietf.org/html/rfc1712) Group ID
    GID,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Binary unspecified payload
    UNSPEC,
    /// [RFC 6742](https://tools.ietf.org/html/rfc6742) ILNP node identifier
    NID,
    /// [RFC 6742](https://tools.ietf.org/html/rfc6742) ILNP 32-bit locator
    L32,
    /// [RFC 6742](https://tools.ietf.org/html/rfc6742) ILNP 64-bit locator
    L64,
    /// [RFC 6742](https://tools.ietf.org/html/rfc6742) ILNP locator pointer
    LP,
    /// [RFC 7043](https://tools.ietf.org/html/rfc7043) EUI-48 address
    EUI48,
    /// [RFC 7043](https://tools.ietf.org/html/rfc7043) EUI-64 address
    EUI64,
    /// [draft-ietf-dnsop-aname](https://tools.ietf.org/html/draft-ietf-dnsop-aname-04) ANAME pseudo-record
    ANAME,
    /// [RFC 7553](https://tools.ietf.org/html/rfc7553) URI record
    URI,
    /// [RFC 6844](https://tools.ietf.org/html/rfc6844) Certification Authority Authorization
    CAA,
    /// [RFC 6844](https://tools.ietf.org/html/rfc6844) Application visibility and control
    AVC,
    /// [RFC 8490](https://tools.ietf.org/html/rfc8490) Digital object architecture
    DOA,
    /// [RFC 8777](https://tools.ietf.org/html/rfc8777) Automatic multicast tunneling relay
    AMTRELAY,
    /// [RFC 9606](https://tools.ietf.org/html/rfc9606) Resolver information
    RESINFO,
    /// [RFC 2930](https://tools.ietf.org/html/rfc2930) Secret key record
    TKEY,
    /// [RFC 8945](https://tools.ietf.org/html/rfc8945) Transaction Signature
    TSIG,
    /// [RFC 1995](https://tools.ietf.org/html/rfc1995) Incremental Zone Transfer
    IXFR,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Authoritative Zone Transfer
    AXFR,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mailbox-related records (obsolete)
    MAILB,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Mail agent records (obsolete)
    MAILA,
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035) All cached records, aka ANY
    ANY,
    /// [RFC 6895](https://www.rfc-editor.org/rfc/rfc6895) DNSSEC trust anchor
    TA,
    /// [RFC 4431](https://tools.ietf.org/html/rfc4431) DNSSEC lookaside validation
    DLV,
    /// Unknown Record type, or unsupported
    Unknown(u16),

    /// This corresponds to a record type of 0, unspecified
    ZERO,
}

impl From<u16> for RecordType {
    /// Convert from `u16` to `RecordType`
    fn from(value: u16) -> Self {
        match value {
            0 => Self::ZERO,
            1 => Self::A,
            2 => Self::NS,
            3 => Self::MD,
            4 => Self::MF,
            5 => Self::CNAME,
            6 => Self::SOA,
            7 => Self::MB,
            8 => Self::MG,
            9 => Self::MR,
            10 => Self::NULL,
            11 => Self::WKS,
            12 => Self::PTR,
            13 => Self::HINFO,
            14 => Self::MINFO,
            15 => Self::MX,
            16 => Self::TXT,
            17 => Self::RP,
            18 => Self::AFSDB,
            19 => Self::X25,
            22 => Self::NSAP,
            20 => Self::ISDN,
            21 => Self::RT,
            31 => Self::EID,
            32 => Self::NIMLOC,
            23 => Self::NSAPPTR,
            24 => Self::SIG,
            25 => Self::KEY,
            26 => Self::PX,
            27 => Self::GPOS,
            28 => Self::AAAA,
            29 => Self::LOC,
            30 => Self::NXT,
            33 => Self::SRV,
            35 => Self::NAPTR,
            36 => Self::KX,
            37 => Self::CERT,
            34 => Self::ATMA,
            38 => Self::A6,
            40 => Self::SINK,
            39 => Self::DNAME,
            41 => Self::OPT,
            42 => Self::APL,
            43 => Self::DS,
            44 => Self::SSHFP,
            45 => Self::IPSECKEY,
            46 => Self::RRSIG,
            47 => Self::NSEC,
            48 => Self::DNSKEY,
            49 => Self::DHCID,
            50 => Self::NSEC3,
            51 => Self::NSEC3PARAM,
            52 => Self::TLSA,
            53 => Self::SMIMEA,
            55 => Self::HIP,
            56 => Self::NINFO,
            57 => Self::RKEY,
            58 => Self::TALINK,
            59 => Self::CDS,
            60 => Self::CDNSKEY,
            61 => Self::OPENPGPKEY,
            62 => Self::CSYNC,
            63 => Self::ZONEMD,
            64 => Self::SVCB,
            65 => Self::HTTPS,
            99 => Self::SPF,
            100 => Self::UINFO,
            101 => Self::UID,
            102 => Self::GID,
            103 => Self::UNSPEC,
            104 => Self::NID,
            105 => Self::L32,
            106 => Self::L64,
            107 => Self::LP,
            108 => Self::EUI48,
            109 => Self::EUI64,
            249 => Self::TKEY,
            250 => Self::TSIG,
            251 => Self::IXFR,
            252 => Self::AXFR,
            253 => Self::MAILB,
            254 => Self::MAILA,
            255 => Self::ANY,
            256 => Self::URI,
            257 => Self::CAA,
            258 => Self::AVC,
            259 => Self::DOA,
            260 => Self::AMTRELAY,
            261 => Self::RESINFO,
            32768 => Self::TA,
            32769 => Self::DLV,
            65305 => Self::ANAME,
            _ => Self::Unknown(value),
        }
    }
}
impl From<RecordType> for u16 {
    fn from(rt: RecordType) -> Self {
        match rt {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::MD => 3,
            RecordType::MF => 4,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::MB => 7,
            RecordType::MG => 8,
            RecordType::MR => 9,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MINFO => 14,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::RP => 17,
            RecordType::AFSDB => 18,
            RecordType::X25 => 19,
            RecordType::NSAP => 22,
            RecordType::ISDN => 20,
            RecordType::RT => 21,
            RecordType::EID => 31,
            RecordType::NIMLOC => 32,
            RecordType::NSAPPTR => 23,
            RecordType::SIG => 24,
            RecordType::KEY => 25,
            RecordType::PX => 26,
            RecordType::GPOS => 27,
            RecordType::AAAA => 28,
            RecordType::LOC => 29,
            RecordType::NXT => 30,
            RecordType::SRV => 33,
            RecordType::NAPTR => 35,
            RecordType::KX => 36,
            RecordType::CERT => 37,
            RecordType::ATMA => 34,
            RecordType::A6 => 38,
            RecordType::SINK => 40,
            RecordType::DNAME => 39,
            RecordType::OPT => 41,
            RecordType::APL => 42,
            RecordType::DS => 43,
            RecordType::SSHFP => 44,
            RecordType::IPSECKEY => 45,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::DHCID => 49,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::TLSA => 52,
            RecordType::SMIMEA => 53,
            RecordType::HIP => 55,
            RecordType::NINFO => 56,
            RecordType::RKEY => 57,
            RecordType::TALINK => 58,
            RecordType::CDS => 59,
            RecordType::CDNSKEY => 60,
            RecordType::OPENPGPKEY => 61,
            RecordType::CSYNC => 62,
            RecordType::ZONEMD => 63,
            RecordType::SVCB => 64,
            RecordType::HTTPS => 65,
            RecordType::SPF => 99,
            RecordType::UINFO => 100,
            RecordType::UID => 101,
            RecordType::GID => 102,
            RecordType::UNSPEC => 103,
            RecordType::NID => 104,
            RecordType::L32 => 105,
            RecordType::L64 => 106,
            RecordType::LP => 107,
            RecordType::EUI48 => 108,
            RecordType::EUI64 => 109,
            RecordType::ANAME => 65305,
            RecordType::URI => 256,
            RecordType::CAA => 257,
            RecordType::AVC => 258,
            RecordType::DOA => 259,
            RecordType::AMTRELAY => 260,
            RecordType::RESINFO => 261,
            RecordType::TKEY => 249,
            RecordType::TSIG => 250,
            RecordType::IXFR => 251,
            RecordType::AXFR => 252,
            RecordType::MAILB => 253,
            RecordType::MAILA => 254,
            RecordType::ANY => 255,
            RecordType::TA => 32768,
            RecordType::DLV => 32769,
            RecordType::ZERO => 0,
            RecordType::Unknown(code) => code,
        }
    }
}

impl FromStr for RecordType {
    type Err = DnsError;

    /// Convert `&str` to `RecordType`
    fn from_str(str: &str) -> DnsResult<Self> {
        match str {
            "A" => Ok(Self::A),
            "NS" => Ok(Self::NS),
            "MD" => Ok(Self::MD),
            "MF" => Ok(Self::MF),
            "CNAME" => Ok(Self::CNAME),
            "SOA" => Ok(Self::SOA),
            "MB" => Ok(Self::MB),
            "MG" => Ok(Self::MG),
            "MR" => Ok(Self::MR),
            "NULL" => Ok(Self::NULL),
            "WKS" => Ok(Self::WKS),
            "PTR" => Ok(Self::PTR),
            "HINFO" => Ok(Self::HINFO),
            "MINFO" => Ok(Self::MINFO),
            "MX" => Ok(Self::MX),
            "TXT" => Ok(Self::TXT),
            "RP" => Ok(Self::RP),
            "AFSDB" => Ok(Self::AFSDB),
            "X25" => Ok(Self::X25),
            "NSAP" => Ok(Self::NSAP),
            "ISDN" => Ok(Self::ISDN),
            "RT" => Ok(Self::RT),
            "EID" => Ok(Self::EID),
            "NIMLOC" => Ok(Self::NIMLOC),
            "NSAPPTR" => Ok(Self::NSAPPTR),
            "SIG" => Ok(Self::SIG),
            "KEY" => Ok(Self::KEY),
            "PX" => Ok(Self::PX),
            "GPOS" => Ok(Self::GPOS),
            "AAAA" => Ok(Self::AAAA),
            "LOC" => Ok(Self::LOC),
            "NXT" => Ok(Self::NXT),
            "SRV" => Ok(Self::SRV),
            "NAPTR" => Ok(Self::NAPTR),
            "KX" => Ok(Self::KX),
            "CERT" => Ok(Self::CERT),
            "ATMA" => Ok(Self::ATMA),
            "A6" => Ok(Self::A6),
            "SINK" => Ok(Self::SINK),
            "DNAME" => Ok(Self::DNAME),
            "OPT" => Ok(Self::OPT),
            "APL" => Ok(Self::APL),
            "DS" => Ok(Self::DS),
            "SSHFP" => Ok(Self::SSHFP),
            "IPSECKEY" => Ok(Self::IPSECKEY),
            "RRSIG" => Ok(Self::RRSIG),
            "NSEC" => Ok(Self::NSEC),
            "DNSKEY" => Ok(Self::DNSKEY),
            "DHCID" => Ok(Self::DHCID),
            "NSEC3" => Ok(Self::NSEC3),
            "NSEC3PARAM" => Ok(Self::NSEC3PARAM),
            "TLSA" => Ok(Self::TLSA),
            "SMIMEA" => Ok(Self::SMIMEA),
            "HIP" => Ok(Self::HIP),
            "NINFO" => Ok(Self::NINFO),
            "RKEY" => Ok(Self::RKEY),
            "TALINK" => Ok(Self::TALINK),
            "CDS" => Ok(Self::CDS),
            "CDNSKEY" => Ok(Self::CDNSKEY),
            "OPENPGPKEY" => Ok(Self::OPENPGPKEY),
            "CSYNC" => Ok(Self::CSYNC),
            "ZONEMD" => Ok(Self::ZONEMD),
            "SVCB" => Ok(Self::SVCB),
            "HTTPS" => Ok(Self::HTTPS),
            "SPF" => Ok(Self::SPF),
            "UINFO" => Ok(Self::UINFO),
            "UID" => Ok(Self::UID),
            "GID" => Ok(Self::GID),
            "UNSPEC" => Ok(Self::UNSPEC),
            "NID" => Ok(Self::NID),
            "L32" => Ok(Self::L32),
            "L64" => Ok(Self::L64),
            "LP" => Ok(Self::LP),
            "EUI48" => Ok(Self::EUI48),
            "EUI64" => Ok(Self::EUI64),
            "ANAME" => Ok(Self::ANAME),
            "URI" => Ok(Self::URI),
            "CAA" => Ok(Self::CAA),
            "AVC" => Ok(Self::AVC),
            "DOA" => Ok(Self::DOA),
            "AMTRELAY" => Ok(Self::AMTRELAY),
            "RESINFO" => Ok(Self::RESINFO),
            "TKEY" => Ok(Self::TKEY),
            "TSIG" => Ok(Self::TSIG),
            "IXFR" => Ok(Self::IXFR),
            "AXFR" => Ok(Self::AXFR),
            "MAILB" => Ok(Self::MAILB),
            "MAILA" => Ok(Self::MAILA),
            "ANY" | "*" => Ok(Self::ANY),
            "TA" => Ok(Self::TA),
            "DLV" => Ok(Self::DLV),
            _ => Err(DnsError::UnknownRecordTypeStr(str.to_string())),
        }
    }
}

/// Convert from `RecordType` to `&str`
impl From<RecordType> for &'static str {
    fn from(rt: RecordType) -> &'static str {
        match rt {
            RecordType::A => "A",
            RecordType::NS => "NS",
            RecordType::MD => "MD",
            RecordType::MF => "MF",
            RecordType::CNAME => "CNAME",
            RecordType::SOA => "SOA",
            RecordType::MB => "MB",
            RecordType::MG => "MG",
            RecordType::MR => "MR",
            RecordType::NULL => "NULL",
            RecordType::WKS => "WKS",
            RecordType::PTR => "PTR",
            RecordType::HINFO => "HINFO",
            RecordType::MINFO => "MINFO",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::RP => "RP",
            RecordType::AFSDB => "AFSDB",
            RecordType::X25 => "X25",
            RecordType::NSAP => "NSAP",
            RecordType::ISDN => "ISDN",
            RecordType::RT => "RT",
            RecordType::EID => "EID",
            RecordType::NIMLOC => "NIMLOC",
            RecordType::NSAPPTR => "NSAPPTR",
            RecordType::SIG => "SIG",
            RecordType::KEY => "KEY",
            RecordType::PX => "PX",
            RecordType::GPOS => "GPOS",
            RecordType::AAAA => "AAAA",
            RecordType::LOC => "LOC",
            RecordType::NXT => "NXT",
            RecordType::SRV => "SRV",
            RecordType::NAPTR => "NAPTR",
            RecordType::KX => "KX",
            RecordType::CERT => "CERT",
            RecordType::ATMA => "ATMA",
            RecordType::A6 => "A6",
            RecordType::SINK => "SINK",
            RecordType::DNAME => "DNAME",
            RecordType::OPT => "OPT",
            RecordType::APL => "APL",
            RecordType::DS => "DS",
            RecordType::SSHFP => "SSHFP",
            RecordType::IPSECKEY => "IPSECKEY",
            RecordType::RRSIG => "RRSIG",
            RecordType::NSEC => "NSEC",
            RecordType::DNSKEY => "DNSKEY",
            RecordType::DHCID => "DHCID",
            RecordType::NSEC3 => "NSEC3",
            RecordType::NSEC3PARAM => "NSEC3PARAM",
            RecordType::TLSA => "TLSA",
            RecordType::SMIMEA => "SMIMEA",
            RecordType::HIP => "HIP",
            RecordType::NINFO => "NINFO",
            RecordType::RKEY => "RKEY",
            RecordType::TALINK => "TALINK",
            RecordType::CDS => "CDS",
            RecordType::CDNSKEY => "CDNSKEY",
            RecordType::OPENPGPKEY => "OPENPGPKEY",
            RecordType::CSYNC => "CSYNC",
            RecordType::ZONEMD => "ZONEMD",
            RecordType::SVCB => "SVCB",
            RecordType::HTTPS => "HTTPS",
            RecordType::SPF => "SPF",
            RecordType::UINFO => "UINFO",
            RecordType::UID => "UID",
            RecordType::GID => "GID",
            RecordType::UNSPEC => "UNSPEC",
            RecordType::NID => "NID",
            RecordType::L32 => "L32",
            RecordType::L64 => "L64",
            RecordType::LP => "LP",
            RecordType::EUI48 => "EUI48",
            RecordType::EUI64 => "EUI64",
            RecordType::ANAME => "ANAME",
            RecordType::URI => "URI",
            RecordType::CAA => "CAA",
            RecordType::AVC => "AVC",
            RecordType::DOA => "DOA",
            RecordType::AMTRELAY => "AMTRELAY",
            RecordType::RESINFO => "RESINFO",
            RecordType::TKEY => "TKEY",
            RecordType::TSIG => "TSIG",
            RecordType::IXFR => "IXFR",
            RecordType::AXFR => "AXFR",
            RecordType::MAILB => "MAILB",
            RecordType::MAILA => "MAILA",
            RecordType::ANY => "ANY",
            RecordType::TA => "TA",
            RecordType::DLV => "DLV",
            RecordType::ZERO => "ZERO",
            RecordType::Unknown(_) => "Unknown",
        }
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(Into::<&str>::into(*self))
    }
}
