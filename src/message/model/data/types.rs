/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS class and record-type enums.

use crate::message::wire::constants::{
    TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_CNAME, TYPE_MX, TYPE_NS, TYPE_OPT, TYPE_PTR, TYPE_SOA,
    TYPE_TXT,
};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// DNS class values supported by ForgeDNS.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum DNSClass {
    /// Internet class.
    IN,
    /// Chaos class.
    CH,
    /// Any other class value preserved numerically.
    Unknown(u16),
}

impl From<u16> for DNSClass {
    /// Convert a numeric DNS class into the owned enum.
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            3 => Self::CH,
            other => Self::Unknown(other),
        }
    }
}

impl From<DNSClass> for u16 {
    /// Convert an owned DNS class back into its numeric wire value.
    fn from(value: DNSClass) -> Self {
        match value {
            DNSClass::IN => 1,
            DNSClass::CH => 3,
            DNSClass::Unknown(other) => other,
        }
    }
}

impl FromStr for DNSClass {
    type Err = String;

    /// Parse a textual DNS class name such as `IN` or `CH`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "IN" => Ok(Self::IN),
            "CH" => Ok(Self::CH),
            other => Err(format!("unsupported dns class '{}'", other)),
        }
    }
}

/// DNS record types supported by ForgeDNS.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum RecordType {
    /// IPv4 address record.
    A,
    /// Authoritative name server record.
    NS,
    /// Canonical name alias record.
    CNAME,
    /// Start of authority record.
    SOA,
    /// Reverse lookup pointer record.
    PTR,
    /// Mail exchanger record.
    MX,
    /// Text record.
    TXT,
    /// IPv6 address record.
    AAAA,
    /// EDNS OPT pseudo-record.
    OPT,
    /// Wildcard query type.
    ANY,
    /// Any other record type preserved numerically.
    Unknown(u16),
}

impl From<u16> for RecordType {
    /// Convert a numeric RR type into the owned enum.
    fn from(value: u16) -> Self {
        match value {
            TYPE_A => Self::A,
            TYPE_NS => Self::NS,
            TYPE_CNAME => Self::CNAME,
            TYPE_SOA => Self::SOA,
            TYPE_PTR => Self::PTR,
            TYPE_MX => Self::MX,
            TYPE_TXT => Self::TXT,
            TYPE_AAAA => Self::AAAA,
            TYPE_OPT => Self::OPT,
            TYPE_ANY => Self::ANY,
            other => Self::Unknown(other),
        }
    }
}

impl From<RecordType> for u16 {
    /// Convert an owned RR type back into its numeric wire value.
    fn from(value: RecordType) -> Self {
        match value {
            RecordType::A => TYPE_A,
            RecordType::NS => TYPE_NS,
            RecordType::CNAME => TYPE_CNAME,
            RecordType::SOA => TYPE_SOA,
            RecordType::PTR => TYPE_PTR,
            RecordType::MX => TYPE_MX,
            RecordType::TXT => TYPE_TXT,
            RecordType::AAAA => TYPE_AAAA,
            RecordType::OPT => TYPE_OPT,
            RecordType::ANY => TYPE_ANY,
            RecordType::Unknown(other) => other,
        }
    }
}

impl FromStr for RecordType {
    type Err = String;

    /// Parse a textual RR type such as `A` or `AAAA`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "NS" => Ok(Self::NS),
            "CNAME" => Ok(Self::CNAME),
            "SOA" => Ok(Self::SOA),
            "PTR" => Ok(Self::PTR),
            "MX" => Ok(Self::MX),
            "TXT" => Ok(Self::TXT),
            "AAAA" => Ok(Self::AAAA),
            "OPT" => Ok(Self::OPT),
            "ANY" => Ok(Self::ANY),
            other => Err(format!("unsupported record type '{}'", other)),
        }
    }
}

impl Display for RecordType {
    /// Format the RR type using presentation-format mnemonics where possible.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::A => f.write_str("A"),
            RecordType::NS => f.write_str("NS"),
            RecordType::CNAME => f.write_str("CNAME"),
            RecordType::SOA => f.write_str("SOA"),
            RecordType::PTR => f.write_str("PTR"),
            RecordType::MX => f.write_str("MX"),
            RecordType::TXT => f.write_str("TXT"),
            RecordType::AAAA => f.write_str("AAAA"),
            RecordType::OPT => f.write_str("OPT"),
            RecordType::ANY => f.write_str("ANY"),
            RecordType::Unknown(other) => write!(f, "TYPE{}", other),
        }
    }
}
