/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::proto::Name;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KX {
    preference: u16,
    exchanger: Name,
}
impl KX {
    pub fn new(preference: u16, exchanger: Name) -> Self {
        Self {
            preference,
            exchanger,
        }
    }
    pub fn preference(&self) -> u16 {
        self.preference
    }
    pub fn exchanger(&self) -> &Name {
        &self.exchanger
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NID {
    preference: u16,
    node_id: u64,
}
impl NID {
    pub fn new(preference: u16, node_id: u64) -> Self {
        Self {
            preference,
            node_id,
        }
    }
    pub fn preference(&self) -> u16 {
        self.preference
    }
    pub fn node_id(&self) -> u64 {
        self.node_id
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct L32 {
    preference: u16,
    locator: Ipv4Addr,
}
impl L32 {
    pub fn new(preference: u16, locator: Ipv4Addr) -> Self {
        Self {
            preference,
            locator,
        }
    }
    pub fn preference(&self) -> u16 {
        self.preference
    }
    pub fn locator(&self) -> Ipv4Addr {
        self.locator
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct L64 {
    preference: u16,
    locator: u64,
}
impl L64 {
    pub fn new(preference: u16, locator: u64) -> Self {
        Self {
            preference,
            locator,
        }
    }
    pub fn preference(&self) -> u16 {
        self.preference
    }
    pub fn locator(&self) -> u64 {
        self.locator
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LP {
    preference: u16,
    fqdn: Name,
}
impl LP {
    pub fn new(preference: u16, fqdn: Name) -> Self {
        Self { preference, fqdn }
    }
    pub fn preference(&self) -> u16 {
        self.preference
    }
    pub fn fqdn(&self) -> &Name {
        &self.fqdn
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EUI48(pub u64);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EUI64(pub u64);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct URI {
    priority: u16,
    weight: u16,
    target: Box<[u8]>,
}
impl URI {
    pub fn new(priority: u16, weight: u16, target: Box<[u8]>) -> Self {
        Self {
            priority,
            weight,
            target,
        }
    }
    pub fn priority(&self) -> u16 {
        self.priority
    }
    pub fn weight(&self) -> u16 {
        self.weight
    }
    pub fn target(&self) -> &[u8] {
        &self.target
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IPSECKEY {
    precedence: u8,
    gateway_type: u8,
    algorithm: u8,
    gateway: Box<[u8]>,
    public_key: Box<[u8]>,
}
impl IPSECKEY {
    pub fn new(
        precedence: u8,
        gateway_type: u8,
        algorithm: u8,
        gateway: Box<[u8]>,
        public_key: Box<[u8]>,
    ) -> Self {
        Self {
            precedence,
            gateway_type,
            algorithm,
            gateway,
            public_key,
        }
    }
    pub fn precedence(&self) -> u8 {
        self.precedence
    }
    pub fn gateway_type(&self) -> u8 {
        self.gateway_type
    }
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }
    pub fn gateway(&self) -> &[u8] {
        &self.gateway
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SvcParam {
    key: u16,
    value: Box<[u8]>,
    parsed: SvcParamValue,
}
impl SvcParam {
    /// Construct one SvcParam from already-decoded wire bytes.
    ///
    /// The raw `value` is retained exactly as supplied so encode roundtrips can preserve
    /// unknown data, while `parsed` eagerly records a structured interpretation for the
    /// well-known keys defined by RFC 9460.
    pub fn new(key: u16, value: Box<[u8]>) -> Self {
        let parsed = SvcParamValue::from_wire(key, &value);
        Self { key, value, parsed }
    }
    /// Return the numeric SvcParamKey.
    pub fn key(&self) -> u16 {
        self.key
    }
    /// Return the original wire value bytes for this parameter.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    /// Return the structured interpretation of `value` for known keys.
    pub fn parsed(&self) -> &SvcParamValue {
        &self.parsed
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SvcParamValue {
    Mandatory(Vec<u16>),
    Alpn(Vec<Box<[u8]>>),
    NoDefaultAlpn,
    Port(u16),
    Ipv4Hint(Vec<Ipv4Addr>),
    Ech(Box<[u8]>),
    Ipv6Hint(Vec<Ipv6Addr>),
    DohPath(Box<[u8]>),
    Ohttp,
    Unknown,
}

impl SvcParamValue {
    /// Decode one SvcParam payload using the key-specific wire rules from RFC 9460.
    ///
    /// Unknown keys, malformed payloads, and known keys with invalid lengths are mapped
    /// to `Unknown` so the owned model can preserve raw bytes without pretending the
    /// payload was semantically understood.
    fn from_wire(key: u16, value: &[u8]) -> Self {
        match key {
            0 => {
                if !value.len().is_multiple_of(2) {
                    return Self::Unknown;
                }
                let mut mandatory = Vec::with_capacity(value.len() / 2);
                for chunk in value.chunks_exact(2) {
                    mandatory.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                }
                Self::Mandatory(mandatory)
            }
            1 => {
                let mut cursor = 0usize;
                let mut list = Vec::new();
                while cursor < value.len() {
                    let len = value[cursor] as usize;
                    cursor += 1;
                    if len == 0 || cursor + len > value.len() {
                        return Self::Unknown;
                    }
                    list.push(value[cursor..cursor + len].to_vec().into_boxed_slice());
                    cursor += len;
                }
                Self::Alpn(list)
            }
            2 => {
                if value.is_empty() {
                    Self::NoDefaultAlpn
                } else {
                    Self::Unknown
                }
            }
            3 => {
                if value.len() == 2 {
                    Self::Port(u16::from_be_bytes([value[0], value[1]]))
                } else {
                    Self::Unknown
                }
            }
            4 => {
                if !value.len().is_multiple_of(4) {
                    return Self::Unknown;
                }
                let hints = value
                    .chunks_exact(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect();
                Self::Ipv4Hint(hints)
            }
            5 => Self::Ech(value.to_vec().into_boxed_slice()),
            6 => {
                if !value.len().is_multiple_of(16) {
                    return Self::Unknown;
                }
                let hints = value
                    .chunks_exact(16)
                    .map(|c| {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(c);
                        Ipv6Addr::from(octets)
                    })
                    .collect();
                Self::Ipv6Hint(hints)
            }
            7 => Self::DohPath(value.to_vec().into_boxed_slice()),
            8 => {
                if value.is_empty() {
                    Self::Ohttp
                } else {
                    Self::Unknown
                }
            }
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SVCB {
    priority: u16,
    target: Name,
    params: Vec<SvcParam>,
}
impl SVCB {
    /// Construct one SVCB/HTTPS parameter set.
    pub fn new(priority: u16, target: Name, params: Vec<SvcParam>) -> Self {
        Self {
            priority,
            target,
            params,
        }
    }
    /// Return the SVCB priority value.
    pub fn priority(&self) -> u16 {
        self.priority
    }
    /// Return the alias target or alternative service target name.
    pub fn target(&self) -> &Name {
        &self.target
    }
    /// Borrow all attached SvcParams in stored order.
    pub fn params(&self) -> &[SvcParam] {
        &self.params
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HTTPS(pub SVCB);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AMTRELAY {
    precedence: u8,
    gateway_type: u8,
    gateway: Box<[u8]>,
}
impl AMTRELAY {
    pub fn new(precedence: u8, gateway_type: u8, gateway: Box<[u8]>) -> Self {
        Self {
            precedence,
            gateway_type,
            gateway,
        }
    }
    pub fn precedence(&self) -> u8 {
        self.precedence
    }
    pub fn gateway_type(&self) -> u8 {
        self.gateway_type
    }
    pub fn gateway(&self) -> &[u8] {
        &self.gateway
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Name;

    #[test]
    // Covers the key-specific interpretation layer separately from the wire codec so
    // malformed known-key payloads can never be mistaken for valid structured values.
    fn svc_param_value_from_wire_matrix() {
        let port_443 = 443u16.to_be_bytes();
        let cases: Vec<(u16, &[u8], SvcParamValue)> = vec![
            (0, &[0, 1, 0, 3], SvcParamValue::Mandatory(vec![1, 3])),
            (
                1,
                &[2, b'h', b'2'],
                SvcParamValue::Alpn(vec![b"h2".to_vec().into_boxed_slice()]),
            ),
            (2, &[], SvcParamValue::NoDefaultAlpn),
            (3, &port_443, SvcParamValue::Port(443)),
            (
                4,
                &[1, 2, 3, 4],
                SvcParamValue::Ipv4Hint(vec![Ipv4Addr::new(1, 2, 3, 4)]),
            ),
            (
                5,
                &[1, 2],
                SvcParamValue::Ech(vec![1, 2].into_boxed_slice()),
            ),
            (
                6,
                &[0; 16],
                SvcParamValue::Ipv6Hint(vec![Ipv6Addr::UNSPECIFIED]),
            ),
            (
                7,
                b"/dns-query",
                SvcParamValue::DohPath(b"/dns-query".to_vec().into_boxed_slice()),
            ),
            (8, &[], SvcParamValue::Ohttp),
            (65000, &[1], SvcParamValue::Unknown),
        ];

        for (key, wire, expected) in cases {
            assert_eq!(SvcParamValue::from_wire(key, wire), expected);
        }
    }

    #[test]
    // RFC 9460 known keys have strict value shapes; malformed ones must degrade to
    // Unknown rather than partially decoding.
    fn svc_param_value_rejects_invalid_known_shapes() {
        let cases = [
            (0, vec![0]),
            (1, vec![0]),
            (2, vec![1]),
            (3, vec![1]),
            (4, vec![1, 2, 3]),
            (6, vec![0; 15]),
            (8, vec![1]),
        ];

        for (key, wire) in cases {
            assert_eq!(SvcParamValue::from_wire(key, &wire), SvcParamValue::Unknown);
        }
    }

    #[test]
    // Keeps the owned model accessors honest after future refactors of the wire layer.
    fn svc_param_and_svcb_model_accessors_work() {
        let param = SvcParam::new(3, 8443u16.to_be_bytes().to_vec().into_boxed_slice());
        assert_eq!(param.key(), 3);
        assert_eq!(param.value(), &8443u16.to_be_bytes());
        assert_eq!(param.parsed(), &SvcParamValue::Port(8443));

        let svcb = SVCB::new(
            1,
            Name::from_ascii("svc.example.com.").unwrap(),
            vec![param.clone()],
        );
        assert_eq!(svcb.priority(), 1);
        assert_eq!(svcb.target().to_fqdn(), "svc.example.com.");
        assert_eq!(svcb.params(), &[param]);
    }
}
