/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Borrowed EDNS views parsed directly from packet bytes.
//!
//! This module mirrors the small subset of EDNS metadata the hot path needs:
//! payload size, extended RCODE, version, flags, and raw option iteration.

use crate::message::model::data::rdata::Edns as OwnedEdns;
use crate::message::model::data::rdata::opt::{
    ClientSubnet as OwnedClientSubnet, EdnsCode, EdnsOption as OwnedEdnsOption,
};
use crate::message::wire::flags::EDNS_FLAG_DO;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;
/// EDNS option code for ECS / client subnet.
const EDNS_OPTION_SUBNET: u16 = 8;

/// Borrowed EDNS option view.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EdnsOptionRef<'a> {
    /// Numeric EDNS option code.
    code: u16,
    /// Borrowed option payload bytes.
    data: &'a [u8],
}

impl<'a> EdnsOptionRef<'a> {
    #[inline]
    /// Return the numeric EDNS option code.
    pub fn code(&self) -> u16 {
        self.code
    }

    #[inline]
    /// Return the borrowed option payload bytes.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Materialize this option into the owned EDNS model.
    pub fn to_owned(&self) -> OwnedEdnsOption {
        let code = self.code();
        match EdnsCode::from(code) {
            EdnsCode::Subnet => self
                .client_subnet()
                .map(OwnedEdnsOption::Subnet)
                .unwrap_or_else(|| OwnedEdnsOption::Unknown(code, self.data().to_vec())),
            EdnsCode::Unknown(other) => OwnedEdnsOption::Unknown(other, self.data().to_vec()),
        }
    }

    /// Decode this option as ECS when possible.
    pub fn client_subnet(&self) -> Option<OwnedClientSubnet> {
        decode_client_subnet(self.data)
    }
}

/// Borrowed ECS option body.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ClientSubnetRef<'a> {
    /// Address family (`1` for IPv4, `2` for IPv6).
    family: u16,
    /// Source prefix length in bits.
    source_prefix: u8,
    /// Scope prefix length in bits.
    scope_prefix: u8,
    /// Truncated network address bytes carried on the wire.
    address: &'a [u8],
}

impl<'a> ClientSubnetRef<'a> {
    #[inline]
    /// Return the ECS address family.
    pub fn family(&self) -> u16 {
        self.family
    }

    #[inline]
    /// Return the source prefix length.
    pub fn source_prefix(&self) -> u8 {
        self.source_prefix
    }

    #[inline]
    /// Return the scope prefix length.
    pub fn scope_prefix(&self) -> u8 {
        self.scope_prefix
    }

    #[inline]
    /// Return the borrowed address bytes.
    pub fn address(&self) -> &'a [u8] {
        self.address
    }

    /// Materialize this ECS option body into the owned EDNS model.
    pub fn to_owned(&self) -> OwnedClientSubnet {
        let addr =
            decode_subnet_addr(self.family, self.address).unwrap_or_else(|| match self.family {
                2 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            });
        OwnedClientSubnet::new(addr, self.source_prefix, self.scope_prefix)
    }
}

/// Borrowed OPT pseudo-record metadata.
#[derive(Debug, Clone)]
pub struct EdnsRef<'a> {
    /// Advertised UDP payload size from the OPT class field.
    udp_payload_size: u16,
    /// Extended response code high bits from the OPT TTL field.
    ext_rcode: u8,
    /// EDNS version from the OPT TTL field.
    version: u8,
    /// Raw EDNS flag bits from the OPT TTL field.
    flags: u16,
    /// Byte range of the option block inside the packet.
    options_range: Range<u16>,
    /// Borrowed packet bytes backing all option views.
    packet: &'a [u8],
}

impl<'a> EdnsRef<'a> {
    /// Construct a borrowed EDNS view from already parsed OPT metadata.
    pub(crate) fn new(
        udp_payload_size: u16,
        ext_rcode: u8,
        version: u8,
        flags: u16,
        options_range: Range<u16>,
        packet: &'a [u8],
    ) -> Self {
        Self {
            udp_payload_size,
            ext_rcode,
            version,
            flags,
            options_range,
            packet,
        }
    }

    #[inline]
    /// Return the advertised UDP payload size.
    pub fn udp_payload_size(&self) -> u16 {
        self.udp_payload_size
    }

    #[inline]
    /// Return the extended response code bits.
    pub fn ext_rcode(&self) -> u8 {
        self.ext_rcode
    }

    #[inline]
    /// Return the negotiated EDNS version.
    pub fn version(&self) -> u8 {
        self.version
    }

    #[inline]
    /// Return the raw EDNS flag bits.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    #[inline]
    /// Return the byte range of the raw option block inside the packet.
    pub fn options_range(&self) -> Range<u16> {
        self.options_range.clone()
    }

    #[inline]
    /// Report whether the DNSSEC OK (`DO`) bit is set.
    pub fn dnssec_ok(&self) -> bool {
        (self.flags & EDNS_FLAG_DO) != 0
    }

    #[inline]
    /// Iterate borrowed EDNS options without allocation.
    pub fn options(&self) -> EdnsOptionsIter<'a> {
        EdnsOptionsIter {
            packet: self.packet,
            cursor: self.options_range.start as usize,
            end: self.options_range.end as usize,
        }
    }

    /// Return the first EDNS option matching `code`.
    pub fn option(&self, code: u16) -> Option<EdnsOptionRef<'a>> {
        self.options().find(|opt| opt.code == code)
    }

    /// Parse the first ECS option, if present and well-formed.
    pub fn client_subnet(&self) -> Option<ClientSubnetRef<'a>> {
        let option = self.option(EDNS_OPTION_SUBNET)?;
        let data = option.data;
        if data.len() < 4 {
            return None;
        }

        Some(ClientSubnetRef {
            family: u16::from_be_bytes([data[0], data[1]]),
            source_prefix: data[2],
            scope_prefix: data[3],
            address: &data[4..],
        })
    }

    /// Materialize the full EDNS state into the owned message model.
    pub fn to_owned(&self) -> OwnedEdns {
        let mut edns = OwnedEdns::new();
        edns.set_udp_payload_size(self.udp_payload_size());
        edns.set_ext_rcode(self.ext_rcode());
        edns.set_version(self.version());
        edns.set_dnssec_ok(self.dnssec_ok());
        for option in self.options() {
            edns.insert(option.to_owned());
        }
        edns
    }
}

/// Iterator over borrowed EDNS options in the OPT record payload.
pub struct EdnsOptionsIter<'a> {
    /// Borrowed packet bytes.
    packet: &'a [u8],
    /// Current iterator cursor inside the option block.
    cursor: usize,
    /// Exclusive end offset of the option block.
    end: usize,
}

impl<'a> Iterator for EdnsOptionsIter<'a> {
    type Item = EdnsOptionRef<'a>;

    /// Decode the next EDNS option, stopping on malformed trailing bytes.
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.end || self.end > self.packet.len() {
            return None;
        }
        if self.cursor + 4 > self.end {
            self.cursor = self.end;
            return None;
        }

        let code = u16::from_be_bytes([self.packet[self.cursor], self.packet[self.cursor + 1]]);
        let len = u16::from_be_bytes([self.packet[self.cursor + 2], self.packet[self.cursor + 3]])
            as usize;
        let data_start = self.cursor + 4;
        let data_end = data_start + len;
        if data_end > self.end {
            self.cursor = self.end;
            return None;
        }

        self.cursor = data_end;
        Some(EdnsOptionRef {
            code,
            data: &self.packet[data_start..data_end],
        })
    }
}

fn decode_client_subnet(data: &[u8]) -> Option<OwnedClientSubnet> {
    if data.len() < 4 {
        return None;
    }

    let family = u16::from_be_bytes([data[0], data[1]]);
    let source_prefix = data[2];
    let scope_prefix = data[3];
    let addr = decode_subnet_addr(family, &data[4..])?;
    Some(OwnedClientSubnet::new(addr, source_prefix, scope_prefix))
}

fn decode_subnet_addr(family: u16, address: &[u8]) -> Option<IpAddr> {
    match family {
        1 => {
            let mut octets = [0u8; 4];
            let copy_len = address.len().min(4);
            octets[..copy_len].copy_from_slice(&address[..copy_len]);
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        2 => {
            let mut octets = [0u8; 16];
            let copy_len = address.len().min(16);
            octets[..copy_len].copy_from_slice(&address[..copy_len]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}
