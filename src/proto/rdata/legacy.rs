/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::proto::Name;
use crate::proto::rdata::basic::TXT;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MD(pub Name);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MF(pub Name);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MB(pub Name);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MG(pub Name);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MR(pub Name);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DNAME(pub Name);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ANAME(pub Name);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NULL {
    data: Box<[u8]>,
}
impl NULL {
    pub fn new(data: Box<[u8]>) -> Self {
        Self { data }
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HINFO {
    cpu: Box<[u8]>,
    os: Box<[u8]>,
}
impl HINFO {
    pub fn new(cpu: Box<[u8]>, os: Box<[u8]>) -> Self {
        Self { cpu, os }
    }
    pub fn cpu(&self) -> &[u8] {
        &self.cpu
    }
    pub fn os(&self) -> &[u8] {
        &self.os
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MINFO {
    rmail: Name,
    email: Name,
}
impl MINFO {
    pub fn new(rmail: Name, email: Name) -> Self {
        Self { rmail, email }
    }
    pub fn rmail(&self) -> &Name {
        &self.rmail
    }
    pub fn email(&self) -> &Name {
        &self.email
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RP {
    mbox: Name,
    txt: Name,
}
impl RP {
    pub fn new(mbox: Name, txt: Name) -> Self {
        Self { mbox, txt }
    }
    pub fn mbox(&self) -> &Name {
        &self.mbox
    }
    pub fn txt(&self) -> &Name {
        &self.txt
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AFSDB {
    subtype: u16,
    hostname: Name,
}
impl AFSDB {
    pub fn new(subtype: u16, hostname: Name) -> Self {
        Self { subtype, hostname }
    }
    pub fn subtype(&self) -> u16 {
        self.subtype
    }
    pub fn hostname(&self) -> &Name {
        &self.hostname
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct X25 {
    psdn_address: Box<[u8]>,
}
impl X25 {
    pub fn new(psdn_address: Box<[u8]>) -> Self {
        Self { psdn_address }
    }
    pub fn psdn_address(&self) -> &[u8] {
        &self.psdn_address
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WKS {
    address: Ipv4Addr,
    protocol: u8,
    bitmap: Box<[u8]>,
}
impl WKS {
    pub fn new(address: Ipv4Addr, protocol: u8, bitmap: Box<[u8]>) -> Self {
        Self {
            address,
            protocol,
            bitmap,
        }
    }
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }
    pub fn protocol(&self) -> u8 {
        self.protocol
    }
    pub fn bitmap(&self) -> &[u8] {
        &self.bitmap
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NSAP(pub Box<[u8]>);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EID(pub Box<[u8]>);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NIMLOC(pub Box<[u8]>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ISDN {
    address: Box<[u8]>,
    sub_address: Option<Box<[u8]>>,
}
impl ISDN {
    pub fn new(address: Box<[u8]>, sub_address: Option<Box<[u8]>>) -> Self {
        Self {
            address,
            sub_address,
        }
    }
    pub fn address(&self) -> &[u8] {
        &self.address
    }
    pub fn sub_address(&self) -> Option<&[u8]> {
        self.sub_address.as_deref()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RT {
    preference: u16,
    host: Name,
}
impl RT {
    pub fn new(preference: u16, host: Name) -> Self {
        Self { preference, host }
    }
    pub fn preference(&self) -> u16 {
        self.preference
    }
    pub fn host(&self) -> &Name {
        &self.host
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PX {
    preference: u16,
    map822: Name,
    mapx400: Name,
}
impl PX {
    pub fn new(preference: u16, map822: Name, mapx400: Name) -> Self {
        Self {
            preference,
            map822,
            mapx400,
        }
    }
    pub fn preference(&self) -> u16 {
        self.preference
    }
    pub fn map822(&self) -> &Name {
        &self.map822
    }
    pub fn mapx400(&self) -> &Name {
        &self.mapx400
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NSAPPTR(pub Name);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GPOS {
    longitude: Box<[u8]>,
    latitude: Box<[u8]>,
    altitude: Box<[u8]>,
}
impl GPOS {
    pub fn new(longitude: Box<[u8]>, latitude: Box<[u8]>, altitude: Box<[u8]>) -> Self {
        Self {
            longitude,
            latitude,
            altitude,
        }
    }
    pub fn longitude(&self) -> &[u8] {
        &self.longitude
    }
    pub fn latitude(&self) -> &[u8] {
        &self.latitude
    }
    pub fn altitude(&self) -> &[u8] {
        &self.altitude
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LOC {
    version: u8,
    size: u8,
    horiz_pre: u8,
    vert_pre: u8,
    latitude: u32,
    longitude: u32,
    altitude: u32,
}
impl LOC {
    pub fn new(
        version: u8,
        size: u8,
        horiz_pre: u8,
        vert_pre: u8,
        latitude: u32,
        longitude: u32,
        altitude: u32,
    ) -> Self {
        Self {
            version,
            size,
            horiz_pre,
            vert_pre,
            latitude,
            longitude,
            altitude,
        }
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn size(&self) -> u8 {
        self.size
    }
    pub fn horiz_pre(&self) -> u8 {
        self.horiz_pre
    }
    pub fn vert_pre(&self) -> u8 {
        self.vert_pre
    }
    pub fn latitude(&self) -> u32 {
        self.latitude
    }
    pub fn longitude(&self) -> u32 {
        self.longitude
    }
    pub fn altitude(&self) -> u32 {
        self.altitude
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AplPrefix {
    family: u16,
    prefix: u8,
    negation: bool,
    afd_part: Box<[u8]>,
}
impl AplPrefix {
    pub fn new(family: u16, prefix: u8, negation: bool, afd_part: Box<[u8]>) -> Self {
        Self {
            family,
            prefix,
            negation,
            afd_part,
        }
    }
    pub fn family(&self) -> u16 {
        self.family
    }
    pub fn prefix(&self) -> u8 {
        self.prefix
    }
    pub fn negation(&self) -> bool {
        self.negation
    }
    pub fn afd_part(&self) -> &[u8] {
        &self.afd_part
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct APL {
    prefixes: Vec<AplPrefix>,
}
impl APL {
    pub fn new(prefixes: Vec<AplPrefix>) -> Self {
        Self { prefixes }
    }
    pub fn prefixes(&self) -> &[AplPrefix] {
        &self.prefixes
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ATMA(pub Box<[u8]>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct A6 {
    prefix_len: u8,
    suffix: Box<[u8]>,
    prefix_name: Option<Name>,
}
impl A6 {
    pub fn new(prefix_len: u8, suffix: Box<[u8]>, prefix_name: Option<Name>) -> Self {
        Self {
            prefix_len,
            suffix,
            prefix_name,
        }
    }
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
    pub fn suffix(&self) -> &[u8] {
        &self.suffix
    }
    pub fn prefix_name(&self) -> Option<&Name> {
        self.prefix_name.as_ref()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SINK {
    coding: u8,
    subcoding: u8,
    data: Box<[u8]>,
}
impl SINK {
    pub fn new(coding: u8, subcoding: u8, data: Box<[u8]>) -> Self {
        Self {
            coding,
            subcoding,
            data,
        }
    }
    pub fn coding(&self) -> u8 {
        self.coding
    }
    pub fn subcoding(&self) -> u8 {
        self.subcoding
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SPF(pub TXT);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AVC(pub TXT);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UINFO(pub Box<[u8]>);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UID(pub u32);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GID(pub u32);
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UNSPEC(pub Box<[u8]>);

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct IXFR;
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct AXFR;
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct MAILB;
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct MAILA;
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ANY;
