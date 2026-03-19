/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS resource records.

use crate::message::{DNSClass, Name, RData, RecordType};
use std::net::IpAddr;

/// Owned resource record.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Record {
    name: Name,
    class: DNSClass,
    ttl: u32,
    data: RData,
}

impl Record {
    /// Construct a record directly from owned RDATA.
    pub fn from_rdata(name: Name, ttl: u32, data: RData) -> Self {
        Self::from_rdata_with_class(name, ttl, DNSClass::IN, data)
    }

    /// Construct a record directly from owned RDATA and an explicit DNS class.
    pub fn from_rdata_with_class(name: Name, ttl: u32, class: DNSClass, data: RData) -> Self {
        Self {
            name,
            class,
            ttl,
            data,
        }
    }

    /// Return the owner name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Return the record class.
    pub fn class(&self) -> DNSClass {
        self.class
    }

    /// Update the record class.
    pub fn set_class(&mut self, class: DNSClass) {
        self.class = class;
    }

    /// Return the TTL in seconds.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Update the record TTL in seconds.
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    /// Return the record type derived from the payload.
    pub fn rr_type(&self) -> RecordType {
        self.data.rr_type()
    }

    /// Borrow the type-specific record payload.
    pub fn data(&self) -> &RData {
        &self.data
    }

    /// Mutably borrow the type-specific record payload.
    pub fn data_mut(&mut self) -> &mut RData {
        &mut self.data
    }

    /// Extract an IP address from `A` and `AAAA` records.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.data.ip_addr()
    }

    /// Return the CNAME target when this record carries one.
    pub fn cname_target(&self) -> Option<&Name> {
        match &self.data {
            RData::CNAME(value) => Some(&value.0),
            _ => None,
        }
    }

    /// Return encoded RR byte length at offset `off`.
    pub(crate) fn bytes_len<'a>(
        &'a self,
        off: usize,
        compression: &mut crate::message::codec::LenCompressionMap<'a>,
    ) -> usize {
        let owner_len = self.name.bytes_len_at(off, true, compression);
        let rdata_off = off + owner_len + 10;
        owner_len + 10 + self.data.bytes_len(rdata_off, compression)
    }
}
