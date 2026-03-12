/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS resource records.

use crate::message::model::data::{DNSClass, Name, RData, RecordType};

/// Owned resource record.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Record {
    /// Owner name of the record.
    name: Name,
    /// Record class.
    dns_class: DNSClass,
    /// Record TTL in seconds.
    ttl: u32,
    /// Type-specific record payload.
    data: RData,
}

impl Record {
    /// Construct a record directly from owned RDATA.
    pub fn from_rdata(name: Name, ttl: u32, data: RData) -> Self {
        Self::from_rdata_with_class(name, ttl, DNSClass::IN, data)
    }

    /// Construct a record directly from owned RDATA and an explicit DNS class.
    pub fn from_rdata_with_class(name: Name, ttl: u32, dns_class: DNSClass, data: RData) -> Self {
        Self {
            name,
            dns_class,
            ttl,
            data,
        }
    }

    /// Return the owner name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Return the record class.
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Update the record class.
    pub fn set_dns_class(&mut self, dns_class: DNSClass) {
        self.dns_class = dns_class;
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
    pub fn record_type(&self) -> RecordType {
        self.data.record_type()
    }

    /// Borrow the type-specific record payload.
    pub fn data(&self) -> &RData {
        &self.data
    }

    /// Mutably borrow the type-specific record payload.
    pub fn data_mut(&mut self) -> &mut RData {
        &mut self.data
    }
}
