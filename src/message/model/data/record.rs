/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS resource records.

use crate::message::model::data::{Name, RData, RecordType};

/// Owned resource record.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Record {
    /// Owner name of the record.
    name: Name,
    /// Record TTL in seconds.
    ttl: u32,
    /// Type-specific record payload.
    data: RData,
}

impl Record {
    /// Construct a record directly from owned RDATA.
    pub fn from_rdata(name: Name, ttl: u32, data: RData) -> Self {
        Self { name, ttl, data }
    }

    /// Return the owner name.
    pub fn name(&self) -> &Name {
        &self.name
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
