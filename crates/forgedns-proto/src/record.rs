/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS resource records.

use crate::proto::{DNSClass, Name, RData, RecordType};
use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use std::sync::Arc;

/// Owned resource record.
#[derive(Clone, Eq, PartialEq)]
pub struct Record {
    inner: Arc<RecordInner>,
}

#[derive(Clone, Eq, PartialEq)]
struct RecordInner {
    name: Name,
    class: DNSClass,
    ttl: u32,
    data: Arc<RData>,
}

impl Debug for Record {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {:?}",
            self.inner.name, self.inner.class, self.inner.data
        )
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {:?}",
            self.inner.name, self.inner.class, self.inner.data
        )
    }
}

impl Record {
    /// Construct a record directly from owned RDATA.
    pub fn from_rdata(name: Name, ttl: u32, data: RData) -> Self {
        Self::from_rdata_with_class(name, ttl, DNSClass::IN, data)
    }
    /// Construct a record directly from arc RDATA.
    pub fn from_arc_rdata(name: Name, ttl: u32, data: Arc<RData>) -> Self {
        Self::from_arc_rdata_with_class(name, ttl, DNSClass::IN, data)
    }

    /// Construct a record directly from arc RDATA and an explicit DNS class.
    pub fn from_arc_rdata_with_class(
        name: Name,
        ttl: u32,
        class: DNSClass,
        data: Arc<RData>,
    ) -> Self {
        Self {
            inner: Arc::new(RecordInner {
                name,
                class,
                ttl,
                data,
            }),
        }
    }

    /// Construct a record directly from owned RDATA and an explicit DNS class.
    pub fn from_rdata_with_class(name: Name, ttl: u32, class: DNSClass, data: RData) -> Self {
        Self {
            inner: Arc::new(RecordInner {
                name,
                class,
                ttl,
                data: Arc::new(data),
            }),
        }
    }

    /// Return the owner name.
    pub fn name(&self) -> &Name {
        &self.inner.name
    }

    /// Return the record class.
    pub fn class(&self) -> DNSClass {
        self.inner.class
    }

    /// Update the record class.
    pub fn set_class(&mut self, class: DNSClass) {
        Arc::make_mut(&mut self.inner).class = class;
    }

    /// Return the TTL in seconds.
    pub fn ttl(&self) -> u32 {
        self.inner.ttl
    }

    /// Update the record TTL in seconds.
    pub fn set_ttl(&mut self, ttl: u32) {
        Arc::make_mut(&mut self.inner).ttl = ttl;
    }

    /// Return the record type derived from the payload.
    pub fn rr_type(&self) -> RecordType {
        self.inner.data.as_ref().rr_type()
    }

    /// Borrow the type-specific record payload.
    pub fn data(&self) -> &RData {
        self.inner.data.as_ref()
    }

    /// Borrow the type-specific record payload.
    pub fn data_arc(&self) -> Arc<RData> {
        self.inner.data.clone()
    }

    /// Mutably borrow the type-specific record payload.
    pub fn data_mut(&mut self) -> &mut RData {
        let inner = Arc::make_mut(&mut self.inner);
        Arc::make_mut(&mut inner.data)
    }

    /// Extract an IP address from `A` and `AAAA` records.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.data().ip_addr()
    }

    /// Return the CNAME target when this record carries one.
    pub fn cname_target(&self) -> Option<&Name> {
        match self.data() {
            RData::CNAME(value) => Some(&value.0),
            _ => None,
        }
    }

    /// Return encoded RR byte length at offset `off`.
    pub(crate) fn bytes_len<'a>(
        &'a self,
        compression: &mut crate::proto::codec::LenCompressionMap<'a>,
    ) -> usize {
        let owner_len = self.name().bytes_len_at(true, compression);
        owner_len + 10 + self.data().bytes_len(compression)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::rdata::{A, TXT};
    use std::net::Ipv4Addr;

    #[test]
    fn clone_then_mutate_does_not_change_original() {
        let original = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
        );
        let mut cloned = original.clone();
        cloned.set_ttl(120);
        cloned.set_class(DNSClass::CH);
        *cloned.data_mut() = RData::TXT(TXT::new(Box::from([2u8, b'o', b'k'])));

        assert_eq!(original.ttl(), 60);
        assert_eq!(original.class(), DNSClass::IN);
        assert!(matches!(original.data(), RData::A(..)));
        assert_eq!(cloned.ttl(), 120);
        assert_eq!(cloned.class(), DNSClass::CH);
        assert!(matches!(cloned.data(), RData::TXT(..)));
    }

    #[test]
    fn ttl_mutation_keeps_rdata_shared_until_data_changes() {
        let original = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
        );
        let mut cloned = original.clone();

        cloned.set_ttl(120);
        assert!(Arc::ptr_eq(&original.inner.data, &cloned.inner.data));

        *cloned.data_mut() = RData::TXT(TXT::new(Box::from([2u8, b'o', b'k'])));
        assert!(!Arc::ptr_eq(&original.inner.data, &cloned.inner.data));
        assert!(matches!(original.data(), RData::A(..)));
        assert!(matches!(cloned.data(), RData::TXT(..)));
    }
}
