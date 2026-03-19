/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS question model.

use crate::message::{DNSClass, Name, RecordType};

/// Owned DNS question used by the message representation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Question {
    name: Name,
    qtype: RecordType,
    qclass: DNSClass,
}

impl Question {
    /// Construct a standard IN-class question.
    pub fn new(name: Name, qtype: RecordType, qclass: DNSClass) -> Self {
        Self {
            name,
            qtype,
            qclass,
        }
    }

    /// Borrow the question name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Replace the question name.
    pub fn set_name(&mut self, name: Name) {
        self.name = name;
    }

    /// Return the requested RR type.
    pub fn qtype(&self) -> RecordType {
        self.qtype
    }

    /// Replace the requested RR type.
    pub fn set_qtype(&mut self, qtype: RecordType) {
        self.qtype = qtype;
    }

    /// Return the requested RR class.
    pub fn qclass(&self) -> DNSClass {
        self.qclass
    }

    /// Replace the requested RR class.
    pub fn set_qclass(&mut self, qclass: DNSClass) {
        self.qclass = qclass;
    }

    /// Return encoded byte length at offset `off`, including QTYPE and QCLASS.
    pub(crate) fn bytes_len<'a>(
        &'a self,
        off: usize,
        compression: &mut crate::message::codec::LenCompressionMap<'a>,
    ) -> usize {
        self.name.bytes_len_at(off, true, compression) + 4
    }
}
