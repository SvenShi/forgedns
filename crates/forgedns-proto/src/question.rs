/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS question model.

use crate::proto::{DNSClass, Name, RecordType};
use std::fmt::{Debug, Display, Formatter};

/// Owned DNS question used by the message representation.
#[derive(Clone, Eq, PartialEq)]
pub struct Question {
    name: Name,
    qtype: RecordType,
    qclass: DNSClass,
}

impl Debug for Question {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.name, self.qclass, self.qtype)
    }
}

impl Display for Question {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.name, self.qclass, self.qtype)
    }
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
        compression: &mut crate::proto::codec::LenCompressionMap<'a>,
    ) -> usize {
        self.name.bytes_len_at(true, compression) + 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_then_mutate_does_not_change_original() {
        let original = Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        );
        let mut cloned = original.clone();
        cloned.set_name(Name::from_ascii("other.example.").unwrap());
        cloned.set_qtype(RecordType::AAAA);
        cloned.set_qclass(DNSClass::CH);

        assert_eq!(original.name().to_fqdn(), "example.com.");
        assert_eq!(original.qtype(), RecordType::A);
        assert_eq!(original.qclass(), DNSClass::IN);
        assert_eq!(cloned.name().to_fqdn(), "other.example.");
        assert_eq!(cloned.qtype(), RecordType::AAAA);
        assert_eq!(cloned.qclass(), DNSClass::CH);
    }

    #[test]
    fn display_formats_question_in_dns_style() {
        let question = Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
            DNSClass::IN,
        );

        assert_eq!(question.to_string(), "example.com IN AAAA");
    }
}
