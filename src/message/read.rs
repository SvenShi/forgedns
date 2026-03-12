/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Unified read-only views over packet-backed and owned message data.

use crate::message::model::data::rdata::Edns as OwnedEdns;
use crate::message::model::data::rdata::opt::{
    ClientSubnet as OwnedClientSubnet, EdnsCode, EdnsOption as OwnedEdnsOption,
};
use crate::message::model::{DNSClass, Name, Question, RecordType};
use crate::message::wire::edns::{EdnsOptionRef, EdnsOptionsIter, EdnsRef};
use crate::message::wire::name::NameRef;
use crate::message::wire::question::QuestionRef;

/// Unified name view over packet-backed and owned names.
pub enum NameAccess<'a> {
    /// Packet-backed borrowed name.
    Wire(NameRef<'a>),
    /// Fully owned name.
    Owned(&'a Name),
}

impl<'a> NameAccess<'a> {
    /// Return the matcher-friendly normalized form without a trailing dot.
    pub fn normalized(&self) -> String {
        match self {
            Self::Wire(name) => name.normalized(),
            Self::Owned(name) => name.normalized(),
        }
    }

    /// Visit raw label bytes from left to right.
    pub fn for_each_label_bytes(&self, mut visitor: impl FnMut(&[u8])) {
        match self {
            Self::Wire(name) => {
                for label in name.iter_label_bytes() {
                    visitor(label);
                }
            }
            Self::Owned(name) => {
                for label in name.iter_label_bytes() {
                    visitor(label);
                }
            }
        }
    }

    /// Materialize the name as an owned value.
    pub fn to_owned(&self) -> Name {
        match self {
            Self::Wire(name) => Name::from_wire_ref(name),
            Self::Owned(name) => (*name).clone(),
        }
    }
}

/// Unified question view over packet-backed and owned questions.
pub enum QuestionAccess<'a> {
    /// Packet-backed borrowed question.
    Wire(QuestionRef<'a>),
    /// Fully owned question.
    Owned(&'a Question),
}

impl<'a> QuestionAccess<'a> {
    /// Return the owner name.
    pub fn name(&self) -> NameAccess<'_> {
        match self {
            Self::Wire(question) => NameAccess::Wire(question.name().clone()),
            Self::Owned(question) => NameAccess::Owned(question.name()),
        }
    }

    /// Return the raw question type value.
    pub fn qtype(&self) -> u16 {
        match self {
            Self::Wire(question) => question.qtype(),
            Self::Owned(question) => u16::from(question.question_type()),
        }
    }

    /// Return the raw question class value.
    pub fn qclass(&self) -> u16 {
        match self {
            Self::Wire(question) => question.qclass(),
            Self::Owned(question) => u16::from(question.question_class()),
        }
    }

    /// Return the decoded question type.
    pub fn question_type(&self) -> RecordType {
        match self {
            Self::Wire(question) => question.question_type(),
            Self::Owned(question) => question.question_type(),
        }
    }

    /// Return the decoded question class.
    pub fn question_class(&self) -> DNSClass {
        match self {
            Self::Wire(question) => question.question_class(),
            Self::Owned(question) => question.question_class(),
        }
    }
}

/// Unified EDNS option view over packet-backed and owned EDNS state.
pub enum EdnsOptionAccess<'a> {
    /// Packet-backed borrowed option.
    Wire(EdnsOptionRef<'a>),
    /// Fully owned option.
    Owned(&'a OwnedEdnsOption),
}

impl<'a> EdnsOptionAccess<'a> {
    /// Return the numeric option code.
    pub fn code(&self) -> u16 {
        match self {
            Self::Wire(option) => option.code(),
            Self::Owned(option) => u16::from(EdnsCode::from(*option)),
        }
    }

    /// Materialize the option as an owned value.
    pub fn to_owned(&self) -> OwnedEdnsOption {
        match self {
            Self::Wire(option) => option.to_owned(),
            Self::Owned(option) => (*option).clone(),
        }
    }
}

/// Iterator over packet-backed or owned EDNS options.
pub enum EdnsOptionAccessIter<'a> {
    /// Packet-backed EDNS option iterator.
    Wire(EdnsOptionsIter<'a>),
    /// Owned EDNS option iterator.
    Owned(std::slice::Iter<'a, OwnedEdnsOption>),
}

impl<'a> Iterator for EdnsOptionAccessIter<'a> {
    type Item = EdnsOptionAccess<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Wire(iter) => iter.next().map(EdnsOptionAccess::Wire),
            Self::Owned(iter) => iter.next().map(EdnsOptionAccess::Owned),
        }
    }
}

/// Unified EDNS view over packet-backed and owned EDNS state.
pub enum EdnsAccess<'a> {
    /// Packet-backed borrowed EDNS metadata.
    Wire(EdnsRef<'a>),
    /// Fully owned EDNS state.
    Owned(&'a OwnedEdns),
}

impl<'a> EdnsAccess<'a> {
    /// Return the advertised UDP payload size.
    pub fn udp_payload_size(&self) -> u16 {
        match self {
            Self::Wire(edns) => edns.udp_payload_size(),
            Self::Owned(edns) => edns.udp_payload_size(),
        }
    }

    /// Return the extended response code high bits.
    pub fn ext_rcode(&self) -> u8 {
        match self {
            Self::Wire(edns) => edns.ext_rcode(),
            Self::Owned(edns) => edns.ext_rcode(),
        }
    }

    /// Return the EDNS version.
    pub fn version(&self) -> u8 {
        match self {
            Self::Wire(edns) => edns.version(),
            Self::Owned(edns) => edns.version(),
        }
    }

    /// Report whether the DO bit is set.
    pub fn dnssec_ok(&self) -> bool {
        match self {
            Self::Wire(edns) => edns.dnssec_ok(),
            Self::Owned(edns) => edns.flags().dnssec_ok,
        }
    }

    /// Return the first ECS option as an owned value, if present.
    pub fn client_subnet(&self) -> Option<OwnedClientSubnet> {
        match self {
            Self::Wire(edns) => edns.client_subnet().map(|subnet| subnet.to_owned()),
            Self::Owned(edns) => edns
                .option(EdnsCode::Subnet)
                .and_then(|option| match option {
                    OwnedEdnsOption::Subnet(value) => Some(value.clone()),
                    OwnedEdnsOption::Unknown(_, _) => None,
                }),
        }
    }

    /// Iterate packet-backed or owned EDNS options.
    pub fn options(&self) -> EdnsOptionAccessIter<'_> {
        match self {
            Self::Wire(edns) => EdnsOptionAccessIter::Wire(edns.options()),
            Self::Owned(edns) => EdnsOptionAccessIter::Owned(edns.options().iter()),
        }
    }
}
