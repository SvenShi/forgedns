/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS question model.

use crate::message::model::data::{DNSClass, Name, RecordType};

/// Owned DNS question used by the owned message representation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Question {
    /// Question name.
    pub(crate) name: Name,
    /// Requested RR type.
    pub(crate) question_type: RecordType,
    /// Requested RR class.
    pub(crate) question_class: DNSClass,
}

impl Question {
    /// Construct a standard IN-class question.
    pub fn new(name: Name, question_type: RecordType) -> Self {
        Self {
            name,
            question_type,
            question_class: DNSClass::IN,
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
    pub fn question_type(&self) -> RecordType {
        self.question_type
    }

    /// Replace the requested RR type.
    pub fn set_question_type(&mut self, question_type: RecordType) {
        self.question_type = question_type;
    }

    /// Return the requested RR class.
    pub fn question_class(&self) -> DNSClass {
        self.question_class
    }

    /// Replace the requested RR class.
    pub fn set_question_class(&mut self, question_class: DNSClass) {
        self.question_class = question_class;
    }
}
