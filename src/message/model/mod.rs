/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS message and record data model.

pub mod data;
pub mod enums;
pub mod message;
pub mod question;

pub use data::rdata;
pub use data::{DNSClass, Name, ParsedArpaName, RData, Record, RecordType};
pub use enums::{MessageType, OpCode, ResponseCode};
pub use question::Question;
