/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Owned DNS names, records, classes, types, and RDATA payloads.

pub mod name;
pub mod rdata;
pub mod record;
pub mod types;

pub use name::{Name, ParsedArpaName};
pub use rdata::RData;
pub use record::Record;
pub use types::{DNSClass, RecordType};
