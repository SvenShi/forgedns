/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Packet-backed DNS views and zero-copy wire parsing.

pub mod constants;
pub mod edns;
pub mod flags;
pub mod header;
pub(crate) mod meta;
pub mod name;
pub mod packet;
pub mod parser;
pub mod question;
pub mod record;
