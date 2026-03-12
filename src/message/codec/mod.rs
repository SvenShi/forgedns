/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared owned-message encoders and decoders.

mod decode;
mod encode;

pub(crate) use decode::decode_owned;
pub(crate) use encode::{encode_owned, encode_owned_into};
