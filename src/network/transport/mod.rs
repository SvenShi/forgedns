/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS transport helpers for stream and socket oriented protocols.
//!
//! This module provides minimal, dependency-light helpers that convert between
//! Hickory `Message` and wire bytes, and perform framed I/O for stream-based
//! transports (length-prefixed), as well as QUIC stream helpers.
pub mod quic_transport;
pub mod tcp_transport;
pub mod udp_transport;
