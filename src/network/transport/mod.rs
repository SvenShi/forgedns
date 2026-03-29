/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS transport helpers for stream and socket oriented protocols.
//!
//! This module provides minimal, dependency-light helpers that convert between
//! ForgeDNS `Message` and wire bytes, and perform framed I/O for stream-based
//! transports (length-prefixed), as well as QUIC stream helpers.
//!
//! It is intentionally lower level than server and upstream plugins:
//!
//! - [`udp_transport`] handles datagram-oriented message I/O;
//! - [`tcp_transport`] handles length-prefixed DNS over TCP / TLS framing; and
//! - [`quic_transport`] handles stream-based DNS over QUIC helpers.
//!
//! Keeping these helpers small makes the protocol plugins easier to review and
//! reduces duplication at transport boundaries.
pub mod quic_transport;
pub mod tcp_transport;
pub mod udp_transport;
