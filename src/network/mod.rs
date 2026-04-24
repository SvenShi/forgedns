/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Networking primitives and protocol-facing infrastructure for ForgeDNS.
//!
//! This module contains the transport and connection-building pieces that sit
//! underneath the server and upstream plugins. In the main request path, these
//! components are responsible for:
//!
//! - turning configured listen addresses into bound sockets;
//! - applying TLS settings for encrypted DNS transports;
//! - providing low-level UDP/TCP/QUIC transport helpers; and
//! - constructing pooled upstream resolvers for outbound queries.
//!
//! The intent is to keep protocol and socket handling isolated from the policy
//! pipeline (`DnsContext -> matcher / executor / provider`) while still making
//! the hot path explicit and easy to reason about.
//!
//! Submodules:
//!
//! - [`buffer_pool`]: shared reusable wire buffers for short-lived encoding and
//!   transport writes;
//! - [`listen`]: shared listen-address parsing helpers used by server and API
//!   entry points.
//! - [`tls_config`]: TLS certificate, key, and client configuration loading for
//!   DoT, DoQ, and HTTPS-based DNS.
//! - [`transport`]: reusable transport adapters for UDP, TCP, and QUIC I/O.
//! - [`upstream`]: outbound DNS resolver construction, bootstrap resolution,
//!   and connection pooling across supported upstream protocols.
pub mod buffer_pool;
pub mod http_client;
pub mod listen;
pub mod tls_config;
pub mod transport;
pub mod upstream;
