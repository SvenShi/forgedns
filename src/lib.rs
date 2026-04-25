// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Public library surface for ForgeDNS.
//!
//! This crate exposes the runtime building blocks used by the CLI binary,
//! integration tests, and embedding scenarios. The architecture is organized
//! around the main request path:
//!
//! `server -> DnsContext -> matcher / executor / provider pipeline -> upstream
//! or side effects -> response`
//!
//! Top-level modules:
//!
//! - [`api`]: management and health HTTP endpoints.
//! - [`app`]: foreground runtime bootstrap, CLI parsing, and logging setup.
//! - [`config`]: YAML configuration schema, loading, and validation.
//! - [`core`]: shared runtime primitives such as errors, request context, task
//!   coordination, and TTL cache helpers.
//! - [`network`]: socket, TLS, transport, and outbound upstream infrastructure.
//! - [`plugin`]: plugin registry plus server, executor, matcher, and provider
//!   extension points.
//! - [`proto`]: owned DNS protocol model and wire codec.
//! - [`service`]: operating-system service install/start/stop helpers.

pub mod api;
pub mod app;
pub mod config;
pub mod core;
pub mod network;
pub mod plugin;
pub mod service;
pub mod upgrade;

pub use forgedns_proto as proto;
