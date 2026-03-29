/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared runtime primitives used across the whole ForgeDNS process.
//!
//! This module contains the small set of foundational types that most other
//! subsystems depend on:
//!
//! - [`app_clock`]: low-overhead elapsed-time tracking for logs and metrics.
//! - [`context`]: [`context::DnsContext`] and related state passed through the plugin
//!   pipeline during request execution.
//! - [`error`]: common error types and result aliases.
//! - [`rule_matcher`]: reusable domain and string matching helpers.
//! - [`task_center`]: shared async task orchestration helpers.
//! - [`ttl_cache`]: concurrent TTL-aware cache building block.
//!
//! Code in this module should stay generic, hot-path aware, and free from
//! plugin-specific policy decisions.

pub mod app_clock;
pub mod context;
pub mod error;
pub mod rule_matcher;
pub mod task_center;
pub mod ttl_cache;

/// ForgeDNS version shared by CLI and management APIs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
