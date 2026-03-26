/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Core functionality module
//!
//! Provides essential infrastructure including:
//! - Application clock for high-performance time tracking
//! - DNS request/response context management

pub mod app_clock;
pub mod context;
pub mod error;
pub mod rule_matcher;
pub mod task_center;
pub mod ttl_cache;

/// ForgeDNS version shared by CLI and management APIs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
