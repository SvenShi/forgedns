/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared high-performance rule matchers used by providers and matchers.

mod domain;
mod ip;

pub use domain::DomainRuleMatcher;
pub use ip::IpPrefixMatcher;
