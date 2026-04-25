// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
//! Matcher plugin category.
//!
//! Matchers are pure predicates used by executors such as `sequence` to branch
//! on request or response state without embedding policy logic directly into
//! the server path.
//!
//! Typical matcher inputs include:
//!
//! - query name, type, and class;
//! - client IP or derived request metadata;
//! - response content such as answer IPs, CNAMEs, or rcode; and
//! - internal marks, random rollout state, or environment-derived signals.
//!
//! Matchers should stay fast and side-effect free. They read from
//! [`DnsContext`] and return a boolean decision through [`Matcher::is_match`].

use crate::core::context::DnsContext;
use crate::plugin::Plugin;

pub mod client_ip;
pub mod cname;
pub mod env;
pub mod false_matcher;
pub mod has_resp;
pub mod has_wanted_ans;
pub mod mark;
pub mod matcher_utils;
pub mod ptr_ip;
pub mod qclass;
pub mod qname;
pub mod qtype;
pub mod question;
pub mod random;
pub mod rate_limiter;
pub mod rcode;
pub mod resp_ip;
pub mod string_exp;
pub mod true_matcher;

#[allow(dead_code)]
pub trait Matcher: Plugin {
    /// is_match checks if the DNS request context matches certain criteria
    fn is_match(&self, context: &mut DnsContext) -> bool;
}
