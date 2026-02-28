/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;

use crate::{core::context::DnsContext, plugin::Plugin};

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
pub mod random;
pub mod rcode;
pub mod resp_ip;
pub mod string_exp;
pub mod true_matcher;

#[async_trait]
#[allow(dead_code)]
pub trait Matcher: Plugin {
    /// is_match checks if the DNS request context matches certain criteria
    async fn is_match(&self, context: &mut DnsContext) -> bool;
}
