/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;

use crate::{core::context::DnsContext, plugin::Plugin};

#[async_trait]
#[allow(dead_code)]
pub trait Matcher: Plugin {
    /// is_match checks if the DNS request context matches certain criteria
    async fn is_match(&self, context: &mut DnsContext) -> bool;
}
