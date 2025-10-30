/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;
use std::sync::Arc;

use crate::plugin::executor::sequence::chain::ChainNode;
use crate::{core::context::DnsContext, plugin::Plugin};

pub mod forward;
pub mod sequence;

#[async_trait]
pub trait Executor: Plugin {
    /// Execute the plugin's logic on a DNS request context
    async fn execute(&self, context: &mut DnsContext, next: Option<&Arc<ChainNode>>);
}
