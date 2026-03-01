/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;
use std::any::Any;

use crate::core::error::Result;
use crate::{core::context::DnsContext, plugin::Plugin};
use recursive::RecursiveHandle;

pub type ExecResult = Result<()>;
pub type ExecState = Box<dyn Any + Send + Sync>;

#[derive(Debug)]
pub enum ExecStep {
    Next,
    NextWithPost(Option<ExecState>),
    Stop,
}

pub mod arbitrary;
pub mod black_hole;
pub mod cache;
pub mod debug_print;
pub mod drop_resp;
pub mod dual_selector;
pub mod ecs_handler;
pub mod fallback;
pub mod forward;
pub mod forward_edns0opt;
pub mod hosts;
pub mod ipset;
pub mod metrics_collector;
#[cfg(target_os = "linux")]
pub mod netlink_nf;
pub mod nftset;
pub mod query_summary;
pub mod recursive;
pub mod redirect;
pub mod reverse_lookup;
pub mod sequence;
pub mod sleep;
pub mod ttl;

#[async_trait]
pub trait Executor: Plugin {
    /// Execute the plugin's logic on a DNS request context.
    ///
    /// Return [`ExecStep`] to instruct the sequence engine how to advance.
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep>;

    /// Optional execute path with access to recursive "next-chain" handle.
    ///
    /// Most executors can ignore this and keep implementing only `execute`.
    async fn execute_with_handle(
        &self,
        context: &mut DnsContext,
        _next: Option<RecursiveHandle>,
    ) -> Result<ExecStep> {
        self.execute(context).await
    }

    /// Optional post-stage callback executed when `execute` returns `NextWithPost`.
    async fn post_execute(
        &self,
        _context: &mut DnsContext,
        _state: Option<ExecState>,
    ) -> ExecResult {
        Ok(())
    }
}
