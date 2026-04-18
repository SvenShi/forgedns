/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Executor plugin category.
//!
//! Executors are the active stages in a ForgeDNS sequence pipeline. They can:
//!
//! - mutate the request before upstream resolution;
//! - call upstream resolvers and populate a response;
//! - rewrite or filter an existing response;
//! - update request-local marks and request-local metadata; and
//! - trigger side effects such as metrics or external system integration.
//!
//! Execution is centered on [`Executor::execute`] and
//! [`Executor::execute_with_next`]. Simple executors act on the current
//! [`DnsContext`] and return [`ExecStep`] to either continue or stop. Advanced
//! executors can wrap downstream stages through the `next` continuation model
//! used by the `sequence` plugin.
//!
//! Hot-path expectations:
//!
//! - avoid unnecessary allocation and blocking work per request;
//! - push expensive initialization into plugin startup when possible; and
//! - keep side effects off the latency-sensitive response path unless required
//!   for correctness.
use async_trait::async_trait;

use crate::core::error::Result;
pub use crate::plugin::executor::sequence::chain::ExecutorNext;
use crate::{core::context::DnsContext, plugin::Plugin};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExecStep {
    /// Continue executing the current chain or report natural completion.
    Next,
    /// Stop the current chain immediately.
    Stop,
    /// Return control to the caller without resuming the current sequence.
    Return,
}

pub mod arbitrary;
pub mod black_hole;
pub mod cache;
pub mod cron;
pub mod debug_print;
pub mod download;
pub mod drop_resp;
pub mod dual_selector;
pub mod ecs_handler;
pub mod fallback;
pub mod forward;
pub mod forward_edns0opt;
pub mod hosts;
pub mod http_request;
pub mod ipset;
pub mod metrics_collector;
pub mod nftset;
pub mod query_summary;
pub mod redirect;
pub mod reload;
pub mod reload_provider;
pub mod reverse_lookup;
pub mod ros_address_list;
pub mod script;
pub mod sequence;
pub mod sleep;
pub(crate) mod template;
pub mod ttl;

// Helper macro to continue to next chain node if present
#[macro_export]
macro_rules! continue_next {
    ($next:expr, $ctx:expr) => {{
        if let Some(next) = $next {
            next.next($ctx).await
        } else {
            Ok($crate::plugin::executor::ExecStep::Next)
        }
    }};
}

#[async_trait]
pub trait Executor: Plugin {
    fn with_next(&self) -> bool {
        false
    }

    /// Execute the plugin's logic on a DNS request context.
    ///
    /// Return [`ExecStep`] to instruct the sequence engine how to advance.
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep>;

    /// Execute around the downstream chain represented by `next`.
    async fn execute_with_next(
        &self,
        context: &mut DnsContext,
        next: Option<ExecutorNext>,
    ) -> Result<ExecStep> {
        let result = self.execute(context).await?;
        match result {
            ExecStep::Next => continue_next!(next, context),
            ExecStep::Stop | ExecStep::Return => Ok(result),
        }
    }
}
