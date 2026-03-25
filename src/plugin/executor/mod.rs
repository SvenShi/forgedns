/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;

use crate::core::error::Result;
pub use crate::plugin::executor::sequence::chain::ExecutorNext;
use crate::{core::context::DnsContext, plugin::Plugin};

#[derive(Debug)]
pub enum ExecStep {
    Next,
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
pub mod mikrotik;
pub mod nftset;
pub mod query_summary;
pub mod redirect;
pub mod reverse_lookup;
pub mod sequence;
pub mod sleep;
pub mod ttl;

// Helper macro to continue to next chain node if present
#[macro_export]
macro_rules! continue_next {
    ($next:expr, $ctx:expr) => {{
        if let Some(next) = $next {
            next.next($ctx).await
        } else {
            if $ctx.flow() == crate::core::context::ExecFlowState::Running {
                $ctx.set_flow(crate::core::context::ExecFlowState::ReachedTail);
            }
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
            ExecStep::Stop => Ok(ExecStep::Stop),
        }
    }
}
