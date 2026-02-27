/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;
use std::sync::Arc;

use crate::core::error::Result;
use crate::plugin::executor::sequence::chain::ChainNode;
use crate::{core::context::DnsContext, plugin::Plugin};

pub type ExecResult = Result<()>;

// Helper macro to continue to next chain node if present
#[macro_export]
macro_rules! continue_next {
    ($next:expr, $ctx:expr) => {{
        if let Some(next) = $next {
            next.next($ctx).await
        } else {
            if $ctx.exec_flow_state == $crate::core::context::ExecFlowState::Running {
                $ctx.exec_flow_state = $crate::core::context::ExecFlowState::ReachedTail;
            }
            Ok(())
        }
    }};
}

pub mod cache;
pub mod forward;
pub mod print;
pub mod sequence;

#[async_trait]
pub trait Executor: Plugin {
    /// Execute the plugin's logic on a DNS request context
    async fn execute(
        &self,
        context: &mut DnsContext,
        next: Option<&Arc<dyn ChainNode>>,
    ) -> ExecResult;
}
