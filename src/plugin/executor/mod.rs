/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;
use std::any::Any;

use crate::core::error::Result;
use crate::{core::context::DnsContext, plugin::Plugin};

pub type ExecResult = Result<()>;
pub type ExecState = Box<dyn Any + Send + Sync>;

#[derive(Debug)]
pub enum ExecStep {
    Next,
    NextWithPost(Option<ExecState>),
    Stop,
}

pub mod cache;
pub mod forward;
pub mod print;
pub mod sequence;

#[async_trait]
pub trait Executor: Plugin {
    /// Execute the plugin's logic on a DNS request context.
    ///
    /// Return [`ExecStep`] to instruct the sequence engine how to advance.
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep>;

    /// Optional post-stage callback executed when `execute` returns `NextWithPost`.
    async fn post_execute(
        &self,
        _context: &mut DnsContext,
        _state: Option<ExecState>,
    ) -> ExecResult {
        Ok(())
    }
}
