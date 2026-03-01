/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Recursive execution primitives for sequence "next-chain" calls.

use crate::core::context::DnsContext;
use crate::core::error::Result;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

/// Internal runner abstraction implemented by sequence programs.
#[async_trait]
pub trait NextChainRunner: Send + Sync + Debug {
    /// Execute instruction stream from `start_pc`.
    async fn run_from(self: Arc<Self>, context: &mut DnsContext, start_pc: usize) -> Result<()>;
}

/// Cloneable handle that allows executors to recursively execute the remaining chain.
#[derive(Clone, Debug)]
pub struct RecursiveHandle {
    runner: Arc<dyn NextChainRunner>,
    next_pc: usize,
}

impl RecursiveHandle {
    pub fn new(runner: Arc<dyn NextChainRunner>, next_pc: usize) -> Self {
        Self { runner, next_pc }
    }

    /// Execute chain from the instruction immediately after the current node.
    pub async fn exec_next(&self, context: &mut DnsContext) -> Result<()> {
        self.runner.clone().run_from(context, self.next_pc).await
    }
}
