/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::DnsContext;
use crate::plugin::executor::Executor;
use std::sync::Arc;

#[derive(Debug)]
pub struct ChainNode {
    executor: Arc<dyn Executor>,
    next: Option<Arc<ChainNode>>,
}

impl ChainNode {
    pub fn new(executor: Arc<dyn Executor>, next: Option<Arc<ChainNode>>) -> Self {
        ChainNode { executor, next }
    }

    pub async fn next(&self, context: &mut DnsContext) {
        // Pass immediate next (if any) to current executor
        self.executor.execute(context, self.next.as_ref()).await;
    }
}
