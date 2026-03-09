/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared test utilities for plugin unit tests.

#![cfg(test)]

use crate::config::types::PluginConfig;
use crate::core::context::{DnsContext, ExecFlowState};
use crate::plugin::PluginRegistry;
use ahash::AHashMap;
use hickory_proto::op::Message;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub(crate) fn test_registry() -> Arc<PluginRegistry> {
    Arc::new(PluginRegistry::new())
}

pub(crate) fn plugin_config(
    tag: impl Into<String>,
    plugin_type: impl Into<String>,
    args: Option<serde_yml::Value>,
) -> PluginConfig {
    PluginConfig {
        tag: tag.into(),
        plugin_type: plugin_type.into(),
        args,
    }
}

pub(crate) fn test_context() -> DnsContext {
    DnsContext {
        src_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 5353)),
        request: Message::new(),
        response: None,
        exec_flow_state: ExecFlowState::Running,
        marks: Default::default(),
        attributes: AHashMap::new(),
        query_view: None,
        registry: test_registry(),
    }
}
