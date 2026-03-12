/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared test utilities for plugin unit tests.

#![cfg(test)]

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::message::Message;
use crate::plugin::PluginRegistry;
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
    DnsContext::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 5353)),
        Message::new(),
        test_registry(),
    )
}
