/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS request/response context management
//!
//! Provides a container for DNS queries as they flow through the plugin pipeline.
//! Each context carries the request, response, metadata, and custom states.

use crate::plugin::PluginRegistry;
use hickory_proto::op::Message;
use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExecFlowState {
    Running,
    ReachedTail,
    Broken,
}

/// Context object for a DNS request/response lifecycle
///
/// This object is passed through the plugin pipeline, carrying:
/// - Source client address
/// - DNS request message
/// - Optional DNS response
/// - Marks for plugin decision tracking
/// - Custom attributes for plugin communication
/// - Reference to the plugin registry for runtime plugin access
#[allow(unused)]
pub struct DnsContext {
    /// Client's socket address
    pub src_addr: SocketAddr,

    /// DNS request message from the client
    pub request: Message,

    /// DNS response message (populated by plugins)
    pub response: Option<Message>,

    /// Current chain execution flow state for request exit classification.
    ///
    /// - `Running`: normal traversal
    /// - `ReachedTail`: execution naturally reached the chain tail
    /// - `Broken`: control flow requested early stop (e.g. `accept`/`reject`)
    pub exec_flow_state: ExecFlowState,

    /// Marks/tags added by plugins for decision tracking
    pub mark: Vec<String>,

    /// Typed state bag for inter-plugin communication.
    pub attributes: HashMap<String, Box<dyn Any + Send + Sync>>,

    /// Reference to the plugin registry for runtime plugin lookup
    ///
    /// Allows plugins to access other plugins during execution without
    /// relying on global state.
    pub registry: Arc<PluginRegistry>,
}

#[allow(unused)]
impl DnsContext {
    /// Set a custom attribute in the context
    ///
    /// Allows plugins to store typed data for later retrieval
    pub fn set_attr<T>(&mut self, name: impl Into<String>, value: T)
    where
        T: Send + Sync + 'static,
    {
        self.attributes.insert(name.into(), Box::new(value));
    }

    /// Get a reference to a custom attribute
    ///
    /// Returns None if the attribute doesn't exist or has a different type
    pub fn get_attr<T>(&self, name: &str) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.attributes.get(name).and_then(|a| a.downcast_ref())
    }

    /// Remove a custom attribute from the context
    pub fn remove_attr<T>(&mut self, name: &str) -> Option<T>
    where
        T: Send + Sync + 'static,
    {
        self.attributes
            .remove(name)
            .and_then(|a| a.downcast::<T>().ok())
            .map(|boxed| *boxed)
    }
}
