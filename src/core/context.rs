/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS request/response context management
//!
//! Provides a container for DNS queries as they flow through the plugin pipeline.
//! Each context carries the request, response, metadata, and custom states.

use crate::plugin::PluginRegistry;
use ahash::AHashMap;
use ahash::AHashSet;
use hickory_proto::op::Message;
use hickory_proto::rr::Name;
use smallvec::SmallVec;
use std::any::Any;
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExecFlowState {
    Running,
    ReachedTail,
    Broken,
}

/// Lazily-built view of the first DNS question name.
#[derive(Debug, Clone)]
pub struct QueryView {
    /// Original query name from request.
    raw_name: Name,
    normalized_name: String,
    label_ranges_rev: SmallVec<[Range<u16>; 8]>,
}

impl QueryView {
    #[inline]
    pub fn raw_name(&self) -> &Name {
        &self.raw_name
    }

    #[inline]
    pub fn normalized_name(&self) -> &str {
        &self.normalized_name
    }

    #[inline]
    pub fn labels_rev(&self) -> SmallVec<[&str; 8]> {
        let mut out = SmallVec::<[&str; 8]>::with_capacity(self.label_ranges_rev.len());
        for range in &self.label_ranges_rev {
            out.push(&self.normalized_name[range.start as usize..range.end as usize]);
        }
        out
    }
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

    /// Marks/tags added by plugins for decision tracking.
    /// Hash-set layout reduces repeated membership checks on hot path.
    pub marks: AHashSet<String>,

    /// Typed state bag for inter-plugin communication.
    pub attributes: AHashMap<String, Box<dyn Any + Send + Sync>>,

    /// Cached first-query view shared by matchers/executors.
    pub query_view: Option<QueryView>,

    /// Reference to the plugin registry for runtime plugin lookup
    ///
    /// Allows plugins to access other plugins during execution without
    /// relying on global state.
    pub registry: Arc<PluginRegistry>,
}

#[allow(unused)]
impl DnsContext {
    /// Context attribute key: TLS SNI server name (DoH/DoT/DoQ).
    pub const ATTR_SERVER_NAME: &'static str = "server_name";

    /// Context attribute key: HTTP URL path for DoH request.
    pub const ATTR_URL_PATH: &'static str = "url_path";

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

    /// Build a sub-query context clone for recursive plugin execution.
    ///
    /// Typed attributes cannot be cloned generically, so only known string
    /// metadata required by server/executor plugins is preserved.
    pub fn clone_for_subquery(&self) -> DnsContext {
        let mut cloned = DnsContext {
            src_addr: self.src_addr,
            request: self.request.clone(),
            response: self.response.clone(),
            exec_flow_state: ExecFlowState::Running,
            marks: self.marks.clone(),
            attributes: AHashMap::new(),
            query_view: self.query_view.clone(),
            registry: self.registry.clone(),
        };

        if let Some(v) = self.get_attr::<String>(DnsContext::ATTR_SERVER_NAME) {
            cloned.set_attr(DnsContext::ATTR_SERVER_NAME, v.clone());
        }
        if let Some(v) = self.get_attr::<String>(DnsContext::ATTR_URL_PATH) {
            cloned.set_attr(DnsContext::ATTR_URL_PATH, v.clone());
        }
        cloned
    }

    /// Replace mutable request state with result produced by a sub-query context.
    pub fn replace_with_subquery_result(&mut self, sub_ctx: DnsContext) {
        self.request = sub_ctx.request;
        self.response = sub_ctx.response;
        self.exec_flow_state = sub_ctx.exec_flow_state;
        self.marks = sub_ctx.marks;
        self.attributes = sub_ctx.attributes;
        self.query_view = sub_ctx.query_view;
    }

    /// Invalidate cached query view after query name mutation.
    pub fn invalidate_query_view(&mut self) {
        self.query_view = None;
    }

    /// Set first query name and invalidate query view cache.
    ///
    /// Returns false when request has no question.
    pub fn set_first_query_name(&mut self, name: Name) -> bool {
        let Some(query) = self.request.queries_mut().first_mut() else {
            return false;
        };
        query.set_name(name);
        self.invalidate_query_view();
        true
    }

    /// Get first-query view from context cache.
    pub fn query_view(&mut self) -> Option<&QueryView> {
        if self.query_view.is_none() {
            let query = self.request.query()?;
            self.query_view = Some(Self::build_query_view(query.name()));
        }
        self.query_view.as_ref()
    }

    /// Normalize DNS name for domain-rule matching.
    pub fn normalize_dns_name(name: &Name) -> String {
        let mut s = name.to_lowercase().to_utf8();
        if s.ends_with('.') {
            s.pop();
        }
        s
    }

    fn build_query_view(name: &Name) -> QueryView {
        let raw_name = name.clone();
        let normalized_name = Self::normalize_dns_name(name);
        let mut label_ranges_rev = SmallVec::<[Range<u16>; 8]>::new();
        let base = normalized_name.as_ptr() as usize;
        for label in normalized_name.rsplit('.') {
            if label.is_empty() {
                continue;
            }
            let start = (label.as_ptr() as usize).saturating_sub(base) as u16;
            let end = start.saturating_add(label.len() as u16);
            label_ranges_rev.push(start..end);
        }
        QueryView {
            raw_name,
            normalized_name,
            label_ranges_rev,
        }
    }
}
