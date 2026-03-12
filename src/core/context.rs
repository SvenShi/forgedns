/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS request/response context management
//!
//! Provides a container for DNS queries as they flow through the plugin pipeline.
//! Each context carries the request, response, metadata, and custom states.

use crate::core::error::Result;
use crate::message::Message;
use crate::message::Name;
use crate::message::{Packet, QuestionAccess, ResponsePlan};
use crate::plugin::PluginRegistry;
use ahash::AHashMap;
use ahash::AHashSet;
use smallvec::SmallVec;
use std::any::Any;
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::Arc;

/// High-level execution state of the current plugin chain.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExecFlowState {
    /// Normal execution is still traversing the current chain.
    Running,
    /// Execution reached the natural end of the chain.
    ReachedTail,
    /// Execution stopped early due to control flow such as `accept` or `reject`.
    Broken,
}

/// Typed metadata attached to the request by the inbound server layer.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct RequestMeta {
    /// SNI or host-like server identifier carried by the server layer.
    pub server_name: Option<String>,
    /// URL path carried by HTTP-based server layers.
    pub url_path: Option<String>,
}

/// Lazily-built view of the first DNS question.
#[derive(Debug, Clone)]
pub struct QuestionView {
    /// Lowercased matcher-friendly query name without trailing dot.
    normalized_name: String,
    /// Reverse label ranges into `normalized_name`.
    label_ranges_rev: SmallVec<[Range<u16>; 8]>,
    /// Raw question type.
    qtype: u16,
    /// Raw question class.
    qclass: u16,
    /// Whether the request advertised DNSSEC OK.
    do_bit: bool,
    /// Whether the request set checking disabled.
    cd_bit: bool,
}

impl QuestionView {
    #[inline]
    /// Return the normalized query name used by matchers.
    pub fn normalized_name(&self) -> &str {
        &self.normalized_name
    }

    #[inline]
    /// Return the raw question type.
    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    #[inline]
    /// Return the raw question class.
    pub fn qclass(&self) -> u16 {
        self.qclass
    }

    #[inline]
    /// Report whether the request set the DO bit.
    pub fn do_bit(&self) -> bool {
        self.do_bit
    }

    #[inline]
    /// Report whether the request set the CD bit.
    pub fn cd_bit(&self) -> bool {
        self.cd_bit
    }

    #[inline]
    /// Iterate normalized labels from right to left.
    pub fn iter_labels_rev(&self) -> QueryLabelsRev<'_> {
        QueryLabelsRev {
            normalized_name: &self.normalized_name,
            ranges: self.label_ranges_rev.iter(),
        }
    }

    #[inline]
    /// Collect normalized labels from right to left into a small buffer.
    pub fn labels_rev(&self) -> SmallVec<[&str; 8]> {
        let mut out = SmallVec::<[&str; 8]>::with_capacity(self.label_ranges_rev.len());
        out.extend(self.iter_labels_rev());
        out
    }
}

/// Backward-compatible alias for `QuestionView`.
pub type QueryView = QuestionView;

/// Iterator over normalized query labels from right to left.
pub struct QueryLabelsRev<'a> {
    /// Full normalized query name.
    normalized_name: &'a str,
    /// Remaining label ranges into `normalized_name`.
    ranges: std::slice::Iter<'a, Range<u16>>,
}

impl<'a> Iterator for QueryLabelsRev<'a> {
    type Item = &'a str;

    #[inline]
    /// Return the next label from the end of the query name.
    fn next(&mut self) -> Option<Self::Item> {
        let range = self.ranges.next()?;
        Some(&self.normalized_name[range.start as usize..range.end as usize])
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
    pub response: Option<ResponsePlan>,

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

    /// Typed request metadata carried from the server layer.
    pub request_meta: RequestMeta,

    /// Cached first-question view shared by matchers/executors.
    pub query_view: Option<QuestionView>,

    /// Request version captured when `query_view` was built.
    pub(crate) query_view_version: Option<u64>,

    /// Reference to the plugin registry for runtime plugin lookup
    ///
    /// Allows plugins to access other plugins during execution without
    /// relying on global state.
    pub registry: Arc<PluginRegistry>,
}

#[allow(unused)]
impl DnsContext {
    /// Construct a fresh DNS context with empty response, marks, and attributes.
    pub fn new(src_addr: SocketAddr, request: Message, registry: Arc<PluginRegistry>) -> Self {
        Self {
            src_addr,
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: AHashMap::new(),
            request_meta: RequestMeta::default(),
            query_view: None,
            query_view_version: None,
            registry,
        }
    }

    /// Context attribute key: dual_selector requests extra preferred-type probe in forward.
    pub const ATTR_FORWARD_PROBE_REQUEST: &'static str = "dual_selector.forward_probe_request";

    /// Context attribute key: forward returns probe result back to dual_selector.
    pub const ATTR_FORWARD_PROBE_RESULT: &'static str = "dual_selector.forward_probe_result";

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

    #[inline]
    /// Replace the request with a packet-backed message and invalidate query caches.
    pub fn set_request_packet(&mut self, packet: Packet) {
        self.request = Message::from_packet(packet)
            .expect("request packet should contain a valid DNS message");
        self.invalidate_query_view();
    }

    #[inline]
    /// Borrow the original request packet when the message is still packet-backed.
    pub fn request_packet(&self) -> Option<&Packet> {
        self.request.packet()
    }

    #[inline]
    /// Replace all typed request metadata from the current server layer.
    pub fn set_request_meta(&mut self, meta: RequestMeta) {
        self.request_meta = meta;
    }

    #[inline]
    /// Borrow the typed request metadata collected by the inbound server.
    pub fn request_meta(&self) -> &RequestMeta {
        &self.request_meta
    }

    #[inline]
    /// Borrow the request server name when the protocol carries one.
    pub fn server_name(&self) -> Option<&str> {
        self.request_meta.server_name.as_deref()
    }

    #[inline]
    /// Borrow the HTTP request path when the inbound protocol exposes one.
    pub fn url_path(&self) -> Option<&str> {
        self.request_meta.url_path.as_deref()
    }

    /// Materialize the current response as a message and borrow it immutably.
    pub fn response_message(&mut self) -> Result<Option<&Message>> {
        let Some(response) = self.response.as_mut() else {
            return Ok(None);
        };
        let message = response.ensure_message()?;
        Ok(Some(message))
    }

    /// Materialize the current response as a message and borrow it mutably.
    pub fn response_message_mut(&mut self) -> Result<Option<&mut Message>> {
        let Some(response) = self.response.as_mut() else {
            return Ok(None);
        };
        let message = response.ensure_message()?;
        Ok(Some(message))
    }

    /// Replace the current response with an already encoded packet plan.
    pub fn set_response_packet(&mut self, packet: Packet) -> Result<()> {
        self.response = Some(ResponsePlan::Packet(packet));
        Ok(())
    }

    #[inline]
    /// Replace the current response with an owned message plan.
    pub fn set_response_message(&mut self, message: Message) {
        self.response = Some(ResponsePlan::Message(message));
    }

    /// Build a sub-query context clone for recursive plugin execution.
    ///
    /// Typed attributes cannot be cloned generically, so only known string
    /// metadata required by server/executor plugins is preserved.
    pub fn clone_for_subquery(&self) -> DnsContext {
        DnsContext {
            src_addr: self.src_addr,
            request: self.request.clone(),
            response: self.response.clone(),
            exec_flow_state: ExecFlowState::Running,
            marks: self.marks.clone(),
            attributes: AHashMap::new(),
            request_meta: self.request_meta.clone(),
            query_view: self.query_view.clone(),
            query_view_version: self.query_view_version,
            registry: self.registry.clone(),
        }
    }

    /// Replace mutable request state with result produced by a sub-query context.
    pub fn replace_with_subquery_result(&mut self, sub_ctx: DnsContext) {
        self.request = sub_ctx.request;
        self.response = sub_ctx.response;
        self.exec_flow_state = sub_ctx.exec_flow_state;
        self.marks = sub_ctx.marks;
        self.attributes = sub_ctx.attributes;
        self.request_meta = sub_ctx.request_meta;
        self.query_view = sub_ctx.query_view;
        self.query_view_version = sub_ctx.query_view_version;
    }

    /// Invalidate cached question view after query name mutation.
    #[inline]
    pub fn invalidate_question_view(&mut self) {
        self.query_view = None;
        self.query_view_version = None;
    }

    /// Invalidate cached question view after query name mutation.
    #[inline]
    pub fn invalidate_query_view(&mut self) {
        self.invalidate_question_view();
    }

    /// Set first query name and invalidate question view cache.
    ///
    /// Returns false when request has no question.
    pub fn set_first_question_name(&mut self, name: Name) -> bool {
        let Some(question) = self.request.questions_mut().first_mut() else {
            return false;
        };
        question.set_name(name);
        self.invalidate_question_view();
        true
    }

    /// Get first-question view from context cache.
    pub fn question_view(&mut self) -> Option<&QuestionView> {
        let request_version = self.request.version();
        if self.query_view.is_none() || self.query_view_version != Some(request_version) {
            let question = self.request.first_question_access()?;
            let built = Some(Self::build_question_view_from_access(
                question,
                self.request
                    .edns_access()
                    .is_some_and(|edns| edns.dnssec_ok()),
                self.request.checking_disabled(),
            ));
            self.query_view = built;
            self.query_view_version = Some(request_version);
        }
        self.query_view.as_ref()
    }

    /// Backward-compatible alias for first-question view access.
    #[inline]
    pub fn query_view(&mut self) -> Option<&QuestionView> {
        self.question_view()
    }

    /// Normalize DNS name for domain-rule matching.
    ///
    /// # Examples
    /// ```
    /// use forgedns::core::context::DnsContext;
    /// use forgedns::message::Name;
    ///
    /// let name = Name::from_ascii("WWW.Example.COM.").unwrap();
    /// assert_eq!(DnsContext::normalize_dns_name(&name), "www.example.com");
    /// ```
    pub fn normalize_dns_name(name: &Name) -> String {
        name.normalized()
    }

    /// Build a normalized first-question view from a unified message question view.
    fn build_question_view_from_access(
        question: QuestionAccess<'_>,
        do_bit: bool,
        cd_bit: bool,
    ) -> QuestionView {
        Self::build_question_view_from_normalized(
            question.name().normalized(),
            question.qtype(),
            question.qclass(),
            do_bit,
            cd_bit,
        )
    }

    /// Build a normalized first-question view and precompute reverse label ranges.
    fn build_question_view_from_normalized(
        normalized_name: String,
        qtype: u16,
        qclass: u16,
        do_bit: bool,
        cd_bit: bool,
    ) -> QuestionView {
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
        QuestionView {
            normalized_name,
            label_ranges_rev,
            qtype,
            qclass,
            do_bit,
            cd_bit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Question;
    use crate::message::{Name, RecordType};
    use crate::plugin::PluginRegistry;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    /// Construct a minimal context fixture used by question-view tests.
    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("WWW.Example.COM.").unwrap(),
            RecordType::A,
        ));
        DnsContext {
            src_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: AHashMap::new(),
            request_meta: RequestMeta::default(),
            query_view: None,
            query_view_version: None,
            registry: Arc::new(PluginRegistry::new()),
        }
    }

    #[test]
    /// Verify the cached question view exposes normalized names and reverse labels.
    fn test_query_view_normalization_and_labels() {
        let mut ctx = make_context();
        let view = ctx.query_view().expect("query view should exist");
        assert_eq!(view.normalized_name(), "www.example.com");
        assert_eq!(view.labels_rev().as_slice(), ["com", "example", "www"]);
        assert_eq!(view.qtype(), u16::from(RecordType::A));
        assert_eq!(view.qclass(), 1);
    }

    #[test]
    /// Ensure renaming the first query invalidates and rebuilds the cached view.
    fn test_set_first_question_name_invalidates_view() {
        let mut ctx = make_context();
        let _ = ctx.query_view();
        assert!(ctx.query_view.is_some());

        assert!(ctx.set_first_question_name(Name::from_ascii("api.example.com.").unwrap()));
        assert!(ctx.query_view.is_none());
        assert_eq!(
            ctx.query_view().unwrap().normalized_name(),
            "api.example.com"
        );
    }

    #[test]
    /// Confirm packet-backed requests populate `QuestionView` without full decode.
    fn test_query_view_prefers_inbound_request_packet_when_present() {
        let mut ctx = make_context();
        let packet = vec![
            0x12, 0x34, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'p', b'i', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x1c, 0x00, 0x01,
        ];

        ctx.set_request_packet(Packet::from_vec(packet));

        let view = ctx.query_view().expect("query view should exist");
        assert_eq!(view.normalized_name(), "api.example.com");
        assert_eq!(view.qtype(), u16::from(RecordType::AAAA));
        assert!(view.cd_bit());
    }

    #[test]
    /// Verify server-side request metadata remains strongly typed and accessible.
    fn test_request_meta_is_typed() {
        let mut ctx = make_context();
        ctx.set_request_meta(RequestMeta {
            server_name: Some("dns.example.com".to_string()),
            url_path: Some("/dns-query".to_string()),
        });

        assert_eq!(ctx.server_name(), Some("dns.example.com"));
        assert_eq!(ctx.url_path(), Some("/dns-query"));
    }
}
