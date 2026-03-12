/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS request/response context management.
//!
//! Provides a layered state container for DNS queries as they flow through the
//! plugin pipeline.

use crate::core::error::Result;
use crate::message::Name;
use crate::message::rdata::opt::ClientSubnet;
use crate::message::{Message, Packet, QuestionAccess, ResponsePlan};
use crate::plugin::PluginRegistry;
use ahash::AHashMap;
use ahash::AHashSet;
use smallvec::SmallVec;
use std::any::Any;
use std::net::SocketAddr;
use std::ops::Deref;
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

#[derive(Debug, Clone, Default)]
struct VersionedCache<T> {
    version: Option<u64>,
    value: Option<T>,
}

impl<T> VersionedCache<T> {
    #[inline]
    fn invalidate(&mut self) {
        self.version = None;
        self.value = None;
    }

    fn get_or_init(&mut self, version: u64, init: impl FnOnce() -> T) -> &T {
        if self.version != Some(version) || self.value.is_none() {
            self.value = Some(init());
            self.version = Some(version);
        }
        self.value
            .as_ref()
            .expect("versioned cache should contain a value after initialization")
    }
}

/// Metadata carried by the inbound transport layer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IngressContext {
    peer_addr: SocketAddr,
    request_meta: RequestMeta,
}

impl Default for IngressContext {
    fn default() -> Self {
        Self {
            peer_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            request_meta: RequestMeta::default(),
        }
    }
}

impl IngressContext {
    #[inline]
    pub fn new(peer_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            request_meta: RequestMeta::default(),
        }
    }

    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    #[inline]
    pub fn set_peer_addr(&mut self, peer_addr: SocketAddr) {
        self.peer_addr = peer_addr;
    }

    #[inline]
    pub fn request_meta(&self) -> &RequestMeta {
        &self.request_meta
    }

    #[inline]
    pub fn set_request_meta(&mut self, meta: RequestMeta) {
        self.request_meta = meta;
    }

    #[inline]
    pub fn server_name(&self) -> Option<&str> {
        self.request_meta.server_name.as_deref()
    }

    #[inline]
    pub fn url_path(&self) -> Option<&str> {
        self.request_meta.url_path.as_deref()
    }
}

/// Lazily-built summary of the first DNS question.
#[derive(Debug, Clone)]
pub struct QuestionFacts {
    /// Lowercased matcher-friendly query name without trailing dot.
    normalized_name: String,
    /// Reverse label ranges into `normalized_name`.
    label_ranges_rev: SmallVec<[Range<u16>; 8]>,
    /// Raw question type.
    qtype: u16,
    /// Raw question class.
    qclass: u16,
}

impl QuestionFacts {
    #[inline]
    pub fn normalized_name(&self) -> &str {
        &self.normalized_name
    }

    #[inline]
    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    #[inline]
    pub fn qclass(&self) -> u16 {
        self.qclass
    }

    #[inline]
    pub fn iter_labels_rev(&self) -> QuestionLabelsRev<'_> {
        QuestionLabelsRev {
            normalized_name: &self.normalized_name,
            ranges: self.label_ranges_rev.iter(),
        }
    }

    #[inline]
    pub fn labels_rev(&self) -> SmallVec<[&str; 8]> {
        let mut out = SmallVec::<[&str; 8]>::with_capacity(self.label_ranges_rev.len());
        out.extend(self.iter_labels_rev());
        out
    }

    fn from_access(question: QuestionAccess<'_>) -> Self {
        Self::from_normalized(
            question.name().normalized(),
            question.qtype(),
            question.qclass(),
        )
    }

    fn from_normalized(normalized_name: String, qtype: u16, qclass: u16) -> Self {
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
        Self {
            normalized_name,
            label_ranges_rev,
            qtype,
            qclass,
        }
    }
}

/// Iterator over normalized query labels from right to left.
pub struct QuestionLabelsRev<'a> {
    normalized_name: &'a str,
    ranges: std::slice::Iter<'a, Range<u16>>,
}

impl<'a> Iterator for QuestionLabelsRev<'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let range = self.ranges.next()?;
        Some(&self.normalized_name[range.start as usize..range.end as usize])
    }
}

/// Cached request summary shared by matchers and executors.
#[derive(Debug, Clone)]
pub struct RequestFacts {
    question_count: u16,
    first_question: Option<QuestionFacts>,
    do_bit: bool,
    cd_bit: bool,
    client_subnet: Option<ClientSubnet>,
    max_payload: u16,
}

impl RequestFacts {
    #[inline]
    pub fn question_count(&self) -> u16 {
        self.question_count
    }

    #[inline]
    pub fn first_question(&self) -> Option<&QuestionFacts> {
        self.first_question.as_ref()
    }

    #[inline]
    pub fn do_bit(&self) -> bool {
        self.do_bit
    }

    #[inline]
    pub fn cd_bit(&self) -> bool {
        self.cd_bit
    }

    #[inline]
    pub fn client_subnet(&self) -> Option<&ClientSubnet> {
        self.client_subnet.as_ref()
    }

    #[inline]
    pub fn max_payload(&self) -> u16 {
        self.max_payload
    }

    fn from_message(message: &Message) -> Self {
        let edns = message.edns_access();
        let do_bit = edns.as_ref().is_some_and(|value| value.dnssec_ok());
        let client_subnet = edns.as_ref().and_then(|value| value.client_subnet());
        let max_payload = edns
            .as_ref()
            .map_or(512, |value| value.udp_payload_size().max(512));
        Self {
            question_count: message.question_count(),
            first_question: message
                .first_question_access()
                .map(QuestionFacts::from_access),
            do_bit,
            cd_bit: message.checking_disabled(),
            client_subnet,
            max_payload,
        }
    }
}

/// Request message plus lazily-derived matcher facts.
#[derive(Debug, Clone)]
pub struct RequestContext {
    message: Message,
    facts: VersionedCache<RequestFacts>,
}

impl RequestContext {
    #[inline]
    pub fn new(message: Message) -> Self {
        Self {
            message,
            facts: VersionedCache {
                version: None,
                value: None,
            },
        }
    }

    #[inline]
    pub fn message(&self) -> &Message {
        &self.message
    }

    #[inline]
    pub fn id(&self) -> u16 {
        self.message.id()
    }

    #[inline]
    pub fn question_count(&self) -> u16 {
        self.message.question_count()
    }

    #[inline]
    pub fn questions(&self) -> &[crate::message::Question] {
        self.message.questions()
    }

    pub fn questions_mut(&mut self) -> &mut Vec<crate::message::Question> {
        self.invalidate_facts();
        self.message.questions_mut()
    }

    #[inline]
    pub fn name_servers(&self) -> &[crate::message::Record] {
        self.message.name_servers()
    }

    #[inline]
    pub fn edns_access(&self) -> Option<crate::message::EdnsAccess<'_>> {
        self.message.edns_access()
    }

    #[inline]
    pub fn first_question_name_owned(&self) -> Option<Name> {
        self.message.first_question_name_owned()
    }

    #[inline]
    pub fn first_question_type(&self) -> Option<crate::message::RecordType> {
        self.message.first_question_type()
    }

    #[inline]
    pub fn first_question_class(&self) -> Option<crate::message::DNSClass> {
        self.message.first_question_class()
    }

    pub fn message_mut(&mut self) -> &mut Message {
        self.invalidate_facts();
        &mut self.message
    }

    pub fn replace_message(&mut self, message: Message) {
        self.message = message;
        self.invalidate_facts();
    }

    #[inline]
    pub fn clone_message(&self) -> Message {
        self.message.clone()
    }

    #[inline]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.message.to_bytes()
    }

    pub fn set_packet(&mut self, packet: Packet) {
        self.message = Message::from_packet(packet)
            .expect("request packet should contain a valid DNS message");
        self.invalidate_facts();
    }

    #[inline]
    pub fn packet(&self) -> Option<&Packet> {
        self.message.packet()
    }

    pub fn set_first_question_name(&mut self, name: Name) -> bool {
        let Some(question) = self.message.questions_mut().first_mut() else {
            return false;
        };
        question.set_name(name);
        self.invalidate_facts();
        true
    }

    #[inline]
    pub fn invalidate_facts(&mut self) {
        self.facts.invalidate();
    }

    pub fn set_checking_disabled(&mut self, value: bool) {
        self.message.set_checking_disabled(value);
        self.invalidate_facts();
    }

    pub fn set_edns(&mut self, edns: crate::message::Edns) {
        self.message.set_edns(edns);
        self.invalidate_facts();
    }

    pub fn facts(&mut self) -> &RequestFacts {
        let version = self.message.version();
        self.facts
            .get_or_init(version, || RequestFacts::from_message(&self.message))
    }

    #[inline]
    pub fn question(&mut self) -> Option<&QuestionFacts> {
        self.facts().first_question()
    }
}

impl Deref for RequestContext {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

/// Response state carried through the executor pipeline.
#[derive(Debug, Clone, Default)]
pub struct ResponseContext {
    plan: Option<ResponsePlan>,
}

impl ResponseContext {
    #[inline]
    pub fn is_some(&self) -> bool {
        self.plan.is_some()
    }

    #[inline]
    pub fn is_none(&self) -> bool {
        self.plan.is_none()
    }

    #[inline]
    pub fn plan(&self) -> Option<&ResponsePlan> {
        self.plan.as_ref()
    }

    #[inline]
    pub fn plan_mut(&mut self) -> Option<&mut ResponsePlan> {
        self.plan.as_mut()
    }

    #[inline]
    pub fn as_ref(&self) -> Option<&ResponsePlan> {
        self.plan.as_ref()
    }

    #[inline]
    pub fn as_mut(&mut self) -> Option<&mut ResponsePlan> {
        self.plan.as_mut()
    }

    #[inline]
    pub fn take(&mut self) -> Option<ResponsePlan> {
        self.plan.take()
    }

    #[inline]
    pub fn expect(&self, msg: &str) -> &ResponsePlan {
        self.plan.as_ref().expect(msg)
    }

    #[inline]
    pub fn set_plan(&mut self, plan: ResponsePlan) {
        self.plan = Some(plan);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.plan = None;
    }

    pub fn message(&mut self) -> Result<Option<&Message>> {
        let Some(plan) = self.plan.as_mut() else {
            return Ok(None);
        };
        Ok(Some(plan.ensure_message()?))
    }

    pub fn message_mut(&mut self) -> Result<Option<&mut Message>> {
        let Some(plan) = self.plan.as_mut() else {
            return Ok(None);
        };
        Ok(Some(plan.ensure_message()?))
    }

    #[inline]
    pub fn set_packet(&mut self, packet: Packet) {
        self.plan = Some(ResponsePlan::Packet(packet));
    }

    #[inline]
    pub fn set_message(&mut self, message: Message) {
        self.plan = Some(ResponsePlan::Message(message));
    }
}

/// Runtime-only mutable execution state.
#[derive(Debug)]
pub struct RuntimeContext {
    flow: ExecFlowState,
    marks: AHashSet<String>,
    extensions: AHashMap<String, Box<dyn Any + Send + Sync>>,
}

impl Default for RuntimeContext {
    fn default() -> Self {
        Self {
            flow: ExecFlowState::Running,
            marks: AHashSet::new(),
            extensions: AHashMap::new(),
        }
    }
}

impl RuntimeContext {
    #[inline]
    pub fn flow(&self) -> ExecFlowState {
        self.flow
    }

    #[inline]
    pub fn set_flow(&mut self, flow: ExecFlowState) {
        self.flow = flow;
    }

    #[inline]
    pub fn marks(&self) -> &AHashSet<String> {
        &self.marks
    }

    #[inline]
    pub fn marks_mut(&mut self) -> &mut AHashSet<String> {
        &mut self.marks
    }

    #[inline]
    pub fn insert_mark(&mut self, mark: impl Into<String>) -> bool {
        self.marks.insert(mark.into())
    }

    pub fn extend_marks(&mut self, marks: impl IntoIterator<Item = String>) {
        self.marks.extend(marks);
    }

    pub fn set_attr<T>(&mut self, name: impl Into<String>, value: T)
    where
        T: Send + Sync + 'static,
    {
        self.extensions.insert(name.into(), Box::new(value));
    }

    pub fn get_attr<T>(&self, name: &str) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.extensions
            .get(name)
            .and_then(|value| value.downcast_ref())
    }

    pub fn remove_attr<T>(&mut self, name: &str) -> Option<T>
    where
        T: Send + Sync + 'static,
    {
        self.extensions
            .remove(name)
            .and_then(|value| value.downcast::<T>().ok())
            .map(|boxed| *boxed)
    }
}

/// Context object for a DNS request/response lifecycle.
pub struct DnsContext {
    pub ingress: IngressContext,
    pub request: RequestContext,
    pub response: ResponseContext,
    pub runtime: RuntimeContext,
    pub registry: Arc<PluginRegistry>,
}

impl DnsContext {
    /// Context attribute key: dual_selector requests extra preferred-type probe in forward.
    pub const ATTR_FORWARD_PROBE_REQUEST: &'static str = "dual_selector.forward_probe_request";

    /// Context attribute key: forward returns probe result back to dual_selector.
    pub const ATTR_FORWARD_PROBE_RESULT: &'static str = "dual_selector.forward_probe_result";

    #[inline]
    pub fn new(peer_addr: SocketAddr, request: Message, registry: Arc<PluginRegistry>) -> Self {
        Self {
            ingress: IngressContext::new(peer_addr),
            request: RequestContext::new(request),
            response: ResponseContext::default(),
            runtime: RuntimeContext::default(),
            registry,
        }
    }

    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.ingress.peer_addr()
    }

    #[inline]
    pub fn set_peer_addr(&mut self, peer_addr: SocketAddr) {
        self.ingress.set_peer_addr(peer_addr);
    }

    #[inline]
    pub fn set_request_packet(&mut self, packet: Packet) {
        self.request.set_packet(packet);
    }

    #[inline]
    pub fn request_packet(&self) -> Option<&Packet> {
        self.request.packet()
    }

    #[inline]
    pub fn set_request_meta(&mut self, meta: RequestMeta) {
        self.ingress.set_request_meta(meta);
    }

    #[inline]
    pub fn request_meta(&self) -> &RequestMeta {
        self.ingress.request_meta()
    }

    #[inline]
    pub fn server_name(&self) -> Option<&str> {
        self.ingress.server_name()
    }

    #[inline]
    pub fn url_path(&self) -> Option<&str> {
        self.ingress.url_path()
    }

    #[inline]
    pub fn response_message(&mut self) -> Result<Option<&Message>> {
        self.response.message()
    }

    #[inline]
    pub fn response_message_mut(&mut self) -> Result<Option<&mut Message>> {
        self.response.message_mut()
    }

    #[inline]
    pub fn set_response_plan(&mut self, plan: ResponsePlan) {
        self.response.set_plan(plan);
    }

    #[inline]
    pub fn take_response_plan(&mut self) -> Option<ResponsePlan> {
        self.response.take()
    }

    #[inline]
    pub fn set_response_packet(&mut self, packet: Packet) -> Result<()> {
        self.response.set_packet(packet);
        Ok(())
    }

    #[inline]
    pub fn set_response_message(&mut self, message: Message) {
        self.response.set_message(message);
    }

    #[inline]
    pub fn flow(&self) -> ExecFlowState {
        self.runtime.flow()
    }

    #[inline]
    pub fn set_flow(&mut self, flow: ExecFlowState) {
        self.runtime.set_flow(flow);
    }

    #[inline]
    pub fn marks(&self) -> &AHashSet<String> {
        self.runtime.marks()
    }

    #[inline]
    pub fn marks_mut(&mut self) -> &mut AHashSet<String> {
        self.runtime.marks_mut()
    }

    #[inline]
    pub fn set_attr<T>(&mut self, name: impl Into<String>, value: T)
    where
        T: Send + Sync + 'static,
    {
        self.runtime.set_attr(name, value);
    }

    #[inline]
    pub fn get_attr<T>(&self, name: &str) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.runtime.get_attr(name)
    }

    #[inline]
    pub fn remove_attr<T>(&mut self, name: &str) -> Option<T>
    where
        T: Send + Sync + 'static,
    {
        self.runtime.remove_attr(name)
    }

    #[inline]
    pub fn request_facts(&mut self) -> &RequestFacts {
        self.request.facts()
    }

    #[inline]
    pub fn question(&mut self) -> Option<&QuestionFacts> {
        self.request.question()
    }

    #[inline]
    pub fn set_first_question_name(&mut self, name: Name) -> bool {
        self.request.set_first_question_name(name)
    }

    pub fn clone_for_subquery(&self) -> DnsContext {
        DnsContext {
            ingress: self.ingress.clone(),
            request: self.request.clone(),
            response: self.response.clone(),
            runtime: RuntimeContext {
                flow: ExecFlowState::Running,
                marks: self.runtime.marks.clone(),
                extensions: AHashMap::new(),
            },
            registry: self.registry.clone(),
        }
    }

    pub fn replace_with_subquery_result(&mut self, sub_ctx: DnsContext) {
        self.ingress = sub_ctx.ingress;
        self.request = sub_ctx.request;
        self.response = sub_ctx.response;
        self.runtime.flow = sub_ctx.runtime.flow;
        self.runtime.marks = sub_ctx.runtime.marks;
        self.runtime.extensions = sub_ctx.runtime.extensions;
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
    #[inline]
    pub fn normalize_dns_name(name: &Name) -> String {
        name.normalized()
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

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("WWW.Example.COM.").unwrap(),
            RecordType::A,
        ));
        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    #[test]
    fn test_question_facts_normalization_and_labels() {
        let mut ctx = make_context();
        let question = ctx.question().expect("question should exist");
        assert_eq!(question.normalized_name(), "www.example.com");
        assert_eq!(question.labels_rev().as_slice(), ["com", "example", "www"]);
        assert_eq!(question.qtype(), u16::from(RecordType::A));
        assert_eq!(question.qclass(), 1);
    }

    #[test]
    fn test_set_first_question_name_invalidates_facts() {
        let mut ctx = make_context();
        let _ = ctx.question();
        assert!(ctx.request.facts.value.is_some());

        assert!(ctx.set_first_question_name(Name::from_ascii("api.example.com.").unwrap()));
        assert!(ctx.request.facts.value.is_none());
        assert_eq!(ctx.question().unwrap().normalized_name(), "api.example.com");
    }

    #[test]
    fn test_question_facts_prefers_inbound_request_packet_when_present() {
        let mut ctx = make_context();
        let packet = vec![
            0x12, 0x34, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'p', b'i', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x1c, 0x00, 0x01,
        ];

        ctx.set_request_packet(Packet::from_vec(packet));

        let question = ctx.question().expect("question should exist");
        assert_eq!(question.normalized_name(), "api.example.com");
        assert_eq!(question.qtype(), u16::from(RecordType::AAAA));
        assert!(ctx.request_facts().cd_bit());
    }

    #[test]
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
