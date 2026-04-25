// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS request/response context management.

use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;

use ahash::{AHashMap, AHashSet};

use crate::plugin::PluginRegistry;
use crate::proto::Message;

/// Typed metadata attached to the request by the inbound server layer.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct RequestMeta {
    /// SNI or host-like server identifier carried by the server layer.
    pub server_name: Option<Arc<str>>,
    /// URL path carried by HTTP-based server layers.
    pub url_path: Option<Arc<str>>,
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

/// Runtime-only mutable execution state.
#[derive(Debug)]
pub struct RuntimeContext {
    marks: AHashSet<u32>,
    extensions: AHashMap<String, Box<dyn Any + Send + Sync>>,
}

impl Default for RuntimeContext {
    fn default() -> Self {
        Self {
            marks: AHashSet::new(),
            extensions: AHashMap::new(),
        }
    }
}

impl RuntimeContext {
    #[inline]
    pub fn marks(&self) -> &AHashSet<u32> {
        &self.marks
    }

    #[inline]
    pub fn marks_mut(&mut self) -> &mut AHashSet<u32> {
        &mut self.marks
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

    pub fn contains_attr(&self, name: &str) -> bool {
        self.extensions.contains_key(name)
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

/// One structured execution-path event captured from the sequence runtime.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExecutionPathEvent {
    pub sequence_tag: String,
    pub node_index: Option<usize>,
    pub kind: String,
    pub tag: Option<String>,
    pub outcome: String,
}

impl ExecutionPathEvent {
    #[inline]
    pub fn new(
        sequence_tag: impl Into<String>,
        node_index: Option<usize>,
        kind: impl Into<String>,
        tag: Option<impl Into<String>>,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            sequence_tag: sequence_tag.into(),
            node_index,
            kind: kind.into(),
            tag: tag.map(Into::into),
            outcome: outcome.into(),
        }
    }
}

/// Request-local execution path recording state.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ExecutionPath {
    enabled: bool,
    events: Vec<ExecutionPathEvent>,
}

impl ExecutionPath {
    #[inline]
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    #[inline]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    #[inline]
    pub fn push(&mut self, event: ExecutionPathEvent) {
        if self.enabled {
            self.events.push(event);
        }
    }

    #[inline]
    pub fn events(&self) -> &[ExecutionPathEvent] {
        &self.events
    }

    #[inline]
    pub fn events_from(&self, start: usize) -> &[ExecutionPathEvent] {
        self.events.get(start..).unwrap_or(&[])
    }
}

/// Context object for a DNS request/response lifecycle.
pub struct DnsContext {
    pub ingress: IngressContext,
    pub request: Message,
    pub response: Option<Message>,
    pub execution_path: ExecutionPath,
    pub runtime: RuntimeContext,
    pub registry: Arc<PluginRegistry>,
}

impl DnsContext {
    /// Context attribute key: dual_selector requests extra preferred-type probe
    /// in forward.
    pub const ATTR_FORWARD_PROBE_REQUEST: &'static str = "dual_selector.forward_probe_request";
    /// Context attribute key: forward returns probe result back to
    /// dual_selector.
    pub const ATTR_FORWARD_PROBE_RESULT: &'static str = "dual_selector.forward_probe_result";

    #[inline]
    pub fn new(peer_addr: SocketAddr, request: Message, registry: Arc<PluginRegistry>) -> Self {
        Self {
            ingress: IngressContext::new(peer_addr),
            request,
            response: None,
            execution_path: ExecutionPath::default(),
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
    pub fn request(&self) -> &Message {
        &self.request
    }

    #[inline]
    pub fn request_mut(&mut self) -> &mut Message {
        &mut self.request
    }

    #[inline]
    pub fn replace_request(&mut self, request: Message) {
        self.request = request;
    }

    #[inline]
    pub fn response(&self) -> Option<&Message> {
        self.response.as_ref()
    }

    #[inline]
    pub fn response_mut(&mut self) -> Option<&mut Message> {
        self.response.as_mut()
    }

    #[inline]
    pub fn set_response(&mut self, response: Message) {
        self.response = Some(response);
    }

    #[inline]
    pub fn clear_response(&mut self) {
        self.response = None;
    }

    #[inline]
    pub fn take_response(&mut self) -> Option<Message> {
        self.response.take()
    }

    #[inline]
    pub fn marks(&self) -> &AHashSet<u32> {
        self.runtime.marks()
    }

    #[inline]
    pub fn marks_mut(&mut self) -> &mut AHashSet<u32> {
        self.runtime.marks_mut()
    }

    #[inline]
    pub fn contains_attr(&self, name: &str) -> bool {
        self.runtime.contains_attr(name)
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
    pub fn enable_execution_path(&mut self) {
        self.execution_path.enable();
    }

    #[inline]
    pub fn execution_path_enabled(&self) -> bool {
        self.execution_path.enabled()
    }

    #[inline]
    pub fn execution_path_len(&self) -> usize {
        self.execution_path.len()
    }

    #[inline]
    pub fn execution_path_events(&self) -> &[ExecutionPathEvent] {
        self.execution_path.events()
    }

    #[inline]
    pub fn execution_path_events_from(&self, start: usize) -> &[ExecutionPathEvent] {
        self.execution_path.events_from(start)
    }

    #[inline]
    pub fn push_execution_path_event(&mut self, event: ExecutionPathEvent) {
        self.execution_path.push(event);
    }

    pub fn copy_for_subquery(&self) -> DnsContext {
        DnsContext {
            ingress: self.ingress.clone(),
            request: self.request.clone(),
            response: self.response.clone(),
            execution_path: self.execution_path.clone(),
            runtime: RuntimeContext {
                marks: self.runtime.marks.clone(),
                extensions: AHashMap::new(),
            },
            registry: self.registry.clone(),
        }
    }

    pub fn apply_subquery_result(&mut self, sub_ctx: DnsContext) {
        self.ingress = sub_ctx.ingress;
        self.request = sub_ctx.request;
        self.response = sub_ctx.response;
        self.execution_path = sub_ctx.execution_path;
        self.runtime.marks = sub_ctx.runtime.marks;
        self.runtime.extensions = sub_ctx.runtime.extensions;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::proto::rdata::A;
    use crate::proto::{DNSClass, Message, Name, Question, RData, Record, RecordType};

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("WWW.Example.COM.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    #[test]
    fn test_request_meta_is_typed() {
        let mut ctx = make_context();
        ctx.set_request_meta(RequestMeta {
            server_name: Some(Arc::from("dns.example.com")),
            url_path: Some(Arc::from("/dns-query")),
        });

        assert_eq!(ctx.server_name(), Some("dns.example.com"));
        assert_eq!(ctx.url_path(), Some("/dns-query"));
    }

    #[test]
    fn test_request_helpers_replace_message() {
        let mut ctx = make_context();
        let packet = vec![
            0x12, 0x34, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
            b'p', b'i', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x1C, 0x00, 0x01,
        ];

        ctx.replace_request(Message::from_bytes(&packet).expect("packet should parse"));
        let question = ctx.request.first_question().expect("question should exist");
        assert_eq!(question.name().normalized(), "api.example.com");
        assert_eq!(question.qtype(), RecordType::AAAA);
        assert!(ctx.request.checking_disabled());
    }

    #[test]
    fn test_response_is_mutated_directly() {
        let mut ctx = make_context();
        let mut response = Message::new();
        response.set_message_type(crate::proto::MessageType::Response);
        response.add_question(Question::new(
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        ctx.set_response(response);

        assert!(
            ctx.response
                .as_ref()
                .unwrap()
                .has_answer_ip(|ip| ip == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );

        ctx.response
            .as_mut()
            .unwrap()
            .add_answer(Record::from_rdata(
                Name::from_ascii("www.example.com.").unwrap(),
                60,
                RData::A(A(Ipv4Addr::new(198, 51, 100, 2))),
            ));

        assert!(
            ctx.response
                .as_ref()
                .unwrap()
                .has_answer_ip(|ip| ip == IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
        );
    }

    #[test]
    fn test_execution_path_is_opt_in() {
        let mut ctx = make_context();
        ctx.push_execution_path_event(ExecutionPathEvent::new(
            "main",
            Some(0),
            "matcher",
            Some("qname"),
            "matched",
        ));
        assert!(ctx.execution_path_events().is_empty());

        ctx.enable_execution_path();
        ctx.push_execution_path_event(ExecutionPathEvent::new(
            "main",
            Some(0),
            "matcher",
            Some("qname"),
            "matched",
        ));
        assert_eq!(ctx.execution_path_len(), 1);
    }

    #[test]
    fn test_execution_path_subquery_copy_and_apply() {
        let mut ctx = make_context();
        ctx.enable_execution_path();
        ctx.push_execution_path_event(ExecutionPathEvent::new(
            "main",
            Some(0),
            "executor",
            Some("cache"),
            "entered",
        ));

        let mut sub_ctx = ctx.copy_for_subquery();
        sub_ctx.push_execution_path_event(ExecutionPathEvent::new(
            "main",
            Some(1),
            "executor",
            Some("forward"),
            "next",
        ));
        ctx.apply_subquery_result(sub_ctx);

        assert_eq!(ctx.execution_path_len(), 2);
        assert_eq!(
            ctx.execution_path_events_from(1)[0].tag.as_deref(),
            Some("forward")
        );
    }
}
