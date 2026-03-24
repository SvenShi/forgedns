/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS request/response context management.

use crate::message::Message;
use crate::plugin::PluginRegistry;
use ahash::{AHashMap, AHashSet};
use std::any::Any;
use std::net::SocketAddr;
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

/// Context object for a DNS request/response lifecycle.
pub struct DnsContext {
    pub ingress: IngressContext,
    pub request: Message,
    pub response: Option<Message>,
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
            request,
            response: None,
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

    pub fn copy_for_subquery(&self) -> DnsContext {
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

    pub fn apply_subquery_result(&mut self, sub_ctx: DnsContext) {
        self.ingress = sub_ctx.ingress;
        self.request = sub_ctx.request;
        self.response = sub_ctx.response;
        self.runtime.flow = sub_ctx.runtime.flow;
        self.runtime.marks = sub_ctx.runtime.marks;
        self.runtime.extensions = sub_ctx.runtime.extensions;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::rdata::A;
    use crate::message::{DNSClass, Question};
    use crate::message::{Message, Name, RData, Record, RecordType};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
            0x00, 0x00, 0x1c, 0x00, 0x01,
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
        response.set_message_type(crate::message::MessageType::Response);
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
}
