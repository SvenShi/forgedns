// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
//! Server plugin category.
//!
//! Server plugins terminate inbound DNS transports and feed normalized requests
//! into the executor pipeline. They own protocol-specific listener concerns
//! such as socket binding, connection lifecycle, TLS or QUIC setup, and request
//! decoding, while delegating policy execution to [`RequestHandle`].
//!
//! Main responsibilities:
//!
//! - accept UDP, TCP, DoT, DoQ, or HTTP-based DNS traffic;
//! - construct [`DnsContext`] inputs from decoded DNS messages plus transport
//!   metadata;
//! - invoke the configured entry executor chain; and
//! - translate the resulting [`crate::proto::Message`] back into the
//!   transport's response format.
//!
//! This separation keeps protocol code isolated from matchers, executors, and
//! providers, while preserving a common request lifecycle across all servers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::{Level, debug, event_enabled, warn};

use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::metrics::{MetricLabel, MetricSample, MetricSink, MetricSource};
pub(crate) use crate::network::listen::parse_listen_addr;
use crate::plugin::Plugin;
use crate::plugin::executor::{ExecStep, Executor};
use crate::proto::{Message, Rcode};

pub mod http;
pub mod quic;
pub mod tcp;
pub mod udp;

pub trait Server: Plugin {
    fn run(&self);
}

pub(crate) struct ConnectionGuard {
    active_connections: Arc<AtomicU64>,
    src: SocketAddr,
    protocol: &'static str,
}

impl ConnectionGuard {
    pub(crate) fn new(
        active_connections: Arc<AtomicU64>,
        src: SocketAddr,
        protocol: &'static str,
    ) -> Self {
        Self {
            active_connections,
            src,
            protocol,
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let active = self
            .active_connections
            .fetch_sub(1, Ordering::Relaxed)
            .saturating_sub(1);
        debug!(
            "{} connection from {} closed (active: {})",
            self.protocol, self.src, active
        );
        if active > 0 && active.is_multiple_of(10) {
            debug!("Active connections: {}", active);
        }
    }
}

/// Shared per-server-plugin request metrics.
///
/// One instance per server plugin tag, shared by every [`RequestHandle`] the
/// plugin owns (the HTTP server owns one handle per route but a single metrics
/// instance). Counters are owned `AtomicU64`s updated with relaxed ordering on
/// the request path; the `protocol` label is startup-fixed and low-cardinality,
/// keeping this within the generic metrics layer's constraints.
#[derive(Debug)]
pub(crate) struct ServerMetrics {
    tag: String,
    protocol: &'static str,
    request_total: AtomicU64,
    completed_total: AtomicU64,
    controlled_total: AtomicU64,
    failed_total: AtomicU64,
    inflight: AtomicU64,
    latency_count: AtomicU64,
    latency_sum_ms: AtomicU64,
}

impl ServerMetrics {
    pub(crate) fn new(tag: String, protocol: &'static str) -> Self {
        Self {
            tag,
            protocol,
            request_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            controlled_total: AtomicU64::new(0),
            failed_total: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            latency_sum_ms: AtomicU64::new(0),
        }
    }

    #[inline]
    fn on_request_start(&self) -> u64 {
        self.request_total.fetch_add(1, Ordering::Relaxed);
        self.inflight.fetch_add(1, Ordering::Relaxed);
        AppClock::elapsed_millis()
    }

    #[inline]
    fn on_request_finish(&self, start_ms: u64, exit: RequestExit) {
        self.inflight.fetch_sub(1, Ordering::Relaxed);
        let counter = match exit {
            RequestExit::Completed => &self.completed_total,
            RequestExit::Controlled => &self.controlled_total,
            RequestExit::Failed => &self.failed_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let elapsed = AppClock::elapsed_millis().saturating_sub(start_ms);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_ms.fetch_add(elapsed, Ordering::Relaxed);
    }
}

impl MetricSource for ServerMetrics {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn plugin_type(&self) -> &'static str {
        "server"
    }

    fn collect(&self, sink: &mut dyn MetricSink) {
        let labels = [
            MetricLabel::new("plugin_tag", self.tag.as_str()),
            MetricLabel::new("protocol", self.protocol),
        ];
        sink.emit(MetricSample::counter(
            "server_request_total",
            "Total inbound DNS requests handled by the server.",
            &labels,
            self.request_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "server_completed_total",
            "Total requests that finished by running the executor chain to completion.",
            &labels,
            self.completed_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "server_controlled_total",
            "Total requests stopped early by an executor (stop/return).",
            &labels,
            self.controlled_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "server_failed_total",
            "Total requests that produced a SERVFAIL because the entry executor failed.",
            &labels,
            self.failed_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::gauge(
            "server_inflight",
            "Current number of in-flight requests being handled by the server.",
            &labels,
            self.inflight.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "server_latency_count",
            "Total requests included in server latency statistics.",
            &labels,
            self.latency_count.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "server_latency_sum_ms",
            "Total server request handling latency in milliseconds.",
            &labels,
            self.latency_sum_ms.load(Ordering::Relaxed),
        ));
    }
}

#[derive(Debug)]
pub struct RequestHandle {
    pub entry_executor: Arc<dyn Executor>,
    /// Shared server metrics. `None` for internal/test handles that should not
    /// emit server-level metrics.
    pub(crate) metrics: Option<Arc<ServerMetrics>>,
}
pub use crate::core::context::RequestMeta;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RequestExit {
    Completed,
    Controlled,
    Failed,
}

#[derive(Debug)]
#[allow(unused)]
pub struct RequestResult {
    pub request: Message,
    pub response: Message,
    pub exit: RequestExit,
}

impl RequestHandle {
    #[hotpath::measure]
    pub async fn handle_request(
        &self,
        msg: Message,
        src_addr: SocketAddr,
        meta: RequestMeta,
    ) -> RequestResult {
        let metrics_start = self.metrics.as_ref().map(|m| m.on_request_start());

        let mut context = DnsContext::new(src_addr, msg);
        self.apply_request_meta(&mut context, meta);

        // Log request details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "DNS request from {}, queries: {:?}, id: {}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                context.request.questions(),
                context.request.id(),
                context.request.edns(),
                context.request.authorities()
            );
        }

        // Execute entry plugin to process the request
        let exec_outcome = self
            .entry_executor
            .execute_with_next(&mut context, None)
            .await;
        let (response, exit) = match exec_outcome {
            Ok(step) => {
                let exit = match step {
                    ExecStep::Next => RequestExit::Completed,
                    ExecStep::Stop | ExecStep::Return => RequestExit::Controlled,
                };
                let response = context
                    .take_response()
                    .unwrap_or_else(|| self.build_empty_response(&context));
                (response, exit)
            }
            Err(e) => {
                warn!(
                    "Entry executor '{}' failed for source {} id {}: {}",
                    self.entry_executor.tag(),
                    src_addr,
                    context.request.id(),
                    e
                );
                (self.build_servfail_response(&context), RequestExit::Failed)
            }
        };

        // Log response details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "Sending response to {}, exit: {:?}, queries: {:?}, id: {}, edns: {:?}, answers: {:?}",
                &src_addr,
                exit,
                context.request.questions(),
                response.id(),
                response.edns(),
                response.answers()
            );
        }

        if let (Some(metrics), Some(start_ms)) = (self.metrics.as_ref(), metrics_start) {
            metrics.on_request_finish(start_ms, exit);
        }

        RequestResult {
            request: context.request,
            response,
            exit,
        }
    }

    #[inline]
    fn apply_request_meta(&self, context: &mut DnsContext, meta: RequestMeta) {
        context.set_request_meta(RequestMeta {
            server_name: meta.server_name.filter(|value| !value.is_empty()),
            url_path: meta.url_path.filter(|value| !value.is_empty()),
        });
    }

    #[inline]
    fn build_servfail_response(&self, context: &DnsContext) -> Message {
        self.build_base_response(context, Rcode::ServFail)
    }

    #[inline]
    fn build_empty_response(&self, context: &DnsContext) -> Message {
        self.build_base_response(context, Rcode::NoError)
    }

    #[inline]
    fn build_base_response(&self, context: &DnsContext, rcode: Rcode) -> Message {
        context.request().response(rcode)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::continue_next;
    use crate::core::error::Result;
    use crate::proto::{Name, Question, RecordType};

    #[test]
    fn test_parse_listen_addr_accepts_port_only_shorthand() {
        let addr = parse_listen_addr(":5337").expect("port-only shorthand should parse");

        assert_eq!(addr, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 5337)));
    }

    #[test]
    fn test_parse_listen_addr_rejects_invalid_port_only_shorthand() {
        let err = parse_listen_addr(":not-a-port").unwrap_err();

        assert!(err.to_string().contains("Invalid listen address"));
    }

    fn make_request(id: u16, qname: &str) -> Message {
        let mut request = Message::new();
        request.set_id(id);
        request.add_question(Question::new(
            Name::from_ascii(qname).expect("query name should be valid"),
            RecordType::A,
            crate::proto::DNSClass::IN,
        ));
        request
    }

    fn make_request_handle(executor: Arc<dyn Executor>) -> RequestHandle {
        RequestHandle {
            entry_executor: executor,
            metrics: None,
        }
    }

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct ObservedMeta {
        server_name: Option<String>,
        url_path: Option<String>,
    }

    #[derive(Debug)]
    struct CaptureMetaExecutor {
        observed: Arc<Mutex<Option<ObservedMeta>>>,
    }

    #[async_trait]
    impl Plugin for CaptureMetaExecutor {
        fn tag(&self) -> &str {
            "capture_meta"
        }

        async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for CaptureMetaExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            let observed = ObservedMeta {
                server_name: context.server_name().map(str::to_string),
                url_path: context.url_path().map(str::to_string),
            };
            self.observed
                .lock()
                .expect("meta capture lock should not be poisoned")
                .replace(observed);
            Ok(ExecStep::Next)
        }
    }

    #[derive(Debug)]
    struct PostResponseExecutor;

    #[async_trait]
    impl Plugin for PostResponseExecutor {
        fn tag(&self) -> &str {
            "post_response"
        }

        async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for PostResponseExecutor {
        fn with_next(&self) -> bool {
            true
        }

        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            Ok(ExecStep::Next)
        }

        async fn execute_with_next(
            &self,
            context: &mut DnsContext,
            next: Option<crate::plugin::executor::ExecutorNext>,
        ) -> Result<ExecStep> {
            let step = continue_next!(next, context)?;
            context.set_response(context.request.response(Rcode::NXDomain));
            Ok(step)
        }
    }

    #[tokio::test]
    async fn test_handle_request_with_meta_applies_server_name_and_url_path() {
        let observed = Arc::new(Mutex::new(None));
        let request_handle = make_request_handle(Arc::new(CaptureMetaExecutor {
            observed: observed.clone(),
        }));
        let request = make_request(13, "example.com.");

        let _result = request_handle
            .handle_request(
                request,
                SocketAddr::from(([127, 0, 0, 1], 5303)),
                RequestMeta {
                    server_name: Some(Arc::from("dns.example.test")),
                    url_path: Some(Arc::from("/dns-query")),
                },
            )
            .await;

        assert_eq!(
            observed
                .lock()
                .expect("meta capture lock should not be poisoned")
                .clone(),
            Some(ObservedMeta {
                server_name: Some("dns.example.test".to_string()),
                url_path: Some("/dns-query".to_string()),
            })
        );
    }

    #[tokio::test]
    async fn test_handle_request_supports_with_next_entry_executor() {
        let request_handle = make_request_handle(Arc::new(PostResponseExecutor));
        let request = make_request(21, "example.com.");

        let result = request_handle
            .handle_request(
                request,
                SocketAddr::from(([127, 0, 0, 1], 5303)),
                RequestMeta::default(),
            )
            .await;

        assert_eq!(result.response.rcode(), Rcode::NXDomain);
        assert_eq!(result.exit, RequestExit::Completed);
    }
}
