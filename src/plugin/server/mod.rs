/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::{DnsContext, ExecFlowState};
use crate::core::error::{DnsError, Result};
use crate::message::{Message, Rcode};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginRegistry};
use std::io::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{Level, debug, event_enabled, warn};

pub mod http;
pub mod quic;
pub mod tcp;
pub mod udp;

pub trait Server: Plugin {
    fn run(&self);
}

/// Parse a server listen address.
///
/// Besides standard `SocketAddr` inputs, this also accepts `:port` shorthand
/// and expands it to `0.0.0.0:port`.
pub(crate) fn parse_listen_addr(listen: &str) -> Result<SocketAddr> {
    let listen = listen.trim();

    if let Ok(addr) = SocketAddr::from_str(listen) {
        return Ok(addr);
    }

    if let Some(port) = listen.strip_prefix(':') {
        let port = port.parse::<u16>().map_err(|e| {
            DnsError::Io(Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid listen address {}: {}", listen, e),
            ))
        })?;
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }

    Err(DnsError::Io(Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "Invalid listen address {}: expected ip:port, [ipv6]:port, or :port",
            listen
        ),
    )))
}

pub(crate) fn normalize_listen_addr(listen: &str) -> Result<String> {
    Ok(parse_listen_addr(listen)?.to_string())
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
        if active > 0 && active % 10 == 0 {
            debug!("Active connections: {}", active);
        }
    }
}

#[derive(Debug)]
pub struct RequestHandle {
    pub entry_executor: Arc<dyn Executor>,
    pub registry: Arc<PluginRegistry>,
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
    pub async fn handle_request(
        &self,
        msg: Message,
        src_addr: SocketAddr,
        meta: RequestMeta,
    ) -> RequestResult {
        let mut context = DnsContext::new(src_addr, msg, self.registry.clone());
        self.apply_request_meta(&mut context, meta);

        // Log request details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "DNS request from {}, queries: {:?}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                context.request.question_count(),
                context.request.edns().is_some(),
                context.request.authorities().len()
            );
        }

        // Execute entry plugin to process the request
        let exec_outcome = self
            .entry_executor
            .execute_with_next(&mut context, None)
            .await;
        let (response, exit) = match exec_outcome {
            Ok(step) => {
                if context.flow() == ExecFlowState::Running {
                    context.set_flow(match step {
                        ExecStep::Next => ExecFlowState::ReachedTail,
                        ExecStep::Stop => ExecFlowState::Broken,
                    });
                }
                let exit = if context.flow() == ExecFlowState::ReachedTail {
                    RequestExit::Completed
                } else {
                    RequestExit::Controlled
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
            let response_len = response.to_bytes().ok().map(|bytes| bytes.len());
            debug!(
                "Sending response to {}, exit: {:?}, question_count: {}, id: {}, response_size: {:?}",
                &src_addr,
                exit,
                context.request.question_count(),
                context.request.id(),
                response_len
            );
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
    use super::*;
    use crate::continue_next;
    use crate::core::error::{DnsError, Result};
    use crate::message::Question;
    use crate::message::{Name, RecordType};
    use crate::plugin::test_utils::test_registry;
    use async_trait::async_trait;
    use std::sync::Mutex;

    #[test]
    fn test_parse_listen_addr_accepts_port_only_shorthand() {
        let addr = parse_listen_addr(":5337").expect("port-only shorthand should parse");

        assert_eq!(addr, SocketAddr::from(([0, 0, 0, 0], 5337)));
    }

    #[test]
    fn test_normalize_listen_addr_expands_port_only_shorthand() {
        let addr = normalize_listen_addr(":5337").expect("port-only shorthand should normalize");

        assert_eq!(addr, "0.0.0.0:5337");
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
            crate::message::DNSClass::IN,
        ));
        request
    }

    fn make_request_handle(executor: Arc<dyn Executor>) -> RequestHandle {
        RequestHandle {
            entry_executor: executor,
            registry: test_registry(),
        }
    }

    #[derive(Debug)]
    struct FallthroughExecutor;

    #[async_trait]
    impl Plugin for FallthroughExecutor {
        fn tag(&self) -> &str {
            "fallthrough"
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for FallthroughExecutor {
        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            Ok(ExecStep::Next)
        }
    }

    #[derive(Debug)]
    struct StopWithResponseExecutor;

    #[async_trait]
    impl Plugin for StopWithResponseExecutor {
        fn tag(&self) -> &str {
            "stop_with_response"
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for StopWithResponseExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            context.set_response(context.request.response(Rcode::Refused));
            Ok(ExecStep::Stop)
        }
    }

    #[derive(Debug)]
    struct ErrorExecutor;

    #[async_trait]
    impl Plugin for ErrorExecutor {
        fn tag(&self) -> &str {
            "error"
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for ErrorExecutor {
        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            Err(DnsError::plugin("execute failed"))
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

        async fn init(&mut self) -> Result<()> {
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

        async fn init(&mut self) -> Result<()> {
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
