/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::{DnsContext, ExecFlowState};
use crate::core::dns_utils::build_response_from_request;
use crate::plugin::executor::{ExecStep, Executor, execute_with_post};
use crate::plugin::{Plugin, PluginRegistry};
use ahash::AHashMap;
use hickory_proto::op::{Message, ResponseCode};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{Level, debug, event_enabled, warn};

pub mod http;
pub mod quic;
pub mod tcp;
pub mod udp;

pub trait Server: Plugin {
    fn run(&self);
}

#[derive(Debug)]
pub struct RequestHandle {
    pub entry_executor: Arc<dyn Executor>,
    pub registry: Arc<PluginRegistry>,
}

#[derive(Debug, Default, Clone)]
pub struct RequestMeta {
    pub server_name: Option<String>,
    pub url_path: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RequestExit {
    Completed,
    Controlled,
    Failed,
}

#[derive(Debug)]
#[allow(unused)]
pub struct RequestResult {
    pub response: Message,
    pub exit: RequestExit,
}

impl RequestHandle {
    pub async fn handle_request(&self, msg: Message, src_addr: SocketAddr) -> RequestResult {
        self.handle_request_with_meta(msg, src_addr, RequestMeta::default())
            .await
    }

    pub async fn handle_request_with_meta(
        &self,
        msg: Message,
        src_addr: SocketAddr,
        meta: RequestMeta,
    ) -> RequestResult {
        // Parse DNS message
        let mut context = DnsContext {
            src_addr,
            request: msg,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: AHashMap::new(),
            query_view: None,
            registry: self.registry.clone(),
        };
        self.apply_request_meta(&mut context, meta);

        // Log request details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "DNS request from {}, queries: {:?}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                context.request.queries(),
                context.request.extensions(),
                context.request.name_servers()
            );
        }

        // Execute entry plugin to process the request
        let exec_outcome = execute_with_post(self.entry_executor.as_ref(), &mut context).await;
        let (response, exit) = match exec_outcome {
            Ok(step) => {
                if context.exec_flow_state == ExecFlowState::Running {
                    context.exec_flow_state = match step {
                        ExecStep::Next => ExecFlowState::ReachedTail,
                        ExecStep::Stop => ExecFlowState::Broken,
                        ExecStep::NextWithPost(_) => ExecFlowState::Running,
                    };
                }
                let exit = if context.exec_flow_state == ExecFlowState::ReachedTail {
                    RequestExit::Completed
                } else {
                    RequestExit::Controlled
                };
                let response = context
                    .response
                    .map(Message::from)
                    .unwrap_or_else(|| self.build_empty_response(&context.request));
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
                (
                    self.build_servfail_response(&context.request),
                    RequestExit::Failed,
                )
            }
        };

        // Log response details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "Sending response to {}, exit: {:?}, queries: {:?}, id: {}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                exit,
                context.request.queries(),
                context.request.id(),
                response.extensions(),
                response.name_servers()
            );
        }

        RequestResult { response, exit }
    }

    #[inline]
    fn apply_request_meta(&self, context: &mut DnsContext, meta: RequestMeta) {
        if let Some(server_name) = meta.server_name.filter(|value| !value.is_empty()) {
            context.set_attr(DnsContext::ATTR_SERVER_NAME, server_name);
        }
        if let Some(url_path) = meta.url_path.filter(|value| !value.is_empty()) {
            context.set_attr(DnsContext::ATTR_URL_PATH, url_path);
        }
    }

    #[inline]
    fn build_empty_response(&self, request: &Message) -> Message {
        self.build_base_response(request, ResponseCode::NoError)
    }

    #[inline]
    fn build_servfail_response(&self, request: &Message) -> Message {
        self.build_base_response(request, ResponseCode::ServFail)
    }

    #[inline]
    fn build_base_response(&self, request: &Message, rcode: ResponseCode) -> Message {
        build_response_from_request(request, rcode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::{DnsError, Result};
    use crate::plugin::test_utils::test_registry;
    use async_trait::async_trait;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};
    use std::sync::Mutex;

    fn make_request(id: u16, qname: &str) -> Message {
        let mut request = Message::new();
        request.set_id(id);
        request.add_query(Query::query(
            Name::from_ascii(qname).expect("query name should be valid"),
            RecordType::A,
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
            context.response = Some(build_response_from_request(
                &context.request,
                ResponseCode::Refused,
            ));
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
                server_name: context
                    .get_attr::<String>(DnsContext::ATTR_SERVER_NAME)
                    .cloned(),
                url_path: context
                    .get_attr::<String>(DnsContext::ATTR_URL_PATH)
                    .cloned(),
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
        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            Ok(ExecStep::NextWithPost(None))
        }

        async fn post_execute(
            &self,
            context: &mut DnsContext,
            _state: Option<crate::plugin::executor::ExecState>,
        ) -> crate::plugin::executor::ExecResult {
            context.response = Some(build_response_from_request(
                &context.request,
                ResponseCode::NXDomain,
            ));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_handle_request_returns_completed_exit_with_default_noerror_response() {
        let request_handle = make_request_handle(Arc::new(FallthroughExecutor));
        let request = make_request(7, "example.com.");

        let result = request_handle
            .handle_request(request, SocketAddr::from(([127, 0, 0, 1], 5300)))
            .await;

        assert_eq!(result.exit, RequestExit::Completed);
        assert_eq!(result.response.id(), 7);
        assert_eq!(result.response.response_code(), ResponseCode::NoError);
        assert_eq!(result.response.queries().len(), 1);
        assert!(result.response.answers().is_empty());
    }

    #[tokio::test]
    async fn test_handle_request_returns_controlled_exit_when_executor_stops() {
        let request_handle = make_request_handle(Arc::new(StopWithResponseExecutor));
        let request = make_request(9, "example.com.");

        let result = request_handle
            .handle_request(request, SocketAddr::from(([127, 0, 0, 1], 5301)))
            .await;

        assert_eq!(result.exit, RequestExit::Controlled);
        assert_eq!(result.response.id(), 9);
        assert_eq!(result.response.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn test_handle_request_returns_failed_exit_and_servfail_on_execute_error() {
        let request_handle = make_request_handle(Arc::new(ErrorExecutor));
        let request = make_request(11, "example.com.");

        let result = request_handle
            .handle_request(request, SocketAddr::from(([127, 0, 0, 1], 5302)))
            .await;

        assert_eq!(result.exit, RequestExit::Failed);
        assert_eq!(result.response.id(), 11);
        assert_eq!(result.response.response_code(), ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn test_handle_request_with_meta_applies_server_name_and_url_path() {
        let observed = Arc::new(Mutex::new(None));
        let request_handle = make_request_handle(Arc::new(CaptureMetaExecutor {
            observed: observed.clone(),
        }));
        let request = make_request(13, "example.com.");

        let _result = request_handle
            .handle_request_with_meta(
                request,
                SocketAddr::from(([127, 0, 0, 1], 5303)),
                RequestMeta {
                    server_name: Some("dns.example.test".to_string()),
                    url_path: Some("/dns-query".to_string()),
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
    async fn test_handle_request_runs_post_callback_and_uses_post_response() {
        let request_handle = make_request_handle(Arc::new(PostResponseExecutor));
        let request = make_request(15, "example.com.");

        let result = request_handle
            .handle_request(request, SocketAddr::from(([127, 0, 0, 1], 5304)))
            .await;

        assert_eq!(result.exit, RequestExit::Completed);
        assert_eq!(result.response.id(), 15);
        assert_eq!(result.response.response_code(), ResponseCode::NXDomain);
    }
}
