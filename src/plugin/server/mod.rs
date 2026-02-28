/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::{DnsContext, ExecFlowState};
use crate::core::dns_utils::build_response_from_request;
use crate::plugin::executor::Executor;
use crate::plugin::{Plugin, PluginRegistry};
use hickory_proto::op::{Message, ResponseCode};
use std::collections::HashMap;
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
        // Parse DNS message
        let mut context = DnsContext {
            src_addr,
            request: msg,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: HashMap::new(),
            registry: self.registry.clone(),
        };

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
        let exec_outcome = self.entry_executor.execute(&mut context).await;
        let (response, exit) = match exec_outcome {
            Ok(_) => {
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
