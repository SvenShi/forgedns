/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use crate::core::context::DnsContext;
use crate::plugin::executor::Executor;
use crate::plugin::{Plugin, PluginRegistry};
use hickory_proto::op::{Message, MessageType, OpCode};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{Level, debug, event_enabled};

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

impl RequestHandle {
    pub async fn handle_request(&self, msg: Message, src_addr: SocketAddr) -> Message {
        // Parse DNS message
        let mut context = DnsContext {
            src_addr,
            request: msg,
            response: None,
            mark: Vec::new(),
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
        self.entry_executor.execute(&mut context).await;

        // Construct response message
        let mut response;
        match context.response {
            None => {
                debug!("No response received from entry plugin");
                response = Message::new();
                response.set_id(context.request.id());
                response.set_op_code(OpCode::Query);
                response.set_message_type(MessageType::Query);
            }
            Some(res) => {
                response = Message::from(res);
            }
        }

        // Log response details only when debug logging is enabled
        if event_enabled!(Level::DEBUG) {
            debug!(
                "Sending response to {}, queries: {:?}, id: {}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                context.request.queries(),
                context.request.id(),
                response.extensions(),
                response.name_servers()
            );
        }

        response
    }
}

