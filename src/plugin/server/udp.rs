// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::config::config::PluginConfig;
use crate::core::context::DnsContext;
use crate::plugin::{Plugin, PluginFactory, PluginInfo, PluginMainType, get_plugin};
use async_trait::async_trait;
use futures::StreamExt;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_proto::udp::UdpStream;
use hickory_proto::xfer::SerialMessage;
use hickory_proto::{BufDnsStreamHandle, DnsStreamHandle};
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tracing::{Level, debug, event_enabled, info, warn};

#[derive(Deserialize)]
pub struct UdpServerConfig {
    /// server执行入口
    pub entry: String,
    /// server监听地址
    pub listen: String,
}

#[allow(unused)]
pub struct UdpServer {
    tag: String,
    entry: Arc<PluginInfo>,
    listen: String,
}

#[async_trait]
impl Plugin for UdpServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self) {
        let listen = self.listen.clone();
        let addr = listen.clone();
        let entry_executor = self.entry.clone();
        tokio::spawn(run_server(addr, entry_executor));
        info!("UDP Server started，listen:{listen}");
    }

    async fn execute(&self, _: &mut DnsContext) {}

    fn main_type(&self) -> PluginMainType {
        PluginMainType::Executor {
            tag: self.tag.to_string(),
            type_name: "UdpServer".to_string(),
        }
    }

    async fn destroy(&mut self) {}
}

async fn run_server(addr: String, entry_executor: Arc<PluginInfo>) {
    let (mut stream, stream_handle) = UdpStream::<TokioRuntimeProvider>::with_bound(
        build_udp_socket(&addr).unwrap(),
        ([127, 255, 255, 254], 0).into(),
    );

    let mut inner_join_set = JoinSet::new();
    let stream_handle = Arc::new(stream_handle);
    loop {
        let message = tokio::select! {
            message = stream.next() => match message {
                None => break,
                Some(message) => message,
            },
        };
        let message = match message {
            Err(error) => {
                warn!(%error, "error receiving message on udp_socket");
                continue;
            }
            Ok(message) => message,
        };

        inner_join_set.spawn(handler_message(
            entry_executor.clone(),
            stream_handle.clone(),
            message,
        ));

        reap_tasks(&mut inner_join_set);
    }
}

async fn handler_message(
    entry_executor: Arc<PluginInfo>,
    stream_handle: Arc<BufDnsStreamHandle>,
    message: SerialMessage,
) {
    let (message, src_addr) = message.into_parts();
    // 解析 DNS 消息
    if let Ok(msg) = Message::from_bytes(message.as_slice()) {
        let mut context = DnsContext {
            src_addr,
            request: msg,
            response: None,
            mark: Vec::new(),
            attributes: HashMap::new(),
        };

        if event_enabled!(Level::DEBUG) {
            debug!(
                "dns:request source:{}, queries:{:?},  edns:{:?}, nameservers:{:?}",
                &src_addr,
                context.request.queries(),
                context.request.extensions(),
                context.request.name_servers()
            );
        }

        // 执行程序入口执行
        entry_executor.plugin.execute(&mut context).await;

        let mut response;
        match context.response {
            None => {
                debug!("No response received");
                response = Message::new();
                response.set_id(context.request.id());
                response.set_op_code(OpCode::Query);
                response.set_message_type(MessageType::Query);
            }
            Some(res) => {
                response = Message::from(res);
            }
        }
        if event_enabled!(Level::DEBUG) {
            debug!(
                "Response received: source:{}, queries:{:?}, sourceId: {}, edns:{:?}, nameservers:{:?}",
                &src_addr,
                context.request.queries(),
                context.request.id(),
                response.extensions(),
                response.name_servers()
            );
        }

        stream_handle
            .with_remote_addr(src_addr)
            .send(SerialMessage::new(response.to_bytes().unwrap(), src_addr))
            .unwrap();
    }
}

fn reap_tasks(join_set: &mut JoinSet<()>) {
    while join_set.try_join_next().is_some() {}
}
fn build_udp_socket(addr: &str) -> Result<UdpSocket, Error> {
    let addr = SocketAddr::from_str(addr).unwrap();

    let sock = if addr.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?
    } else {
        Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?
    };

    let _ = sock.set_nonblocking(true);
    let _ = sock.set_reuse_address(true);
    let _ = sock.set_reuse_port(true);

    sock.bind(&addr.into())?;

    UdpSocket::from_std(sock.into())
}

pub struct UdpServerFactory {}

#[async_trait]
impl PluginFactory for UdpServerFactory {
    fn create(&self, plugin_info: &PluginConfig) -> Box<dyn Plugin> {
        let udp_config = match plugin_info.args.clone() {
            Some(args) => serde_yml::from_value::<UdpServerConfig>(args)
                .unwrap_or_else(|e| panic!("UDP Server init failed, config error. Error:{}", e)),
            None => {
                panic!("UDP Server must set 'listen' and 'entry' in config file.)")
            }
        };

        let entry = get_plugin(&udp_config.entry).expect(
            format!(
                "UDP Server [{}] entry plugin [{}] not found",
                plugin_info.tag, udp_config.entry
            )
            .as_str(),
        );

        Box::new(UdpServer {
            tag: plugin_info.tag.clone(),
            entry: entry.clone(),
            listen: udp_config.listen,
        })
    }

    fn plugin_type(&self, tag: &str) -> PluginMainType {
        PluginMainType::Server {
            tag: tag.to_string(),
            type_name: "udp".to_string(),
        }
    }
}
