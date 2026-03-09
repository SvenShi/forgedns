/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `ecs_handler` executor plugin.
//!
//! Implements EDNS Client Subnet (ECS) processing for outgoing queries.
//!
//! Supported policies:
//! - `forward = true`: keep client-supplied ECS when present.
//! - `forward = false`: remove client-supplied ECS.
//! - `send = true`: synthesize ECS from source IP when request has no ECS.
//! - `preset`: force ECS source IP regardless of client source address.
//!
//! Post-stage behavior:
//! - when ECS was not forwarded from client, response ECS is stripped to avoid
//!   leaking internally generated subnet metadata back to downstream clients.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use hickory_proto::rr::DNSClass;
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::OPT;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct EcsHandlerConfig {
    /// Keep client-supplied ECS option when present.
    #[serde(default)]
    forward: bool,
    /// Synthesize ECS from source IP when request has no ECS.
    #[serde(default)]
    send: bool,
    /// Optional fixed IP used as ECS source instead of client source IP.
    preset: Option<String>,
    /// Source prefix length for synthesized IPv4 ECS.
    mask4: Option<u8>,
    /// Source prefix length for synthesized IPv6 ECS.
    mask6: Option<u8>,
}

#[derive(Debug)]
struct EcsHandler {
    tag: String,
    forward: bool,
    send: bool,
    preset: Option<IpAddr>,
    mask4: u8,
    mask6: u8,
}

#[derive(Debug)]
struct PostState {
    forwarded_client_ecs: bool,
}

#[async_trait]
impl Plugin for EcsHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for EcsHandler {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let Some(query_class) = context.request.query().map(|q| q.query_class) else {
            return Ok(ExecStep::Next);
        };

        if query_class != DNSClass::IN {
            return Ok(ExecStep::Next);
        }

        let mut forwarded_client_ecs = false;
        if request_has_ecs(&context.request) {
            if self.forward {
                forwarded_client_ecs = true;
            } else {
                strip_ecs_from_message(&mut context.request);
            }
        } else {
            let source_ip = if let Some(preset) = self.preset {
                Some(unmap_ip(preset))
            } else if self.send {
                Some(unmap_ip(context.src_addr.ip()))
            } else {
                None
            };

            if let Some(source_ip) = source_ip {
                let mask = match source_ip {
                    IpAddr::V4(_) => self.mask4,
                    IpAddr::V6(_) => self.mask6,
                };
                let ecs = EdnsOption::Subnet(ClientSubnet::new(source_ip, mask, 0));
                let opt = ensure_opt_record(&mut context.request);
                opt.insert(ecs);
            }
        }

        Ok(ExecStep::NextWithPost(Some(Box::new(PostState {
            forwarded_client_ecs,
        }) as ExecState)))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let forwarded_client_ecs = state
            .and_then(|boxed| boxed.downcast::<PostState>().ok())
            .map(|boxed| boxed.forwarded_client_ecs)
            .unwrap_or(false);

        if forwarded_client_ecs {
            return Ok(());
        }

        if let Some(response) = context.response.as_mut() {
            strip_ecs_from_message(response);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EcsHandlerFactory;

register_plugin_factory!("ecs_handler", EcsHandlerFactory {});

impl PluginFactory for EcsHandlerFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let handler =
            parse_handler_from_value(plugin_config.tag.as_str(), plugin_config.args.clone())?;
        Ok(UninitializedPlugin::Executor(Box::new(handler)))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        // Quick setup syntax: `ecs [ip[/mask]]`.
        let preset = param
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .and_then(|s| {
                let (ip, _) = s.split_once('/').unwrap_or((&s, ""));
                ip.parse::<IpAddr>().ok()
            });

        Ok(UninitializedPlugin::Executor(Box::new(EcsHandler {
            tag: tag.to_string(),
            forward: false,
            send: false,
            preset,
            mask4: 24,
            mask6: 48,
        })))
    }
}

fn parse_handler_from_value(tag: &str, args: Option<serde_yml::Value>) -> Result<EcsHandler> {
    let cfg = match args {
        Some(args) => serde_yml::from_value::<EcsHandlerConfig>(args)
            .map_err(|e| DnsError::plugin(format!("failed to parse ecs_handler config: {}", e)))?,
        None => EcsHandlerConfig::default(),
    };

    let mask4 = cfg.mask4.unwrap_or(24);
    let mask6 = cfg.mask6.unwrap_or(48);

    if mask4 > 32 {
        return Err(DnsError::plugin(
            "ecs_handler mask4 must be in range 0..=32",
        ));
    }
    if mask6 > 128 {
        return Err(DnsError::plugin(
            "ecs_handler mask6 must be in range 0..=128",
        ));
    }

    let preset = cfg
        .preset
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .map(|v| {
            v.parse::<IpAddr>()
                .map_err(|e| DnsError::plugin(format!("invalid ecs_handler preset '{}': {}", v, e)))
        })
        .transpose()?;

    Ok(EcsHandler {
        tag: tag.to_string(),
        forward: cfg.forward,
        send: cfg.send,
        preset,
        mask4,
        mask6,
    })
}

fn request_has_ecs(message: &hickory_proto::op::Message) -> bool {
    for record in message.additionals() {
        let RData::OPT(opt) = record.data() else {
            continue;
        };
        if opt.get(EdnsCode::Subnet).is_some() {
            return true;
        }
    }
    false
}

fn strip_ecs_from_message(message: &mut hickory_proto::op::Message) {
    for record in message.additionals_mut() {
        let RData::OPT(opt) = record.data_mut() else {
            continue;
        };
        opt.remove(EdnsCode::Subnet);
    }
}

fn ensure_opt_record(message: &mut hickory_proto::op::Message) -> &mut OPT {
    let mut opt_idx = None;
    for (idx, record) in message.additionals().iter().enumerate() {
        if matches!(record.data(), RData::OPT(_)) {
            opt_idx = Some(idx);
            break;
        }
    }

    let idx = match opt_idx {
        Some(idx) => idx,
        None => {
            message.add_additional(hickory_proto::rr::Record::from_rdata(
                hickory_proto::rr::Name::root(),
                0,
                RData::OPT(OPT::default()),
            ));
            message.additionals().len() - 1
        }
    };

    match message.additionals_mut()[idx].data_mut() {
        RData::OPT(opt) => opt,
        _ => unreachable!("OPT record must contain OPT rdata"),
    }
}

fn unmap_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{DnsContext, ExecFlowState};
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::test_utils::test_registry;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_parse_handler_from_value_validation() {
        assert!(parse_handler_from_value("ecs", None).is_ok());
        assert!(
            parse_handler_from_value("ecs", Some(serde_yml::from_str("mask4: 64").unwrap()),)
                .is_err()
        );
    }

    fn make_context(qclass: DNSClass) -> DnsContext {
        let mut request = Message::new();
        let mut query = Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A);
        query.set_query_class(qclass);
        request.add_query(query);
        DnsContext {
            src_addr: SocketAddr::from((Ipv4Addr::new(10, 1, 1, 9), 5353)),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: Default::default(),
            query_view: None,
            registry: test_registry(),
        }
    }

    fn add_ecs_option(message: &mut Message, ip: IpAddr, mask: u8) {
        let opt = ensure_opt_record(message);
        opt.insert(EdnsOption::Subnet(ClientSubnet::new(ip, mask, 0)));
    }

    #[tokio::test]
    async fn test_ecs_handler_send_inserts_request_ecs_and_strips_response_ecs() {
        let plugin = EcsHandler {
            tag: "ecs".to_string(),
            forward: false,
            send: true,
            preset: None,
            mask4: 24,
            mask6: 48,
        };
        let mut ctx = make_context(DNSClass::IN);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };
        assert!(request_has_ecs(&ctx.request));

        let mut response = Message::new();
        add_ecs_option(&mut response, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 24);
        ctx.response = Some(response);

        plugin
            .post_execute(&mut ctx, state)
            .await
            .expect("post_execute should succeed");
        assert!(
            !request_has_ecs(ctx.response.as_ref().expect("response should exist")),
            "response ECS should be stripped when not forwarded from client"
        );
    }

    #[tokio::test]
    async fn test_ecs_handler_forward_keeps_client_and_response_ecs() {
        let plugin = EcsHandler {
            tag: "ecs".to_string(),
            forward: true,
            send: false,
            preset: None,
            mask4: 24,
            mask6: 48,
        };
        let mut ctx = make_context(DNSClass::IN);
        add_ecs_option(&mut ctx.request, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 24);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };
        assert!(request_has_ecs(&ctx.request));

        let mut response = Message::new();
        add_ecs_option(&mut response, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 24);
        ctx.response = Some(response);

        plugin
            .post_execute(&mut ctx, state)
            .await
            .expect("post_execute should succeed");
        assert!(request_has_ecs(
            ctx.response.as_ref().expect("response should exist")
        ));
    }

    #[tokio::test]
    async fn test_ecs_handler_strips_client_ecs_when_forward_disabled() {
        let plugin = EcsHandler {
            tag: "ecs".to_string(),
            forward: false,
            send: false,
            preset: None,
            mask4: 24,
            mask6: 48,
        };
        let mut ctx = make_context(DNSClass::IN);
        add_ecs_option(&mut ctx.request, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 24);

        plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(!request_has_ecs(&ctx.request));
    }
}
