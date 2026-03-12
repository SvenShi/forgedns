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
use crate::message::DNSClass;
use crate::message::RData;
use crate::message::rdata::OPT;
use crate::message::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use crate::message::{Packet, RDataView, RecordType};
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
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
        let Some(query_class) = context.request.first_question_class() else {
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
                let rewritten = match context.request.packet() {
                    Some(packet) => strip_ecs_from_packet(packet)?,
                    None => None,
                };
                if let Some(rewritten) = rewritten {
                    context.set_request_packet(rewritten);
                } else {
                    strip_ecs_from_message(&mut context.request);
                }
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
                if let Some(packet) = context.request.packet() {
                    let rewritten = append_ecs_to_packet(packet, &ecs)?;
                    context.set_request_packet(rewritten);
                } else {
                    let opt = ensure_opt_record(&mut context.request);
                    opt.insert(ecs);
                }
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

        let packet_rewritten = match context
            .response
            .as_ref()
            .and_then(|response| response.packet())
        {
            Some(packet) => Some(strip_ecs_from_packet(packet)?),
            None => None,
        };
        if let Some(rewritten) = packet_rewritten {
            if let Some(rewritten) = rewritten {
                context.set_response_packet(rewritten)?;
            }
            return Ok(());
        }

        if let Some(response) = context.response_message_mut()? {
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

fn request_has_ecs(message: &crate::message::Message) -> bool {
    message
        .edns_access()
        .is_some_and(|edns| edns.client_subnet().is_some())
}

fn strip_ecs_from_message(message: &mut crate::message::Message) {
    for record in message.additionals_mut() {
        let RData::OPT(opt) = record.data_mut() else {
            continue;
        };
        opt.remove(EdnsCode::Subnet);
    }
}

fn strip_ecs_from_packet(packet: &Packet) -> Result<Option<Packet>> {
    let parsed = packet.parse()?;
    let bytes = packet.as_slice();
    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0usize;
    let mut changed = false;

    for record in parsed.additional_records() {
        let record = record?;
        if record.record_type() != RecordType::OPT {
            continue;
        }
        let RDataView::Opt(_) = record.rdata() else {
            continue;
        };

        let (removed_ecs, filtered_rdata) = strip_ecs_from_opt_rdata(record.raw_rdata());
        if !removed_ecs {
            continue;
        }

        changed = true;
        let rdata_range = record.rdata_range();
        let rdlength_offset = rdata_range.start as usize - 2;
        out.extend_from_slice(&bytes[cursor..rdlength_offset]);
        out.extend_from_slice(&(filtered_rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&filtered_rdata);
        cursor = record.wire_range().end as usize;
    }

    if !changed {
        return Ok(None);
    }

    out.extend_from_slice(&bytes[cursor..]);
    Ok(Some(Packet::from_vec(out)))
}

fn strip_ecs_from_opt_rdata(rdata: &[u8]) -> (bool, Vec<u8>) {
    let mut cursor = 0usize;
    let mut out = Vec::with_capacity(rdata.len());
    let mut removed = false;

    while cursor + 4 <= rdata.len() {
        let code = u16::from_be_bytes([rdata[cursor], rdata[cursor + 1]]);
        let len = u16::from_be_bytes([rdata[cursor + 2], rdata[cursor + 3]]) as usize;
        let end = cursor + 4 + len;
        if end > rdata.len() {
            out.extend_from_slice(&rdata[cursor..]);
            return (removed, out);
        }

        if code == u16::from(EdnsCode::Subnet) {
            removed = true;
        } else {
            out.extend_from_slice(&rdata[cursor..end]);
        }
        cursor = end;
    }

    out.extend_from_slice(&rdata[cursor..]);
    (removed, out)
}

fn append_ecs_to_packet(packet: &Packet, ecs: &EdnsOption) -> Result<Packet> {
    let parsed = packet.parse()?;
    let bytes = packet.as_slice();
    let mut ecs_wire = Vec::with_capacity(16);
    encode_edns_option_wire(&mut ecs_wire, ecs)?;

    for record in parsed.additional_records() {
        let record = record?;
        if record.record_type() != RecordType::OPT {
            continue;
        }
        let RDataView::Opt(_) = record.rdata() else {
            continue;
        };

        let rdata_range = record.rdata_range();
        let rdlength_offset = rdata_range.start as usize - 2;
        let new_rdlength = record
            .raw_rdata()
            .len()
            .checked_add(ecs_wire.len())
            .ok_or_else(|| DnsError::protocol("edns option block too large"))?;
        let new_rdlength = u16::try_from(new_rdlength)
            .map_err(|_| DnsError::protocol("edns option block too large"))?;

        let mut out = Vec::with_capacity(bytes.len() + ecs_wire.len());
        out.extend_from_slice(&bytes[..rdlength_offset]);
        out.extend_from_slice(&new_rdlength.to_be_bytes());
        out.extend_from_slice(record.raw_rdata());
        out.extend_from_slice(&ecs_wire);
        out.extend_from_slice(&bytes[record.wire_range().end as usize..]);
        return Ok(Packet::from_vec(out));
    }

    let additional_count = parsed
        .header()
        .arcount()
        .checked_add(1)
        .ok_or_else(|| DnsError::protocol("dns additional record count overflow"))?;
    let opt_record = encode_opt_record_wire(&ecs_wire)?;
    let mut out = Vec::with_capacity(bytes.len() + opt_record.len());
    out.extend_from_slice(bytes);
    out.extend_from_slice(&opt_record);
    out[10..12].copy_from_slice(&additional_count.to_be_bytes());
    Ok(Packet::from_vec(out))
}

fn encode_edns_option_wire(out: &mut Vec<u8>, option: &EdnsOption) -> Result<()> {
    match option {
        EdnsOption::Subnet(value) => {
            let code = u16::from(EdnsCode::Subnet);
            let (family, addr_bytes, max_prefix) = match value.addr() {
                IpAddr::V4(addr) => (1u16, addr.octets().to_vec(), 32u8),
                IpAddr::V6(addr) => (2u16, addr.octets().to_vec(), 128u8),
            };
            let prefix = value.source_prefix().min(max_prefix);
            let network_len = usize::from(prefix.div_ceil(8));
            let mut truncated = addr_bytes[..network_len].to_vec();
            if let Some(last) = truncated.last_mut() {
                let remaining_bits = prefix % 8;
                if remaining_bits != 0 {
                    *last &= 0xFFu8 << (8 - remaining_bits);
                }
            }
            out.extend_from_slice(&code.to_be_bytes());
            let body_len = 4usize
                .checked_add(truncated.len())
                .ok_or_else(|| DnsError::protocol("edns option too large"))?;
            let body_len =
                u16::try_from(body_len).map_err(|_| DnsError::protocol("edns option too large"))?;
            out.extend_from_slice(&body_len.to_be_bytes());
            out.extend_from_slice(&family.to_be_bytes());
            out.push(prefix);
            out.push(value.scope_prefix().min(max_prefix));
            out.extend_from_slice(&truncated);
        }
        EdnsOption::Unknown(code, data) => {
            let data_len = u16::try_from(data.len())
                .map_err(|_| DnsError::protocol("edns option too large"))?;
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(&data_len.to_be_bytes());
            out.extend_from_slice(data);
        }
    }
    Ok(())
}

fn encode_opt_record_wire(rdata: &[u8]) -> Result<Vec<u8>> {
    let rdlength = u16::try_from(rdata.len())
        .map_err(|_| DnsError::protocol("edns option block too large"))?;
    let opt = OPT::default();
    let mut out = Vec::with_capacity(11 + rdata.len());
    out.push(0);
    out.extend_from_slice(&u16::from(RecordType::OPT).to_be_bytes());
    out.extend_from_slice(&opt.udp_payload_size().to_be_bytes());
    out.extend_from_slice(&opt.raw_ttl().to_be_bytes());
    out.extend_from_slice(&rdlength.to_be_bytes());
    out.extend_from_slice(rdata);
    Ok(out)
}

fn ensure_opt_record(message: &mut crate::message::Message) -> &mut OPT {
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
            message.add_additional(crate::message::Record::from_rdata(
                crate::message::Name::root(),
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
    use crate::message::{Message, Question};
    use crate::message::{Name, RecordType};
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::test_utils::test_registry;
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
        let mut query = Question::new(Name::from_ascii("example.com.").unwrap(), RecordType::A);
        query.set_question_class(qclass);
        request.add_question(query);
        DnsContext {
            src_addr: SocketAddr::from((Ipv4Addr::new(10, 1, 1, 9), 5353)),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: Default::default(),
            request_meta: Default::default(),
            query_view: None,
            query_view_version: None,
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
        ctx.response = Some(response.into());

        plugin
            .post_execute(&mut ctx, state)
            .await
            .expect("post_execute should succeed");
        assert!(
            !request_has_ecs(
                &ctx.response
                    .as_ref()
                    .expect("response should exist")
                    .to_message()
                    .expect("response should materialize")
            ),
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
        ctx.response = Some(response.into());

        plugin
            .post_execute(&mut ctx, state)
            .await
            .expect("post_execute should succeed");
        assert!(request_has_ecs(
            &ctx.response
                .as_ref()
                .expect("response should exist")
                .to_message()
                .expect("response should materialize")
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

    #[tokio::test]
    async fn test_ecs_handler_strips_client_ecs_from_packet_request() {
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
        let packet = Packet::from_vec(ctx.request.to_bytes().unwrap());
        ctx.set_request_packet(packet);

        plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(
            ctx.request.packet().is_some(),
            "request should stay packet-backed"
        );
        assert!(!request_has_ecs(&ctx.request));
    }

    #[tokio::test]
    async fn test_ecs_handler_send_appends_ecs_to_existing_packet_opt() {
        let plugin = EcsHandler {
            tag: "ecs".to_string(),
            forward: false,
            send: true,
            preset: None,
            mask4: 24,
            mask6: 48,
        };
        let mut ctx = make_context(DNSClass::IN);
        let _ = ensure_opt_record(&mut ctx.request);
        let packet = Packet::from_vec(ctx.request.to_bytes().unwrap());
        ctx.set_request_packet(packet);

        plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(
            ctx.request.packet().is_some(),
            "request should stay packet-backed"
        );
        assert!(request_has_ecs(&ctx.request));
    }

    #[tokio::test]
    async fn test_ecs_handler_send_creates_packet_opt_when_request_has_none() {
        let plugin = EcsHandler {
            tag: "ecs".to_string(),
            forward: false,
            send: true,
            preset: None,
            mask4: 24,
            mask6: 48,
        };
        let mut ctx = make_context(DNSClass::IN);
        let packet = Packet::from_vec(ctx.request.to_bytes().unwrap());
        ctx.set_request_packet(packet);

        plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(
            ctx.request.packet().is_some(),
            "request should stay packet-backed"
        );
        assert!(request_has_ecs(&ctx.request));
        assert_eq!(
            ctx.request
                .packet()
                .expect("request packet should exist")
                .parse()
                .expect("packet should parse")
                .header()
                .arcount(),
            1
        );
    }

    #[tokio::test]
    async fn test_ecs_handler_strips_ecs_from_packet_response() {
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

        let mut response = Message::new();
        add_ecs_option(&mut response, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 24);
        ctx.set_response_packet(Packet::from_vec(response.to_bytes().unwrap()))
            .expect("packet response should decode");

        plugin
            .post_execute(&mut ctx, state)
            .await
            .expect("post_execute should succeed");
        assert!(
            ctx.response
                .as_ref()
                .and_then(|response| response.packet())
                .is_some(),
            "response should stay packet-backed"
        );
        assert!(
            !request_has_ecs(
                &ctx.response
                    .as_ref()
                    .expect("response should exist")
                    .to_message()
                    .expect("response should materialize")
            ),
            "response ECS should be stripped when not forwarded from client"
        );
    }
}
