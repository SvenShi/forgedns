/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `forward_edns0opt` executor plugin.
//!
//! Forwards selected EDNS0 option codes from downstream request to final
//! response.
//!
//! Runtime behavior:
//! - `execute`: extracts configured option codes from request OPT records and
//!   stores them in post state.
//! - `post_execute`: re-inserts those options into response OPT records after
//!   downstream executors complete.
//!
//! Safety/perf notes:
//! - options are filtered by code allow-list (`codes`) and deduplicated.
//! - response OPT record is created only when needed.
//! - when no codes are configured, plugin becomes near no-op.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::message::RData;
use crate::message::rdata::OPT;
use crate::message::rdata::opt::{EdnsCode, EdnsOption};
use crate::message::{Packet, RDataView, RecordType};
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct ForwardEdns0OptConfig {
    /// EDNS option codes to preserve and forward.
    #[serde(default)]
    codes: Vec<u16>,
}

#[derive(Debug)]
struct ForwardEdns0Opt {
    tag: String,
    code_set: AHashSet<u16>,
}

#[async_trait]
impl Plugin for ForwardEdns0Opt {
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
impl Executor for ForwardEdns0Opt {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if self.code_set.is_empty() {
            return Ok(ExecStep::Next);
        }

        let selected = collect_selected_options(&context.request, &self.code_set);
        if selected.is_empty() {
            return Ok(ExecStep::Next);
        }

        Ok(ExecStep::NextWithPost(
            Some(Box::new(selected) as ExecState),
        ))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let mut selected = state
            .and_then(|boxed| boxed.downcast::<Vec<EdnsOption>>().ok())
            .map(|boxed| *boxed)
            .unwrap_or_default();

        if selected.is_empty() {
            return Ok(());
        }

        let packet_rewritten = if let Some(packet) = context
            .response
            .as_ref()
            .and_then(|response| response.packet())
        {
            let existing_codes = collect_selected_codes_from_packet(packet, &self.code_set)?;
            selected.retain(|option| !existing_codes.contains(&u16::from(EdnsCode::from(option))));
            if selected.is_empty() {
                return Ok(());
            }
            append_selected_options_to_packet(packet, &selected)?
        } else {
            None
        };
        if let Some(rewritten) = packet_rewritten {
            context.set_response_packet(rewritten)?;
            return Ok(());
        }

        if let Some(response) = context.response_message_mut()? {
            let mut existing_codes = collect_selected_codes(response, &self.code_set);
            let opt = ensure_opt_record(response);
            for option in selected {
                let code = u16::from(EdnsCode::from(&option));
                if existing_codes.insert(code) {
                    opt.insert(option);
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ForwardEdns0OptFactory;

register_plugin_factory!("forward_edns0opt", ForwardEdns0OptFactory {});

impl PluginFactory for ForwardEdns0OptFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let code_set = parse_codes_from_value(plugin_config.args.clone())?;
        Ok(UninitializedPlugin::Executor(Box::new(ForwardEdns0Opt {
            tag: plugin_config.tag.clone(),
            code_set,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let mut code_set = AHashSet::new();
        let raw = param.unwrap_or_default();
        for token in split_tokens(&raw) {
            let code = token.parse::<u16>().map_err(|e| {
                DnsError::plugin(format!("invalid EDNS0 option code '{}': {}", token, e))
            })?;
            code_set.insert(code);
        }

        Ok(UninitializedPlugin::Executor(Box::new(ForwardEdns0Opt {
            tag: tag.to_string(),
            code_set,
        })))
    }
}

fn parse_codes_from_value(args: Option<serde_yml::Value>) -> Result<AHashSet<u16>> {
    let Some(args) = args else {
        return Ok(AHashSet::new());
    };

    if let Some(raw) = args.as_str() {
        let mut out = AHashSet::new();
        for token in split_tokens(raw) {
            let code = token.parse::<u16>().map_err(|e| {
                DnsError::plugin(format!("invalid EDNS0 option code '{}': {}", token, e))
            })?;
            out.insert(code);
        }
        return Ok(out);
    }

    let cfg: ForwardEdns0OptConfig = serde_yml::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse forward_edns0opt config: {}", e)))?;

    Ok(cfg.codes.into_iter().collect())
}

fn collect_selected_options(
    message: &crate::message::Message,
    code_set: &AHashSet<u16>,
) -> Vec<EdnsOption> {
    let Some(edns) = message.edns_access() else {
        return Vec::new();
    };

    let mut selected = Vec::new();
    for option in edns.options() {
        if code_set.contains(&option.code()) {
            selected.push(option.to_owned());
        }
    }
    selected
}

fn collect_selected_codes(
    message: &crate::message::Message,
    code_set: &AHashSet<u16>,
) -> AHashSet<u16> {
    let Some(edns) = message.edns_access() else {
        return AHashSet::new();
    };

    let mut out = AHashSet::new();
    for option in edns.options() {
        let code = option.code();
        if code_set.contains(&code) {
            out.insert(code);
        }
    }
    out
}

fn collect_selected_codes_from_packet(
    packet: &Packet,
    code_set: &AHashSet<u16>,
) -> Result<AHashSet<u16>> {
    let parsed = packet.parse()?;
    let mut out = AHashSet::new();
    for record in parsed.additional_records() {
        let record = record?;
        let RDataView::Opt(edns) = record.rdata() else {
            continue;
        };
        for option in edns.options() {
            let code = option.code();
            if code_set.contains(&code) {
                out.insert(code);
            }
        }
    }
    Ok(out)
}

fn append_selected_options_to_packet(
    packet: &Packet,
    selected: &[EdnsOption],
) -> Result<Option<Packet>> {
    if selected.is_empty() {
        return Ok(None);
    }

    let parsed = packet.parse()?;
    let bytes = packet.as_slice();
    let mut appended = Vec::with_capacity(selected.len() * 16);
    for option in selected {
        encode_edns_option_wire(&mut appended, option)?;
    }

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
            .checked_add(appended.len())
            .ok_or_else(|| DnsError::protocol("edns option block too large"))?;
        let new_rdlength = u16::try_from(new_rdlength)
            .map_err(|_| DnsError::protocol("edns option block too large"))?;

        let mut out = Vec::with_capacity(bytes.len() + appended.len());
        out.extend_from_slice(&bytes[..rdlength_offset]);
        out.extend_from_slice(&new_rdlength.to_be_bytes());
        out.extend_from_slice(record.raw_rdata());
        out.extend_from_slice(&appended);
        out.extend_from_slice(&bytes[record.wire_range().end as usize..]);
        return Ok(Some(Packet::from_vec(out)));
    }

    let additional_count = parsed
        .header()
        .arcount()
        .checked_add(1)
        .ok_or_else(|| DnsError::protocol("dns additional record count overflow"))?;
    let opt_record = encode_opt_record_wire(&appended)?;
    let mut out = Vec::with_capacity(bytes.len() + opt_record.len());
    out.extend_from_slice(bytes);
    out.extend_from_slice(&opt_record);
    out[10..12].copy_from_slice(&additional_count.to_be_bytes());
    Ok(Some(Packet::from_vec(out)))
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

fn split_tokens(raw: &str) -> Vec<&str> {
    raw.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::message::rdata::opt::ClientSubnet;
    use crate::message::{Message, Question};
    use crate::message::{Name, RecordType};
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::test_utils::test_registry;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_parse_codes_from_value_validation() {
        assert!(parse_codes_from_value(Some(serde_yml::Value::String("x".into()))).is_err());
        assert!(
            parse_codes_from_value(Some(serde_yml::from_str("codes: [8, 15]").unwrap())).is_ok()
        );
    }

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        )
    }

    fn add_ecs(message: &mut Message, ip: Ipv4Addr, mask: u8) {
        let opt = ensure_opt_record(message);
        opt.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::V4(ip),
            mask,
            0,
        )));
    }

    fn count_code(plan: &crate::message::ResponsePlan, code: u16) -> usize {
        let message = plan
            .to_message()
            .expect("response should materialize for inspection");
        let mut total = 0usize;
        for record in message.additionals() {
            let RData::OPT(opt) = record.data() else {
                continue;
            };
            for (_, option) in opt.as_ref() {
                if u16::from(EdnsCode::from(option)) == code {
                    total += 1;
                }
            }
        }
        total
    }

    #[tokio::test]
    async fn test_forward_edns0opt_moves_selected_request_options_to_response() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request.message_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        ctx.response.set_message(Message::new());
        plugin
            .post_execute(&mut ctx, state)
            .await
            .expect("post_execute should succeed");
        assert_eq!(
            count_code(ctx.response.as_ref().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_post_execute_deduplicates_existing_code() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request.message_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        let mut response = Message::new();
        add_ecs(&mut response, Ipv4Addr::new(2, 2, 2, 2), 24);
        ctx.response.set_message(response);

        plugin
            .post_execute(&mut ctx, state)
            .await
            .expect("post_execute should succeed");
        assert_eq!(
            count_code(ctx.response.as_ref().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_reads_selected_options_from_packet_request() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request.message_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);
        let packet = crate::message::Packet::from_vec(ctx.request.to_bytes().unwrap());
        ctx.set_request_packet(packet);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        ctx.response.set_message(Message::new());
        plugin
            .post_execute(&mut ctx, state)
            .await
            .expect("post_execute should succeed");
        assert_eq!(
            count_code(ctx.response.as_ref().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_short_circuits_packet_response_with_existing_code() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request.message_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        let mut response = Message::new();
        add_ecs(&mut response, Ipv4Addr::new(2, 2, 2, 2), 24);
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
            "packet-backed response should stay packet-backed"
        );
        assert_eq!(
            count_code(ctx.response.as_ref().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_appends_to_existing_packet_opt() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request.message_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        let mut response = Message::new();
        let _ = ensure_opt_record(&mut response);
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
            "packet-backed response should stay packet-backed"
        );
        assert_eq!(
            count_code(ctx.response.as_ref().expect("response should exist"), 8),
            1
        );
    }

    #[tokio::test]
    async fn test_forward_edns0opt_creates_packet_opt_when_response_has_none() {
        let plugin = ForwardEdns0Opt {
            tag: "forward_opt".to_string(),
            code_set: [8u16].into_iter().collect(),
        };
        let mut ctx = make_context();
        add_ecs(ctx.request.message_mut(), Ipv4Addr::new(1, 1, 1, 1), 24);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        let state = match step {
            ExecStep::NextWithPost(state) => state,
            _ => panic!("expected NextWithPost"),
        };

        let response = Message::new();
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
            "packet-backed response should stay packet-backed"
        );

        let updated = ctx
            .response
            .as_ref()
            .expect("response should exist")
            .to_message()
            .expect("response should materialize");
        assert_eq!(updated.additionals().len(), 1);
        assert_eq!(updated.additionals()[0].record_type(), RecordType::OPT);
        assert_eq!(
            count_code(ctx.response.as_ref().expect("response should exist"), 8),
            1
        );
    }
}
