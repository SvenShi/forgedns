/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `black_hole` executor plugin.
//!
//! Generates synthetic A/AAAA responses for matched query type.
//!
//! Typical usage is ad-blocking / sinkhole policy where matched domains should
//! be answered locally without upstream queries.
//!
//! Behavior:
//! - only handles single-question requests.
//! - for `A` queries returns configured IPv4 list.
//! - for `AAAA` queries returns configured IPv6 list.
//! - for other types, plugin is pass-through (`Next` without response changes).

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::dns_utils::build_response_from_request;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct BlackHoleConfig {
    /// IP addresses returned as synthesized black-hole answers.
    ///
    /// IPv4 values are used for A queries, IPv6 values for AAAA queries.
    #[serde(default)]
    ips: Vec<String>,
}

#[derive(Debug)]
struct BlackHole {
    tag: String,
    ipv4: Vec<std::net::Ipv4Addr>,
    ipv6: Vec<std::net::Ipv6Addr>,
}

#[async_trait]
impl Plugin for BlackHole {
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
impl Executor for BlackHole {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if context.request.queries().len() != 1 {
            return Ok(ExecStep::Next);
        }

        let Some((response_type, qname)) = context
            .request
            .query()
            .map(|q| (q.query_type, q.name().clone()))
        else {
            return Ok(ExecStep::Next);
        };

        let mut response = build_response_from_request(&context.request, ResponseCode::NoError);

        match response_type {
            RecordType::A if !self.ipv4.is_empty() => {
                for ip in &self.ipv4 {
                    response.answers_mut().push(Record::from_rdata(
                        qname.clone(),
                        300,
                        RData::A(A(*ip)),
                    ));
                }
                context.response = Some(response);
            }
            RecordType::AAAA if !self.ipv6.is_empty() => {
                for ip in &self.ipv6 {
                    response.answers_mut().push(Record::from_rdata(
                        qname.clone(),
                        300,
                        RData::AAAA(AAAA(*ip)),
                    ));
                }
                context.response = Some(response);
            }
            _ => {}
        }

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct BlackHoleFactory;

register_plugin_factory!("black_hole", BlackHoleFactory {});

impl PluginFactory for BlackHoleFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let ips = parse_ip_tokens_from_value(plugin_config.args.clone())?;
        let (ipv4, ipv6) = split_ips(ips);

        Ok(UninitializedPlugin::Executor(Box::new(BlackHole {
            tag: plugin_config.tag.clone(),
            ipv4,
            ipv6,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let raw = param.unwrap_or_default();
        let ips = parse_ip_tokens(split_tokens(&raw).into_iter().map(str::to_string).collect())?;
        let (ipv4, ipv6) = split_ips(ips);

        Ok(UninitializedPlugin::Executor(Box::new(BlackHole {
            tag: tag.to_string(),
            ipv4,
            ipv6,
        })))
    }
}

fn parse_ip_tokens_from_value(args: Option<serde_yml::Value>) -> Result<Vec<IpAddr>> {
    let Some(args) = args else {
        return Ok(Vec::new());
    };

    if let Some(raw) = args.as_str() {
        return parse_ip_tokens(split_tokens(raw).into_iter().map(str::to_string).collect());
    }

    if let Some(seq) = args.as_sequence() {
        let mut out = Vec::new();
        for item in seq {
            let token = item
                .as_str()
                .ok_or_else(|| DnsError::plugin("black_hole args list must contain strings"))?;
            out.extend(parse_ip_tokens(
                split_tokens(token)
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            )?);
        }
        return Ok(out);
    }

    let cfg: BlackHoleConfig = serde_yml::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse black_hole config: {}", e)))?;
    parse_ip_tokens(cfg.ips)
}

fn parse_ip_tokens(raw_tokens: Vec<String>) -> Result<Vec<IpAddr>> {
    let mut out = Vec::with_capacity(raw_tokens.len());
    for token in raw_tokens {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let ip = token
            .parse::<IpAddr>()
            .map_err(|e| DnsError::plugin(format!("invalid black_hole ip '{}': {}", token, e)))?;
        out.push(ip);
    }
    Ok(out)
}

fn split_tokens(raw: &str) -> Vec<&str> {
    raw.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

fn split_ips(ips: Vec<IpAddr>) -> (Vec<std::net::Ipv4Addr>, Vec<std::net::Ipv6Addr>) {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    for ip in ips {
        match ip {
            IpAddr::V4(v4) => ipv4.push(v4),
            IpAddr::V6(v6) => ipv6.push(v6),
        }
    }

    (ipv4, ipv6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::ExecFlowState;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::test_registry;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{DNSClass, Name};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn make_context(qtype: RecordType) -> DnsContext {
        let mut request = Message::new();
        let mut query = Query::query(Name::from_ascii("example.com.").unwrap(), qtype);
        query.set_query_class(DNSClass::IN);
        request.add_query(query);

        DnsContext {
            src_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: Default::default(),
            query_view: None,
            registry: test_registry(),
        }
    }

    #[test]
    fn test_parse_ip_tokens_validation() {
        assert!(parse_ip_tokens(vec![]).is_ok());
        assert!(parse_ip_tokens(vec!["invalid".to_string()]).is_err());
        assert!(parse_ip_tokens(vec!["1.1.1.1".to_string()]).is_ok());
    }

    #[tokio::test]
    async fn test_black_hole_execute_generates_a_answers() {
        let plugin = BlackHole {
            tag: "bh".to_string(),
            ipv4: vec![Ipv4Addr::new(1, 1, 1, 1)],
            ipv6: vec![],
        };
        let mut ctx = make_context(RecordType::A);
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        let resp = ctx.response.expect("response should exist");
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::A);
    }

    #[tokio::test]
    async fn test_black_hole_execute_generates_aaaa_answers() {
        let plugin = BlackHole {
            tag: "bh".to_string(),
            ipv4: vec![],
            ipv6: vec![Ipv6Addr::LOCALHOST],
        };
        let mut ctx = make_context(RecordType::AAAA);
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        let resp = ctx.response.expect("response should exist");
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn test_black_hole_execute_skips_multi_question_request() {
        let plugin = BlackHole {
            tag: "bh".to_string(),
            ipv4: vec![Ipv4Addr::new(1, 1, 1, 1)],
            ipv6: vec![],
        };
        let mut ctx = make_context(RecordType::A);
        ctx.request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        assert!(ctx.response.is_none());
    }
}
