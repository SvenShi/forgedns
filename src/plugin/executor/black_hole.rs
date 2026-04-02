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
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{A, AAAA, RData, RecordType};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct BlackHoleConfig {
    /// IP addresses returned as synthesized black-hole answers.
    ///
    /// IPv4 values are used for A queries, IPv6 values for AAAA queries.
    #[serde(default)]
    ips: Vec<String>,
    /// Whether to stop the executor chain after producing a local answer.
    #[serde(default)]
    short_circuit: bool,
}

#[derive(Debug)]
struct BlackHole {
    tag: String,
    ipv4: Vec<Arc<RData>>,
    ipv6: Vec<Arc<RData>>,
    short_circuit: bool,
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
        let Some(question) = context.request.first_question() else {
            return Ok(ExecStep::Next);
        };
        let response = match question.qtype() {
            RecordType::A if !self.ipv4.is_empty() => context
                .request
                .address_response_rdata(question, 300, &self.ipv4)?,
            RecordType::AAAA if !self.ipv6.is_empty() => context
                .request
                .address_response_rdata(question, 300, &self.ipv6)?,
            _ => return Ok(ExecStep::Next),
        };
        context.set_response(response);

        if self.short_circuit {
            Ok(ExecStep::Stop)
        } else {
            Ok(ExecStep::Next)
        }
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
        let (ips, short_circuit) = parse_ip_tokens_from_value(plugin_config.args.clone())?;
        let (ipv4, ipv6) = split_ips(ips);

        Ok(UninitializedPlugin::Executor(Box::new(BlackHole {
            tag: plugin_config.tag.clone(),
            ipv4,
            ipv6,
            short_circuit,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let raw = param.unwrap_or_default();
        let (raw, short_circuit) = strip_short_circuit_suffix(&raw)?;
        let ips = parse_ip_tokens(split_tokens(&raw).into_iter().map(str::to_string).collect())?;
        let (ipv4, ipv6) = split_ips(ips);

        Ok(UninitializedPlugin::Executor(Box::new(BlackHole {
            tag: tag.to_string(),
            ipv4,
            ipv6,
            short_circuit,
        })))
    }
}

fn parse_ip_tokens_from_value(args: Option<Value>) -> Result<(Vec<IpAddr>, bool)> {
    let Some(args) = args else {
        return Ok((Vec::new(), false));
    };

    if let Some(raw) = args.as_str() {
        return Ok((
            parse_ip_tokens(split_tokens(raw).into_iter().map(str::to_string).collect())?,
            false,
        ));
    }

    if let Some(seq) = args.as_sequence() {
        let mut out = Vec::new();
        for item in seq {
            let token: &str = item
                .as_str()
                .ok_or_else(|| DnsError::plugin("black_hole args list must contain strings"))?;
            out.extend(parse_ip_tokens(
                split_tokens(token)
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            )?);
        }
        return Ok((out, false));
    }

    let cfg: BlackHoleConfig = serde_yaml_ng::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse black_hole config: {}", e)))?;
    let ips = parse_ip_tokens(cfg.ips)?;
    Ok((ips, cfg.short_circuit))
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

fn strip_short_circuit_suffix(raw: &str) -> Result<(String, bool)> {
    let mut tokens: Vec<&str> = raw.split_whitespace().collect();
    let mut short_circuit = false;

    while let Some(last) = tokens.last().copied() {
        let Some(value) = parse_short_circuit_token(last)? else {
            break;
        };
        short_circuit = value;
        tokens.pop();
    }

    Ok((tokens.join(" "), short_circuit))
}

fn parse_short_circuit_token(token: &str) -> Result<Option<bool>> {
    if token == "short_circuit" {
        return Ok(Some(true));
    }

    let Some(value) = token.strip_prefix("short_circuit=") else {
        return Ok(None);
    };

    match value {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        _ => Err(DnsError::plugin(format!(
            "invalid short_circuit value '{}', expected true or false",
            value
        ))),
    }
}

fn split_ips(ips: Vec<IpAddr>) -> (Vec<Arc<RData>>, Vec<Arc<RData>>) {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    for ip in ips {
        match ip {
            IpAddr::V4(v4) => ipv4.push(Arc::new(RData::A(A(v4)))),
            IpAddr::V6(v6) => ipv6.push(Arc::new(RData::AAAA(AAAA(v6)))),
        }
    }

    (ipv4, ipv6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::UninitializedPlugin;
    use crate::plugin::executor::ExecStep;
    use crate::plugin::test_utils::test_registry;
    use crate::proto::{DNSClass, Name};
    use crate::proto::{Message, Question};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn make_context(qtype: RecordType) -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            qtype,
            DNSClass::IN,
        ));

        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        )
    }

    #[test]
    fn test_parse_ip_tokens_validation() {
        assert!(parse_ip_tokens(vec![]).is_ok());
        assert!(parse_ip_tokens(vec!["invalid".to_string()]).is_err());
        assert!(parse_ip_tokens(vec!["1.1.1.1".to_string()]).is_ok());
    }

    #[tokio::test]
    async fn test_black_hole_quick_setup_supports_short_circuit() {
        let plugin = BlackHoleFactory
            .quick_setup(
                "bh_quick",
                Some("0.0.0.0 short_circuit=true".to_string()),
                test_registry(),
            )
            .expect("quick setup should succeed");

        let UninitializedPlugin::Executor(plugin) = plugin else {
            panic!("expected executor plugin");
        };
        let mut ctx = make_context(RecordType::A);
        let step = plugin.execute(&mut ctx).await.expect("execute should work");
        assert!(matches!(step, ExecStep::Stop));
        assert!(ctx.response().is_some());
    }

    #[tokio::test]
    async fn test_black_hole_execute_generates_a_answers() {
        let plugin = BlackHole {
            tag: "bh".to_string(),
            ipv4: vec![Arc::new(RData::A(A(Ipv4Addr::new(1, 1, 1, 1))))],
            ipv6: vec![],
            short_circuit: false,
        };
        let mut ctx = make_context(RecordType::A);
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        let resp = ctx.response().expect("response should exist");
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].rr_type(), RecordType::A);
    }

    #[tokio::test]
    async fn test_black_hole_execute_generates_aaaa_answers() {
        let plugin = BlackHole {
            tag: "bh".to_string(),
            ipv4: vec![],
            ipv6: vec![Arc::new(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)))],
            short_circuit: false,
        };
        let mut ctx = make_context(RecordType::AAAA);
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        let resp = ctx.response().expect("response should exist");
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].rr_type(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn test_black_hole_execute_builds_response_from_request_message() {
        let plugin = BlackHole {
            tag: "bh".to_string(),
            ipv4: vec![Arc::new(RData::A(A(Ipv4Addr::new(1, 1, 1, 1))))],
            ipv6: vec![],
            short_circuit: false,
        };
        let mut ctx = make_context(RecordType::A);

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        let resp = ctx.response().expect("response should exist");
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].rr_type(), RecordType::A);
    }

    #[tokio::test]
    async fn test_black_hole_execute_skips_multi_question_request() {
        let plugin = BlackHole {
            tag: "bh".to_string(),
            ipv4: vec![Arc::new(RData::A(A(Ipv4Addr::new(1, 1, 1, 1))))],
            ipv6: vec![],
            short_circuit: false,
        };
        let mut ctx = make_context(RecordType::A);
        ctx.request.questions_mut().push(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));

        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        let resp = ctx.response().expect("response should exist");
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].rr_type(), RecordType::A);
    }

    #[tokio::test]
    async fn test_black_hole_execute_stops_when_short_circuit_enabled() {
        let plugin = BlackHole {
            tag: "bh".to_string(),
            ipv4: vec![Arc::new(RData::A(A(Ipv4Addr::new(1, 1, 1, 1))))],
            ipv6: vec![],
            short_circuit: true,
        };
        let mut ctx = make_context(RecordType::A);
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Stop));
        assert!(ctx.response().is_some());
    }
}
