/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `arbitrary` executor plugin.
//!
//! Loads static resource records and returns synthetic replies when query name
//! and query type match loaded records. This implementation focuses on common
//! record types used in DNS forwarding scenarios.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::message::Rcode;
use crate::message::rdata::{A, AAAA, MX, TXT};
use crate::message::{CNAME, DNSClass, NS, Name, PTR, RData, Record, RecordType};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashMap;
use async_trait::async_trait;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct ArbitraryConfig {
    /// Inline arbitrary DNS records.
    ///
    /// Each item uses the same syntax as quick setup rules.
    #[serde(default)]
    rules: Vec<String>,
    /// Paths to rule files containing arbitrary DNS records.
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug)]
struct Arbitrary {
    tag: String,
    records: AHashMap<String, NameRecords>,
}

#[derive(Debug, Default)]
struct NameRecords {
    by_type: AHashMap<RecordType, PreparedAnswer>,
    any: SharedRecords,
}

#[derive(Debug, Clone, Default)]
struct SharedRecords {
    records: Arc<[Record]>,
}

#[derive(Debug, Clone)]
enum PreparedAnswer {
    Shared(SharedRecords),
    FastV4(FastAddressV4),
    FastV6(FastAddressV6),
}

#[derive(Debug, Clone)]
struct FastAddressV4 {
    ttl: u32,
    addresses: Vec<Arc<RData>>,
}

#[derive(Debug, Clone)]
struct FastAddressV6 {
    ttl: u32,
    addresses: Vec<Arc<RData>>,
}

impl Default for PreparedAnswer {
    fn default() -> Self {
        Self::Shared(SharedRecords::default())
    }
}

impl SharedRecords {
    #[inline]
    fn len(&self) -> usize {
        self.records.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[inline]
    fn extend_answers_into(&self, answers: &mut Vec<Record>) {
        answers.reserve(self.records.len());
        answers.extend(self.records.iter().cloned());
    }
}

impl PreparedAnswer {
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Shared(records) => records.len(),
            Self::FastV4(answer) => answer.addresses.len(),
            Self::FastV6(answer) => answer.addresses.len(),
        }
    }
}

#[async_trait]
impl Plugin for Arbitrary {
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
impl Executor for Arbitrary {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let Some(question) = context.request.first_question() else {
            return Ok(ExecStep::Next);
        };
        let qclass = question.qclass();
        let qtype = question.qtype();
        let qname = question.name().normalized();

        let Some(name_records) = self.records.get(qname) else {
            return Ok(ExecStep::Next);
        };

        let answers = if qtype == RecordType::ANY {
            None
        } else {
            let Some(records) = name_records.by_type.get(&qtype) else {
                return Ok(ExecStep::Next);
            };
            Some(records)
        };

        if qtype == RecordType::ANY {
            if name_records.any.is_empty() {
                return Ok(ExecStep::Next);
            }

            let mut response = context.request().response(Rcode::NoError);
            name_records.any.extend_answers_into(response.answers_mut());
            context.set_response(response);
            return Ok(ExecStep::Next);
        }

        let Some(answers) = answers else {
            return Ok(ExecStep::Next);
        };
        if answers.len() == 0 {
            return Ok(ExecStep::Next);
        }

        if qclass == DNSClass::IN {
            match answers {
                PreparedAnswer::FastV4(answer) => {
                    let response = context.request.address_response_rdata(
                        question,
                        answer.ttl,
                        &answer.addresses,
                    )?;
                    context.set_response(response);
                    return Ok(ExecStep::Next);
                }
                PreparedAnswer::FastV6(answer) => {
                    let response = context.request.address_response_rdata(
                        question,
                        answer.ttl,
                        &answer.addresses,
                    )?;
                    context.set_response(response);
                    return Ok(ExecStep::Next);
                }
                PreparedAnswer::Shared(_) => {}
            }
        }

        let PreparedAnswer::Shared(records) = answers else {
            return Ok(ExecStep::Next);
        };
        let mut response = context.request().response(Rcode::NoError);
        records.extend_answers_into(response.answers_mut());
        context.set_response(response);

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct ArbitraryFactory;

register_plugin_factory!("arbitrary", ArbitraryFactory {});

impl PluginFactory for ArbitraryFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cfg = parse_config(plugin_config.args.clone())?;
        let records = build_records(&cfg)?;

        Ok(UninitializedPlugin::Executor(Box::new(Arbitrary {
            tag: plugin_config.tag.clone(),
            records,
        })))
    }
}

fn parse_config(args: Option<serde_yml::Value>) -> Result<ArbitraryConfig> {
    let Some(args) = args else {
        return Ok(ArbitraryConfig::default());
    };

    serde_yml::from_value::<ArbitraryConfig>(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse arbitrary config: {}", e)))
}

fn build_records(cfg: &ArbitraryConfig) -> Result<AHashMap<String, NameRecords>> {
    let mut map: AHashMap<String, BuildNameRecords> = AHashMap::new();

    for (idx, line) in cfg.rules.iter().enumerate() {
        let record = parse_zone_line(line).map_err(|e| {
            DnsError::plugin(format!("invalid arbitrary rule #{} '{}': {}", idx, line, e))
        })?;
        let entry = map
            .entry(record.name().normalized().to_string())
            .or_default();
        entry
            .by_type
            .entry(record.rr_type())
            .or_default()
            .push(record.clone());
        entry.any.push(record);
    }

    for path in &cfg.files {
        if path.trim().is_empty() {
            continue;
        }
        let file = File::open(path).map_err(|e| {
            DnsError::plugin(format!("failed to open arbitrary file '{}': {}", path, e))
        })?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut line_no = 0usize;
        loop {
            line.clear();
            let n = reader.read_line(&mut line).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to read arbitrary file '{}' at line {}: {}",
                    path,
                    line_no + 1,
                    e
                ))
            })?;
            if n == 0 {
                break;
            }
            line_no += 1;

            let raw = line.trim();
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }

            let record = parse_zone_line(raw).map_err(|e| {
                DnsError::plugin(format!(
                    "invalid arbitrary file '{}' line {} '{}': {}",
                    path, line_no, raw, e
                ))
            })?;
            let entry = map
                .entry(record.name().normalized().to_string())
                .or_default();
            entry
                .by_type
                .entry(record.rr_type())
                .or_default()
                .push(record.clone());
            entry.any.push(record);
        }
    }

    Ok(map
        .into_iter()
        .map(|(name, records)| (name, records.finalize()))
        .collect())
}

#[derive(Debug, Default)]
struct BuildNameRecords {
    by_type: AHashMap<RecordType, Vec<Record>>,
    any: Vec<Record>,
}

impl BuildNameRecords {
    fn finalize(self) -> NameRecords {
        let any = SharedRecords {
            records: Arc::<[Record]>::from(self.any),
        };
        let by_type = self
            .by_type
            .into_iter()
            .map(|(record_type, records)| (record_type, finalize_prepared_answer(records)))
            .collect();
        NameRecords { by_type, any }
    }
}

fn finalize_prepared_answer(records: Vec<Record>) -> PreparedAnswer {
    if let Some(answer) = build_fast_address_answer_v4(&records) {
        return PreparedAnswer::FastV4(answer);
    }
    if let Some(answer) = build_fast_address_answer_v6(&records) {
        return PreparedAnswer::FastV6(answer);
    }
    PreparedAnswer::Shared(SharedRecords {
        records: Arc::<[Record]>::from(records),
    })
}

fn build_fast_address_answer_v4(records: &[Record]) -> Option<FastAddressV4> {
    let first = records.first()?;
    if first.rr_type() != RecordType::A || first.class() != DNSClass::IN {
        return None;
    }
    let ttl = first.ttl();
    let mut addresses = Vec::with_capacity(records.len());
    for record in records {
        if record.rr_type() != RecordType::A
            || record.class() != DNSClass::IN
            || record.ttl() != ttl
        {
            return None;
        }
        if matches!(record.data(), RData::A(_)) {
            addresses.push(record.data_arc());
        } else {
            return None;
        }
    }

    Some(FastAddressV4 { ttl, addresses })
}

fn build_fast_address_answer_v6(records: &[Record]) -> Option<FastAddressV6> {
    let first = records.first()?;
    if first.rr_type() != RecordType::AAAA || first.class() != DNSClass::IN {
        return None;
    }

    let ttl = first.ttl();
    let mut addresses = Vec::with_capacity(records.len());
    for record in records {
        if record.rr_type() != RecordType::AAAA
            || record.class() != DNSClass::IN
            || record.ttl() != ttl
        {
            return None;
        }
        if matches!(record.data(), RData::AAAA(_)) {
            addresses.push(record.data_arc());
        } else {
            return None;
        }
    }

    Some(FastAddressV6 { ttl, addresses })
}

fn parse_zone_line(raw: &str) -> std::result::Result<Record, String> {
    let fields: Vec<&str> = raw.split_whitespace().collect();
    if fields.len() < 3 {
        return Err("zone line requires at least 3 fields".to_string());
    }

    let owner = parse_name(fields[0])?;
    let mut idx = 1usize;

    let mut ttl = 300u32;
    if let Ok(parsed_ttl) = fields[idx].parse::<u32>() {
        ttl = parsed_ttl;
        idx += 1;
        if idx >= fields.len() {
            return Err("missing record class/type".to_string());
        }
    }

    if idx < fields.len() && fields[idx].eq_ignore_ascii_case("IN") {
        idx += 1;
    }
    if idx >= fields.len() {
        return Err("missing record type".to_string());
    }

    let record_type = RecordType::from_str(&fields[idx].to_ascii_uppercase())
        .map_err(|_| format!("unsupported record type '{}'", fields[idx]))?;
    idx += 1;
    if idx >= fields.len() {
        return Err("missing record data".to_string());
    }

    let rdata_tokens = &fields[idx..];
    let rdata = parse_rdata(record_type, rdata_tokens)?;

    Ok(Record::from_rdata(owner, ttl, rdata))
}

fn parse_rdata(record_type: RecordType, fields: &[&str]) -> std::result::Result<RData, String> {
    match record_type {
        RecordType::A => {
            let ip: IpAddr = fields[0]
                .parse()
                .map_err(|e| format!("invalid A address '{}': {}", fields[0], e))?;
            match ip {
                IpAddr::V4(v4) => Ok(RData::A(A(v4))),
                IpAddr::V6(_) => Err("A record requires IPv4 address".to_string()),
            }
        }
        RecordType::AAAA => {
            let ip: IpAddr = fields[0]
                .parse()
                .map_err(|e| format!("invalid AAAA address '{}': {}", fields[0], e))?;
            match ip {
                IpAddr::V6(v6) => Ok(RData::AAAA(AAAA(v6))),
                IpAddr::V4(_) => Err("AAAA record requires IPv6 address".to_string()),
            }
        }
        RecordType::CNAME => Ok(RData::CNAME(CNAME(parse_name(fields[0])?))),
        RecordType::PTR => Ok(RData::PTR(PTR(parse_name(fields[0])?))),
        RecordType::NS => Ok(RData::NS(NS(parse_name(fields[0])?))),
        RecordType::MX => {
            if fields.len() < 2 {
                return Err("MX record requires: <preference> <exchange>".to_string());
            }
            let preference = fields[0]
                .parse::<u16>()
                .map_err(|e| format!("invalid MX preference '{}': {}", fields[0], e))?;
            let exchange = parse_name(fields[1])?;
            Ok(RData::MX(MX::new(preference, exchange)))
        }
        RecordType::TXT => {
            let mut wire = Vec::new();

            for field in fields {
                let part = field.trim_matches('"').as_bytes();
                if part.len() > u8::MAX as usize {
                    return Err(format!("TXT chunk exceeds 255 bytes: '{}'", field));
                }
                wire.push(part.len() as u8);
                wire.extend_from_slice(part);
            }

            Ok(RData::TXT(TXT::new(wire.into_boxed_slice())))
        }
        _ => Err(format!(
            "record type '{}' is not supported by arbitrary plugin",
            record_type
        )),
    }
}

fn parse_name(raw: &str) -> std::result::Result<Name, String> {
    let fqdn = if raw.ends_with('.') {
        raw.to_string()
    } else {
        format!("{}.", raw)
    };
    Name::from_ascii(&fqdn).map_err(|e| format!("invalid name '{}': {}", raw, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Message, Question};
    use crate::message::{Name, RecordType};
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::test_utils::test_registry;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_parse_zone_line_rejects_short_record() {
        let err = parse_zone_line("example.com.").expect_err("short zone line should fail");
        assert!(err.contains("at least 3 fields"));
    }

    fn make_context(name: &str, qtype: RecordType) -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii(name).unwrap(),
            qtype,
            DNSClass::IN,
        ));
        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        )
    }

    #[tokio::test]
    async fn test_arbitrary_execute_returns_matching_type_records() {
        let cfg = ArbitraryConfig {
            rules: vec![
                "example.com. 60 IN A 1.1.1.1".to_string(),
                "example.com. 60 IN AAAA ::1".to_string(),
            ],
            files: vec![],
        };
        let plugin = Arbitrary {
            tag: "arbitrary".to_string(),
            records: build_records(&cfg).expect("records should parse"),
        };

        let mut ctx = make_context("example.com.", RecordType::A);
        let step = plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        assert!(matches!(step, ExecStep::Next));
        let response = ctx.response().expect("response should exist");
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].rr_type(), RecordType::A);
    }

    #[tokio::test]
    async fn test_arbitrary_execute_any_query_returns_all_records() {
        let cfg = ArbitraryConfig {
            rules: vec![
                "example.com. 60 IN A 1.1.1.1".to_string(),
                "example.com. 60 IN AAAA ::1".to_string(),
            ],
            files: vec![],
        };
        let plugin = Arbitrary {
            tag: "arbitrary".to_string(),
            records: build_records(&cfg).expect("records should parse"),
        };

        let mut ctx = make_context("example.com.", RecordType::ANY);
        plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");
        let response = ctx.response().expect("response should exist");
        assert_eq!(response.answers().len(), 2);
    }

    #[tokio::test]
    async fn test_arbitrary_execute_uses_message_static_address_answer() {
        let cfg = ArbitraryConfig {
            rules: vec!["example.com. 60 IN A 1.1.1.1".to_string()],
            files: vec![],
        };
        let plugin = Arbitrary {
            tag: "arbitrary".to_string(),
            records: build_records(&cfg).expect("records should parse"),
        };

        let mut ctx = make_context("example.com.", RecordType::A);
        plugin
            .execute(&mut ctx)
            .await
            .expect("execute should succeed");

        assert!(ctx.response().is_some());
        assert!(ctx.response().is_some_and(|response| {
            response.has_answer_ip(|ip| ip == IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        }));
    }
}
