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
use crate::core::dns_utils::build_response_from_request;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashMap;
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::name::{CNAME, NS, PTR};
use hickory_proto::rr::rdata::{A, AAAA, MX, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct ArbitraryConfig {
    #[serde(default)]
    rules: Vec<String>,
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug)]
struct Arbitrary {
    tag: String,
    records: AHashMap<(String, RecordType), Vec<Record>>,
}

#[async_trait]
impl Plugin for Arbitrary {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for Arbitrary {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let Some(qtype) = context.request.query().map(|q| q.query_type) else {
            return Ok(ExecStep::Next);
        };

        let Some(query_view) = context.query_view() else {
            return Ok(ExecStep::Next);
        };
        let qname = query_view.normalized_name();

        let mut answers = Vec::new();
        if qtype == RecordType::ANY {
            for ((name, _), records) in &self.records {
                if *name == qname {
                    answers.extend(records.iter().cloned());
                }
            }
        } else if let Some(records) = self.records.get(&(qname.to_string(), qtype)) {
            answers.extend(records.iter().cloned());
        }

        if !answers.is_empty() {
            let mut response = build_response_from_request(&context.request, ResponseCode::NoError);
            *response.answers_mut() = answers;
            context.response = Some(response);
        }

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct ArbitraryFactory;

register_plugin_factory!("arbitrary", ArbitraryFactory {});

impl PluginFactory for ArbitraryFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let cfg = parse_config(plugin_config.args.clone())?;
        let _ = build_records(&cfg)?;
        Ok(())
    }

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

fn build_records(cfg: &ArbitraryConfig) -> Result<AHashMap<(String, RecordType), Vec<Record>>> {
    let mut map: AHashMap<(String, RecordType), Vec<Record>> = AHashMap::new();

    for (idx, line) in cfg.rules.iter().enumerate() {
        let record = parse_zone_line(line).map_err(|e| {
            DnsError::plugin(format!("invalid arbitrary rule #{} '{}': {}", idx, line, e))
        })?;
        let key = (normalize_name(record.name()), record.record_type());
        map.entry(key).or_default().push(record);
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
            let key = (normalize_name(record.name()), record.record_type());
            map.entry(key).or_default().push(record);
        }
    }

    Ok(map)
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
            let text = fields
                .iter()
                .map(|f| f.trim_matches('"').to_string())
                .collect::<Vec<_>>();
            Ok(RData::TXT(TXT::new(text)))
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

#[inline]
fn normalize_name(name: &Name) -> String {
    crate::core::context::DnsContext::normalize_dns_name(name)
}
