/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `hosts` executor plugin.
//!
//! Maps domain rules to static IP responses.

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
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use regex::Regex;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct HostsConfig {
    #[serde(default)]
    entries: Vec<String>,
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Clone)]
enum RuleMatcher {
    Full(String),
    Domain(String),
    Keyword(String),
    Regexp(Regex),
}

#[derive(Debug, Clone)]
struct HostsRule {
    matcher: RuleMatcher,
    ipv4: Vec<std::net::Ipv4Addr>,
    ipv6: Vec<std::net::Ipv6Addr>,
}

#[derive(Debug)]
struct HostsExecutor {
    tag: String,
    rules: Vec<HostsRule>,
}

#[async_trait]
impl Plugin for HostsExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for HostsExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let Some((qclass, qtype)) = context
            .request
            .query()
            .map(|q| (q.query_class, q.query_type))
        else {
            return Ok(ExecStep::Next);
        };

        if qclass != DNSClass::IN {
            return Ok(ExecStep::Next);
        }

        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return Ok(ExecStep::Next);
        }

        let Some(query_view) = context.query_view() else {
            return Ok(ExecStep::Next);
        };
        let qname_wire = query_view.raw_name().clone();
        let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule_matches(&rule.matcher, query_view.normalized_name()))
        else {
            return Ok(ExecStep::Next);
        };

        let mut response = build_response_from_request(&context.request, ResponseCode::NoError);
        match qtype {
            RecordType::A => {
                for ip in &rule.ipv4 {
                    response.answers_mut().push(Record::from_rdata(
                        qname_wire.clone(),
                        300,
                        RData::A(A(*ip)),
                    ));
                }
            }
            RecordType::AAAA => {
                for ip in &rule.ipv6 {
                    response.answers_mut().push(Record::from_rdata(
                        qname_wire.clone(),
                        300,
                        RData::AAAA(AAAA(*ip)),
                    ));
                }
            }
            _ => {}
        }

        if !response.answers().is_empty() {
            context.response = Some(response);
        }

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct HostsFactory;

register_plugin_factory!("hosts", HostsFactory {});

impl PluginFactory for HostsFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let cfg = parse_config(plugin_config.args.clone())?;
        let _ = build_rules(&cfg)?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cfg = parse_config(plugin_config.args.clone())?;
        let rules = build_rules(&cfg)?;

        Ok(UninitializedPlugin::Executor(Box::new(HostsExecutor {
            tag: plugin_config.tag.clone(),
            rules,
        })))
    }
}

fn parse_config(args: Option<serde_yml::Value>) -> Result<HostsConfig> {
    let Some(args) = args else {
        return Ok(HostsConfig::default());
    };

    serde_yml::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse hosts config: {}", e)))
}

fn build_rules(cfg: &HostsConfig) -> Result<Vec<HostsRule>> {
    let mut out = Vec::new();

    for (idx, entry) in cfg.entries.iter().enumerate() {
        let rule = parse_hosts_line(entry).map_err(|e| {
            DnsError::plugin(format!("invalid hosts entry #{} '{}': {}", idx, entry, e))
        })?;
        out.push(rule);
    }

    for file in &cfg.files {
        if file.trim().is_empty() {
            continue;
        }

        let file_handle = File::open(file).map_err(|e| {
            DnsError::plugin(format!("failed to open hosts file '{}': {}", file, e))
        })?;
        let mut reader = BufReader::new(file_handle);
        let mut line = String::new();
        let mut line_no = 0usize;

        loop {
            line.clear();
            let n = reader.read_line(&mut line).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to read hosts file '{}' at line {}: {}",
                    file,
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
            let line_no_comment = raw
                .split_once('#')
                .map(|(left, _)| left)
                .unwrap_or(raw)
                .trim();
            if line_no_comment.is_empty() {
                continue;
            }

            let rule = parse_hosts_line(line_no_comment).map_err(|e| {
                DnsError::plugin(format!(
                    "invalid hosts file '{}' line {} '{}': {}",
                    file, line_no, line_no_comment, e
                ))
            })?;
            out.push(rule);
        }
    }

    Ok(out)
}

fn parse_hosts_line(raw: &str) -> std::result::Result<HostsRule, String> {
    let fields: Vec<&str> = raw.split_whitespace().collect();
    if fields.len() < 2 {
        return Err("hosts rule must include domain rule and at least one IP".to_string());
    }

    let matcher = parse_rule_matcher(fields[0])?;

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for token in &fields[1..] {
        match token.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => ipv4.push(v4),
            Ok(IpAddr::V6(v6)) => ipv6.push(v6),
            Err(e) => return Err(format!("invalid hosts IP '{}': {}", token, e)),
        }
    }

    if ipv4.is_empty() && ipv6.is_empty() {
        return Err("hosts rule contains no valid IP".to_string());
    }

    Ok(HostsRule {
        matcher,
        ipv4,
        ipv6,
    })
}

fn parse_rule_matcher(raw_rule: &str) -> std::result::Result<RuleMatcher, String> {
    let raw_rule = raw_rule.trim();
    if raw_rule.is_empty() {
        return Err("empty hosts domain rule".to_string());
    }

    if let Some(v) = raw_rule.strip_prefix("full:") {
        return Ok(RuleMatcher::Full(normalize_name(v)));
    }
    if let Some(v) = raw_rule.strip_prefix("domain:") {
        return Ok(RuleMatcher::Domain(normalize_name(v)));
    }
    if let Some(v) = raw_rule.strip_prefix("keyword:") {
        return Ok(RuleMatcher::Keyword(v.to_ascii_lowercase()));
    }
    if let Some(v) = raw_rule.strip_prefix("regexp:") {
        let re = Regex::new(v).map_err(|e| format!("invalid hosts regexp '{}': {}", v, e))?;
        return Ok(RuleMatcher::Regexp(re));
    }

    // hosts defaults to full match when prefix is omitted.
    Ok(RuleMatcher::Full(normalize_name(raw_rule)))
}

fn rule_matches(rule: &RuleMatcher, domain: &str) -> bool {
    match rule {
        RuleMatcher::Full(v) => domain == v,
        RuleMatcher::Domain(v) => {
            domain == v
                || domain
                    .strip_suffix(v)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }
        RuleMatcher::Keyword(v) => domain.contains(v),
        RuleMatcher::Regexp(v) => v.is_match(domain),
    }
}

fn normalize_name(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}
