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
use ahash::AHashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use regex::{Regex, RegexSet, RegexSetBuilder};
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
    Regexp(String),
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
    index: RuleIndex,
}

#[derive(Debug, Default)]
struct RuleIndex {
    full_rules: AHashMap<Box<str>, usize>,
    domain_rules: AHashMap<Box<str>, usize>,
    keyword_matcher: Option<AhoCorasick>,
    keyword_rule_indices: Vec<usize>,
    regex_matcher: Option<RegexSet>,
    regex_rule_indices: Vec<usize>,
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
            .index
            .match_rule(&self.rules, query_view.normalized_name())
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
        let (rules, index) = build_rules(&cfg)?;

        Ok(UninitializedPlugin::Executor(Box::new(HostsExecutor {
            tag: plugin_config.tag.clone(),
            rules,
            index,
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

fn build_rules(cfg: &HostsConfig) -> Result<(Vec<HostsRule>, RuleIndex)> {
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

    let index = build_rule_index(&out)?;
    Ok((out, index))
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
        Regex::new(v).map_err(|e| format!("invalid hosts regexp '{}': {}", v, e))?;
        return Ok(RuleMatcher::Regexp(v.to_string()));
    }

    // hosts defaults to full match when prefix is omitted.
    Ok(RuleMatcher::Full(normalize_name(raw_rule)))
}

fn build_rule_index(rules: &[HostsRule]) -> Result<RuleIndex> {
    let mut index = RuleIndex::default();
    let mut keyword_patterns = Vec::new();
    let mut regex_patterns = Vec::new();

    for (rule_idx, rule) in rules.iter().enumerate() {
        match &rule.matcher {
            RuleMatcher::Full(v) => {
                index
                    .full_rules
                    .entry(v.clone().into_boxed_str())
                    .or_insert(rule_idx);
            }
            RuleMatcher::Domain(v) => {
                index
                    .domain_rules
                    .entry(v.clone().into_boxed_str())
                    .or_insert(rule_idx);
            }
            RuleMatcher::Keyword(v) => {
                keyword_patterns.push(v.clone());
                index.keyword_rule_indices.push(rule_idx);
            }
            RuleMatcher::Regexp(v) => {
                regex_patterns.push(v.clone());
                index.regex_rule_indices.push(rule_idx);
            }
        }
    }

    if !keyword_patterns.is_empty() {
        index.keyword_matcher = Some(
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(false)
                .build(&keyword_patterns)
                .map_err(|e| {
                    DnsError::plugin(format!("failed to build hosts keyword matcher: {}", e))
                })?,
        );
    }

    if !regex_patterns.is_empty() {
        index.regex_matcher = Some(RegexSetBuilder::new(&regex_patterns).build().map_err(|e| {
            DnsError::plugin(format!("failed to build hosts regex matcher: {}", e))
        })?);
    }

    Ok(index)
}

impl RuleIndex {
    fn match_rule<'a>(&self, rules: &'a [HostsRule], domain: &str) -> Option<&'a HostsRule> {
        let mut best: Option<usize> = None;

        if let Some(rule_idx) = self.full_rules.get(domain) {
            best = Some(*rule_idx);
        }

        let mut suffix = domain;
        loop {
            if let Some(rule_idx) = self.domain_rules.get(suffix) {
                best = Some(best.map_or(*rule_idx, |cur| cur.min(*rule_idx)));
            }
            let Some(dot) = suffix.find('.') else {
                break;
            };
            suffix = &suffix[dot + 1..];
        }

        if let Some(matcher) = &self.keyword_matcher {
            for m in matcher.find_iter(domain) {
                let rule_idx = self.keyword_rule_indices[m.pattern().as_usize()];
                best = Some(best.map_or(rule_idx, |cur| cur.min(rule_idx)));
            }
        }

        if let Some(matcher) = &self.regex_matcher {
            let matched = matcher.matches(domain);
            for pid in matched.iter() {
                let rule_idx = self.regex_rule_indices[pid];
                best = Some(best.map_or(rule_idx, |cur| cur.min(rule_idx)));
            }
        }

        best.map(|idx| &rules[idx])
    }
}

fn normalize_name(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}
