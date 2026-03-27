/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `hosts` executor plugin.
//!
//! Maps domain rules to static IP responses.
//!
//! Rule sources:
//! - inline `entries`
//! - external files (`files`)
//!
//! Supported matchers follow mosdns-style expressions:
//! - exact name (`full:example.com`)
//! - suffix domain (`domain:example.com`)
//! - keyword (`keyword:cdn`)
//! - regex (`regexp:^api\\.`)
//!
//! Execution only answers IN-class `A`/`AAAA` requests. Non-matching queries
//! pass through to downstream executors unchanged.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{A, AAAA, DNSClass, RData, RecordType};
use crate::register_plugin_factory;
use ahash::AHashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use async_trait::async_trait;
use regex::{Regex, RegexSet, RegexSetBuilder};
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct HostsConfig {
    /// Inline hosts rules.
    #[serde(default)]
    entries: Vec<String>,
    /// Paths to hosts rule files.
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
    ipv4: Vec<Arc<RData>>,
    ipv6: Vec<Arc<RData>>,
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

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for HostsExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let Some(question) = context.request.first_question() else {
            return Ok(ExecStep::Next);
        };
        let qclass = question.qclass();
        let qtype = question.qtype();
        if qclass != DNSClass::IN {
            return Ok(ExecStep::Next);
        }
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return Ok(ExecStep::Next);
        }
        let Some(rule) = self
            .index
            .match_rule(&self.rules, question.name().normalized())
        else {
            return Ok(ExecStep::Next);
        };

        let response = match qtype {
            RecordType::A if !rule.ipv4.is_empty() => context
                .request
                .address_response_rdata(question, 300, &rule.ipv4)?,
            RecordType::AAAA if !rule.ipv6.is_empty() => context
                .request
                .address_response_rdata(question, 300, &rule.ipv6)?,
            _ => return Ok(ExecStep::Next),
        };

        context.set_response(response);

        Ok(ExecStep::Next)
    }
}

#[derive(Debug, Clone)]
pub struct HostsFactory;

register_plugin_factory!("hosts", HostsFactory {});

impl PluginFactory for HostsFactory {
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
            Ok(IpAddr::V4(v4)) => ipv4.push(Arc::new(RData::A(A(v4)))),
            Ok(IpAddr::V6(v6)) => ipv6.push(Arc::new(RData::AAAA(AAAA(v6)))),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::executor::{ExecStep, Executor};
    use crate::plugin::test_utils::test_registry;
    use crate::proto::{DNSClass, Name, RecordType};
    use crate::proto::{Message, Question};
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_parse_hosts_line_validation() {
        assert!(parse_hosts_line("").is_err());
        assert!(parse_hosts_line("full:example.com").is_err());
        assert!(parse_hosts_line("full:example.com 1.1.1.1").is_ok());
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
    async fn test_hosts_execute_matches_and_returns_static_answer() {
        let cfg = HostsConfig {
            entries: vec!["full:example.com 1.1.1.1 ::1".to_string()],
            files: vec![],
        };
        let (rules, index) = build_rules(&cfg).expect("rules should parse");
        let plugin = HostsExecutor {
            tag: "hosts".to_string(),
            rules,
            index,
        };

        let mut a_ctx = make_context("example.com.", RecordType::A);
        let step = plugin
            .execute(&mut a_ctx)
            .await
            .expect("execute should work");
        assert!(matches!(step, ExecStep::Next));
        let a_resp = a_ctx.response().expect("response should exist");
        assert_eq!(a_resp.answers().len(), 1);
        assert_eq!(a_resp.answers()[0].rr_type(), RecordType::A);

        let mut aaaa_ctx = make_context("example.com.", RecordType::AAAA);
        plugin
            .execute(&mut aaaa_ctx)
            .await
            .expect("execute should work");
        let aaaa_resp = aaaa_ctx.response().expect("response should exist");
        assert_eq!(aaaa_resp.answers().len(), 1);
        assert_eq!(aaaa_resp.answers()[0].rr_type(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn test_hosts_execute_builds_response_from_request_message() {
        let cfg = HostsConfig {
            entries: vec!["full:example.com 1.1.1.1".to_string()],
            files: vec![],
        };
        let (rules, index) = build_rules(&cfg).expect("rules should parse");
        let plugin = HostsExecutor {
            tag: "hosts".to_string(),
            rules,
            index,
        };

        let mut ctx = make_context("example.com.", RecordType::A);
        let step = plugin.execute(&mut ctx).await.expect("execute should work");
        assert!(matches!(step, ExecStep::Next));
        let response = ctx.response().expect("response should exist");
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].rr_type(), RecordType::A);
    }

    #[tokio::test]
    async fn test_hosts_execute_no_match_keeps_response_empty() {
        let cfg = HostsConfig {
            entries: vec!["full:example.com 1.1.1.1".to_string()],
            files: vec![],
        };
        let (rules, index) = build_rules(&cfg).expect("rules should parse");
        let plugin = HostsExecutor {
            tag: "hosts".to_string(),
            rules,
            index,
        };

        let mut ctx = make_context("other.com.", RecordType::A);
        plugin.execute(&mut ctx).await.expect("execute should work");
        assert!(ctx.response().is_none());
    }
}
