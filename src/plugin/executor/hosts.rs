/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `hosts` executor plugin.
//!
//! Maps host-style domain rules to static IP responses with mosdns-compatible
//! matching and response semantics.
//!
//! Rule sources:
//! - inline `entries`
//! - external files (`files`)
//!
//! Supported matchers:
//! - exact name (`full:example.com`)
//! - suffix domain (`domain:example.com`)
//! - keyword (`keyword:cdn`)
//! - regex (`regexp:^api\\.`)
//!
//! Unprefixed rules default to `full:` to mirror mosdns `hosts`.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{
    A, AAAA, DNSClass, Message, Name, Question, RData, Rcode, Record, RecordType, SOA,
};
use crate::register_plugin_factory;
use ahash::AHashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use async_trait::async_trait;
use regex::{Regex, RegexSet, RegexSetBuilder};
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::Arc;

const HOSTS_ANSWER_TTL: u32 = 10;
const HOSTS_FAKE_SOA_TTL: u32 = 300;

lazy_static::lazy_static! {
    static ref FAKE_SOA_RDATA: Arc<RData> = Arc::new(RData::SOA(SOA::new(
        Name::from_ascii("fake-ns.mosdns.fake.root.").expect("fake SOA mname should parse"),
        Name::from_ascii("fake-mbox.mosdns.fake.root.").expect("fake SOA rname should parse"),
        2021110400,
        1800,
        900,
        604800,
        86400,
    )));
}

#[derive(Debug, Clone, Deserialize, Default)]
struct HostsConfig {
    /// Inline hosts rules.
    #[serde(default)]
    entries: Vec<String>,
    /// Paths to hosts rule files.
    #[serde(default)]
    files: Vec<String>,
    /// Whether to stop the executor chain after producing a local answer.
    #[serde(default)]
    short_circuit: bool,
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
    answers: HostsAnswers,
}

#[derive(Debug, Clone)]
struct HostsAnswers {
    ipv4: Vec<Arc<RData>>,
    ipv6: Vec<Arc<RData>>,
}

#[derive(Debug)]
struct HostsExecutor {
    tag: String,
    index: RuleIndex,
    short_circuit: bool,
}

#[derive(Debug)]
struct RuleIndex {
    payloads: Vec<Arc<HostsAnswers>>,
    full_rules: AHashMap<Box<str>, usize>,
    domain_rules: DomainTrie,
    keyword_rules: Option<KeywordIndex>,
    regex_rules: Option<RegexIndex>,
}

#[derive(Debug, Default)]
struct RuleIndexBuilder {
    payloads: Vec<Arc<HostsAnswers>>,
    full_rules: AHashMap<Box<str>, usize>,
    domain_rules: DomainTrie,
    keyword_rules: KeywordIndexBuilder,
    regex_rules: RegexIndexBuilder,
}

#[derive(Debug, Default)]
struct KeywordIndexBuilder {
    patterns: Vec<String>,
    payload_slots: Vec<usize>,
    pattern_ids: AHashMap<Box<str>, usize>,
}

#[derive(Debug, Default)]
struct RegexIndexBuilder {
    patterns: Vec<String>,
    payload_slots: Vec<usize>,
    pattern_ids: AHashMap<Box<str>, usize>,
}

#[derive(Debug)]
struct KeywordIndex {
    matcher: AhoCorasick,
    payload_slots: Vec<usize>,
}

#[derive(Debug)]
struct RegexIndex {
    matcher: RegexSet,
    payload_slots: Vec<usize>,
}

#[derive(Debug, Default)]
struct DomainTrieNode {
    payload_slot: Option<usize>,
    children: AHashMap<Box<str>, u32>,
}

#[derive(Debug)]
struct DomainTrie {
    nodes: Vec<DomainTrieNode>,
}

impl Default for DomainTrie {
    fn default() -> Self {
        Self {
            nodes: vec![DomainTrieNode::default()],
        }
    }
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
        if context.request.questions().len() != 1 {
            return Ok(ExecStep::Next);
        }

        let Some(question) = context.request.first_question() else {
            return Ok(ExecStep::Next);
        };
        if question.qclass() != DNSClass::IN {
            return Ok(ExecStep::Next);
        }
        if question.qtype() != RecordType::A && question.qtype() != RecordType::AAAA {
            return Ok(ExecStep::Next);
        }

        let Some(answers) = self.index.match_answers(question.name().normalized()) else {
            return Ok(ExecStep::Next);
        };

        let response = build_hosts_response(&context.request, question, answers)?;
        context.set_response(response);

        if self.short_circuit {
            Ok(ExecStep::Stop)
        } else {
            Ok(ExecStep::Next)
        }
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
        let index = build_rule_index(&cfg)?;

        Ok(UninitializedPlugin::Executor(Box::new(HostsExecutor {
            tag: plugin_config.tag.clone(),
            index,
            short_circuit: cfg.short_circuit,
        })))
    }
}

fn parse_config(args: Option<Value>) -> Result<HostsConfig> {
    let Some(args) = args else {
        return Ok(HostsConfig::default());
    };

    serde_yaml_ng::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse hosts config: {}", e)))
}

fn build_rule_index(cfg: &HostsConfig) -> Result<RuleIndex> {
    let mut builder = RuleIndexBuilder::default();

    for (idx, entry) in cfg.entries.iter().enumerate() {
        let rule = parse_hosts_line(entry).map_err(|e| {
            DnsError::plugin(format!("invalid hosts entry #{} '{}': {}", idx, entry, e))
        })?;
        builder.add_rule(rule);
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
            builder.add_rule(rule);
        }
    }

    builder.build()
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
        answers: HostsAnswers { ipv4, ipv6 },
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
        return Ok(RuleMatcher::Keyword(normalize_name(v)));
    }
    if let Some(v) = raw_rule.strip_prefix("regexp:") {
        Regex::new(v).map_err(|e| format!("invalid hosts regexp '{}': {}", v, e))?;
        return Ok(RuleMatcher::Regexp(v.to_string()));
    }

    // mosdns hosts defaults to full match when prefix is omitted.
    Ok(RuleMatcher::Full(normalize_name(raw_rule)))
}

fn build_hosts_response(
    request: &Message,
    question: &Question,
    answers: &HostsAnswers,
) -> Result<Message> {
    match question.qtype() {
        RecordType::A if !answers.ipv4.is_empty() => {
            Ok(request.address_response_rdata(question, HOSTS_ANSWER_TTL, &answers.ipv4)?)
        }
        RecordType::AAAA if !answers.ipv6.is_empty() => {
            Ok(request.address_response_rdata(question, HOSTS_ANSWER_TTL, &answers.ipv6)?)
        }
        RecordType::A | RecordType::AAAA => Ok(build_nodata_response(request, question)),
        _ => Err(DnsError::protocol(
            "hosts synthetic response only supports A/AAAA questions",
        )),
    }
}

fn build_nodata_response(request: &Message, question: &Question) -> Message {
    let mut response = request.response(Rcode::NoError);
    response.add_authority(Record::from_arc_rdata(
        question.name().clone(),
        HOSTS_FAKE_SOA_TTL,
        FAKE_SOA_RDATA.clone(),
    ));
    response
}

impl RuleIndexBuilder {
    fn add_rule(&mut self, rule: HostsRule) {
        match rule.matcher {
            RuleMatcher::Full(name) => self.add_full_rule(name, rule.answers),
            RuleMatcher::Domain(name) => self.add_domain_rule(name, rule.answers),
            RuleMatcher::Keyword(pattern) => {
                self.keyword_rules
                    .add(pattern, rule.answers, &mut self.payloads)
            }
            RuleMatcher::Regexp(pattern) => {
                self.regex_rules
                    .add(pattern, rule.answers, &mut self.payloads)
            }
        }
    }

    fn add_full_rule(&mut self, name: String, answers: HostsAnswers) {
        if let Some(slot) = self.full_rules.get(name.as_str()).copied() {
            self.payloads[slot] = Arc::new(answers);
        } else {
            let slot = self.push_answers(answers);
            self.full_rules.insert(name.into_boxed_str(), slot);
        }
    }

    fn add_domain_rule(&mut self, name: String, answers: HostsAnswers) {
        if let Some(slot) = self.domain_rules.exact_payload_slot(name.as_str()) {
            self.payloads[slot] = Arc::new(answers);
        } else {
            let slot = self.push_answers(answers);
            self.domain_rules.insert(name.as_str(), slot);
        }
    }

    fn push_answers(&mut self, answers: HostsAnswers) -> usize {
        let slot = self.payloads.len();
        self.payloads.push(Arc::new(answers));
        slot
    }

    fn build(self) -> Result<RuleIndex> {
        Ok(RuleIndex {
            payloads: self.payloads,
            full_rules: self.full_rules,
            domain_rules: self.domain_rules,
            keyword_rules: self.keyword_rules.build()?,
            regex_rules: self.regex_rules.build()?,
        })
    }
}

impl KeywordIndexBuilder {
    fn add(
        &mut self,
        pattern: String,
        answers: HostsAnswers,
        payloads: &mut Vec<Arc<HostsAnswers>>,
    ) {
        if let Some(&pattern_id) = self.pattern_ids.get(pattern.as_str()) {
            let payload_slot = self.payload_slots[pattern_id];
            payloads[payload_slot] = Arc::new(answers);
        } else {
            let payload_slot = payloads.len();
            payloads.push(Arc::new(answers));
            let pattern_id = self.patterns.len();
            self.pattern_ids
                .insert(pattern.clone().into_boxed_str(), pattern_id);
            self.patterns.push(pattern);
            self.payload_slots.push(payload_slot);
        }
    }

    fn build(self) -> Result<Option<KeywordIndex>> {
        if self.patterns.is_empty() {
            return Ok(None);
        }

        let matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(false)
            .build(&self.patterns)
            .map_err(|e| {
                DnsError::plugin(format!("failed to build hosts keyword matcher: {}", e))
            })?;

        Ok(Some(KeywordIndex {
            matcher,
            payload_slots: self.payload_slots,
        }))
    }
}

impl RegexIndexBuilder {
    fn add(
        &mut self,
        pattern: String,
        answers: HostsAnswers,
        payloads: &mut Vec<Arc<HostsAnswers>>,
    ) {
        if let Some(&pattern_id) = self.pattern_ids.get(pattern.as_str()) {
            let payload_slot = self.payload_slots[pattern_id];
            payloads[payload_slot] = Arc::new(answers);
        } else {
            let payload_slot = payloads.len();
            payloads.push(Arc::new(answers));
            let pattern_id = self.patterns.len();
            self.pattern_ids
                .insert(pattern.clone().into_boxed_str(), pattern_id);
            self.patterns.push(pattern);
            self.payload_slots.push(payload_slot);
        }
    }

    fn build(self) -> Result<Option<RegexIndex>> {
        if self.patterns.is_empty() {
            return Ok(None);
        }

        let matcher = RegexSetBuilder::new(&self.patterns)
            .build()
            .map_err(|e| DnsError::plugin(format!("failed to build hosts regex matcher: {}", e)))?;

        Ok(Some(RegexIndex {
            matcher,
            payload_slots: self.payload_slots,
        }))
    }
}

impl RuleIndex {
    fn match_answers(&self, domain: &str) -> Option<&HostsAnswers> {
        if let Some(&slot) = self.full_rules.get(domain) {
            return Some(self.payloads[slot].as_ref());
        }

        if let Some(slot) = self.domain_rules.match_payload_slot(domain) {
            return Some(self.payloads[slot].as_ref());
        }

        if let Some(slot) = self
            .regex_rules
            .as_ref()
            .and_then(|index| index.match_payload_slot(domain))
        {
            return Some(self.payloads[slot].as_ref());
        }

        self.keyword_rules
            .as_ref()
            .and_then(|index| index.match_payload_slot(domain))
            .map(|slot| self.payloads[slot].as_ref())
    }
}

impl DomainTrie {
    fn insert(&mut self, domain: &str, payload_slot: usize) {
        let mut cursor = 0u32;
        for label in domain.rsplit('.') {
            if label.is_empty() {
                continue;
            }

            let next = if let Some(next) = self.nodes[cursor as usize].children.get(label) {
                *next
            } else {
                let idx = self.nodes.len() as u32;
                self.nodes.push(DomainTrieNode::default());
                self.nodes[cursor as usize]
                    .children
                    .insert(label.to_owned().into_boxed_str(), idx);
                idx
            };
            cursor = next;
        }

        self.nodes[cursor as usize].payload_slot = Some(payload_slot);
    }

    fn exact_payload_slot(&self, domain: &str) -> Option<usize> {
        let mut cursor = 0u32;
        for label in domain.rsplit('.') {
            if label.is_empty() {
                continue;
            }

            let next = self.nodes[cursor as usize].children.get(label)?;
            cursor = *next;
        }
        self.nodes[cursor as usize].payload_slot
    }

    fn match_payload_slot(&self, domain: &str) -> Option<usize> {
        let mut cursor = 0u32;
        let mut matched = self.nodes[cursor as usize].payload_slot;

        for label in domain.rsplit('.') {
            if label.is_empty() {
                continue;
            }

            let Some(next) = self.nodes[cursor as usize].children.get(label) else {
                break;
            };
            cursor = *next;
            if let Some(slot) = self.nodes[cursor as usize].payload_slot {
                matched = Some(slot);
            }
        }

        matched
    }
}

impl KeywordIndex {
    fn match_payload_slot(&self, domain: &str) -> Option<usize> {
        let mut best_pattern: Option<usize> = None;
        for matched in self.matcher.find_iter(domain) {
            let pattern_id = matched.pattern().as_usize();
            best_pattern = Some(best_pattern.map_or(pattern_id, |current| current.min(pattern_id)));
        }

        best_pattern.map(|pattern_id| self.payload_slots[pattern_id])
    }
}

impl RegexIndex {
    fn match_payload_slot(&self, domain: &str) -> Option<usize> {
        let matched = self.matcher.matches(domain);
        matched
            .iter()
            .next()
            .map(|pattern_id| self.payload_slots[pattern_id])
    }
}

fn normalize_name(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::test_registry;
    use crate::proto::{DNSClass, Name, Question};
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr};
    use tempfile::NamedTempFile;

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

    fn build_plugin(cfg: HostsConfig) -> HostsExecutor {
        HostsExecutor {
            tag: "hosts".to_string(),
            index: build_rule_index(&cfg).expect("rules should parse"),
            short_circuit: cfg.short_circuit,
        }
    }

    #[tokio::test]
    async fn test_hosts_execute_defaults_unprefixed_rule_to_full_match() {
        let plugin = build_plugin(HostsConfig {
            entries: vec!["example.com 1.1.1.1".to_string()],
            files: vec![],
            short_circuit: false,
        });

        let mut exact = make_context("example.com.", RecordType::A);
        plugin
            .execute(&mut exact)
            .await
            .expect("execute should work");
        assert_eq!(
            exact
                .response()
                .expect("response should exist")
                .answer_ips(),
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
        );

        let mut subdomain = make_context("www.example.com.", RecordType::A);
        plugin
            .execute(&mut subdomain)
            .await
            .expect("execute should work");
        assert!(subdomain.response().is_none());
    }

    #[tokio::test]
    async fn test_hosts_execute_prefers_longest_domain_suffix() {
        let plugin = build_plugin(HostsConfig {
            entries: vec![
                "domain:example.com 192.0.2.10".to_string(),
                "domain:svc.example.com 192.0.2.11".to_string(),
            ],
            files: vec![],
            short_circuit: false,
        });

        let mut ctx = make_context("api.svc.example.com.", RecordType::A);
        plugin.execute(&mut ctx).await.expect("execute should work");

        assert_eq!(
            ctx.response().expect("response should exist").answer_ips(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
    }

    #[tokio::test]
    async fn test_hosts_execute_respects_family_priority() {
        let plugin = build_plugin(HostsConfig {
            entries: vec![
                "keyword:test 192.0.2.1".to_string(),
                "regexp:^svc\\.example\\.com$ 192.0.2.2".to_string(),
                "domain:example.com 192.0.2.3".to_string(),
                "full:api.example.com 192.0.2.4".to_string(),
                "regexp:^api-only\\.test$ 192.0.2.5".to_string(),
            ],
            files: vec![],
            short_circuit: false,
        });

        let mut full_hit = make_context("api.example.com.", RecordType::A);
        plugin
            .execute(&mut full_hit)
            .await
            .expect("execute should work");
        assert_eq!(
            full_hit
                .response()
                .expect("response should exist")
                .answer_ips(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4))]
        );

        let mut domain_hit = make_context("svc.example.com.", RecordType::A);
        plugin
            .execute(&mut domain_hit)
            .await
            .expect("execute should work");
        assert_eq!(
            domain_hit
                .response()
                .expect("response should exist")
                .answer_ips(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3))]
        );

        let mut regex_hit = make_context("api-only.test.", RecordType::A);
        plugin
            .execute(&mut regex_hit)
            .await
            .expect("execute should work");
        assert_eq!(
            regex_hit
                .response()
                .expect("response should exist")
                .answer_ips(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))]
        );
    }

    #[tokio::test]
    async fn test_hosts_execute_replaces_duplicate_rules_in_load_order() {
        let plugin = build_plugin(HostsConfig {
            entries: vec![
                "full:example.com 192.0.2.10".to_string(),
                "full:example.com 192.0.2.11".to_string(),
                "keyword:test 192.0.2.20".to_string(),
                "keyword:test 192.0.2.21".to_string(),
            ],
            files: vec![],
            short_circuit: false,
        });

        let mut full_ctx = make_context("example.com.", RecordType::A);
        plugin
            .execute(&mut full_ctx)
            .await
            .expect("execute should work");
        assert_eq!(
            full_ctx
                .response()
                .expect("response should exist")
                .answer_ips(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );

        let mut keyword_ctx = make_context("cache.test.", RecordType::A);
        plugin
            .execute(&mut keyword_ctx)
            .await
            .expect("execute should work");
        assert_eq!(
            keyword_ctx
                .response()
                .expect("response should exist")
                .answer_ips(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21))]
        );
    }

    #[tokio::test]
    async fn test_hosts_execute_uses_ttl_10_for_positive_answers() {
        let plugin = build_plugin(HostsConfig {
            entries: vec!["full:example.com 1.1.1.1".to_string()],
            files: vec![],
            short_circuit: false,
        });

        let mut ctx = make_context("example.com.", RecordType::A);
        plugin.execute(&mut ctx).await.expect("execute should work");

        let response = ctx.response().expect("response should exist");
        assert_eq!(response.answers().len(), 1);
        assert_eq!(response.answers()[0].ttl(), HOSTS_ANSWER_TTL);
    }

    #[tokio::test]
    async fn test_hosts_execute_returns_nodata_with_fake_soa_for_family_mismatch() {
        let plugin = build_plugin(HostsConfig {
            entries: vec!["full:example.com 1.1.1.1".to_string()],
            files: vec![],
            short_circuit: false,
        });

        let mut ctx = make_context("example.com.", RecordType::AAAA);
        let step = plugin.execute(&mut ctx).await.expect("execute should work");

        assert!(matches!(step, ExecStep::Next));
        let response = ctx.response().expect("response should exist");
        assert_eq!(response.rcode(), Rcode::NoError);
        assert!(response.answers().is_empty());
        assert_eq!(response.authorities().len(), 1);
        assert_eq!(response.authorities()[0].rr_type(), RecordType::SOA);
        assert_eq!(response.authorities()[0].ttl(), HOSTS_FAKE_SOA_TTL);
    }

    #[tokio::test]
    async fn test_hosts_execute_stops_on_empty_local_answer_when_short_circuit_enabled() {
        let plugin = build_plugin(HostsConfig {
            entries: vec!["full:example.com 1.1.1.1".to_string()],
            files: vec![],
            short_circuit: true,
        });

        let mut ctx = make_context("example.com.", RecordType::AAAA);
        let step = plugin.execute(&mut ctx).await.expect("execute should work");

        assert!(matches!(step, ExecStep::Stop));
        assert!(ctx.response().is_some());
    }

    #[tokio::test]
    async fn test_hosts_execute_ignores_multi_question_requests() {
        let plugin = build_plugin(HostsConfig {
            entries: vec!["full:example.com 1.1.1.1".to_string()],
            files: vec![],
            short_circuit: false,
        });

        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        request.add_question(Question::new(
            Name::from_ascii("example.net.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        let mut ctx = DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        );

        let step = plugin.execute(&mut ctx).await.expect("execute should work");
        assert!(matches!(step, ExecStep::Next));
        assert!(ctx.response().is_none());
    }

    #[test]
    fn test_build_rule_index_loads_files_after_entries() {
        let mut file = NamedTempFile::new().expect("temp file should be created");
        writeln!(file, "full:example.com 192.0.2.11").expect("temp file should be writable");

        let cfg = HostsConfig {
            entries: vec!["full:example.com 192.0.2.10".to_string()],
            files: vec![file.path().to_string_lossy().to_string()],
            short_circuit: false,
        };
        let index = build_rule_index(&cfg).expect("rule index should build");
        let answers = index
            .match_answers("example.com")
            .expect("example.com should match");
        let response = build_hosts_response(
            &Message::new(),
            &Question::new(
                Name::from_ascii("example.com.").unwrap(),
                RecordType::A,
                DNSClass::IN,
            ),
            answers,
        )
        .expect("response should build");

        assert_eq!(
            response.answer_ips(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))]
        );
    }
}
