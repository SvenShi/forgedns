/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `redirect` executor plugin.
//!
//! Rewrites request qname to target qname, executes subsequent chain, then
//! restores original question and prepends a CNAME answer.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecState, ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use hickory_proto::op::Query;
use hickory_proto::rr::rdata::name::CNAME;
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use regex::Regex;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Default)]
struct RedirectConfig {
    #[serde(default)]
    rules: Vec<String>,
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
struct RedirectRule {
    matcher: RuleMatcher,
    target: Name,
}

#[derive(Debug)]
struct RedirectExecutor {
    tag: String,
    rules: Vec<RedirectRule>,
}

#[derive(Debug)]
struct RedirectPostState {
    original: Name,
    target: Name,
}

#[async_trait]
impl Plugin for RedirectExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for RedirectExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        if context.request.queries().len() != 1 {
            return Ok(ExecStep::Next);
        }

        let Some(qclass) = context.request.query().map(|q| q.query_class) else {
            return Ok(ExecStep::Next);
        };

        if qclass != DNSClass::IN {
            return Ok(ExecStep::Next);
        }

        let Some(query_view) = context.query_view() else {
            return Ok(ExecStep::Next);
        };
        let original = query_view.raw_name().clone();
        let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule_matches(&rule.matcher, query_view.normalized_name()))
        else {
            return Ok(ExecStep::Next);
        };

        let target = rule.target.clone();
        set_query_name(context, target.clone())?;

        Ok(ExecStep::NextWithPost(Some(
            Box::new(RedirectPostState { original, target }) as ExecState,
        )))
    }

    async fn post_execute(&self, context: &mut DnsContext, state: Option<ExecState>) -> Result<()> {
        let Some(state) = state
            .and_then(|boxed| boxed.downcast::<RedirectPostState>().ok())
            .map(|boxed| *boxed)
        else {
            return Ok(());
        };

        set_query_name(context, state.original.clone())?;

        let Some(response) = context.response.as_mut() else {
            return Ok(());
        };

        for query in response.queries_mut() {
            if query.name() == &state.target {
                query.set_name(state.original.clone());
            }
        }

        let mut answer = Vec::with_capacity(response.answers().len() + 1);
        answer.push(Record::from_rdata(
            state.original,
            1,
            RData::CNAME(CNAME(state.target)),
        ));
        answer.extend(response.answers().iter().cloned());
        *response.answers_mut() = answer;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RedirectFactory;

register_plugin_factory!("redirect", RedirectFactory {});

impl PluginFactory for RedirectFactory {
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

        Ok(UninitializedPlugin::Executor(Box::new(RedirectExecutor {
            tag: plugin_config.tag.clone(),
            rules,
        })))
    }
}

fn parse_config(args: Option<serde_yml::Value>) -> Result<RedirectConfig> {
    let Some(args) = args else {
        return Ok(RedirectConfig::default());
    };

    serde_yml::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse redirect config: {}", e)))
}

fn build_rules(cfg: &RedirectConfig) -> Result<Vec<RedirectRule>> {
    let mut out = Vec::new();

    for (idx, rule) in cfg.rules.iter().enumerate() {
        out.push(parse_redirect_rule(rule).map_err(|e| {
            DnsError::plugin(format!("invalid redirect rule #{} '{}': {}", idx, rule, e))
        })?);
    }

    for file in &cfg.files {
        if file.trim().is_empty() {
            continue;
        }
        let handle = File::open(file).map_err(|e| {
            DnsError::plugin(format!("failed to open redirect file '{}': {}", file, e))
        })?;
        let mut reader = BufReader::new(handle);
        let mut line = String::new();
        let mut line_no = 0usize;
        loop {
            line.clear();
            let n = reader.read_line(&mut line).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to read redirect file '{}' at line {}: {}",
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
            let raw = raw
                .split_once('#')
                .map(|(left, _)| left)
                .unwrap_or(raw)
                .trim();
            if raw.is_empty() {
                continue;
            }

            out.push(parse_redirect_rule(raw).map_err(|e| {
                DnsError::plugin(format!(
                    "invalid redirect file '{}' line {} '{}': {}",
                    file, line_no, raw, e
                ))
            })?);
        }
    }

    Ok(out)
}

fn parse_redirect_rule(raw: &str) -> std::result::Result<RedirectRule, String> {
    let fields: Vec<&str> = raw.split_whitespace().collect();
    if fields.len() != 2 {
        return Err(format!(
            "redirect rule requires exactly 2 fields, got {}",
            fields.len()
        ));
    }

    let matcher = parse_rule_matcher(fields[0])?;
    let target = parse_name(fields[1])?;

    Ok(RedirectRule { matcher, target })
}

fn parse_rule_matcher(raw_rule: &str) -> std::result::Result<RuleMatcher, String> {
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
        let re = Regex::new(v).map_err(|e| format!("invalid regexp '{}': {}", v, e))?;
        return Ok(RuleMatcher::Regexp(re));
    }

    // redirect defaults to full match when prefix is omitted.
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

fn set_query_name(context: &mut DnsContext, name: Name) -> Result<()> {
    if !context.set_first_query_name(name) {
        return Err(DnsError::plugin("redirect requires one question"));
    }
    Ok(())
}

fn parse_name(raw: &str) -> std::result::Result<Name, String> {
    let fqdn = if raw.ends_with('.') {
        raw.to_string()
    } else {
        format!("{}.", raw)
    };
    Name::from_ascii(&fqdn).map_err(|e| format!("invalid domain '{}': {}", raw, e))
}

#[inline]
fn normalize_name(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[allow(dead_code)]
fn _query_name(query: &Query) -> &Name {
    query.name()
}
