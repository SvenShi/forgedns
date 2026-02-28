/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `string_exp` matcher plugin.
//!
//! Experimental string expression matcher.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::dns_utils::{response_records, rr_to_ip};
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use regex::Regex;
use serde_yml::Value;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct StringExpFactory {}

register_plugin_factory!("string_exp", StringExpFactory {});

impl PluginFactory for StringExpFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let expression = parse_expression_from_value(plugin_config.args.clone())?;
        let _ = parse_string_expression(&expression)?;
        Ok(())
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let expression = parse_expression_from_value(plugin_config.args.clone())?;
        let expression = parse_string_expression(&expression)?;
        Ok(UninitializedPlugin::Matcher(Box::new(StringExpMatcher {
            tag: plugin_config.tag.clone(),
            expression,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let expression =
            param.ok_or_else(|| DnsError::plugin("string_exp requires expression parameter"))?;
        let expression = parse_string_expression(&expression)?;
        Ok(UninitializedPlugin::Matcher(Box::new(StringExpMatcher {
            tag: tag.to_string(),
            expression,
        })))
    }
}

fn parse_expression_from_value(args: Option<Value>) -> DnsResult<String> {
    let args = args.ok_or_else(|| DnsError::plugin("string_exp requires args"))?;
    match args {
        Value::String(s) => Ok(s.trim().to_string()),
        Value::Sequence(seq) => {
            if seq.is_empty() {
                return Err(DnsError::plugin("string_exp requires expression"));
            }
            let mut parts = Vec::with_capacity(seq.len());
            for item in seq {
                match item {
                    Value::String(s) => parts.push(s.trim().to_string()),
                    other => {
                        return Err(DnsError::plugin(format!(
                            "string_exp args must be string list, got {:?}",
                            other
                        )));
                    }
                }
            }
            Ok(parts.join(" "))
        }
        other => Err(DnsError::plugin(format!(
            "string_exp args must be string or string array, got {:?}",
            other
        ))),
    }
}

#[derive(Debug)]
struct StringExpMatcher {
    tag: String,
    expression: StringExpression,
}

#[derive(Debug)]
struct StringExpression {
    source: StringSource,
    op: StringOp,
}

#[derive(Debug)]
enum StringSource {
    Qname,
    Qtype,
    Qclass,
    Rcode,
    RespIp,
    Mark,
    ClientIp,
    Listener,
    ServerName,
    UrlPath,
    Env(String),
}

#[derive(Debug)]
enum StringOp {
    Eq(Vec<String>),
    Prefix(Vec<String>),
    Suffix(Vec<String>),
    Contains(Vec<String>),
    Regexp(Vec<Regex>),
    ZeroLength,
}

#[async_trait]
impl Plugin for StringExpMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Matcher for StringExpMatcher {
    async fn is_match(&self, context: &mut DnsContext) -> bool {
        let value = self.expression.source.read(context);
        self.expression.op.evaluate(&value)
    }
}

impl StringSource {
    fn read(&self, context: &DnsContext) -> String {
        match self {
            StringSource::Qname => context
                .request
                .queries()
                .first()
                .map(|q| {
                    q.name()
                        .to_utf8()
                        .trim_end_matches('.')
                        .to_ascii_lowercase()
                })
                .unwrap_or_default(),
            StringSource::Qtype => context
                .request
                .queries()
                .first()
                .map(|q| u16::from(q.query_type()).to_string())
                .unwrap_or_default(),
            StringSource::Qclass => context
                .request
                .queries()
                .first()
                .map(|q| u16::from(q.query_class()).to_string())
                .unwrap_or_default(),
            StringSource::Rcode => context
                .response
                .as_ref()
                .map(|r| u16::from(r.response_code()).to_string())
                .unwrap_or_default(),
            StringSource::RespIp => {
                let Some(response) = context.response.as_ref() else {
                    return String::new();
                };
                response_records(response)
                    .filter_map(rr_to_ip)
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            }
            StringSource::Mark => context.marks.iter().cloned().collect::<Vec<_>>().join(","),
            StringSource::ClientIp => context.src_addr.ip().to_string(),
            StringSource::Listener => context
                .get_attr::<String>("listener")
                .cloned()
                .unwrap_or_default(),
            StringSource::ServerName => context
                .get_attr::<String>("server_name")
                .cloned()
                .unwrap_or_default(),
            StringSource::UrlPath => context
                .get_attr::<String>("url_path")
                .cloned()
                .unwrap_or_default(),
            StringSource::Env(key) => std::env::var(key).unwrap_or_default(),
        }
    }
}

impl StringOp {
    fn evaluate(&self, value: &str) -> bool {
        match self {
            StringOp::Eq(rules) => rules.iter().any(|rule| value == rule),
            StringOp::Prefix(rules) => rules.iter().any(|rule| value.starts_with(rule)),
            StringOp::Suffix(rules) => rules.iter().any(|rule| value.ends_with(rule)),
            StringOp::Contains(rules) => rules.iter().any(|rule| value.contains(rule)),
            StringOp::Regexp(rules) => rules.iter().any(|rule| rule.is_match(value)),
            StringOp::ZeroLength => value.is_empty(),
        }
    }
}

fn parse_string_expression(raw: &str) -> DnsResult<StringExpression> {
    let tokens: Vec<&str> = raw
        .split_ascii_whitespace()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if tokens.is_empty() {
        return Err(DnsError::plugin("string_exp requires non-empty expression"));
    }

    let (source_raw, op_raw, arg_start) =
        if let Some((src, op)) = split_compact_source_op(tokens[0]) {
            (src.to_string(), op.to_string(), 1usize)
        } else {
            if tokens.len() < 2 {
                return Err(DnsError::plugin(
                    "string_exp expression requires source and operation",
                ));
            }
            (tokens[0].to_string(), tokens[1].to_string(), 2usize)
        };

    let source = parse_source(&source_raw)?;
    let args = tokens[arg_start..]
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>();
    let op = parse_operation(&op_raw, args)?;

    Ok(StringExpression { source, op })
}

fn split_compact_source_op(raw: &str) -> Option<(&str, &str)> {
    const OPS: [&str; 6] = ["contains", "prefix", "suffix", "regexp", "eq", "zl"];

    for op in OPS {
        if raw.len() > op.len() && raw.ends_with(op) {
            return Some((&raw[..raw.len() - op.len()], op));
        }
    }
    None
}

fn parse_source(raw: &str) -> DnsResult<StringSource> {
    if let Some(env) = raw.strip_prefix('$') {
        if env.is_empty() {
            return Err(DnsError::plugin("string_exp env source cannot be empty"));
        }
        return Ok(StringSource::Env(env.to_string()));
    }

    match raw {
        "qname" => Ok(StringSource::Qname),
        "qtype" => Ok(StringSource::Qtype),
        "qclass" => Ok(StringSource::Qclass),
        "rcode" => Ok(StringSource::Rcode),
        "resp_ip" => Ok(StringSource::RespIp),
        "mark" => Ok(StringSource::Mark),
        "client_ip" => Ok(StringSource::ClientIp),
        "listener" => Ok(StringSource::Listener),
        "server_name" => Ok(StringSource::ServerName),
        "url_path" => Ok(StringSource::UrlPath),
        _ => Err(DnsError::plugin(format!(
            "unsupported string_exp source '{}'",
            raw
        ))),
    }
}

fn parse_operation(raw: &str, args: Vec<String>) -> DnsResult<StringOp> {
    match raw {
        "eq" => build_rules_op(args, StringOp::Eq, "eq"),
        "prefix" => build_rules_op(args, StringOp::Prefix, "prefix"),
        "suffix" => build_rules_op(args, StringOp::Suffix, "suffix"),
        "contains" => build_rules_op(args, StringOp::Contains, "contains"),
        "regexp" => {
            if args.is_empty() {
                return Err(DnsError::plugin(
                    "string_exp regexp requires at least one rule",
                ));
            }
            let mut rules = Vec::with_capacity(args.len());
            for raw in args {
                let regex = Regex::new(&raw).map_err(|e| {
                    DnsError::plugin(format!("invalid string_exp regexp '{}': {}", raw, e))
                })?;
                rules.push(regex);
            }
            Ok(StringOp::Regexp(rules))
        }
        "zl" => {
            if !args.is_empty() {
                return Err(DnsError::plugin("string_exp zl does not accept rule args"));
            }
            Ok(StringOp::ZeroLength)
        }
        _ => Err(DnsError::plugin(format!(
            "unsupported string_exp operation '{}'",
            raw
        ))),
    }
}

fn build_rules_op<F>(args: Vec<String>, build: F, op: &str) -> DnsResult<StringOp>
where
    F: FnOnce(Vec<String>) -> StringOp,
{
    if args.is_empty() {
        return Err(DnsError::plugin(format!(
            "string_exp {} requires at least one rule",
            op
        )));
    }
    Ok(build(args))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{DnsContext, ExecFlowState};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::collections::HashMap;
    use std::net::SocketAddr;

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_query(Query::query(
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
        ));

        DnsContext {
            src_addr: SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: ["1".to_string()].into_iter().collect(),
            attributes: HashMap::new(),
            registry: Arc::new(PluginRegistry::new()),
        }
    }

    #[tokio::test]
    async fn test_string_exp_eq_qname() {
        let matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("qname eq www.example.com").unwrap(),
        };
        let mut ctx = make_context();
        assert!(matcher.is_match(&mut ctx).await);
    }

    #[tokio::test]
    async fn test_string_exp_compact_syntax() {
        let matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("markcontains 1").unwrap(),
        };
        let mut ctx = make_context();
        assert!(matcher.is_match(&mut ctx).await);
    }
}
