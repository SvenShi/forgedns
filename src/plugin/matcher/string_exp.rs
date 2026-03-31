/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `string_exp` matcher plugin.
//!
//! String expression matcher for context-derived values.
//!
//! Expression format:
//! - `<source> <op> <arg...>` (or compact `<source><op> <arg...>`).
//! - sources include `qname`, `qtype`, `rcode`, `resp_ip`, `mark`,
//!   `client_ip`, `server_name`, `url_path`, and `$ENV_KEY`.
//! - operations include `eq`, `prefix`, `suffix`, `contains`, `regexp`, `zl`.
//!
//! This matcher is designed for flexible policy composition when dedicated
//! typed matchers are not enough.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use regex::Regex;
use serde_yaml_ng::Value;
use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Write as _;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct StringExpFactory {}

register_plugin_factory!("string_exp", StringExpFactory {});

impl PluginFactory for StringExpFactory {
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
            env_cache: None,
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
            env_cache: None,
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
    env_cache: Option<String>,
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

    async fn init(&mut self) -> DnsResult<()> {
        if let StringSource::Env(key) = &self.expression.source {
            self.env_cache = std::env::var(key).ok();
        }
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for StringExpMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        let value: Cow<'_, str> = match &self.expression.source {
            StringSource::Env(_) => Cow::Borrowed(self.env_cache.as_deref().unwrap_or("")),
            source => source.read(context),
        };
        self.expression.op.evaluate(value.as_ref())
    }
}

impl StringSource {
    fn read<'a>(&self, context: &'a mut DnsContext) -> Cow<'a, str> {
        match self {
            StringSource::Qname => context
                .request
                .first_question()
                .map(|question| Cow::Borrowed(question.name().normalized()))
                .unwrap_or_else(|| Cow::Borrowed("")),
            StringSource::Qtype => Cow::Owned(
                context
                    .request
                    .first_qtype()
                    .map(|qtype| u16::from(qtype).to_string())
                    .unwrap_or_default(),
            ),
            StringSource::Qclass => Cow::Owned(
                context
                    .request
                    .first_qclass()
                    .map(|qclass| u16::from(qclass).to_string())
                    .unwrap_or_default(),
            ),
            StringSource::Rcode => Cow::Owned(
                context
                    .response()
                    .map(|response| response.rcode())
                    .map(|rcode| rcode.value().to_string())
                    .unwrap_or_default(),
            ),
            StringSource::RespIp => {
                let mut out = String::new();
                if let Some(response) = context.response() {
                    for ip in response.answer_ips() {
                        if !out.is_empty() {
                            out.push(',');
                        }
                        // Writing directly avoids temporary Vec allocations.
                        let _ = write!(&mut out, "{}", ip);
                    }
                }
                Cow::Owned(out)
            }
            StringSource::Mark => {
                let mut out = String::new();
                for mark in context.marks() {
                    if !out.is_empty() {
                        out.push(',');
                    }
                    out.push_str(mark);
                }
                Cow::Owned(out)
            }
            StringSource::ClientIp => Cow::Owned(context.peer_addr().ip().to_string()),
            StringSource::ServerName => context
                .server_name()
                .map(Cow::Borrowed)
                .unwrap_or_else(|| Cow::Borrowed("")),
            StringSource::UrlPath => context
                .url_path()
                .map(Cow::Borrowed)
                .unwrap_or_else(|| Cow::Borrowed("")),
            StringSource::Env(_) => Cow::Borrowed(""),
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
    use crate::core::context::DnsContext;
    use crate::plugin::matcher::Matcher;
    use crate::proto::rdata::A;
    use crate::proto::{Message, Question, Rcode};
    use crate::proto::{Name, RData, Record, RecordType};
    use std::net::{Ipv4Addr, SocketAddr};

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
            crate::proto::DNSClass::IN,
        ));
        let mut context = DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            Arc::new(PluginRegistry::new()),
        );
        context.marks_mut().insert("1".to_string());
        context
    }

    fn add_response_with_ip_and_rcode(ctx: &mut DnsContext, ip: Ipv4Addr, rcode: Rcode) {
        let mut response = Message::new();
        response.set_rcode(rcode);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("www.example.com.").unwrap(),
            60,
            RData::A(A(ip)),
        ));
        ctx.set_response(response);
    }

    #[tokio::test]
    async fn test_string_exp_eq_qname() {
        let matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("qname eq www.example.com").unwrap(),
            env_cache: None,
        };
        let mut ctx = make_context();
        assert!(matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_string_exp_compact_syntax() {
        let matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("markcontains 1").unwrap(),
            env_cache: None,
        };
        let mut ctx = make_context();
        assert!(matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_string_exp_supports_multiple_sources_and_operations() {
        let mut ctx = make_context();
        ctx.set_request_meta(crate::core::context::RequestMeta {
            server_name: Some(Arc::from("dns.example.com")),
            url_path: Some(Arc::from("/dns-query")),
        });
        add_response_with_ip_and_rcode(&mut ctx, Ipv4Addr::new(8, 8, 8, 8), Rcode::NoError);

        let qtype_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("qtype eq 1").unwrap(),
            env_cache: None,
        };
        assert!(qtype_matcher.is_match(&mut ctx));

        let qclass_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("qclass eq 1").unwrap(),
            env_cache: None,
        };
        assert!(qclass_matcher.is_match(&mut ctx));

        let client_ip_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("client_ip prefix 127.0.0.").unwrap(),
            env_cache: None,
        };
        assert!(client_ip_matcher.is_match(&mut ctx));

        let rcode_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("rcode eq 0").unwrap(),
            env_cache: None,
        };
        assert!(rcode_matcher.is_match(&mut ctx));

        let resp_ip_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("resp_ip contains 8.8.8").unwrap(),
            env_cache: None,
        };
        assert!(resp_ip_matcher.is_match(&mut ctx));

        let server_name_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("server_name suffix example.com").unwrap(),
            env_cache: None,
        };
        assert!(server_name_matcher.is_match(&mut ctx));

        let url_path_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("url_path prefix /dns").unwrap(),
            env_cache: None,
        };
        assert!(url_path_matcher.is_match(&mut ctx));

        let mark_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("mark contains 1").unwrap(),
            env_cache: None,
        };
        assert!(mark_matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_string_exp_supports_zl_and_env_cache() {
        let mut ctx = make_context();

        let zl_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("url_path zl").unwrap(),
            env_cache: None,
        };
        assert!(zl_matcher.is_match(&mut ctx));

        let env_matcher = StringExpMatcher {
            tag: "string_exp".into(),
            expression: parse_string_expression("$UNIT_TEST_ENV eq expected").unwrap(),
            env_cache: Some("expected".to_string()),
        };
        assert!(env_matcher.is_match(&mut ctx));
    }

    #[test]
    fn test_parse_string_expression_validation_errors() {
        assert!(parse_string_expression("").is_err());
        assert!(parse_string_expression("qname").is_err());
        assert!(parse_string_expression("unsupported eq v").is_err());
        assert!(parse_string_expression("qname unsupported value").is_err());
        assert!(parse_string_expression("qname regexp (").is_err());
        assert!(parse_string_expression("qname zl not_allowed").is_err());
    }
}
