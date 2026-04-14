/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared request-context templating utilities for executor plugins.
//!
//! These templates intentionally expose only a stable built-in key set so
//! plugin behavior remains predictable and safe to validate during startup.

use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use serde_json::{Number as JsonNumber, Value as JsonValue};

pub(crate) const BUILTIN_KEYS: &[&str] = &[
    "qname",
    "qtype",
    "qtype_name",
    "qclass",
    "qclass_name",
    "client_ip",
    "client_port",
    "server_name",
    "url_path",
    "marks",
    "has_resp",
    "rcode",
    "rcode_name",
    "resp_ip",
    "cron_plugin_tag",
    "cron_job_name",
    "cron_trigger_kind",
    "cron_scheduled_at_unix_ms",
];

const CRON_ATTR_PLUGIN_TAG: &str = "cron.plugin_tag";
const CRON_ATTR_JOB_NAME: &str = "cron.job_name";
const CRON_ATTR_TRIGGER_KIND: &str = "cron.trigger_kind";
const CRON_ATTR_SCHEDULED_AT_UNIX_MS: &str = "cron.scheduled_at_unix_ms";

#[derive(Debug, Clone)]
pub(crate) struct Template {
    segments: Vec<TemplateSegment>,
}

#[derive(Debug, Clone)]
enum TemplateSegment {
    Literal(String),
    Builtin(&'static str),
}

#[derive(Debug, Clone)]
pub(crate) enum JsonTemplateValue {
    Null,
    Bool(bool),
    Number(JsonNumber),
    String(Template),
    Array(Vec<JsonTemplateValue>),
    Object(Vec<(String, JsonTemplateValue)>),
}

impl Template {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let mut segments = Vec::new();
        let mut literal = String::new();
        let mut chars = raw.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch != '$' {
                literal.push(ch);
                continue;
            }

            match chars.peek().copied() {
                Some('$') => {
                    chars.next();
                    literal.push('$');
                }
                Some('{') => {
                    chars.next();
                    if !literal.is_empty() {
                        segments.push(TemplateSegment::Literal(std::mem::take(&mut literal)));
                    }

                    let mut key = String::new();
                    let mut closed = false;
                    for ch in chars.by_ref() {
                        if ch == '}' {
                            closed = true;
                            break;
                        }
                        key.push(ch);
                    }

                    if !closed {
                        return Err(DnsError::plugin(format!(
                            "invalid template '{}': missing closing '}}'",
                            raw
                        )));
                    }

                    let builtin = validate_builtin_key(key.trim(), raw)?;
                    segments.push(TemplateSegment::Builtin(builtin));
                }
                _ => literal.push('$'),
            }
        }

        if !literal.is_empty() {
            segments.push(TemplateSegment::Literal(literal));
        }

        Ok(Self { segments })
    }

    pub(crate) fn render(&self, context: &DnsContext) -> String {
        let mut out = String::new();
        for segment in &self.segments {
            match segment {
                TemplateSegment::Literal(value) => out.push_str(value),
                TemplateSegment::Builtin(key) => {
                    out.push_str(resolve_builtin(context, key).as_str())
                }
            }
        }
        out
    }
}

impl JsonTemplateValue {
    pub(crate) fn compile(value: JsonValue) -> Result<Self> {
        match value {
            JsonValue::Null => Ok(Self::Null),
            JsonValue::Bool(value) => Ok(Self::Bool(value)),
            JsonValue::Number(value) => Ok(Self::Number(value)),
            JsonValue::String(value) => Template::parse(value.as_str()).map(Self::String),
            JsonValue::Array(values) => values
                .into_iter()
                .map(Self::compile)
                .collect::<Result<Vec<_>>>()
                .map(Self::Array),
            JsonValue::Object(values) => values
                .into_iter()
                .map(|(key, value)| Self::compile(value).map(|value| (key, value)))
                .collect::<Result<Vec<_>>>()
                .map(Self::Object),
        }
    }

    pub(crate) fn render(&self, context: &DnsContext) -> JsonValue {
        match self {
            Self::Null => JsonValue::Null,
            Self::Bool(value) => JsonValue::Bool(*value),
            Self::Number(value) => JsonValue::Number(value.clone()),
            Self::String(value) => JsonValue::String(value.render(context)),
            Self::Array(values) => {
                JsonValue::Array(values.iter().map(|value| value.render(context)).collect())
            }
            Self::Object(values) => JsonValue::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), value.render(context)))
                    .collect(),
            ),
        }
    }
}

fn validate_builtin_key(key: &str, raw: &str) -> Result<&'static str> {
    if key.is_empty() {
        return Err(DnsError::plugin(format!(
            "invalid template '{}': placeholder key cannot be empty",
            raw
        )));
    }

    BUILTIN_KEYS
        .iter()
        .copied()
        .find(|candidate| *candidate == key)
        .ok_or_else(|| {
            DnsError::plugin(format!(
                "invalid template '{}': unsupported placeholder '{}'",
                raw, key
            ))
        })
}

pub(crate) fn resolve_builtin(context: &DnsContext, key: &str) -> String {
    match key {
        "qname" => context
            .request()
            .first_question()
            .map(|question| question.name().normalized().to_string())
            .unwrap_or_default(),
        "qtype" => context
            .request()
            .first_qtype()
            .map(|qtype| u16::from(qtype).to_string())
            .unwrap_or_default(),
        "qtype_name" => context
            .request()
            .first_qtype()
            .map(|qtype| format!("{:?}", qtype))
            .unwrap_or_default(),
        "qclass" => context
            .request()
            .first_qclass()
            .map(|qclass| u16::from(qclass).to_string())
            .unwrap_or_default(),
        "qclass_name" => context
            .request()
            .first_qclass()
            .map(|qclass| format!("{:?}", qclass))
            .unwrap_or_default(),
        "client_ip" => context.peer_addr().ip().to_string(),
        "client_port" => context.peer_addr().port().to_string(),
        "server_name" => context.server_name().unwrap_or_default().to_string(),
        "url_path" => context.url_path().unwrap_or_default().to_string(),
        "marks" => {
            let mut marks = context
                .marks()
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>();
            marks.sort_unstable();
            marks.join(",")
        }
        "has_resp" => context.response().is_some().to_string(),
        "rcode" => context
            .response()
            .map(|response| response.rcode().value().to_string())
            .unwrap_or_default(),
        "rcode_name" => context
            .response()
            .map(|response| format!("{:?}", response.rcode()))
            .unwrap_or_default(),
        "resp_ip" => {
            let mut ips = context
                .response()
                .map(|response| {
                    response
                        .answer_ips()
                        .into_iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            ips.sort_unstable();
            ips.join(",")
        }
        "cron_plugin_tag" => context
            .get_attr::<String>(CRON_ATTR_PLUGIN_TAG)
            .cloned()
            .unwrap_or_default(),
        "cron_job_name" => context
            .get_attr::<String>(CRON_ATTR_JOB_NAME)
            .cloned()
            .unwrap_or_default(),
        "cron_trigger_kind" => context
            .get_attr::<String>(CRON_ATTR_TRIGGER_KIND)
            .cloned()
            .unwrap_or_default(),
        "cron_scheduled_at_unix_ms" => context
            .get_attr::<i64>(CRON_ATTR_SCHEDULED_AT_UNIX_MS)
            .map(i64::to_string)
            .unwrap_or_default(),
        _ => String::new(),
    }
}
