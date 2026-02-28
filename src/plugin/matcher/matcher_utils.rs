/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared helpers for matcher plugins.

use crate::core::dns_utils::parse_named_response_code;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::provider::Provider;
use crate::plugin::{PluginRegistry, PluginType};
use ahash::AHashSet;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use serde_yml::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct IpRule {
    network: ipnet::IpNet,
}

impl IpRule {
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        self.network.contains(&ip)
    }
}

pub(crate) fn parse_rules_from_value(args: Option<Value>) -> DnsResult<Vec<String>> {
    let args = args.ok_or_else(|| DnsError::plugin("matcher requires args"))?;
    parse_rule_list_value(args)
}

pub(crate) fn parse_u16_rules(
    field: &str,
    raw_rules: &[String],
    named_parser: fn(&str) -> Option<u16>,
) -> DnsResult<AHashSet<u16>> {
    let mut parsed = AHashSet::with_capacity(raw_rules.len());
    for raw in raw_rules {
        let v = raw.trim();
        if v.is_empty() {
            continue;
        }
        let num = if let Ok(num) = v.parse::<u16>() {
            num
        } else {
            named_parser(v).ok_or_else(|| {
                DnsError::plugin(format!(
                    "invalid {} value '{}': unsupported token",
                    field, v
                ))
            })?
        };
        parsed.insert(num);
    }
    Ok(parsed)
}

pub(crate) fn parse_record_type(raw: &str) -> Option<u16> {
    RecordType::from_str(&raw.to_ascii_uppercase())
        .ok()
        .map(u16::from)
}

pub(crate) fn parse_dns_class(raw: &str) -> Option<u16> {
    DNSClass::from_str(&raw.to_ascii_uppercase())
        .ok()
        .map(u16::from)
}

pub(crate) fn parse_rcode(raw: &str) -> Option<u16> {
    parse_named_response_code(raw).map(u16::from)
}

pub(crate) fn parse_ip_rules(field: &str, raw_rules: &[String]) -> DnsResult<Vec<IpRule>> {
    let mut rules = Vec::with_capacity(raw_rules.len());
    for raw in raw_rules {
        let v = raw.trim();
        if v.is_empty() {
            continue;
        }
        let network = if v.contains('/') {
            ipnet::IpNet::from_str(v)
        } else if let Ok(ip) = IpAddr::from_str(v) {
            Ok(ipnet::IpNet::from(ip))
        } else {
            ipnet::IpNet::from_str(v)
        }
        .map_err(|e| DnsError::plugin(format!("invalid {} rule '{}': {}", field, v, e)))?;
        rules.push(IpRule { network });
    }
    Ok(rules)
}

pub(crate) fn parse_quick_setup_rules(param: Option<String>) -> DnsResult<Vec<String>> {
    let raw = param.ok_or_else(|| DnsError::plugin("quick setup requires matcher parameter"))?;
    let rules = split_rule_tokens(&raw);
    if rules.is_empty() {
        return Err(DnsError::plugin(
            "quick setup requires non-empty matcher parameter",
        ));
    }
    Ok(rules)
}

pub(crate) fn normalize_domain_rules(rules: Vec<String>) -> Vec<String> {
    rules
        .into_iter()
        .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

pub(crate) fn validate_non_empty_rules(field: &str, rules: &[String]) -> DnsResult<()> {
    if rules.is_empty() {
        return Err(DnsError::plugin(format!(
            "{} matcher requires at least one rule",
            field
        )));
    }
    Ok(())
}

pub(crate) fn normalize_name(name: &Name) -> String {
    name.to_utf8().trim_end_matches('.').to_ascii_lowercase()
}

pub(crate) fn domain_match(rule: &str, query_name: &str) -> bool {
    query_name == rule
        || query_name
            .strip_suffix(rule)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

pub(crate) fn split_rule_sources(
    raw_rules: Vec<String>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut inline_rules = Vec::new();
    let mut set_tags = Vec::new();
    let mut files = Vec::new();

    for raw in raw_rules {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        if let Some(tag) = token.strip_prefix('$') {
            if !tag.trim().is_empty() {
                set_tags.push(tag.trim().to_string());
            }
        } else if let Some(path) = token.strip_prefix('&') {
            if !path.trim().is_empty() {
                files.push(path.trim().to_string());
            }
        } else {
            inline_rules.push(token.to_string());
        }
    }

    (inline_rules, set_tags, files)
}

pub(crate) fn load_rules_from_files(files: &[String], field: &str) -> DnsResult<Vec<String>> {
    let mut rules = Vec::new();
    for path in files {
        if path.trim().is_empty() {
            continue;
        }
        let file = File::open(path).map_err(|e| {
            DnsError::plugin(format!("failed to open {} file '{}': {}", field, path, e))
        })?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut line_no = 0usize;
        loop {
            line.clear();
            let n = reader.read_line(&mut line).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to read {} file '{}' at line {}: {}",
                    field,
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
            rules.extend(split_rule_tokens(raw));
        }
    }
    Ok(rules)
}

pub(crate) fn resolve_provider_tags(
    registry: &PluginRegistry,
    tags: &[String],
    matcher_name: &str,
    matcher_tag: &str,
) -> Vec<Arc<dyn Provider>> {
    let mut providers = Vec::with_capacity(tags.len());
    for tag in tags {
        let Some(plugin) = registry.get_plugin(tag) else {
            panic!(
                "{} matcher '{}' depends on missing provider '{}'",
                matcher_name, matcher_tag, tag
            );
        };
        if !matches!(plugin.plugin_type, PluginType::Provider) {
            panic!(
                "{} matcher '{}' dependency '{}' is not provider",
                matcher_name, matcher_tag, tag
            );
        }
        providers.push(plugin.to_provider());
    }
    providers
}

fn parse_rule_list_value(value: Value) -> DnsResult<Vec<String>> {
    match value {
        Value::String(s) => Ok(split_rule_tokens(&s)),
        Value::Sequence(seq) => {
            let mut out = Vec::with_capacity(seq.len());
            for item in seq {
                match item {
                    Value::String(s) => out.extend(split_rule_tokens(&s)),
                    other => {
                        return Err(DnsError::plugin(format!(
                            "matcher args must be string list, got {:?}",
                            other
                        )));
                    }
                }
            }
            Ok(out)
        }
        other => Err(DnsError::plugin(format!(
            "matcher args must be string or string array, got {:?}",
            other
        ))),
    }
}

fn split_rule_tokens(raw: &str) -> Vec<String> {
    raw.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}
