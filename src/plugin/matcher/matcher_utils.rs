/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared helpers for matcher plugins.

use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::{DomainRuleMatcher, IpPrefixMatcher};
use crate::message::{DNSClass, Rcode, RecordType};
use crate::plugin::PluginRegistry;
use crate::plugin::provider::Provider;
use ahash::AHashSet;
use serde_yml::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use std::sync::Arc;

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

pub(crate) fn parse_rr_type(raw: &str) -> Option<u16> {
    RecordType::from_str(&raw.to_ascii_uppercase())
        .ok()
        .map(u16::from)
}

pub(crate) fn parse_class(raw: &str) -> Option<u16> {
    DNSClass::from_str(&raw.to_ascii_uppercase())
        .ok()
        .map(u16::from)
}

/// Parse rcode matcher input.
///
/// Current config only accepts decimal numeric rcodes. Mnemonic tokens such as
/// `NOERROR` or `SERVFAIL` are intentionally not mapped here.
pub(crate) fn parse_rcode(raw: &str) -> Option<u16> {
    if let Ok(code) = raw.parse::<u16>() {
        return Some(u16::from(Rcode::from(code)));
    }
    None
}

pub(crate) fn parse_ip_prefix_matcher(
    field: &str,
    raw_rules: &[String],
) -> DnsResult<IpPrefixMatcher> {
    let mut matcher = IpPrefixMatcher::default();
    for raw in raw_rules {
        let v = raw.trim();
        if v.is_empty() {
            continue;
        }
        matcher
            .add_rule(v)
            .map_err(|e| DnsError::plugin(format!("invalid {} rule '{}': {}", field, v, e)))?;
    }
    matcher.finalize();
    Ok(matcher)
}

pub(crate) fn parse_domain_rules_and_set_tags(
    raw_rules: Vec<String>,
    field: &str,
) -> DnsResult<(DomainRuleMatcher, Vec<String>)> {
    // Rule source grammar:
    // - plain token => inline rule
    // - '$tag'      => provider tag
    // - '&path'     => external rule file
    let (mut inline_rules, set_tags, files) = split_rule_sources(raw_rules);
    let file_rules = load_rules_from_files(&files, field)?;
    inline_rules.extend(file_rules);

    let mut domain_rules = DomainRuleMatcher::default();
    for (idx, rule) in inline_rules.into_iter().enumerate() {
        let source = format!("{} rule[{}]", field, idx);
        domain_rules
            .add_expression(&rule, &source)
            .map_err(DnsError::plugin)?;
    }
    domain_rules.finalize().map_err(DnsError::plugin)?;
    Ok((domain_rules, set_tags))
}

pub(crate) fn validate_non_empty_domain_rules_or_set_tags(
    field: &str,
    domain_rules: &DomainRuleMatcher,
    set_tags: &[String],
    set_name: &str,
) -> DnsResult<()> {
    if !domain_rules.has_rules() && set_tags.is_empty() {
        return Err(DnsError::plugin(format!(
            "{} matcher requires at least one domain rule or {} tag",
            field, set_name
        )));
    }
    Ok(())
}

pub(crate) fn parse_ip_rules_and_set_tags(
    raw_rules: Vec<String>,
    field: &str,
) -> DnsResult<(IpPrefixMatcher, Vec<String>)> {
    // Keep the same source grammar as domain rules so matcher configs stay uniform.
    let (mut inline_rules, set_tags, files) = split_rule_sources(raw_rules);
    let file_rules = load_rules_from_files(&files, field)?;
    inline_rules.extend(file_rules);
    let ip_rules = parse_ip_prefix_matcher(field, &inline_rules)?;
    Ok((ip_rules, set_tags))
}

pub(crate) fn validate_non_empty_ip_rules_or_set_tags(
    field: &str,
    ip_rules: &IpPrefixMatcher,
    set_tags: &[String],
    set_name: &str,
) -> DnsResult<()> {
    if !ip_rules.has_v4_rules() && !ip_rules.has_v6_rules() && set_tags.is_empty() {
        return Err(DnsError::plugin(format!(
            "{} matcher requires at least one IP rule or {} tag",
            field, set_name
        )));
    }
    Ok(())
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

pub(crate) fn validate_non_empty_rules(field: &str, rules: &[String]) -> DnsResult<()> {
    if rules.is_empty() {
        return Err(DnsError::plugin(format!(
            "{} matcher requires at least one rule",
            field
        )));
    }
    Ok(())
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
        // '$' and '&' are reserved prefixes for provider/file sources; all other
        // tokens are treated as inline rules and parsed by concrete matcher logic.
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
) -> DnsResult<Vec<Arc<dyn Provider>>> {
    let mut providers = Vec::with_capacity(tags.len());
    for (idx, tag) in tags.iter().enumerate() {
        let field = format!("{}.provider_tags[{}]", matcher_name, idx);
        let provider = registry.get_provider_dependency(matcher_tag, &field, tag)?;
        providers.push(provider);
    }
    Ok(providers)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_quick_setup_rules_validation() {
        assert!(parse_quick_setup_rules(None).is_err());
        assert!(parse_quick_setup_rules(Some("   ".to_string())).is_err());
        let rules =
            parse_quick_setup_rules(Some("a, b c".to_string())).expect("rules should parse");
        assert_eq!(rules, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_split_rule_sources_classification() {
        let (inline, tags, files) = split_rule_sources(vec![
            "a.com".to_string(),
            "$set_a".to_string(),
            "&/tmp/rules.txt".to_string(),
            "  ".to_string(),
        ]);

        assert_eq!(inline, vec!["a.com"]);
        assert_eq!(tags, vec!["set_a"]);
        assert_eq!(files, vec!["/tmp/rules.txt"]);
    }
}
