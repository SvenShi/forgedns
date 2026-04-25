// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::str::FromStr;

use regex::RegexBuilder;
use serde_yaml_ng::Value;
use tracing::warn;

use super::model::{AdGuardRuleConfig, DnsTypeConstraint, ParsedRule, PatternMatcher, RuleInput};
use crate::core::error::{DnsError, Result as DnsResult};
use crate::proto::RecordType;

pub(super) fn parse_config(args: Option<Value>) -> DnsResult<AdGuardRuleConfig> {
    let Some(args) = args else {
        return Ok(AdGuardRuleConfig::default());
    };

    serde_yaml_ng::from_value(args)
        .map_err(|e| DnsError::plugin(format!("failed to parse adguard_rule config: {}", e)))
}

pub(super) fn load_rule_inputs(cfg: &AdGuardRuleConfig) -> DnsResult<Vec<RuleInput>> {
    let mut out = Vec::new();

    for (idx, raw) in cfg.rules.iter().enumerate() {
        out.push(RuleInput {
            raw: raw.clone(),
            source: format!("args.rules[{}]", idx),
        });
    }

    for path in &cfg.files {
        if path.trim().is_empty() {
            continue;
        }

        let file = File::open(path).map_err(|e| {
            DnsError::plugin(format!(
                "failed to open adguard_rule file '{}': {}",
                path, e
            ))
        })?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut line_no = 0usize;

        loop {
            line.clear();
            let n = reader.read_line(&mut line).map_err(|e| {
                DnsError::plugin(format!(
                    "failed to read adguard_rule file '{}' at line {}: {}",
                    path,
                    line_no + 1,
                    e
                ))
            })?;
            if n == 0 {
                break;
            }
            line_no += 1;

            out.push(RuleInput {
                raw: line.trim().to_string(),
                source: format!("file '{}', line {}", path, line_no),
            });
        }
    }

    Ok(out)
}

pub(super) fn parse_rule(input: &RuleInput) -> Result<Option<ParsedRule>, String> {
    let raw = input.raw.trim();
    if raw.is_empty() || raw.starts_with('!') || raw.starts_with('#') {
        return Ok(None);
    }

    if is_hosts_style_rule(raw) {
        warn!(
            source = %input.source,
            rule = raw,
            "adguard_rule does not support /etc/hosts style rules yet; skipping"
        );
        return Ok(None);
    }

    if is_non_dns_rule(raw) {
        warn!(
            source = %input.source,
            rule = raw,
            "adguard_rule skipped unsupported non-DNS rule"
        );
        return Ok(None);
    }

    let mut body = raw;
    let is_exception = if let Some(rest) = body.strip_prefix("@@") {
        body = rest.trim();
        true
    } else {
        false
    };

    let (pattern_raw, modifiers_raw) = split_pattern_and_modifiers(body)?;
    let pattern_raw = pattern_raw.trim();
    if pattern_raw.is_empty() {
        return Err("empty rule pattern".to_string());
    }

    let expression = compile_domain_rule_expression(pattern_raw)?;
    let matcher = compile_pattern(pattern_raw)?;
    let matcher_key = canonical_pattern_key(pattern_raw);
    let mut important = false;
    let mut badfilter = false;
    let mut denyallow = Vec::new();
    let mut dnstype = None;

    if let Some(modifiers_raw) = modifiers_raw {
        let modifiers = modifiers_raw
            .split(',')
            .map(str::trim)
            .filter(|modifier| !modifier.is_empty())
            .collect::<Vec<_>>();

        for modifier in modifiers {
            let (name, value) = modifier
                .split_once('=')
                .map(|(left, right)| (left.trim(), Some(right.trim())))
                .unwrap_or((modifier, None));
            let name = name.to_ascii_lowercase();

            match name.as_str() {
                "important" => important = true,
                "badfilter" => badfilter = true,
                "denyallow" => {
                    let Some(value) = value else {
                        return Err("denyallow modifier requires a value".to_string());
                    };
                    denyallow = parse_denyallow(value)?;
                }
                "dnstype" => {
                    let Some(value) = value else {
                        return Err("dnstype modifier requires a value".to_string());
                    };
                    dnstype = Some(parse_dnstype(value)?);
                }
                "dnsrewrite" | "client" | "ctag" => {
                    warn!(
                        source = %input.source,
                        rule = raw,
                        modifier = %name,
                        "adguard_rule skipped unsupported modifier"
                    );
                    return Ok(None);
                }
                _ => {
                    warn!(
                        source = %input.source,
                        rule = raw,
                        modifier = %name,
                        "adguard_rule skipped rule with unknown modifier"
                    );
                    return Ok(None);
                }
            }
        }
    }

    Ok(Some(ParsedRule {
        source: input.source.clone(),
        expression,
        matcher,
        matcher_key,
        is_exception,
        important,
        badfilter,
        dnstype,
        denyallow,
    }))
}

pub(super) fn split_pattern_and_modifiers(raw: &str) -> Result<(&str, Option<&str>), String> {
    if let Some(rest) = raw.strip_prefix('/') {
        let Some(regex_end) = rest.rfind('/') else {
            return Err("unterminated regex rule".to_string());
        };
        let regex_end = regex_end + 1;
        let pattern = &raw[..=regex_end];
        let tail = raw[regex_end + 1..].trim();
        if tail.is_empty() {
            return Ok((pattern, None));
        }
        if let Some(modifiers) = tail.strip_prefix('$') {
            return Ok((pattern, Some(modifiers)));
        }
        return Err("unexpected trailing content after regex rule".to_string());
    }

    Ok(match raw.split_once('$') {
        Some((pattern, modifiers)) => (pattern, Some(modifiers)),
        None => (raw, None),
    })
}

pub(super) fn compile_pattern(raw: &str) -> Result<PatternMatcher, String> {
    if raw.starts_with('/') {
        return compile_regex_pattern(raw);
    }

    let normalized = normalize_domain(raw);
    if normalized.is_empty() {
        return Err("empty domain pattern".to_string());
    }

    if let Some(domain) = normalized
        .strip_prefix("||")
        .and_then(|v| v.strip_suffix('^'))
        && is_simple_hostname(domain)
    {
        return Ok(PatternMatcher::Domain(domain.to_string().into_boxed_str()));
    }

    if !normalized.contains('*') && !normalized.contains('^') && !normalized.contains('|') {
        return Ok(PatternMatcher::Exact(normalized.into_boxed_str()));
    }

    if let Some(prefix) = normalized.strip_prefix('|')
        && !prefix.contains('*')
        && !prefix.contains('^')
        && !prefix.contains('|')
    {
        return Ok(PatternMatcher::Prefix(prefix.to_string().into_boxed_str()));
    }

    if let Some(suffix) = normalized.strip_suffix('|')
        && !suffix.contains('*')
        && !suffix.contains('^')
        && !suffix.contains('|')
    {
        return Ok(PatternMatcher::Suffix(suffix.to_string().into_boxed_str()));
    }

    let regex = translate_pattern_to_regex(&normalized)?;
    let regex = RegexBuilder::new(&regex)
        .case_insensitive(false)
        .build()
        .map_err(|e| format!("failed to build adguard mask '{}': {}", raw, e))?;
    Ok(PatternMatcher::Regex(regex))
}

pub(super) fn compile_domain_rule_expression(raw: &str) -> Result<String, String> {
    if raw.starts_with('/') {
        let body = raw
            .strip_prefix('/')
            .and_then(|v| v.strip_suffix('/'))
            .ok_or_else(|| "unterminated regex rule".to_string())?;
        if body.trim().is_empty() {
            return Err("empty regex rule".to_string());
        }
        return Ok(format!("regexp:{}", body));
    }

    let normalized = normalize_domain(raw);
    if normalized.is_empty() {
        return Err("empty domain pattern".to_string());
    }

    if let Some(domain) = normalized
        .strip_prefix("||")
        .and_then(|v| v.strip_suffix('^'))
        && is_simple_hostname(domain)
    {
        return Ok(format!("domain:{}", domain));
    }

    if !normalized.contains('*') && !normalized.contains('^') && !normalized.contains('|') {
        return Ok(format!("full:{}", normalized));
    }

    let regex = translate_pattern_to_regex(&normalized)?;
    Ok(format!("regexp:{}", regex))
}

pub(super) fn parse_denyallow(raw: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for domain in raw.split('|').map(str::trim).filter(|v| !v.is_empty()) {
        let normalized = normalize_domain(domain);
        if !is_simple_hostname(&normalized) {
            return Err(format!("invalid denyallow domain '{}'", domain));
        }
        out.push(normalized);
    }
    Ok(out)
}

pub(super) fn parse_dnstype(raw: &str) -> Result<DnsTypeConstraint, String> {
    let mut include = Vec::new();
    let mut exclude = Vec::new();

    for token in raw.split('|').map(str::trim).filter(|v| !v.is_empty()) {
        let (negated, rr_type_raw) = token
            .strip_prefix('~')
            .map(|rest| (true, rest))
            .unwrap_or((false, token));
        let rr_type = RecordType::from_str(&rr_type_raw.to_ascii_uppercase())
            .map_err(|_| format!("invalid dnstype value '{}'", rr_type_raw))?;
        if negated {
            exclude.push(rr_type);
        } else {
            include.push(rr_type);
        }
    }

    if !include.is_empty() {
        include.sort_unstable_by_key(|item| u16::from(*item));
        include.dedup();
        return Ok(DnsTypeConstraint::Allow(include));
    }

    exclude.sort_unstable_by_key(|item| u16::from(*item));
    exclude.dedup();
    Ok(DnsTypeConstraint::Deny(exclude))
}

pub(super) fn canonical_pattern_key(raw: &str) -> String {
    if raw.starts_with('/') {
        raw.to_string()
    } else {
        normalize_domain(raw)
    }
}

pub(super) fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn compile_regex_pattern(raw: &str) -> Result<PatternMatcher, String> {
    let body = raw
        .strip_prefix('/')
        .and_then(|v| v.strip_suffix('/'))
        .ok_or_else(|| "unterminated regex rule".to_string())?;
    if body.trim().is_empty() {
        return Err("empty regex rule".to_string());
    }
    let regex = RegexBuilder::new(body)
        .case_insensitive(true)
        .build()
        .map_err(|e| format!("invalid regex '{}': {}", raw, e))?;
    Ok(PatternMatcher::Regex(regex))
}

fn translate_pattern_to_regex(raw: &str) -> Result<String, String> {
    let mut rest = raw;
    let mut prefix = String::new();
    if let Some(stripped) = rest.strip_prefix("||") {
        prefix.push_str(r"(^|.+\.)");
        rest = stripped;
    } else if let Some(stripped) = rest.strip_prefix('|') {
        prefix.push('^');
        rest = stripped;
    }

    let mut suffix = String::new();
    if let Some(stripped) = rest.strip_suffix('|') {
        suffix.push('$');
        rest = stripped;
    }

    let mut out = prefix;
    for ch in rest.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '^' => out.push('$'),
            '.' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            '|' => return Err(format!("unsupported interior '|' in pattern '{}'", raw)),
            other => out.push(other),
        }
    }
    out.push_str(&suffix);
    Ok(out)
}

fn is_hosts_style_rule(raw: &str) -> bool {
    let mut parts = raw.split_whitespace();
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(_second) = parts.next() else {
        return false;
    };
    first.parse::<IpAddr>().is_ok()
}

fn is_non_dns_rule(raw: &str) -> bool {
    raw.contains("##")
        || raw.contains("#@#")
        || raw.contains("#$#")
        || raw.contains("#%#")
        || raw.contains("#?#")
}

fn is_simple_hostname(raw: &str) -> bool {
    !raw.is_empty()
        && raw
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_')
}
