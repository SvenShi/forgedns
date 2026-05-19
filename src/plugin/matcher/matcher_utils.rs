// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared helpers for matcher plugins.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;
use std::sync::Arc;

use ahash::AHashSet;
use serde_yaml_ng::{Number, Value};

use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::{DomainRuleMatcher, IpPrefixMatcher};
use crate::plugin::PluginInitContext;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::provider::Provider;
use crate::proto::{DNSClass, Rcode, RecordType};

pub(crate) fn parse_rules_from_value(args: Option<Value>) -> DnsResult<Vec<String>> {
    let args = args.ok_or_else(|| DnsError::plugin("matcher requires args"))?;
    parse_rule_list_value(args)
}

pub(crate) fn parse_enum_rules_from_value(
    field: &str,
    args: Option<Value>,
) -> DnsResult<Vec<String>> {
    let args = args.ok_or_else(|| DnsError::plugin(format!("{field} matcher requires args")))?;
    parse_enum_rule_list_value(field, args)
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
        let num = if let Some(num) = parse_u16_rule_token(field, v)? {
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

fn parse_u16_rule_token(field: &str, raw: &str) -> DnsResult<Option<u16>> {
    if let Ok(num) = raw.parse::<u16>() {
        return Ok(Some(num));
    }

    if raw.parse::<u64>().is_ok() || raw.parse::<i64>().is_ok() {
        return Err(DnsError::plugin(format!(
            "invalid {} value '{}': numeric value must be between 0 and 65535",
            field, raw
        )));
    }

    if raw.parse::<f64>().is_ok() {
        return Err(DnsError::plugin(format!(
            "invalid {} value '{}': numeric value must be an integer between 0 and 65535",
            field, raw
        )));
    }

    Ok(None)
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

pub(crate) fn parse_rcode(raw: &str) -> Option<u16> {
    if let Ok(code) = raw.parse::<u16>() {
        return Some(u16::from(Rcode::from(code)));
    }

    let rcode = match raw.to_ascii_uppercase().as_str() {
        "NOERROR" => Rcode::NoError,
        "FORMERR" => Rcode::FormErr,
        "SERVFAIL" => Rcode::ServFail,
        "NXDOMAIN" => Rcode::NXDomain,
        "NOTIMP" => Rcode::NotImp,
        "REFUSED" => Rcode::Refused,
        "YXDOMAIN" => Rcode::YXDomain,
        "YXRRSET" => Rcode::YXRRSet,
        "NXRRSET" => Rcode::NXRRSet,
        "NOTAUTH" => Rcode::NotAuth,
        "NOTZONE" => Rcode::NotZone,
        "BADVERS" => Rcode::BADVERS,
        "BADSIG" => Rcode::BADSIG,
        "BADKEY" => Rcode::BADKEY,
        "BADTIME" => Rcode::BADTIME,
        "BADMODE" => Rcode::BADMODE,
        "BADNAME" => Rcode::BADNAME,
        "BADALG" => Rcode::BADALG,
        "BADTRUNC" => Rcode::BADTRUNC,
        "BADCOOKIE" => Rcode::BADCOOKIE,
        _ => return None,
    };
    Some(u16::from(rcode))
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

pub(crate) fn provider_dependency_specs(
    field_prefix: &str,
    tags: Vec<String>,
) -> Vec<DependencySpec> {
    tags.into_iter()
        .enumerate()
        .map(|(idx, tag)| DependencySpec::provider(format!("{field_prefix}[{idx}]"), tag))
        .collect()
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
    context: &PluginInitContext<'_>,
    tags: &[String],
    matcher_name: &str,
) -> DnsResult<Vec<Arc<dyn Provider>>> {
    let mut providers = Vec::with_capacity(tags.len());
    for (idx, tag) in tags.iter().enumerate() {
        let field = format!("{}.provider_tags[{}]", matcher_name, idx);
        let provider = context.provider(&field, tag)?;
        providers.push(provider);
    }
    Ok(providers)
}

pub(crate) fn ensure_ip_capable_providers(
    providers: &[Arc<dyn Provider>],
    matcher_name: &str,
    matcher_tag: &str,
    tags: &[String],
) -> DnsResult<()> {
    for (idx, provider) in providers.iter().enumerate() {
        if provider.supports_ip_matching() {
            continue;
        }
        let tag = tags.get(idx).map(String::as_str).unwrap_or("<unknown>");
        return Err(DnsError::plugin(format!(
            "{} matcher '{}' requires provider '{}' to support IP matching",
            matcher_name, matcher_tag, tag
        )));
    }
    Ok(())
}

pub(crate) fn ensure_domain_capable_providers(
    providers: &[Arc<dyn Provider>],
    matcher_name: &str,
    matcher_tag: &str,
    tags: &[String],
) -> DnsResult<()> {
    for (idx, provider) in providers.iter().enumerate() {
        if provider.supports_domain_matching() {
            continue;
        }
        let tag = tags.get(idx).map(String::as_str).unwrap_or("<unknown>");
        return Err(DnsError::plugin(format!(
            "{} matcher '{}' requires provider '{}' to support domain matching",
            matcher_name, matcher_tag, tag
        )));
    }
    Ok(())
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

fn parse_enum_rule_list_value(field: &str, value: Value) -> DnsResult<Vec<String>> {
    match value {
        Value::String(s) => Ok(split_rule_tokens(&s)),
        Value::Number(n) => Ok(vec![parse_u16_number_rule(field, &n)?]),
        Value::Sequence(seq) => {
            let mut out = Vec::with_capacity(seq.len());
            for (idx, item) in seq.into_iter().enumerate() {
                match item {
                    Value::String(s) => out.extend(split_rule_tokens(&s)),
                    Value::Number(n) => out.push(parse_u16_number_rule(field, &n)?),
                    other => {
                        return Err(DnsError::plugin(format!(
                            "{} matcher args[{}] must be a string or unsigned integer, got {:?}",
                            field, idx, other
                        )));
                    }
                }
            }
            Ok(out)
        }
        other => Err(DnsError::plugin(format!(
            "{} matcher args must be a string, unsigned integer, or list of strings/unsigned integers, got {:?}",
            field, other
        ))),
    }
}

fn parse_u16_number_rule(field: &str, number: &Number) -> DnsResult<String> {
    if let Some(value) = number.as_u64() {
        let value = u16::try_from(value).map_err(|_| {
            DnsError::plugin(format!(
                "invalid {} value {}: numeric value must be between 0 and 65535",
                field, value
            ))
        })?;
        return Ok(value.to_string());
    }

    if let Some(value) = number.as_i64() {
        return Err(DnsError::plugin(format!(
            "invalid {} value {}: numeric value must be between 0 and 65535",
            field, value
        )));
    }

    Err(DnsError::plugin(format!(
        "invalid {} value {}: numeric value must be an integer between 0 and 65535",
        field, number
    )))
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
    fn test_parse_enum_rules_from_value_accepts_strings_and_numbers() {
        let value = serde_yaml_ng::from_str::<Value>(
            r#"
- 1
- A,AAAA
- ServFail
"#,
        )
        .expect("yaml should parse");

        let rules = parse_enum_rules_from_value("qtype", Some(value))
            .expect("enum matcher rules should parse");

        assert_eq!(rules, vec!["1", "A", "AAAA", "ServFail"]);
    }

    #[test]
    fn test_parse_enum_rules_from_value_rejects_invalid_values() {
        let negative = serde_yaml_ng::from_str::<Value>("-1").expect("yaml should parse");
        let err = parse_enum_rules_from_value("qtype", Some(negative))
            .expect_err("negative values should be rejected");
        assert!(err.to_string().contains("between 0 and 65535"));

        let float = serde_yaml_ng::from_str::<Value>("256.0").expect("yaml should parse");
        let err = parse_enum_rules_from_value("qtype", Some(float))
            .expect_err("floating-point values should be rejected");
        assert!(err.to_string().contains("must be an integer"));

        let out_of_range = serde_yaml_ng::from_str::<Value>("70000").expect("yaml should parse");
        let err = parse_enum_rules_from_value("qtype", Some(out_of_range))
            .expect_err("out-of-range values should be rejected");
        assert!(err.to_string().contains("between 0 and 65535"));

        let bool_value = serde_yaml_ng::from_str::<Value>("true").expect("yaml should parse");
        let err = parse_enum_rules_from_value("qtype", Some(bool_value))
            .expect_err("booleans should be rejected");
        assert!(err.to_string().contains("must be a string"));
    }

    #[test]
    fn test_parse_u16_rules_rejects_invalid_numeric_strings() {
        let out_of_range = vec!["70000".to_string()];
        let err = parse_u16_rules("qtype", &out_of_range, parse_rr_type)
            .expect_err("out-of-range string values should be rejected");
        assert!(err.to_string().contains("between 0 and 65535"));

        let negative = vec!["-1".to_string()];
        let err = parse_u16_rules("qtype", &negative, parse_rr_type)
            .expect_err("negative string values should be rejected");
        assert!(err.to_string().contains("between 0 and 65535"));

        let float = vec!["1.0".to_string()];
        let err = parse_u16_rules("qtype", &float, parse_rr_type)
            .expect_err("floating-point string values should be rejected");
        assert!(err.to_string().contains("must be an integer"));
    }

    #[test]
    fn test_named_enum_parsers_are_case_insensitive() {
        assert_eq!(parse_rr_type("a"), Some(1));
        assert_eq!(parse_rr_type("AAAA"), Some(28));
        assert_eq!(parse_class("in"), Some(1));
        assert_eq!(parse_class("CH"), Some(3));
        assert_eq!(parse_rcode("ServFail"), Some(2));
        assert_eq!(parse_rcode("NXDOMAIN"), Some(3));
        assert_eq!(parse_rcode("BADSIG"), Some(16));
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
