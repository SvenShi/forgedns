// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use tracing::info;

use super::model::{AdGuardRuleConfig, BuildStats, CompiledRule, CompiledRuleSet, ParsedRule};
use super::parser::{load_rule_inputs, parse_rule};
use crate::core::error::{DnsError, Result as DnsResult};

pub(super) fn build_rule_buckets(
    tag: &str,
    cfg: &AdGuardRuleConfig,
) -> DnsResult<(
    CompiledRuleSet,
    CompiledRuleSet,
    CompiledRuleSet,
    CompiledRuleSet,
    BuildStats,
)> {
    let rule_inputs = load_rule_inputs(cfg)?;
    let mut stats = BuildStats {
        total_rules: rule_inputs.len(),
        ..BuildStats::default()
    };
    let mut parsed_rules = Vec::new();

    for input in rule_inputs {
        match parse_rule(&input) {
            Ok(Some(rule)) => {
                stats.supported_rules += 1;
                if rule.is_exception {
                    stats.exception_rules += 1;
                }
                if rule.important {
                    stats.important_rules += 1;
                }
                parsed_rules.push(rule);
            }
            Ok(None) => {
                stats.skipped_rules += 1;
            }
            Err(err) => {
                return Err(DnsError::plugin(format!(
                    "adguard_rule '{}' failed to parse {}: {}",
                    tag, input.source, err
                )));
            }
        }
    }

    let badfilter_keys = parsed_rules
        .iter()
        .filter(|rule| rule.badfilter)
        .map(rule_cache_key)
        .collect::<Vec<_>>();

    let mut important_exceptions = CompiledRuleSet::default();
    let mut important_blocks = CompiledRuleSet::default();
    let mut exceptions = CompiledRuleSet::default();
    let mut blocks = CompiledRuleSet::default();

    for rule in parsed_rules {
        if rule.badfilter {
            continue;
        }
        if badfilter_keys
            .iter()
            .any(|key| key == &rule_cache_key(&rule))
        {
            info!(
                source = %rule.source,
                "adguard_rule skipped rule disabled by badfilter"
            );
            continue;
        }

        let target = match (rule.important, rule.is_exception) {
            (true, true) => &mut important_exceptions,
            (true, false) => &mut important_blocks,
            (false, true) => &mut exceptions,
            (false, false) => &mut blocks,
        };

        if rule.dnstype.is_none() && rule.denyallow.is_empty() {
            target
                .fast_matcher
                .add_expression(&rule.expression, &rule.source)
                .map_err(|e| {
                    DnsError::plugin(format!(
                        "adguard_rule '{}' failed to compile {}: {}",
                        tag, rule.source, e
                    ))
                })?;
        } else {
            target.conditional_rules.push(CompiledRule {
                matcher: rule.matcher,
                dnstype: rule.dnstype,
                denyallow: rule.denyallow,
            });
        }
    }

    for set in [
        &mut important_exceptions,
        &mut important_blocks,
        &mut exceptions,
        &mut blocks,
    ] {
        set.finalize().map_err(|e| {
            DnsError::plugin(format!(
                "adguard_rule '{}' failed to finalize compiled matcher: {}",
                tag, e
            ))
        })?;
    }

    Ok((
        important_exceptions,
        important_blocks,
        exceptions,
        blocks,
        stats,
    ))
}

fn rule_cache_key(rule: &ParsedRule) -> String {
    let mut key = format!(
        "{}|{}|{}|{}",
        if rule.is_exception { "except" } else { "block" },
        rule.matcher_key,
        rule.important,
        rule.dnstype
            .as_ref()
            .map(canonical_dnstype_key)
            .unwrap_or_default()
    );
    if !rule.denyallow.is_empty() {
        key.push('|');
        key.push_str(&rule.denyallow.join(","));
    }
    key
}

fn canonical_dnstype_key(value: &super::model::DnsTypeConstraint) -> String {
    match value {
        super::model::DnsTypeConstraint::Allow(items) => format!(
            "allow:{}",
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        super::model::DnsTypeConstraint::Deny(items) => format!(
            "deny:{}",
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}
