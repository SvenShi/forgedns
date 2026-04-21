/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! High-performance IP/CIDR set provider.
//!
//! Design goals:
//! - Constant-time-ish membership checks on hot path.
//! - Unified IPv4/IPv6 semantics.
//! - Local matcher plus stable referenced providers for composed sets.
//! - Precise parse errors for file-based rules.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::IpPrefixMatcher;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::provider::Provider;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use serde::Deserialize;
use std::any::Any;
use std::fmt::Debug;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Debug, Clone, Deserialize, Default)]
struct IpSetArgs {
    /// Inline ip/cidr rules.
    #[serde(default)]
    ips: Vec<String>,
    /// Referenced ip_set plugin tags.
    #[serde(default)]
    sets: Vec<String>,
    /// Text files containing one ip/cidr rule per line.
    #[serde(default)]
    files: Vec<String>,
}

#[derive(Debug, Default)]
struct IpSetSnapshot {
    matcher: IpPrefixMatcher,
    /// Family-level fast guards to avoid useless scans.
    has_v4_rules: bool,
    has_v6_rules: bool,
}

#[derive(Debug)]
pub struct IpSet {
    tag: String,
    args: IpSetArgs,
    registry: Arc<PluginRegistry>,
    referenced_sets: Vec<Arc<dyn Provider>>,
    snapshot: ArcSwap<IpSetSnapshot>,
}

impl IpSet {
    #[hotpath::measure]
    fn build_local_snapshot(&self) -> DnsResult<IpSetSnapshot> {
        let start_ms = AppClock::elapsed_millis();
        let mut rules = self.args.ips.clone();
        for file in &self.args.files {
            append_rules_from_file(&mut rules, file)?;
        }

        let mut matcher = IpPrefixMatcher::default();
        load_ip_rules(&mut matcher, &rules)?;
        matcher.finalize_compact();

        let has_v4_rules = matcher.has_v4_rules();
        let has_v6_rules = matcher.has_v6_rules();
        let total_v4_rules = matcher.v4_rule_count();
        let total_v6_rules = matcher.v6_rule_count();
        let elapsed_ms = AppClock::elapsed_millis().saturating_sub(start_ms);
        info!(
            tag = %self.tag,
            local_rules = rules.len(),
            referenced_sets = self.args.sets.len(),
            v4_rules = total_v4_rules,
            v6_rules = total_v6_rules,
            has_v4_rules,
            has_v6_rules,
            elapsed_ms,
            "ip_set snapshot built"
        );

        Ok(IpSetSnapshot {
            matcher,
            has_v4_rules,
            has_v6_rules,
        })
    }
}

#[async_trait]
impl Plugin for IpSet {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        let mut providers = Vec::with_capacity(self.args.sets.len());
        for (set_idx, set_tag) in self.args.sets.iter().enumerate() {
            let field = format!("args.sets[{}]", set_idx);
            debug!(
                tag = %self.tag,
                referenced_set = %set_tag,
                "resolving referenced ip provider"
            );
            let provider =
                self.registry
                    .get_provider_dependency(&self.tag, &field, set_tag.as_str())?;
            if !provider.supports_ip_matching() {
                return Err(DnsError::plugin(format!(
                    "plugin '{}' field '{}' expects provider '{}' to support IP matching",
                    self.tag, field, set_tag
                )));
            }
            providers.push(provider);
        }
        self.referenced_sets = providers;
        self.reload().await
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

#[async_trait]
impl Provider for IpSet {
    fn as_any(&self) -> &dyn Any {
        self
    }

    #[inline]
    #[hotpath::measure]
    fn contains_ip(&self, ip: IpAddr) -> bool {
        let snapshot = self.snapshot.load();
        let has_family_rules = match ip {
            IpAddr::V4(_) => snapshot.has_v4_rules,
            IpAddr::V6(_) => snapshot.has_v6_rules,
        };
        if has_family_rules && snapshot.matcher.contains_ip(ip) {
            return true;
        }

        self.referenced_sets.iter().any(|set| set.contains_ip(ip))
    }

    #[hotpath::measure]
    async fn reload(&self) -> DnsResult<()> {
        let snapshot = self.build_local_snapshot()?;
        self.snapshot.store(Arc::new(snapshot));
        Ok(())
    }

    fn supports_ip_matching(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct IpSetFactory {}

register_plugin_factory!("ip_set", IpSetFactory {});

impl PluginFactory for IpSetFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        plugin_config
            .args
            .clone()
            .and_then(|args| serde_yaml_ng::from_value::<IpSetArgs>(args).ok())
            .map(|args| {
                args.sets
                    .into_iter()
                    .enumerate()
                    .map(|(idx, tag)| DependencySpec::provider(format!("args.sets[{}]", idx), tag))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let args = plugin_config
            .args
            .clone()
            .map(serde_yaml_ng::from_value::<IpSetArgs>)
            .transpose()
            .map_err(|e| DnsError::plugin(format!("failed to parse ip_set config: {}", e)))?
            .unwrap_or_default();
        info!(
            tag = %plugin_config.tag,
            ips = args.ips.len(),
            files = args.files.len(),
            sets = args.sets.len(),
            "ip_set configured"
        );

        Ok(UninitializedPlugin::Provider(Box::new(IpSet {
            tag: plugin_config.tag.clone(),
            args,
            registry,
            referenced_sets: Vec::new(),
            snapshot: ArcSwap::from_pointee(IpSetSnapshot::default()),
        })))
    }
}

fn append_rules_from_file(rules: &mut Vec<String>, path: &str) -> DnsResult<()> {
    crate::plugin::provider::provider_utils::for_each_nonempty_rule_line(
        path,
        "ip rules",
        |raw, _| {
            let rule = normalize_ip_rule_line(raw);
            if !rule.is_empty() {
                rules.push(rule.to_string());
            }
            Ok(())
        },
    )
}

fn load_ip_rules(matcher: &mut IpPrefixMatcher, rules: &[String]) -> DnsResult<()> {
    for (idx, rule) in rules.iter().enumerate() {
        add_ip_rule(matcher, rule, &format!("rules[{}]", idx))?;
    }
    Ok(())
}

fn add_ip_rule(matcher: &mut IpPrefixMatcher, rule: &str, source: &str) -> DnsResult<()> {
    let rule = rule.trim();
    if rule.is_empty() {
        return Ok(());
    }
    matcher.add_rule(rule).map_err(|e| {
        DnsError::plugin(format!("invalid ip/cidr '{}' in {}: {}", rule, source, e))
    })?;
    Ok(())
}

fn normalize_ip_rule_line(line: &str) -> &str {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return "";
    }
    line.split_once('#')
        .map(|(rule, _)| rule)
        .unwrap_or(line)
        .trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::provider::provider_utils::for_each_nonempty_rule_text;

    fn load_rules_text(
        matcher: &mut IpPrefixMatcher,
        source_name: &str,
        content: &str,
    ) -> DnsResult<()> {
        for_each_nonempty_rule_text(content, |raw, line_no| {
            let rule = normalize_ip_rule_line(raw);
            if rule.is_empty() {
                return Ok(());
            }
            let source = format!("file '{}', line {}", source_name, line_no);
            add_ip_rule(matcher, rule, &source)
        })
    }

    #[test]
    fn test_ipv4_and_ipv6_match() {
        let mut m = IpPrefixMatcher::default();
        add_ip_rule(&mut m, "192.168.1.0/24", "test").unwrap();
        add_ip_rule(&mut m, "2001:db8::/32", "test").unwrap();
        m.finalize();

        assert!(m.contains_ip("192.168.1.7".parse().unwrap()));
        assert!(!m.contains_ip("192.168.2.1".parse().unwrap()));
        assert!(m.contains_ip("2001:db8:1::1".parse().unwrap()));
        assert!(!m.contains_ip("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_single_ip_default_prefix() {
        let mut m = IpPrefixMatcher::default();
        add_ip_rule(&mut m, "1.1.1.1", "test").unwrap();
        add_ip_rule(&mut m, "2001:db8::1", "test").unwrap();
        m.finalize();

        assert!(m.contains_ip("1.1.1.1".parse().unwrap()));
        assert!(!m.contains_ip("1.1.1.2".parse().unwrap()));
        assert!(m.contains_ip("2001:db8::1".parse().unwrap()));
        assert!(!m.contains_ip("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn test_cidr_host_bits_are_masked() {
        let mut m = IpPrefixMatcher::default();
        add_ip_rule(&mut m, "10.10.10.7/24", "test").unwrap();
        m.finalize();
        assert!(m.contains_ip("10.10.10.200".parse().unwrap()));
        assert!(!m.contains_ip("10.10.11.1".parse().unwrap()));
    }

    #[test]
    fn test_file_line_error_has_line_number() {
        let mut m = IpPrefixMatcher::default();
        let err = load_rules_text(&mut m, "inline-ip-test", "1.1.1.1\n2001::1/200\n").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("line 2"),
            "error should include line number: {msg}"
        );
    }

    #[test]
    fn test_parse_error_includes_input() {
        let mut m = IpPrefixMatcher::default();
        let err = add_ip_rule(&mut m, "1.1.1.1/abc", "test").unwrap_err();
        assert!(err.to_string().contains("1.1.1.1/abc"));
    }

    #[test]
    fn test_inline_comment_in_file() {
        let mut m = IpPrefixMatcher::default();
        load_rules_text(
            &mut m,
            "inline-ip-comment-test",
            "1.1.1.1 # test\n# ignore\n\n",
        )
        .unwrap();
        m.finalize();
        assert!(m.contains_ip("1.1.1.1".parse().unwrap()));
    }
}
