/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `adguard_rule` provider plugin.
//!
//! This provider evaluates the request-side subset of AdGuard Home DNS rules.
//!
//! Scope of this implementation:
//! - supported: basic domain masks, exception rules, `important`, `badfilter`,
//!   `denyallow`, and request-side `dnstype`
//! - intentionally unsupported: `/etc/hosts` style rules, `dnsrewrite`,
//!   `$client`, `$ctag`, and unknown modifiers
//!
//! Unsupported rules are skipped with warnings so mixed upstream rule files can
//! still load, while invalid syntax inside the supported subset remains a hard
//! error.

mod compiler;
mod model;
mod parser;

use self::compiler::build_rule_buckets;
use self::model::{AdGuardRuleConfig, CompiledRuleSet};
use self::parser::parse_config;
use crate::config::types::PluginConfig;
use crate::core::error::Result as DnsResult;
use crate::plugin::provider::Provider;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{Name, Question};
use crate::register_plugin_factory;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::info;

#[derive(Debug)]
struct AdGuardRuleSnapshot {
    important_exceptions: CompiledRuleSet,
    important_blocks: CompiledRuleSet,
    exceptions: CompiledRuleSet,
    blocks: CompiledRuleSet,
}

#[derive(Debug)]
pub struct AdGuardRule {
    tag: String,
    cfg: AdGuardRuleConfig,
    snapshot: ArcSwap<AdGuardRuleSnapshot>,
}

impl AdGuardRule {
    fn contains_name_only(&self, qname: &Name) -> bool {
        let snapshot = self.snapshot.load();
        if snapshot.important_exceptions.is_match_name_only(qname) {
            return false;
        }
        if snapshot.important_blocks.is_match_name_only(qname) {
            return true;
        }
        if snapshot.exceptions.is_match_name_only(qname) {
            return false;
        }
        snapshot.blocks.is_match_name_only(qname)
    }

    fn contains_question_rule(&self, question: &Question) -> bool {
        let snapshot = self.snapshot.load();
        let qname = question.name();
        let qtype = question.qtype();

        if snapshot.important_exceptions.is_match(qname, qtype) {
            return false;
        }
        if snapshot.important_blocks.is_match(qname, qtype) {
            return true;
        }
        if snapshot.exceptions.is_match(qname, qtype) {
            return false;
        }
        snapshot.blocks.is_match(qname, qtype)
    }

    fn build_snapshot(&self) -> DnsResult<AdGuardRuleSnapshot> {
        let (important_exceptions, important_blocks, exceptions, blocks, stats) =
            build_rule_buckets(self.tag.as_str(), &self.cfg)?;

        info!(
            tag = %self.tag,
            total_rules = stats.total_rules,
            supported_rules = stats.supported_rules,
            skipped_rules = stats.skipped_rules,
            exception_rules = stats.exception_rules,
            important_rules = stats.important_rules,
            "adguard_rule snapshot built"
        );

        Ok(AdGuardRuleSnapshot {
            important_exceptions,
            important_blocks,
            exceptions,
            blocks,
        })
    }
}

#[async_trait]
impl Plugin for AdGuardRule {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        self.reload().await
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AdGuardRuleFactory;

register_plugin_factory!("adguard_rule", AdGuardRuleFactory {});

#[async_trait]
impl Provider for AdGuardRule {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn supports_domain_matching(&self) -> bool {
        // This provider participates through runtime `contains_name` and
        // `contains_question` evaluation. That keeps exception precedence and
        // request-scoped modifiers intact when another provider composes it.
        true
    }

    fn contains_name(&self, name: &Name) -> bool {
        self.contains_name_only(name)
    }

    fn contains_question(&self, question: &Question) -> bool {
        self.contains_question_rule(question)
    }

    async fn reload(&self) -> DnsResult<()> {
        let snapshot = self.build_snapshot()?;
        self.snapshot.store(Arc::new(snapshot));
        Ok(())
    }
}

impl PluginFactory for AdGuardRuleFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let cfg = parse_config(plugin_config.args.clone())?;

        Ok(UninitializedPlugin::Provider(Box::new(AdGuardRule {
            tag: plugin_config.tag.clone(),
            cfg,
            snapshot: ArcSwap::from_pointee(AdGuardRuleSnapshot {
                important_exceptions: CompiledRuleSet::default(),
                important_blocks: CompiledRuleSet::default(),
                exceptions: CompiledRuleSet::default(),
                blocks: CompiledRuleSet::default(),
            }),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::provider::adguard_rule::model::RuleInput;
    use crate::plugin::provider::adguard_rule::parser::parse_rule;
    use crate::plugin::test_utils::test_registry;
    use crate::proto::{DNSClass, Message, Name, Question, RecordType};
    use std::net::{Ipv4Addr, SocketAddr};

    fn make_context(name: &str, qtype: RecordType) -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii(name).unwrap(),
            qtype,
            DNSClass::IN,
        ));
        DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        )
    }

    fn make_input(raw: &str) -> RuleInput {
        RuleInput {
            raw: raw.to_string(),
            source: "test".to_string(),
        }
    }

    fn make_provider(cfg: model::AdGuardRuleConfig) -> AdGuardRule {
        let (important_exceptions, important_blocks, exceptions, blocks, _) =
            build_rule_buckets("agh", &cfg).expect("rules should build");
        AdGuardRule {
            tag: "agh".to_string(),
            cfg,
            snapshot: ArcSwap::from_pointee(AdGuardRuleSnapshot {
                important_exceptions,
                important_blocks,
                exceptions,
                blocks,
            }),
        }
    }

    #[test]
    fn plain_domain_rule_matches_exact_only() {
        let rule = parse_rule(&make_input("example.org"))
            .unwrap()
            .expect("rule should parse");
        let compiled = model::CompiledRule {
            matcher: rule.matcher,
            dnstype: rule.dnstype,
            denyallow: rule.denyallow,
        };

        assert!(compiled.is_match("example.org", RecordType::A));
        assert!(!compiled.is_match("www.example.org", RecordType::A));
    }

    #[test]
    fn domain_anchor_rule_matches_subdomains() {
        let rule = parse_rule(&make_input("||example.org^"))
            .unwrap()
            .expect("rule should parse");
        let compiled = model::CompiledRule {
            matcher: rule.matcher,
            dnstype: rule.dnstype,
            denyallow: rule.denyallow,
        };

        assert!(compiled.is_match("example.org", RecordType::A));
        assert!(compiled.is_match("www.example.org", RecordType::A));
        assert!(!compiled.is_match("testexample.org", RecordType::A));
    }

    #[test]
    fn regex_rule_is_case_insensitive() {
        let rule = parse_rule(&make_input("/EXAMPLE\\.(org|net)/"))
            .unwrap()
            .expect("rule should parse");
        let compiled = model::CompiledRule {
            matcher: rule.matcher,
            dnstype: rule.dnstype,
            denyallow: rule.denyallow,
        };

        assert!(compiled.is_match("example.org", RecordType::A));
        assert!(compiled.is_match("example.net", RecordType::A));
    }

    #[test]
    fn unsupported_modifier_skips_rule() {
        let parsed = parse_rule(&make_input("||example.org^$dnsrewrite=1.2.3.4")).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn invalid_supported_regex_is_error() {
        let err = parse_rule(&make_input("/(/")).expect_err("invalid regex should fail");
        assert!(err.contains("invalid regex"));
    }

    #[test]
    fn denyallow_excludes_domains() {
        let rule = parse_rule(&make_input("||example.org^$denyallow=sub.example.org"))
            .unwrap()
            .expect("rule should parse");
        let compiled = model::CompiledRule {
            matcher: rule.matcher,
            dnstype: rule.dnstype,
            denyallow: rule.denyallow,
        };

        assert!(compiled.is_match("example.org", RecordType::A));
        assert!(!compiled.is_match("sub.example.org", RecordType::A));
    }

    #[test]
    fn dnstype_uses_request_type() {
        let rule = parse_rule(&make_input("||example.org^$dnstype=AAAA"))
            .unwrap()
            .expect("rule should parse");
        let compiled = model::CompiledRule {
            matcher: rule.matcher,
            dnstype: rule.dnstype,
            denyallow: rule.denyallow,
        };

        assert!(compiled.is_match("example.org", RecordType::AAAA));
        assert!(!compiled.is_match("example.org", RecordType::A));
    }

    #[test]
    fn badfilter_disables_matching_rule() {
        let cfg = model::AdGuardRuleConfig {
            rules: vec![
                "||example.org^$important".to_string(),
                "||example.org^$important,badfilter".to_string(),
            ],
            files: Vec::new(),
        };

        let (_, important_blocks, _, blocks, _) =
            build_rule_buckets("agh", &cfg).expect("rules should build");
        assert!(important_blocks.is_empty());
        assert!(blocks.is_empty());
    }

    #[tokio::test]
    async fn provider_returns_true_only_for_effective_block() {
        let cfg = model::AdGuardRuleConfig {
            rules: vec![
                "||example.org^".to_string(),
                "@@||safe.example.org^".to_string(),
                "||ads.example.org^$important".to_string(),
            ],
            files: Vec::new(),
        };
        let provider = make_provider(cfg);

        let ads = make_context("ads.example.org.", RecordType::A);
        assert!(
            provider.contains_question(
                ads.request()
                    .first_question()
                    .expect("question should exist")
            )
        );

        let safe = make_context("safe.example.org.", RecordType::A);
        assert!(
            !provider.contains_question(
                safe.request()
                    .first_question()
                    .expect("question should exist")
            )
        );
    }

    #[tokio::test]
    async fn contains_name_ignores_dnstype_rules() {
        let cfg = model::AdGuardRuleConfig {
            rules: vec![
                "||always.example.org^".to_string(),
                "||type-only.example.org^$dnstype=AAAA".to_string(),
                "@@||safe.example.org^".to_string(),
            ],
            files: Vec::new(),
        };
        let provider = make_provider(cfg);

        assert!(provider.contains_name(&Name::from_ascii("always.example.org.").unwrap()));
        assert!(!provider.contains_name(&Name::from_ascii("type-only.example.org.").unwrap()));
        assert!(!provider.contains_name(&Name::from_ascii("safe.example.org.").unwrap()));
    }
}
