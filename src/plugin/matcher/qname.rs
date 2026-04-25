// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `qname` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches request query names against configured domain rules.

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::core::rule_matcher::DomainRuleMatcher;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    ensure_domain_capable_providers, parse_domain_rules_and_set_tags, parse_quick_setup_rules,
    parse_rules_from_value, provider_dependency_specs, resolve_provider_tags,
    validate_non_empty_domain_rules_or_set_tags,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;

#[derive(Debug, Clone)]
pub struct QnameFactory {}

register_plugin_factory!("qname", QnameFactory {});

impl PluginFactory for QnameFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let Ok(rules) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };
        let Ok((_, domain_set_tags)) = parse_domain_rules_and_set_tags(rules, "qname") else {
            return vec![];
        };
        provider_dependency_specs("args.domain_set_tags", domain_set_tags)
    }

    fn get_quick_setup_dependency_specs(&self, param: Option<&str>) -> Vec<DependencySpec> {
        let Ok(rules) = parse_quick_setup_rules(param.map(str::to_owned)) else {
            return vec![];
        };
        let Ok((_, domain_set_tags)) = parse_domain_rules_and_set_tags(rules, "qname") else {
            return vec![];
        };
        provider_dependency_specs("domain_set_tags", domain_set_tags)
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        build_qname_matcher(plugin_config.tag.clone(), rules, registry)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_qname_matcher(tag.to_string(), rules, registry)
    }
}

fn build_qname_matcher(
    tag: String,
    rules: Vec<String>,
    registry: Arc<PluginRegistry>,
) -> DnsResult<UninitializedPlugin> {
    let (domains, domain_set_tags) = parse_domain_rules_and_set_tags(rules, "qname")?;
    validate_non_empty_domain_rules_or_set_tags("qname", &domains, &domain_set_tags, "domain_set")?;

    Ok(UninitializedPlugin::Matcher(Box::new(QnameMatcher {
        tag,
        domains,
        domain_set_tags,
        domain_sets: Vec::new(),
        registry,
    })))
}

#[derive(Debug)]
struct QnameMatcher {
    tag: String,
    domains: DomainRuleMatcher,
    domain_set_tags: Vec<String>,
    domain_sets: Vec<Arc<dyn crate::plugin::provider::Provider>>,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for QnameMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        self.domain_sets =
            resolve_provider_tags(&self.registry, &self.domain_set_tags, "qname", &self.tag)?;
        ensure_domain_capable_providers(
            &self.domain_sets,
            "qname",
            &self.tag,
            &self.domain_set_tags,
        )?;
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for QnameMatcher {
    #[hotpath::measure]
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context.request().questions().iter().any(|q| {
            self.domains.is_match_name(q.name())
                || self
                    .domain_sets
                    .iter()
                    .any(|set| set.contains_name(q.name()))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::matcher::Matcher;
    use crate::proto::{DNSClass, Message, Name, Question, RecordType};

    fn make_context(name: &str) -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii(name).unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));

        DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    fn make_context_without_query() -> DnsContext {
        DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            Message::new(),
            Arc::new(PluginRegistry::new()),
        )
    }

    #[tokio::test]
    async fn test_qname_matcher_only_checks_domain() {
        let matcher = QnameMatcher {
            tag: "qname".into(),
            domains: {
                let mut rules = DomainRuleMatcher::default();
                rules.add_expression("example.com", "test").unwrap();
                rules.finalize().unwrap();
                rules
            },
            domain_set_tags: vec![],
            domain_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };
        let mut ctx = make_context("www.example.com.");
        assert!(matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_qname_matcher_supports_full_keyword_regexp() {
        let matcher = QnameMatcher {
            tag: "qname".into(),
            domains: {
                let mut rules = DomainRuleMatcher::default();
                rules
                    .add_expression("full:www.example.com", "test")
                    .unwrap();
                rules.add_expression("keyword:example", "test").unwrap();
                rules
                    .add_expression("regexp:^www\\.example\\.com$", "test")
                    .unwrap();
                rules.finalize().unwrap();
                rules
            },
            domain_set_tags: vec![],
            domain_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };
        let mut ctx = make_context("www.example.com.");
        assert!(matcher.is_match(&mut ctx));
    }

    #[test]
    fn test_build_qname_matcher_rejects_empty_rule_and_set_tag() {
        let result =
            build_qname_matcher("qname".to_string(), vec![], Arc::new(PluginRegistry::new()));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_qname_matcher_returns_false_when_query_mismatch_or_missing() {
        let matcher = QnameMatcher {
            tag: "qname".into(),
            domains: {
                let mut rules = DomainRuleMatcher::default();
                rules.add_expression("example.com", "test").unwrap();
                rules.finalize().unwrap();
                rules
            },
            domain_set_tags: vec![],
            domain_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        let mut mismatch = make_context("www.other.com.");
        assert!(!matcher.is_match(&mut mismatch));

        let mut no_query = make_context_without_query();
        assert!(!matcher.is_match(&mut no_query));
    }
}
