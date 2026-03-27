/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `cname` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches CNAME targets in response sections against configured domain rules.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::core::rule_matcher::DomainRuleMatcher;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    parse_domain_rules_and_set_tags, parse_quick_setup_rules, parse_rules_from_value,
    resolve_provider_tags, validate_non_empty_domain_rules_or_set_tags,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CnameFactory {}

register_plugin_factory!("cname", CnameFactory {});

impl PluginFactory for CnameFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let Ok(rules) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };
        let Ok((_, domain_set_tags)) = parse_domain_rules_and_set_tags(rules, "cname") else {
            return vec![];
        };
        domain_set_tags
            .into_iter()
            .enumerate()
            .map(|(idx, tag)| {
                DependencySpec::provider_type(
                    format!("args.domain_set_tags[{}]", idx),
                    tag,
                    "domain_set",
                )
            })
            .collect()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        build_cname_matcher(plugin_config.tag.clone(), rules, registry)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_cname_matcher(tag.to_string(), rules, registry)
    }
}

fn build_cname_matcher(
    tag: String,
    rules: Vec<String>,
    registry: Arc<PluginRegistry>,
) -> DnsResult<UninitializedPlugin> {
    let (cname_rules, domain_set_tags) = parse_domain_rules_and_set_tags(rules, "cname")?;
    validate_non_empty_domain_rules_or_set_tags(
        "cname",
        &cname_rules,
        &domain_set_tags,
        "domain_set",
    )?;

    Ok(UninitializedPlugin::Matcher(Box::new(CnameMatcher {
        tag,
        cname_rules,
        domain_set_tags,
        domain_sets: Vec::new(),
        registry,
    })))
}

#[derive(Debug)]
struct CnameMatcher {
    tag: String,
    cname_rules: DomainRuleMatcher,
    domain_set_tags: Vec<String>,
    domain_sets: Vec<Arc<dyn crate::plugin::provider::Provider>>,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for CnameMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        self.domain_sets =
            resolve_provider_tags(&self.registry, &self.domain_set_tags, "cname", &self.tag)?;
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for CnameMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context.response().is_some_and(|response| {
            response.cnames().into_iter().any(|cname| {
                if self.cname_rules.is_match_name(cname) {
                    return true;
                }
                self.domain_sets.iter().any(|set| set.contains_name(cname))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::matcher::Matcher;
    use crate::proto::rdata::{A, CNAME};
    use crate::proto::{Message, Question};
    use crate::proto::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            crate::proto::DNSClass::IN,
        ));

        DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    #[tokio::test]
    async fn test_cname_matcher_only_checks_cname_rr() {
        let matcher = CnameMatcher {
            tag: "cname".into(),
            cname_rules: {
                let mut rules = DomainRuleMatcher::default();
                rules.add_expression("target.example.com", "test").unwrap();
                rules.finalize().unwrap();
                rules
            },
            domain_set_tags: vec![],
            domain_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        let mut ctx = make_context();
        let mut response = Message::new();
        response.add_authority(Record::from_rdata(
            Name::from_ascii("alias.example.com.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("target.example.com.").unwrap())),
        ));
        ctx.set_response(response);

        assert!(matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_cname_matcher_supports_full_keyword_regexp() {
        let matcher = CnameMatcher {
            tag: "cname".into(),
            cname_rules: {
                let mut rules = DomainRuleMatcher::default();
                rules
                    .add_expression("full:target.example.com", "test")
                    .unwrap();
                rules.add_expression("keyword:example", "test").unwrap();
                rules
                    .add_expression("regexp:^target\\.example\\.com$", "test")
                    .unwrap();
                rules.finalize().unwrap();
                rules
            },
            domain_set_tags: vec![],
            domain_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        let mut ctx = make_context();
        let mut response = Message::new();
        response.add_authority(Record::from_rdata(
            Name::from_ascii("alias.example.com.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("target.example.com.").unwrap())),
        ));
        ctx.set_response(response);
        assert!(matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_cname_matcher_ignores_non_cname_or_missing_response() {
        let matcher = CnameMatcher {
            tag: "cname".into(),
            cname_rules: {
                let mut rules = DomainRuleMatcher::default();
                rules.add_expression("target.example.com", "test").unwrap();
                rules.finalize().unwrap();
                rules
            },
            domain_set_tags: vec![],
            domain_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        let mut no_response = make_context();
        assert!(!matcher.is_match(&mut no_response));

        let mut non_cname_response = make_context();
        let mut response = Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        non_cname_response.set_response(response);
        assert!(!matcher.is_match(&mut non_cname_response));
    }
}
