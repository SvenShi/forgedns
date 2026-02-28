/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `qname` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches request query names against configured domain rules.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    domain_match, load_rules_from_files, normalize_domain_rules, normalize_name,
    parse_quick_setup_rules, parse_rules_from_value, resolve_provider_tags, split_rule_sources,
    validate_non_empty_rules,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct QnameFactory {}

register_plugin_factory!("qname", QnameFactory {});

impl PluginFactory for QnameFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        let (domains, domain_set_tags) = parse_qname_rules(rules)?;
        validate_non_empty_qname_rules(&domains, &domain_set_tags)
    }

    fn get_dependencies(&self, plugin_config: &PluginConfig) -> Vec<String> {
        let Ok(rules) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };
        let Ok((_, domain_set_tags)) = parse_qname_rules(rules) else {
            return vec![];
        };
        domain_set_tags
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
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
    let (domains, domain_set_tags) = parse_qname_rules(rules)?;
    validate_non_empty_qname_rules(&domains, &domain_set_tags)?;

    Ok(UninitializedPlugin::Matcher(Box::new(QnameMatcher {
        tag,
        domains,
        domain_set_tags,
        domain_sets: Vec::new(),
        registry,
    })))
}

fn parse_qname_rules(rules: Vec<String>) -> DnsResult<(Vec<String>, Vec<String>)> {
    let (mut inline_rules, domain_set_tags, files) = split_rule_sources(rules);
    let file_rules = load_rules_from_files(&files, "qname")?;
    inline_rules.extend(file_rules);
    Ok((normalize_domain_rules(inline_rules), domain_set_tags))
}

fn validate_non_empty_qname_rules(domains: &[String], domain_set_tags: &[String]) -> DnsResult<()> {
    if domains.is_empty() && domain_set_tags.is_empty() {
        return Err(DnsError::plugin(
            "qname matcher requires at least one domain rule or domain_set tag",
        ));
    }
    if !domains.is_empty() {
        validate_non_empty_rules("qname", domains)?;
    }
    Ok(())
}

#[derive(Debug)]
struct QnameMatcher {
    tag: String,
    domains: Vec<String>,
    domain_set_tags: Vec<String>,
    domain_sets: Vec<Arc<dyn crate::plugin::provider::Provider>>,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for QnameMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {
        self.domain_sets =
            resolve_provider_tags(&self.registry, &self.domain_set_tags, "qname", &self.tag);
    }

    async fn destroy(&self) {}
}

#[async_trait]
impl Matcher for QnameMatcher {
    async fn is_match(&self, context: &mut DnsContext) -> bool {
        context.request.queries().iter().any(|query| {
            let query_name = normalize_name(query.name());
            self.domains
                .iter()
                .any(|domain| domain_match(domain, &query_name))
                || self
                    .domain_sets
                    .iter()
                    .any(|set| set.contains_domain(&query_name))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{DnsContext, ExecFlowState};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::collections::HashMap;
    use std::net::SocketAddr;

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        let mut query = Query::query(Name::from_ascii("www.example.com.").unwrap(), RecordType::A);
        query.set_query_class(DNSClass::IN);
        request.add_query(query);

        DnsContext {
            src_addr: SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: HashMap::new(),
            registry: Arc::new(PluginRegistry::new()),
        }
    }

    #[tokio::test]
    async fn test_qname_matcher_only_checks_domain() {
        let matcher = QnameMatcher {
            tag: "qname".into(),
            domains: vec!["example.com".into()],
            domain_set_tags: vec![],
            domain_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };
        let mut ctx = make_context();
        assert!(matcher.is_match(&mut ctx).await);
    }
}
