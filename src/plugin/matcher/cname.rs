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
use crate::core::dns_utils::{response_records, rr_to_cname};
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    domain_match, load_rules_from_files, normalize_domain_rules, parse_quick_setup_rules,
    parse_rules_from_value, resolve_provider_tags, split_rule_sources,
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
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        let (cname_rules, domain_set_tags) = parse_cname_rules(rules)?;
        validate_non_empty_cname_rules(&cname_rules, &domain_set_tags)
    }

    fn get_dependencies(&self, plugin_config: &PluginConfig) -> Vec<String> {
        let Ok(rules) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };
        let Ok((_, domain_set_tags)) = parse_cname_rules(rules) else {
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
    let (cname_rules, domain_set_tags) = parse_cname_rules(rules)?;
    validate_non_empty_cname_rules(&cname_rules, &domain_set_tags)?;

    Ok(UninitializedPlugin::Matcher(Box::new(CnameMatcher {
        tag,
        cname_rules,
        domain_set_tags,
        domain_sets: Vec::new(),
        registry,
    })))
}

fn parse_cname_rules(rules: Vec<String>) -> DnsResult<(Vec<String>, Vec<String>)> {
    let (mut inline_rules, domain_set_tags, files) = split_rule_sources(rules);
    let file_rules = load_rules_from_files(&files, "cname")?;
    inline_rules.extend(file_rules);
    Ok((normalize_domain_rules(inline_rules), domain_set_tags))
}

fn validate_non_empty_cname_rules(
    cname_rules: &[String],
    domain_set_tags: &[String],
) -> DnsResult<()> {
    if cname_rules.is_empty() && domain_set_tags.is_empty() {
        return Err(DnsError::plugin(
            "cname matcher requires at least one domain rule or domain_set tag",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct CnameMatcher {
    tag: String,
    cname_rules: Vec<String>,
    domain_set_tags: Vec<String>,
    domain_sets: Vec<Arc<dyn crate::plugin::provider::Provider>>,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for CnameMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {
        self.domain_sets =
            resolve_provider_tags(&self.registry, &self.domain_set_tags, "cname", &self.tag);
    }

    async fn destroy(&self) {}
}

#[async_trait]
impl Matcher for CnameMatcher {
    async fn is_match(&self, context: &mut DnsContext) -> bool {
        let Some(response) = context.response.as_ref() else {
            return false;
        };

        response_records(response).any(|record| {
            rr_to_cname(record).is_some_and(|cname| {
                self.cname_rules
                    .iter()
                    .any(|rule| domain_match(rule, &cname))
                    || self
                        .domain_sets
                        .iter()
                        .any(|set| set.contains_domain(&cname))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{DnsContext, ExecFlowState};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::rdata::CNAME;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::SocketAddr;

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));

        DnsContext {
            src_addr: SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: Default::default(),
            registry: Arc::new(PluginRegistry::new()),
        }
    }

    #[tokio::test]
    async fn test_cname_matcher_only_checks_cname_rr() {
        let matcher = CnameMatcher {
            tag: "cname".into(),
            cname_rules: vec!["target.example.com".into()],
            domain_set_tags: vec![],
            domain_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        let mut ctx = make_context();
        let mut response = Message::new();
        response.add_name_server(Record::from_rdata(
            Name::from_ascii("alias.example.com.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("target.example.com.").unwrap())),
        ));
        ctx.response = Some(response);

        assert!(matcher.is_match(&mut ctx).await);
    }
}
