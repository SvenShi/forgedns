// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `resp_ip` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches A/AAAA records in the answer section against configured IP rules.

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::core::rule_matcher::IpPrefixMatcher;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::matcher::Matcher;
#[cfg(test)]
use crate::plugin::matcher::matcher_utils::parse_ip_prefix_matcher;
use crate::plugin::matcher::matcher_utils::{
    ensure_ip_capable_providers, parse_ip_rules_and_set_tags, parse_quick_setup_rules,
    parse_rules_from_value, provider_dependency_specs, resolve_provider_tags,
    validate_non_empty_ip_rules_or_set_tags,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;

#[derive(Debug, Clone)]
pub struct RespIpFactory {}

register_plugin_factory!("resp_ip", RespIpFactory {});

impl PluginFactory for RespIpFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let Ok(rules) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };
        let Ok((_, ip_set_tags)) = parse_ip_rules_and_set_tags(rules, "resp_ip") else {
            return vec![];
        };
        provider_dependency_specs("args.ip_set_tags", ip_set_tags)
    }

    fn get_quick_setup_dependency_specs(&self, param: Option<&str>) -> Vec<DependencySpec> {
        let Ok(rules) = parse_quick_setup_rules(param.map(str::to_owned)) else {
            return vec![];
        };
        let Ok((_, ip_set_tags)) = parse_ip_rules_and_set_tags(rules, "resp_ip") else {
            return vec![];
        };
        provider_dependency_specs("ip_set_tags", ip_set_tags)
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        build_resp_ip_matcher(plugin_config.tag.clone(), rules, registry)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_resp_ip_matcher(tag.to_string(), rules, registry)
    }
}

fn build_resp_ip_matcher(
    tag: String,
    rules: Vec<String>,
    registry: Arc<PluginRegistry>,
) -> DnsResult<UninitializedPlugin> {
    let (ip_rules, ip_set_tags) = parse_ip_rules_and_set_tags(rules, "resp_ip")?;
    validate_non_empty_ip_rules_or_set_tags("resp_ip", &ip_rules, &ip_set_tags, "ip_set")?;

    Ok(UninitializedPlugin::Matcher(Box::new(RespIpMatcher {
        tag,
        ip_rules,
        ip_set_tags,
        ip_sets: Vec::new(),
        registry,
    })))
}

#[derive(Debug)]
struct RespIpMatcher {
    tag: String,
    ip_rules: IpPrefixMatcher,
    ip_set_tags: Vec<String>,
    ip_sets: Vec<Arc<dyn crate::plugin::provider::Provider>>,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for RespIpMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        self.ip_sets =
            resolve_provider_tags(&self.registry, &self.ip_set_tags, "resp_ip", &self.tag)?;
        ensure_ip_capable_providers(&self.ip_sets, "resp_ip", &self.tag, &self.ip_set_tags)?;
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for RespIpMatcher {
    #[hotpath::measure]
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context.response().is_some_and(|response| {
            response.has_answer_ip(|ip| {
                self.ip_rules.contains_ip(ip) || self.ip_sets.iter().any(|set| set.contains_ip(ip))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::matcher::Matcher;
    use crate::proto::rdata::A;
    use crate::proto::{Message, Name, Question, RData, Record, RecordType};

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
    async fn test_resp_ip_matcher_only_checks_ip_rr() {
        let matcher = RespIpMatcher {
            tag: "resp_ip".into(),
            ip_rules: parse_ip_prefix_matcher("resp_ip", &["8.8.8.0/24".into()]).unwrap(),
            ip_set_tags: vec![],
            ip_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        let mut ctx = make_context();
        let mut response = Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(1, 1, 1, 8))),
        ));
        ctx.set_response(response);

        assert!(!matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_resp_ip_matcher_only_checks_answer_section() {
        let matcher = RespIpMatcher {
            tag: "resp_ip".into(),
            ip_rules: parse_ip_prefix_matcher("resp_ip", &["8.8.8.0/24".into()]).unwrap(),
            ip_set_tags: vec![],
            ip_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        let mut ctx = make_context();
        let mut response = Message::new();
        response.add_additional(Record::from_rdata(
            Name::from_ascii("ns.example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
        ));
        ctx.set_response(response);

        assert!(!matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_resp_ip_matcher_matches_a_record_and_requires_response() {
        let matcher = RespIpMatcher {
            tag: "resp_ip".into(),
            ip_rules: parse_ip_prefix_matcher("resp_ip", &["8.8.8.0/24".into()]).unwrap(),
            ip_set_tags: vec![],
            ip_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        let mut no_response_ctx = make_context();
        assert!(!matcher.is_match(&mut no_response_ctx));

        let mut hit_ctx = make_context();
        let mut response = Message::new();
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
        ));
        hit_ctx.set_response(response);
        assert!(matcher.is_match(&mut hit_ctx));
    }
}
