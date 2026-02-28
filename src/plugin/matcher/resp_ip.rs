/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `resp_ip` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches A/AAAA records in response sections against configured IP rules.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::dns_utils::{response_records, rr_to_ip};
use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::IpPrefixMatcher;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    load_rules_from_files, parse_ip_prefix_matcher, parse_quick_setup_rules,
    parse_rules_from_value, resolve_provider_tags, split_rule_sources,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RespIpFactory {}

register_plugin_factory!("resp_ip", RespIpFactory {});

impl PluginFactory for RespIpFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        let (ip_rules, ip_set_tags) = parse_resp_ip_rules(rules)?;
        validate_non_empty_resp_ip_rules(&ip_rules, &ip_set_tags)
    }

    fn get_dependencies(&self, plugin_config: &PluginConfig) -> Vec<String> {
        let Ok(rules) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };
        let Ok((_, ip_set_tags)) = parse_resp_ip_rules(rules) else {
            return vec![];
        };
        ip_set_tags
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
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
    let (ip_rules, ip_set_tags) = parse_resp_ip_rules(rules)?;
    validate_non_empty_resp_ip_rules(&ip_rules, &ip_set_tags)?;

    Ok(UninitializedPlugin::Matcher(Box::new(RespIpMatcher {
        tag,
        ip_rules,
        ip_set_tags,
        ip_sets: Vec::new(),
        registry,
    })))
}

fn parse_resp_ip_rules(rules: Vec<String>) -> DnsResult<(IpPrefixMatcher, Vec<String>)> {
    let (mut inline_rules, ip_set_tags, files) = split_rule_sources(rules);
    let file_rules = load_rules_from_files(&files, "resp_ip")?;
    inline_rules.extend(file_rules);
    let ip_rules = parse_ip_prefix_matcher("resp_ip", &inline_rules)?;
    Ok((ip_rules, ip_set_tags))
}

fn validate_non_empty_resp_ip_rules(
    ip_rules: &IpPrefixMatcher,
    ip_set_tags: &[String],
) -> DnsResult<()> {
    if !ip_rules.has_v4_rules() && !ip_rules.has_v6_rules() && ip_set_tags.is_empty() {
        return Err(DnsError::plugin(
            "resp_ip matcher requires at least one IP rule or ip_set tag",
        ));
    }
    Ok(())
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

    async fn init(&mut self) {
        self.ip_sets =
            resolve_provider_tags(&self.registry, &self.ip_set_tags, "resp_ip", &self.tag);
    }

    async fn destroy(&self) {}
}

impl Matcher for RespIpMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        let Some(response) = context.response.as_ref() else {
            return false;
        };

        response_records(response).any(|record| {
            rr_to_ip(record).is_some_and(|ip| {
                self.ip_rules.contains_ip(ip) || self.ip_sets.iter().any(|set| set.contains_ip(ip))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{DnsContext, ExecFlowState};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::{Ipv4Addr, SocketAddr};

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
        ctx.response = Some(response);

        assert!(!matcher.is_match(&mut ctx));
    }
}
