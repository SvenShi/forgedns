// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `client_ip` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches request source address against configured IP rules.

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
pub struct ClientIpFactory {}

register_plugin_factory!("client_ip", ClientIpFactory {});

impl PluginFactory for ClientIpFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let Ok(rules) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };
        let Ok((_, ip_set_tags)) = parse_ip_rules_and_set_tags(rules, "client_ip") else {
            return vec![];
        };
        provider_dependency_specs("args.ip_set_tags", ip_set_tags)
    }

    fn get_quick_setup_dependency_specs(&self, param: Option<&str>) -> Vec<DependencySpec> {
        let Ok(rules) = parse_quick_setup_rules(param.map(str::to_owned)) else {
            return vec![];
        };
        let Ok((_, ip_set_tags)) = parse_ip_rules_and_set_tags(rules, "client_ip") else {
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
        build_client_ip_matcher(plugin_config.tag.clone(), rules, registry)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_client_ip_matcher(tag.to_string(), rules, registry)
    }
}

fn build_client_ip_matcher(
    tag: String,
    rules: Vec<String>,
    registry: Arc<PluginRegistry>,
) -> DnsResult<UninitializedPlugin> {
    let (client_ip_rules, ip_set_tags) = parse_ip_rules_and_set_tags(rules, "client_ip")?;
    validate_non_empty_ip_rules_or_set_tags("client_ip", &client_ip_rules, &ip_set_tags, "ip_set")?;

    Ok(UninitializedPlugin::Matcher(Box::new(ClientIpMatcher {
        tag,
        client_ip_rules,
        ip_set_tags,
        ip_sets: Vec::new(),
        registry,
    })))
}

#[derive(Debug)]
struct ClientIpMatcher {
    tag: String,
    client_ip_rules: IpPrefixMatcher,
    ip_set_tags: Vec<String>,
    ip_sets: Vec<Arc<dyn crate::plugin::provider::Provider>>,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for ClientIpMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        self.ip_sets =
            resolve_provider_tags(&self.registry, &self.ip_set_tags, "client_ip", &self.tag)?;
        ensure_ip_capable_providers(&self.ip_sets, "client_ip", &self.tag, &self.ip_set_tags)?;
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for ClientIpMatcher {
    #[hotpath::measure]
    fn is_match(&self, context: &mut DnsContext) -> bool {
        let client_ip = context.peer_addr().ip();
        self.client_ip_rules.contains_ip(client_ip)
            || self.ip_sets.iter().any(|set| set.contains_ip(client_ip))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::matcher::Matcher;
    use crate::proto::{DNSClass, Message, Name, Question, RecordType};

    fn make_context() -> DnsContext {
        let mut request = Message::new();
        let mut query = Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            crate::proto::DNSClass::IN,
        );
        query.set_qclass(DNSClass::IN);
        request.add_question(query);

        DnsContext::new(
            SocketAddr::new("192.168.1.10".parse().unwrap(), 5353),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    #[tokio::test]
    async fn test_client_ip_matcher_only_checks_src_ip() {
        let matcher = ClientIpMatcher {
            tag: "client_ip".into(),
            client_ip_rules: parse_ip_prefix_matcher("client_ip", &["10.0.0.0/8".into()]).unwrap(),
            ip_set_tags: vec![],
            ip_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };
        let mut ctx = make_context();
        assert!(!matcher.is_match(&mut ctx));
    }

    #[test]
    fn test_build_client_ip_matcher_rejects_empty_rules_and_set_tags() {
        let result = build_client_ip_matcher(
            "client_ip".to_string(),
            vec![],
            Arc::new(PluginRegistry::new()),
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_client_ip_matcher_matches_allowed_prefix() {
        let matcher = ClientIpMatcher {
            tag: "client_ip".into(),
            client_ip_rules: parse_ip_prefix_matcher("client_ip", &["192.168.0.0/16".into()])
                .unwrap(),
            ip_set_tags: vec![],
            ip_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };
        let mut ctx = make_context();
        ctx.set_peer_addr(SocketAddr::from((Ipv4Addr::new(192, 168, 2, 9), 5353)));
        assert!(matcher.is_match(&mut ctx));
    }
}
