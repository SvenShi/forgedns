// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ptr_ip` matcher plugin.
//!
//! Matches IP decoded from PTR query names.

use std::fmt::Debug;
use std::net::IpAddr;
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
use crate::proto::RecordType;
use crate::register_plugin_factory;

#[derive(Debug, Clone)]
pub struct PtrIpFactory {}

register_plugin_factory!("ptr_ip", PtrIpFactory {});

impl PluginFactory for PtrIpFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        let Ok(rules) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };
        let Ok((_, ip_set_tags)) = parse_ip_rules_and_set_tags(rules, "ptr_ip") else {
            return vec![];
        };
        provider_dependency_specs("args.ip_set_tags", ip_set_tags)
    }

    fn get_quick_setup_dependency_specs(&self, param: Option<&str>) -> Vec<DependencySpec> {
        let Ok(rules) = parse_quick_setup_rules(param.map(str::to_owned)) else {
            return vec![];
        };
        let Ok((_, ip_set_tags)) = parse_ip_rules_and_set_tags(rules, "ptr_ip") else {
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
        build_ptr_ip_matcher(plugin_config.tag.clone(), rules, registry)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_ptr_ip_matcher(tag.to_string(), rules, registry)
    }
}

fn build_ptr_ip_matcher(
    tag: String,
    rules: Vec<String>,
    registry: Arc<PluginRegistry>,
) -> DnsResult<UninitializedPlugin> {
    let (ip_rules, ip_set_tags) = parse_ip_rules_and_set_tags(rules, "ptr_ip")?;
    validate_non_empty_ip_rules_or_set_tags("ptr_ip", &ip_rules, &ip_set_tags, "ip_set")?;

    Ok(UninitializedPlugin::Matcher(Box::new(PtrIpMatcher {
        tag,
        ip_rules,
        ip_set_tags,
        ip_sets: Vec::new(),
        registry,
    })))
}

#[derive(Debug)]
struct PtrIpMatcher {
    tag: String,
    ip_rules: IpPrefixMatcher,
    ip_set_tags: Vec<String>,
    ip_sets: Vec<Arc<dyn crate::plugin::provider::Provider>>,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for PtrIpMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        self.ip_sets =
            resolve_provider_tags(&self.registry, &self.ip_set_tags, "ptr_ip", &self.tag)?;
        ensure_ip_capable_providers(&self.ip_sets, "ptr_ip", &self.tag, &self.ip_set_tags)?;
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for PtrIpMatcher {
    #[hotpath::measure]
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context.request.questions().iter().any(|query| {
            if query.qtype() != RecordType::PTR {
                return false;
            }
            let Some(ip) = parse_ptr_name_ip(query.name()) else {
                return false;
            };
            self.ip_rules.contains_ip(ip) || self.ip_sets.iter().any(|set| set.contains_ip(ip))
        })
    }
}

fn parse_ptr_name_ip(name: &crate::proto::Name) -> Option<IpAddr> {
    name.parse_arpa_name()
        .ok()
        .map(|net| normalize_ip(net.addr()))
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::core::context::DnsContext;
    use crate::plugin::matcher::Matcher;
    use crate::proto::{Message, Name, Question, RecordType};

    #[tokio::test]
    async fn test_ptr_ip_match_ipv4_arpa() {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("1.0.168.192.in-addr.arpa.").unwrap(),
            RecordType::PTR,
            crate::proto::DNSClass::IN,
        ));
        let mut ctx = DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            Arc::new(PluginRegistry::new()),
        );

        let matcher = PtrIpMatcher {
            tag: "ptr_ip".into(),
            ip_rules: parse_ip_prefix_matcher("ptr_ip", &["192.168.0.0/16".into()]).unwrap(),
            ip_set_tags: vec![],
            ip_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        assert!(matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn test_ptr_ip_matcher_rejects_non_ptr_or_invalid_ptr_name() {
        let matcher = PtrIpMatcher {
            tag: "ptr_ip".into(),
            ip_rules: parse_ip_prefix_matcher("ptr_ip", &["192.168.0.0/16".into()]).unwrap(),
            ip_set_tags: vec![],
            ip_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        let mut non_ptr_request = Message::new();
        non_ptr_request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            crate::proto::DNSClass::IN,
        ));
        let mut non_ptr_ctx = DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            non_ptr_request,
            Arc::new(PluginRegistry::new()),
        );
        assert!(!matcher.is_match(&mut non_ptr_ctx));

        let mut invalid_ptr_request = Message::new();
        invalid_ptr_request.add_question(Question::new(
            Name::from_ascii("bad.ptr.example.com.").unwrap(),
            RecordType::PTR,
            crate::proto::DNSClass::IN,
        ));
        let mut invalid_ptr_ctx = DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            invalid_ptr_request,
            Arc::new(PluginRegistry::new()),
        );
        assert!(!matcher.is_match(&mut invalid_ptr_ctx));
    }
}
