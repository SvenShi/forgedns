/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `ptr_ip` matcher plugin.
//!
//! Matches IP decoded from PTR query names.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
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
use hickory_proto::rr::RecordType;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct PtrIpFactory {}

register_plugin_factory!("ptr_ip", PtrIpFactory {});

impl PluginFactory for PtrIpFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> DnsResult<()> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        let (ip_rules, ip_set_tags) = parse_ptr_ip_rules(rules)?;
        validate_non_empty_ptr_ip_rules(&ip_rules, &ip_set_tags)
    }

    fn get_dependencies(&self, plugin_config: &PluginConfig) -> Vec<String> {
        let Ok(rules) = parse_rules_from_value(plugin_config.args.clone()) else {
            return vec![];
        };
        let Ok((_, ip_set_tags)) = parse_ptr_ip_rules(rules) else {
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
    let (ip_rules, ip_set_tags) = parse_ptr_ip_rules(rules)?;
    validate_non_empty_ptr_ip_rules(&ip_rules, &ip_set_tags)?;

    Ok(UninitializedPlugin::Matcher(Box::new(PtrIpMatcher {
        tag,
        ip_rules,
        ip_set_tags,
        ip_sets: Vec::new(),
        registry,
    })))
}

fn parse_ptr_ip_rules(rules: Vec<String>) -> DnsResult<(IpPrefixMatcher, Vec<String>)> {
    let (mut inline_rules, ip_set_tags, files) = split_rule_sources(rules);
    let file_rules = load_rules_from_files(&files, "ptr_ip")?;
    inline_rules.extend(file_rules);
    let ip_rules = parse_ip_prefix_matcher("ptr_ip", &inline_rules)?;
    Ok((ip_rules, ip_set_tags))
}

fn validate_non_empty_ptr_ip_rules(
    ip_rules: &IpPrefixMatcher,
    ip_set_tags: &[String],
) -> DnsResult<()> {
    if !ip_rules.has_v4_rules() && !ip_rules.has_v6_rules() && ip_set_tags.is_empty() {
        return Err(DnsError::plugin(
            "ptr_ip matcher requires at least one IP rule or ip_set tag",
        ));
    }
    Ok(())
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

    async fn init(&mut self) {
        self.ip_sets =
            resolve_provider_tags(&self.registry, &self.ip_set_tags, "ptr_ip", &self.tag);
    }

    async fn destroy(&self) {}
}

impl Matcher for PtrIpMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context.request.queries().iter().any(|query| {
            if query.query_type() != RecordType::PTR {
                return false;
            }
            let name = query.name().to_utf8();
            let name = name.trim_end_matches('.');
            let Some(ip) = parse_ptr_name_ip(&name) else {
                return false;
            };
            self.ip_rules.contains_ip(ip) || self.ip_sets.iter().any(|set| set.contains_ip(ip))
        })
    }
}

fn parse_ptr_name_ip(name: &str) -> Option<IpAddr> {
    if let Some(v4) = parse_in_addr_arpa(name) {
        return Some(IpAddr::V4(v4));
    }
    if let Some(v6) = parse_ip6_arpa(name) {
        return Some(IpAddr::V6(v6));
    }
    None
}

fn parse_in_addr_arpa(name: &str) -> Option<Ipv4Addr> {
    let body = strip_ascii_case_suffix(name, ".in-addr.arpa")?;
    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for part in body.split('.') {
        if part.is_empty() || count >= 4 {
            return None;
        }
        octets[3 - count] = part.parse::<u8>().ok()?;
        count += 1;
    }
    if count != 4 {
        return None;
    }
    Some(Ipv4Addr::from(octets))
}

fn parse_ip6_arpa(name: &str) -> Option<Ipv6Addr> {
    let body = strip_ascii_case_suffix(name, ".ip6.arpa")?;
    let mut nibbles = [0u8; 32];
    let mut count = 0usize;
    for part in body.split('.') {
        if part.len() != 1 || count >= 32 {
            return None;
        }
        nibbles[31 - count] = u8::from_str_radix(part, 16).ok()?;
        count += 1;
    }
    if count != 32 {
        return None;
    }

    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = (nibbles[i * 2] << 4) | nibbles[i * 2 + 1];
    }

    Some(Ipv6Addr::from(bytes))
}

#[inline]
fn strip_ascii_case_suffix<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    if name.len() < suffix.len() {
        return None;
    }
    let split_at = name.len() - suffix.len();
    let (prefix, tail) = name.split_at(split_at);
    if !tail.eq_ignore_ascii_case(suffix) {
        return None;
    }
    Some(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{DnsContext, ExecFlowState};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::collections::HashMap;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_ptr_ip_match_ipv4_arpa() {
        let mut request = Message::new();
        request.add_query(Query::query(
            Name::from_ascii("1.0.168.192.in-addr.arpa.").unwrap(),
            RecordType::PTR,
        ));
        let mut ctx = DnsContext {
            src_addr: SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            response: None,
            exec_flow_state: ExecFlowState::Running,
            marks: Default::default(),
            attributes: HashMap::new(),
            registry: Arc::new(PluginRegistry::new()),
        };

        let matcher = PtrIpMatcher {
            tag: "ptr_ip".into(),
            ip_rules: parse_ip_prefix_matcher("ptr_ip", &["192.168.0.0/16".into()]).unwrap(),
            ip_set_tags: vec![],
            ip_sets: vec![],
            registry: Arc::new(PluginRegistry::new()),
        };

        assert!(matcher.is_match(&mut ctx));
    }
}
