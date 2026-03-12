/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `ptr_ip` matcher plugin.
//!
//! Matches IP decoded from PTR query names.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::core::rule_matcher::IpPrefixMatcher;
use crate::message::RecordType;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::matcher::Matcher;
#[cfg(test)]
use crate::plugin::matcher::matcher_utils::parse_ip_prefix_matcher;
use crate::plugin::matcher::matcher_utils::{
    parse_ip_rules_and_set_tags, parse_quick_setup_rules, parse_rules_from_value,
    resolve_provider_tags, validate_non_empty_ip_rules_or_set_tags,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use std::fmt::Debug;
use std::net::IpAddr;
use std::sync::Arc;

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
        ip_set_tags
            .into_iter()
            .enumerate()
            .map(|(idx, tag)| {
                DependencySpec::provider_type(format!("args.ip_set_tags[{}]", idx), tag, "ip_set")
            })
            .collect()
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
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for PtrIpMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        if context.request.question_count() == 1
            && let Some(question) = context.question()
        {
            if question.qtype() != u16::from(RecordType::PTR) {
                return false;
            }
            let Some(ip) = parse_ptr_name_ip_str(question.normalized_name()) else {
                return false;
            };
            return self.ip_rules.contains_ip(ip)
                || self.ip_sets.iter().any(|set| set.contains_ip(ip));
        }

        if let Some(packet) = context.request.packet() {
            let Ok(parsed) = packet.parse() else {
                return false;
            };
            for question in parsed.question_records() {
                let Ok(question) = question else {
                    return false;
                };
                if question.question_type() != RecordType::PTR {
                    continue;
                }
                let Some(ip) = parse_ptr_name_ip_ref(question.name()) else {
                    continue;
                };
                if self.ip_rules.contains_ip(ip)
                    || self.ip_sets.iter().any(|set| set.contains_ip(ip))
                {
                    return true;
                }
            }
            return false;
        }

        context.request.questions().iter().any(|query| {
            if query.question_type() != RecordType::PTR {
                return false;
            }
            let Some(ip) = parse_ptr_name_ip(query.name()) else {
                return false;
            };
            self.ip_rules.contains_ip(ip) || self.ip_sets.iter().any(|set| set.contains_ip(ip))
        })
    }
}

fn parse_ptr_name_ip(name: &crate::message::Name) -> Option<IpAddr> {
    name.parse_arpa_name()
        .ok()
        .map(|net| normalize_ip(net.addr()))
}

fn parse_ptr_name_ip_ref(name: &crate::message::NameRef<'_>) -> Option<IpAddr> {
    let mut labels = name.iter_labels_rev();
    let suffix = labels.next()?;
    if !suffix.eq_ignore_ascii_case("arpa") {
        return None;
    }

    let zone = labels.next()?;
    if zone.eq_ignore_ascii_case("in-addr") {
        let mut octets = [0u8; 4];
        for octet in &mut octets {
            *octet = labels.next()?.parse::<u8>().ok()?;
        }
        return labels.next().is_none().then_some(IpAddr::V4(octets.into()));
    }

    if zone.eq_ignore_ascii_case("ip6") {
        let mut bytes = [0u8; 16];
        for byte in &mut bytes {
            let high = parse_hex_nibble(labels.next()?)?;
            let low = parse_hex_nibble(labels.next()?)?;
            *byte = (high << 4) | low;
        }
        return labels
            .next()
            .is_none()
            .then_some(normalize_ip(IpAddr::V6(bytes.into())));
    }

    None
}

fn parse_ptr_name_ip_str(name: &str) -> Option<IpAddr> {
    if let Some(prefix) = name.strip_suffix(".in-addr.arpa") {
        let mut parts = prefix
            .split('.')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        if parts.len() != 4 {
            return None;
        }
        parts.reverse();
        let mut octets = [0u8; 4];
        for (idx, part) in parts.into_iter().enumerate() {
            octets[idx] = part.parse::<u8>().ok()?;
        }
        return Some(IpAddr::V4(octets.into()));
    }

    if let Some(prefix) = name.strip_suffix(".ip6.arpa") {
        let nibbles = prefix
            .split('.')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        if nibbles.len() != 32 {
            return None;
        }

        let mut hex = String::with_capacity(32);
        for nibble in nibbles.iter().rev() {
            if nibble.len() != 1 || !nibble.as_bytes()[0].is_ascii_hexdigit() {
                return None;
            }
            hex.push_str(nibble);
        }

        let mut bytes = [0u8; 16];
        for idx in 0..16 {
            bytes[idx] = u8::from_str_radix(&hex[idx * 2..idx * 2 + 2], 16).ok()?;
        }
        return Some(normalize_ip(IpAddr::V6(bytes.into())));
    }

    None
}

fn parse_hex_nibble(label: &str) -> Option<u8> {
    if label.len() != 1 {
        return None;
    }
    label
        .as_bytes()
        .first()
        .and_then(|byte| (*byte as char).to_digit(16))
        .map(|digit| digit as u8)
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
    use super::*;
    use crate::core::context::DnsContext;
    use crate::message::{Message, Question};
    use crate::message::{Name, RecordType};
    use crate::plugin::matcher::Matcher;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_ptr_ip_match_ipv4_arpa() {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("1.0.168.192.in-addr.arpa.").unwrap(),
            RecordType::PTR,
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
        ));
        let mut invalid_ptr_ctx = DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            invalid_ptr_request,
            Arc::new(PluginRegistry::new()),
        );
        assert!(!matcher.is_match(&mut invalid_ptr_ctx));
    }
}
