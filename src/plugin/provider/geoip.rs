/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! V2Ray geoip.dat-backed IP provider.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::IpPrefixMatcher;
use crate::plugin::provider::Provider;
use crate::plugin::provider::v2ray_dat::{
    GeoIp, GeoIpList, cidr_to_rule, geoip_code, normalized_selectors,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use prost::Message;
use serde::Deserialize;
use std::any::Any;
use std::fs;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Debug, Clone, Deserialize)]
struct GeoIpArgs {
    file: String,
    #[serde(default)]
    selectors: Vec<String>,
}

#[derive(Debug)]
pub struct GeoIpProvider {
    tag: String,
    rules: Vec<String>,
    matcher: IpPrefixMatcher,
    has_v4_rules: bool,
    has_v6_rules: bool,
}

#[async_trait]
impl Plugin for GeoIpProvider {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

#[async_trait]
impl Provider for GeoIpProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ip_rules(&self) -> Option<&[String]> {
        Some(&self.rules)
    }

    fn contains_ip(&self, ip: IpAddr) -> bool {
        let has_family_rules = match ip {
            IpAddr::V4(_) => self.has_v4_rules,
            IpAddr::V6(_) => self.has_v6_rules,
        };
        if !has_family_rules {
            return false;
        }
        self.matcher.contains_ip(ip)
    }
}

#[derive(Debug, Clone)]
pub struct GeoIpFactory;

register_plugin_factory!("geoip", GeoIpFactory {});

impl PluginFactory for GeoIpFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let start_ms = AppClock::elapsed_millis();
        let args = plugin_config
            .args
            .clone()
            .ok_or_else(|| DnsError::plugin("geoip provider requires args"))?;
        let args = serde_yaml_ng::from_value::<GeoIpArgs>(args)
            .map_err(|e| DnsError::plugin(format!("failed to parse geoip config: {}", e)))?;

        if args.file.trim().is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' geoip args.file must not be empty",
                plugin_config.tag
            )));
        }

        let data = fs::read(&args.file).map_err(|e| {
            DnsError::plugin(format!(
                "plugin '{}' failed to read geoip dat file '{}': {}",
                plugin_config.tag, args.file, e
            ))
        })?;
        let geoip = GeoIpList::decode(data.as_slice()).map_err(|e| {
            DnsError::plugin(format!(
                "plugin '{}' failed to decode geoip dat file '{}': {}",
                plugin_config.tag, args.file, e
            ))
        })?;

        let requested_selectors = normalized_selectors(&args.selectors);
        let mut rules = Vec::new();
        let mut matcher = IpPrefixMatcher::default();
        let mut matched_entries = 0usize;

        for entry in geoip
            .entry
            .iter()
            .filter(|entry| matches_selector(entry, &requested_selectors))
        {
            matched_entries += 1;
            for cidr in &entry.cidr {
                let rule = cidr_to_rule(cidr).ok_or_else(|| {
                    DnsError::plugin(format!(
                        "plugin '{}' invalid CIDR bytes in geoip code '{}'",
                        plugin_config.tag,
                        geoip_code(entry)
                    ))
                })?;
                let source = format!("geoip code '{}'", geoip_code(entry));
                add_ip_rule(&mut matcher, &rule, &source)?;
                rules.push(rule);
            }
        }

        if matched_entries == 0 && !requested_selectors.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' found no geoip entries in '{}' for selectors {:?}",
                plugin_config.tag, args.file, args.selectors
            )));
        }

        matcher.finalize();
        if matcher.v4_rule_count() == 0 && matcher.v6_rule_count() == 0 {
            return Err(DnsError::plugin(format!(
                "plugin '{}' produced no IP rules from geoip dat '{}'",
                plugin_config.tag, args.file
            )));
        }

        let has_v4_rules = matcher.has_v4_rules();
        let has_v6_rules = matcher.has_v6_rules();
        let elapsed_ms = AppClock::elapsed_millis().saturating_sub(start_ms);
        info!(
            tag = %plugin_config.tag,
            file = %args.file,
            selectors = ?args.selectors,
            matched_entries,
            v4_rules = matcher.v4_rule_count(),
            v6_rules = matcher.v6_rule_count(),
            elapsed_ms,
            "geoip initialized"
        );
        debug!(tag = %plugin_config.tag, has_v4_rules, has_v6_rules, "geoip matcher compiled");

        Ok(UninitializedPlugin::Provider(Box::new(GeoIpProvider {
            tag: plugin_config.tag.clone(),
            rules,
            matcher,
            has_v4_rules,
            has_v6_rules,
        })))
    }
}

fn add_ip_rule(matcher: &mut IpPrefixMatcher, rule: &str, source: &str) -> DnsResult<()> {
    matcher.add_rule(rule).map_err(|e| {
        DnsError::plugin(format!("invalid ip/cidr '{}' in {}: {}", rule, source, e))
    })?;
    Ok(())
}

fn matches_selector(entry: &GeoIp, requested_selectors: &[String]) -> bool {
    if requested_selectors.is_empty() {
        return true;
    }
    let code = geoip_code(entry).to_ascii_lowercase();
    requested_selectors.iter().any(|wanted| wanted == &code)
}
