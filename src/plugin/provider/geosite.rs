/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! V2Ray geosite.dat-backed domain provider.

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::core::rule_matcher::DomainRuleMatcher;
use crate::plugin::provider::Provider;
use crate::plugin::provider::v2ray_dat::{
    GeoSiteList, geosite_code, geosite_domain_expression, geosite_domain_matches_selectors,
    matched_geosite_selectors, parse_geosite_selectors,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::proto::{Name, Question};
use crate::register_plugin_factory;
use async_trait::async_trait;
use prost::Message;
use serde::Deserialize;
use std::any::Any;
use std::fs;
use std::sync::Arc;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
struct GeoSiteArgs {
    file: String,
    #[serde(default)]
    selectors: Vec<String>,
}

#[derive(Debug)]
pub struct GeoSiteProvider {
    tag: String,
    rules: Vec<String>,
    matcher: DomainRuleMatcher,
}

#[async_trait]
impl Plugin for GeoSiteProvider {
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
impl Provider for GeoSiteProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn contains_name(&self, name: &Name) -> bool {
        self.matcher.is_match_name(name)
    }

    fn contains_question(&self, question: &Question) -> bool {
        self.contains_name(question.name())
    }

    fn domain_rules(&self) -> Option<&[String]> {
        Some(&self.rules)
    }
}

#[derive(Debug, Clone)]
pub struct GeoSiteFactory;

register_plugin_factory!("geosite", GeoSiteFactory {});

impl PluginFactory for GeoSiteFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let start_ms = AppClock::elapsed_millis();
        let args = plugin_config
            .args
            .clone()
            .ok_or_else(|| DnsError::plugin("geosite provider requires args"))?;
        let args = serde_yaml_ng::from_value::<GeoSiteArgs>(args)
            .map_err(|e| DnsError::plugin(format!("failed to parse geosite config: {}", e)))?;

        if args.file.trim().is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' geosite args.file must not be empty",
                plugin_config.tag
            )));
        }

        let data = fs::read(&args.file).map_err(|e| {
            DnsError::plugin(format!(
                "plugin '{}' failed to read geosite dat file '{}': {}",
                plugin_config.tag, args.file, e
            ))
        })?;
        let geosite = GeoSiteList::decode(data.as_slice()).map_err(|e| {
            DnsError::plugin(format!(
                "plugin '{}' failed to decode geosite dat file '{}': {}",
                plugin_config.tag, args.file, e
            ))
        })?;

        let selectors = parse_geosite_selectors(&args.selectors).map_err(|e| {
            DnsError::plugin(format!(
                "plugin '{}' failed to parse geosite selectors: {}",
                plugin_config.tag, e
            ))
        })?;
        let mut rules = Vec::new();
        let mut matcher = DomainRuleMatcher::default();
        let mut matched_entries = 0usize;
        let mut matched_domains = 0usize;

        for entry in &geosite.entry {
            if selectors.is_empty() {
                matched_entries += 1;
                for domain in &entry.domain {
                    let exp = geosite_domain_expression(domain).map_err(|e| {
                        DnsError::plugin(format!(
                            "plugin '{}' geosite code '{}' {}",
                            plugin_config.tag,
                            geosite_code(entry),
                            e
                        ))
                    })?;
                    let source = format!("geosite code '{}'", geosite_code(entry));
                    matcher
                        .add_expression(&exp, &source)
                        .map_err(DnsError::plugin)?;
                    rules.push(exp);
                    matched_domains += 1;
                }
                continue;
            }

            let matched_selectors = matched_geosite_selectors(entry, &selectors);
            if matched_selectors.is_empty() {
                continue;
            }
            matched_entries += 1;
            for domain in &entry.domain {
                if !geosite_domain_matches_selectors(domain, &matched_selectors) {
                    continue;
                }
                let exp = geosite_domain_expression(domain).map_err(|e| {
                    DnsError::plugin(format!(
                        "plugin '{}' geosite code '{}' {}",
                        plugin_config.tag,
                        geosite_code(entry),
                        e
                    ))
                })?;
                let source = format!("geosite code '{}'", geosite_code(entry));
                matcher
                    .add_expression(&exp, &source)
                    .map_err(DnsError::plugin)?;
                rules.push(exp);
                matched_domains += 1;
            }
        }

        if matched_entries == 0 && !selectors.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' found no geosite entries in '{}' for selectors {:?}",
                plugin_config.tag, args.file, args.selectors
            )));
        }

        if matched_domains == 0 && !selectors.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' found no geosite rules in '{}' for selectors {:?}",
                plugin_config.tag, args.file, args.selectors
            )));
        }

        matcher.finalize()?;
        let has_rules = matcher.full_rule_count()
            + matcher.trie_rule_count()
            + matcher.keyword_rule_count()
            + matcher.regexp_rule_count();
        if has_rules == 0 {
            return Err(DnsError::plugin(format!(
                "plugin '{}' produced no domain rules from geosite dat '{}'",
                plugin_config.tag, args.file
            )));
        }

        let elapsed_ms = AppClock::elapsed_millis().saturating_sub(start_ms);
        info!(
            tag = %plugin_config.tag,
            file = %args.file,
            selectors = ?args.selectors,
            matched_entries,
            matched_domains,
            full_rules = matcher.full_rule_count(),
            domain_rules = matcher.trie_rule_count(),
            keyword_rules = matcher.keyword_rule_count(),
            regex_rules = matcher.regexp_rule_count(),
            elapsed_ms,
            "geosite initialized"
        );

        Ok(UninitializedPlugin::Provider(Box::new(GeoSiteProvider {
            tag: plugin_config.tag.clone(),
            rules,
            matcher,
        })))
    }
}
