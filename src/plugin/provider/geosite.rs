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
use arc_swap::ArcSwap;
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

#[derive(Debug, Default)]
struct GeoSiteSnapshot {
    matcher: DomainRuleMatcher,
}

#[derive(Debug)]
pub struct GeoSiteProvider {
    tag: String,
    args: GeoSiteArgs,
    snapshot: ArcSwap<GeoSiteSnapshot>,
}

impl GeoSiteProvider {
    #[hotpath::measure]
    fn build_snapshot(&self) -> DnsResult<GeoSiteSnapshot> {
        let start_ms = AppClock::elapsed_millis();

        let data = fs::read(&self.args.file).map_err(|e| {
            DnsError::plugin(format!(
                "plugin '{}' failed to read geosite dat file '{}': {}",
                self.tag, self.args.file, e
            ))
        })?;
        let geosite = GeoSiteList::decode(data.as_slice()).map_err(|e| {
            DnsError::plugin(format!(
                "plugin '{}' failed to decode geosite dat file '{}': {}",
                self.tag, self.args.file, e
            ))
        })?;

        let selectors = parse_geosite_selectors(&self.args.selectors).map_err(|e| {
            DnsError::plugin(format!(
                "plugin '{}' failed to parse geosite selectors: {}",
                self.tag, e
            ))
        })?;

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
                            self.tag,
                            geosite_code(entry),
                            e
                        ))
                    })?;
                    let source = format!("geosite code '{}'", geosite_code(entry));
                    matcher
                        .add_expression(&exp, &source)
                        .map_err(DnsError::plugin)?;
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
                        self.tag,
                        geosite_code(entry),
                        e
                    ))
                })?;
                let source = format!("geosite code '{}'", geosite_code(entry));
                matcher
                    .add_expression(&exp, &source)
                    .map_err(DnsError::plugin)?;
                matched_domains += 1;
            }
        }

        if matched_entries == 0 && !selectors.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' found no geosite entries in '{}' for selectors {:?}",
                self.tag, self.args.file, self.args.selectors
            )));
        }

        if matched_domains == 0 && !selectors.is_empty() {
            return Err(DnsError::plugin(format!(
                "plugin '{}' found no geosite rules in '{}' for selectors {:?}",
                self.tag, self.args.file, self.args.selectors
            )));
        }

        matcher.finalize().map_err(DnsError::plugin)?;
        let has_rules = matcher.full_rule_count()
            + matcher.trie_rule_count()
            + matcher.keyword_rule_count()
            + matcher.regexp_rule_count();
        if has_rules == 0 {
            return Err(DnsError::plugin(format!(
                "plugin '{}' produced no domain rules from geosite dat '{}'",
                self.tag, self.args.file
            )));
        }

        let elapsed_ms = AppClock::elapsed_millis().saturating_sub(start_ms);
        info!(
            tag = %self.tag,
            file = %self.args.file,
            selectors = ?self.args.selectors,
            matched_entries,
            matched_domains,
            full_rules = matcher.full_rule_count(),
            domain_rules = matcher.trie_rule_count(),
            keyword_rules = matcher.keyword_rule_count(),
            regex_rules = matcher.regexp_rule_count(),
            elapsed_ms,
            "geosite snapshot built"
        );

        Ok(GeoSiteSnapshot { matcher })
    }
}

#[async_trait]
impl Plugin for GeoSiteProvider {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        self.reload().await
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

    #[hotpath::measure]
    fn contains_name(&self, name: &Name) -> bool {
        self.snapshot.load().matcher.is_match_name(name)
    }

    #[hotpath::measure]
    fn contains_question(&self, question: &Question) -> bool {
        self.contains_name(question.name())
    }

    #[hotpath::measure]
    async fn reload(&self) -> DnsResult<()> {
        let snapshot = self.build_snapshot()?;
        self.snapshot.store(Arc::new(snapshot));
        Ok(())
    }

    fn supports_domain_matching(&self) -> bool {
        true
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
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
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

        Ok(UninitializedPlugin::Provider(Box::new(GeoSiteProvider {
            tag: plugin_config.tag.clone(),
            args,
            snapshot: ArcSwap::from_pointee(GeoSiteSnapshot::default()),
        })))
    }
}
