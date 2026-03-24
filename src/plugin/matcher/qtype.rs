/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `qtype` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches DNS question types in request queries.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    parse_quick_setup_rules, parse_rr_type, parse_rules_from_value, parse_u16_rules,
    validate_non_empty_rules,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct QtypeFactory {}

register_plugin_factory!("qtype", QtypeFactory {});

impl PluginFactory for QtypeFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        build_qtype_matcher(plugin_config.tag.clone(), rules)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_qtype_matcher(tag.to_string(), rules)
    }
}

fn build_qtype_matcher(tag: String, rules: Vec<String>) -> DnsResult<UninitializedPlugin> {
    validate_non_empty_rules("qtype", &rules)?;
    let qtypes = parse_u16_rules("qtype", &rules, parse_rr_type)?;
    Ok(UninitializedPlugin::Matcher(Box::new(QtypeMatcher {
        tag,
        qtypes,
    })))
}

#[derive(Debug)]
struct QtypeMatcher {
    tag: String,
    qtypes: AHashSet<u16>,
}

#[async_trait]
impl Plugin for QtypeMatcher {
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

impl Matcher for QtypeMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        context
            .request
            .questions()
            .iter()
            .any(|q| self.qtypes.contains(&u16::from(q.qtype())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::message::{DNSClass, Name, RecordType};
    use crate::message::{Message, Question};
    use crate::plugin::matcher::Matcher;
    use std::net::SocketAddr;

    fn make_context(qtypes: &[RecordType]) -> DnsContext {
        let mut request = Message::new();
        for qtype in qtypes {
            let mut query = Question::new(
                Name::from_ascii("example.com.").unwrap(),
                *qtype,
                crate::message::DNSClass::IN,
            );
            query.set_qclass(DNSClass::IN);
            request.add_question(query);
        }

        DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    #[tokio::test]
    async fn test_qtype_matcher_only_checks_qtype() {
        let matcher = QtypeMatcher {
            tag: "qtype".into(),
            qtypes: [u16::from(RecordType::AAAA)].into_iter().collect(),
        };
        let mut ctx = make_context(&[RecordType::A]);
        assert!(!matcher.is_match(&mut ctx));
    }

    #[test]
    fn test_build_qtype_matcher_rejects_empty_rules() {
        assert!(build_qtype_matcher("qtype".to_string(), vec![]).is_err());
    }

    #[tokio::test]
    async fn test_qtype_matcher_matches_when_any_query_type_matches() {
        let matcher = QtypeMatcher {
            tag: "qtype".into(),
            qtypes: [u16::from(RecordType::AAAA)].into_iter().collect(),
        };
        let mut ctx = make_context(&[RecordType::A, RecordType::AAAA]);
        assert!(matcher.is_match(&mut ctx));
    }
}
