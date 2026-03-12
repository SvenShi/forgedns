/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `qclass` matcher plugin.
//!
//! This plugin follows standard plugin lifecycle (`init/destroy`) and
//! matches DNS question classes in request queries.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::Result as DnsResult;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    parse_dns_class, parse_quick_setup_rules, parse_rules_from_value, parse_u16_rules,
    validate_non_empty_rules,
};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use ahash::AHashSet;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct QclassFactory {}

register_plugin_factory!("qclass", QclassFactory {});

impl PluginFactory for QclassFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_rules_from_value(plugin_config.args.clone())?;
        build_qclass_matcher(plugin_config.tag.clone(), rules)
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        _registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let rules = parse_quick_setup_rules(param)?;
        build_qclass_matcher(tag.to_string(), rules)
    }
}

fn build_qclass_matcher(tag: String, rules: Vec<String>) -> DnsResult<UninitializedPlugin> {
    validate_non_empty_rules("qclass", &rules)?;
    let qclasses = parse_u16_rules("qclass", &rules, parse_dns_class)?;
    Ok(UninitializedPlugin::Matcher(Box::new(QclassMatcher {
        tag,
        qclasses,
    })))
}

#[derive(Debug)]
struct QclassMatcher {
    tag: String,
    qclasses: AHashSet<u16>,
}

#[async_trait]
impl Plugin for QclassMatcher {
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

impl Matcher for QclassMatcher {
    fn is_match(&self, context: &mut DnsContext) -> bool {
        if context.request.question_count() == 1
            && let Some(qclass) = context.request.first_question_class()
        {
            return self.qclasses.contains(&u16::from(qclass));
        }

        context
            .request
            .questions()
            .iter()
            .any(|q| self.qclasses.contains(&u16::from(q.question_class())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::DnsContext;
    use crate::message::{DNSClass, Name, RecordType};
    use crate::message::{Message, Question};
    use std::net::SocketAddr;

    fn make_context(qclass: DNSClass) -> DnsContext {
        let mut request = Message::new();
        let mut query = Question::new(Name::from_ascii("example.com.").unwrap(), RecordType::A);
        query.set_question_class(qclass);
        request.add_question(query);

        DnsContext::new(
            SocketAddr::new("127.0.0.1".parse().unwrap(), 5353),
            request,
            Arc::new(PluginRegistry::new()),
        )
    }

    #[test]
    fn test_build_qclass_matcher_rejects_empty_rules() {
        assert!(build_qclass_matcher("qclass".to_string(), vec![]).is_err());
    }

    #[test]
    fn test_qclass_matcher_checks_query_class() {
        let matcher = QclassMatcher {
            tag: "qclass".to_string(),
            qclasses: [u16::from(DNSClass::CH)].into_iter().collect(),
        };

        let mut in_ctx = make_context(DNSClass::IN);
        assert!(!matcher.is_match(&mut in_ctx));

        let mut ch_ctx = make_context(DNSClass::CH);
        assert!(matcher.is_match(&mut ch_ctx));
    }
}
