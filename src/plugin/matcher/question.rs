// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! `question` matcher plugin.
//!
//! Matches request questions against provider plugins that implement
//! [`Provider::contains_question`].

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use serde_yaml_ng::Value;

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result as DnsResult};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::matcher::Matcher;
use crate::plugin::matcher::matcher_utils::{
    parse_quick_setup_rules, parse_rules_from_value, provider_dependency_specs,
    resolve_provider_tags, split_rule_sources,
};
use crate::plugin::provider::Provider;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;

#[derive(Debug, Clone)]
pub struct QuestionFactory;

register_plugin_factory!("question", QuestionFactory {});

impl PluginFactory for QuestionFactory {
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        parse_provider_tags_from_value(plugin_config.args.clone())
            .map(|provider_tags| provider_dependency_specs("args", provider_tags))
            .unwrap_or_default()
    }

    fn get_quick_setup_dependency_specs(&self, param: Option<&str>) -> Vec<DependencySpec> {
        parse_quick_setup_rules(param.map(str::to_owned))
            .and_then(parse_provider_tags)
            .map(|provider_tags| provider_dependency_specs("provider_tags", provider_tags))
            .unwrap_or_default()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
        _context: &crate::plugin::PluginCreateContext,
    ) -> DnsResult<UninitializedPlugin> {
        let provider_tags = parse_provider_tags_from_value(plugin_config.args.clone())?;

        Ok(UninitializedPlugin::Matcher(Box::new(QuestionMatcher {
            tag: plugin_config.tag.clone(),
            provider_tags,
            providers: Vec::new(),
            registry,
        })))
    }

    fn quick_setup(
        &self,
        tag: &str,
        param: Option<String>,
        registry: Arc<PluginRegistry>,
    ) -> DnsResult<UninitializedPlugin> {
        let provider_tags = parse_provider_tags(parse_quick_setup_rules(param)?)?;
        Ok(UninitializedPlugin::Matcher(Box::new(QuestionMatcher {
            tag: tag.to_string(),
            provider_tags,
            providers: Vec::new(),
            registry,
        })))
    }
}

#[derive(Debug)]
struct QuestionMatcher {
    tag: String,
    provider_tags: Vec<String>,
    providers: Vec<Arc<dyn Provider>>,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl Plugin for QuestionMatcher {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) -> DnsResult<()> {
        self.providers =
            resolve_provider_tags(&self.registry, &self.provider_tags, "question", &self.tag)?;
        Ok(())
    }

    async fn destroy(&self) -> DnsResult<()> {
        Ok(())
    }
}

impl Matcher for QuestionMatcher {
    #[hotpath::measure]
    fn is_match(&self, context: &mut crate::core::context::DnsContext) -> bool {
        context.request().questions().iter().any(|question| {
            self.providers
                .iter()
                .any(|provider| provider.contains_question(question))
        })
    }
}

fn parse_provider_tags_from_value(args: Option<Value>) -> DnsResult<Vec<String>> {
    parse_provider_tags(parse_rules_from_value(args)?)
}

fn parse_provider_tags(raw_rules: Vec<String>) -> DnsResult<Vec<String>> {
    let (inline_rules, provider_tags, files) = split_rule_sources(raw_rules);
    if !inline_rules.is_empty() || !files.is_empty() {
        return Err(DnsError::plugin(
            "question matcher only accepts provider references like '$provider_tag'",
        ));
    }
    if provider_tags.is_empty() {
        return Err(DnsError::plugin(
            "question matcher requires at least one provider tag",
        ));
    }
    Ok(provider_tags)
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use crate::plugin::matcher::Matcher;
    use crate::plugin::test_utils::test_registry;
    use crate::proto::{DNSClass, Message, Name, Question, RecordType};

    #[derive(Debug)]
    struct StubQuestionProvider;

    #[async_trait]
    impl Plugin for StubQuestionProvider {
        fn tag(&self) -> &str {
            "stub"
        }

        async fn init(&mut self) -> DnsResult<()> {
            Ok(())
        }

        async fn destroy(&self) -> DnsResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Provider for StubQuestionProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn contains_question(&self, question: &Question) -> bool {
            question.name().to_fqdn() == "match.example."
        }
    }

    fn make_context(names: &[&str]) -> crate::core::context::DnsContext {
        let mut request = Message::new();
        for name in names {
            request.add_question(Question::new(
                Name::from_ascii(name).unwrap(),
                RecordType::A,
                DNSClass::IN,
            ));
        }
        crate::core::context::DnsContext::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
            request,
            test_registry(),
        )
    }

    #[tokio::test]
    async fn question_matcher_matches_when_any_question_matches() {
        let matcher = QuestionMatcher {
            tag: "question".into(),
            provider_tags: vec![],
            providers: vec![Arc::new(StubQuestionProvider)],
            registry: test_registry(),
        };
        let mut ctx = make_context(&["miss.example.", "match.example."]);
        assert!(matcher.is_match(&mut ctx));
    }

    #[tokio::test]
    async fn question_matcher_returns_false_when_no_question_matches() {
        let matcher = QuestionMatcher {
            tag: "question".into(),
            provider_tags: vec![],
            providers: vec![Arc::new(StubQuestionProvider)],
            registry: test_registry(),
        };
        let mut ctx = make_context(&["miss.example."]);
        assert!(!matcher.is_match(&mut ctx));
    }
}
