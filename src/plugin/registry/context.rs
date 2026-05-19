// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Plugin dependency resolver interfaces and initialization context.

use std::sync::Arc;

use crate::core::error::Result;
use crate::plugin::executor::Executor;
use crate::plugin::matcher::Matcher;
use crate::plugin::provider::Provider;
use crate::plugin::{
    PluginCreateContext, PluginDependent, PluginHolder, PluginInfo, PluginRegistry,
};

pub trait PluginResolver {
    fn executor(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
    ) -> Result<Arc<dyn Executor>>;
    fn executor_of_type(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
        expected_plugin_type: &str,
    ) -> Result<Arc<dyn Executor>>;
    fn matcher(&self, source_tag: &str, field: &str, target_tag: &str) -> Result<Arc<dyn Matcher>>;
    fn provider(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
    ) -> Result<Arc<dyn Provider>>;
    fn provider_of_type(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
        expected_plugin_type: &str,
    ) -> Result<Arc<dyn Provider>>;
}

#[derive(Debug)]
pub struct PluginInitContext<'a> {
    registry: Arc<PluginRegistry>,
    tag: String,
    create_context: &'a PluginCreateContext,
}

impl<'a> PluginInitContext<'a> {
    pub(crate) fn new(
        registry: Arc<PluginRegistry>,
        tag: impl Into<String>,
        create_context: &'a PluginCreateContext,
    ) -> Self {
        Self {
            registry,
            tag: tag.into(),
            create_context,
        }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn dependents(&self) -> &[PluginDependent] {
        &self.create_context.dependents
    }

    pub fn plugin(&self, field: &str, target_tag: &str) -> Result<Arc<PluginInfo>> {
        self.registry
            .get_required_plugin(&self.tag, field, target_tag)
    }

    pub fn executor(&self, field: &str, target_tag: &str) -> Result<Arc<dyn Executor>> {
        self.registry
            .get_executor_dependency(&self.tag, field, target_tag)
    }

    pub fn executor_of_type(
        &self,
        field: &str,
        target_tag: &str,
        expected_plugin_type: &str,
    ) -> Result<Arc<dyn Executor>> {
        self.registry.get_executor_dependency_of_type(
            &self.tag,
            field,
            target_tag,
            expected_plugin_type,
        )
    }

    pub fn matcher(&self, field: &str, target_tag: &str) -> Result<Arc<dyn Matcher>> {
        self.registry
            .get_matcher_dependency(&self.tag, field, target_tag)
    }

    pub fn provider(&self, field: &str, target_tag: &str) -> Result<Arc<dyn Provider>> {
        self.registry
            .get_provider_dependency(&self.tag, field, target_tag)
    }

    pub fn provider_of_type(
        &self,
        field: &str,
        target_tag: &str,
        expected_plugin_type: &str,
    ) -> Result<Arc<dyn Provider>> {
        self.registry.get_provider_dependency_of_type(
            &self.tag,
            field,
            target_tag,
            expected_plugin_type,
        )
    }

    pub async fn init_quick_setup(
        &self,
        plugin_type: &str,
        tag: &str,
        param: Option<String>,
    ) -> Result<PluginHolder> {
        let uninitialized = self.registry.clone().quick_setup(plugin_type, tag, param)?;
        let context = PluginCreateContext::default();
        let init_context = PluginInitContext::new(self.registry.clone(), tag, &context);
        uninitialized.init_and_wrap(&init_context).await
    }
}

impl PluginResolver for PluginRegistry {
    fn executor(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
    ) -> Result<Arc<dyn Executor>> {
        self.get_executor_dependency(source_tag, field, target_tag)
    }

    fn executor_of_type(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
        expected_plugin_type: &str,
    ) -> Result<Arc<dyn Executor>> {
        self.get_executor_dependency_of_type(source_tag, field, target_tag, expected_plugin_type)
    }

    fn matcher(&self, source_tag: &str, field: &str, target_tag: &str) -> Result<Arc<dyn Matcher>> {
        self.get_matcher_dependency(source_tag, field, target_tag)
    }

    fn provider(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
    ) -> Result<Arc<dyn Provider>> {
        self.get_provider_dependency(source_tag, field, target_tag)
    }

    fn provider_of_type(
        &self,
        source_tag: &str,
        field: &str,
        target_tag: &str,
        expected_plugin_type: &str,
    ) -> Result<Arc<dyn Provider>> {
        self.get_provider_dependency_of_type(source_tag, field, target_tag, expected_plugin_type)
    }
}
