/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `fallback` executor plugin.
//!
//! Runs a primary executable and falls back to secondary on failure / timeout.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, PluginType, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use hickory_proto::op::Message;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Deserialize)]
struct FallbackConfig {
    primary: String,
    secondary: String,
    #[serde(default)]
    threshold: u64,
    #[serde(default)]
    always_standby: bool,
}

#[derive(Debug)]
struct FallbackExecutor {
    tag: String,
    primary_tag: String,
    secondary_tag: String,
    primary: Arc<dyn Executor>,
    secondary: Arc<dyn Executor>,
    threshold: Duration,
    always_standby: bool,
}

#[derive(Debug)]
struct Outcome {
    response: Option<Message>,
    source: &'static str,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PrimaryState {
    Running,
    Success,
    Failed,
}

#[async_trait]
impl Plugin for FallbackExecutor {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {}

    async fn destroy(&self) {}
}

#[async_trait]
impl Executor for FallbackExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let base = context.clone_for_subquery();
        let mut join_set = JoinSet::new();
        let (primary_state_tx, primary_state_rx) = watch::channel(PrimaryState::Running);

        let primary = self.primary.clone();
        let mut primary_ctx = base.clone_for_subquery();
        join_set.spawn(async move {
            let outcome = run_executor(primary, &mut primary_ctx, "primary").await;
            let state = if outcome.response.is_some() {
                PrimaryState::Success
            } else {
                PrimaryState::Failed
            };
            let _ = primary_state_tx.send(state);
            outcome
        });

        let secondary = self.secondary.clone();
        let mut secondary_ctx = base.clone_for_subquery();
        let delay = self.threshold;
        let always_standby = self.always_standby;
        let mut primary_state_rx = primary_state_rx.clone();
        join_set.spawn(async move {
            if !always_standby {
                let sleeper = tokio::time::sleep(delay);
                tokio::pin!(sleeper);
                loop {
                    tokio::select! {
                        _ = &mut sleeper => break,
                        changed = primary_state_rx.changed() => {
                            if changed.is_err() {
                                break;
                            }
                            match *primary_state_rx.borrow() {
                                PrimaryState::Running => {}
                                PrimaryState::Success => {
                                    return Outcome {
                                        response: None,
                                        source: "secondary",
                                        error: None,
                                    };
                                }
                                PrimaryState::Failed => break,
                            }
                        }
                    }
                }
            }
            run_executor(secondary, &mut secondary_ctx, "secondary").await
        });

        let mut last_err = String::new();
        let mut buffered_secondary: Option<Message> = None;
        let mut threshold_reached = !self.always_standby;
        let standby_timer = tokio::time::sleep(self.threshold);
        tokio::pin!(standby_timer);
        loop {
            tokio::select! {
                _ = &mut standby_timer, if self.always_standby && !threshold_reached => {
                    threshold_reached = true;
                    if let Some(response) = buffered_secondary.take() {
                        context.response = Some(response);
                        join_set.abort_all();
                        return Ok(ExecStep::Next);
                    }
                }
                joined = join_set.join_next() => {
                    let Some(joined) = joined else {
                        break;
                    };
                    let outcome = match joined {
                        Ok(outcome) => outcome,
                        Err(e) => {
                            last_err = format!("fallback subtask join error: {}", e);
                            continue;
                        }
                    };

                    match outcome.source {
                        "primary" => {
                            if let Some(response) = outcome.response {
                                context.response = Some(response);
                                join_set.abort_all();
                                return Ok(ExecStep::Next);
                            }
                            if let Some(response) = buffered_secondary.take() {
                                context.response = Some(response);
                                join_set.abort_all();
                                return Ok(ExecStep::Next);
                            }
                        }
                        "secondary" => {
                            if let Some(response) = outcome.response {
                                if !self.always_standby || threshold_reached {
                                    context.response = Some(response);
                                    join_set.abort_all();
                                    return Ok(ExecStep::Next);
                                }
                                buffered_secondary = Some(response);
                            }
                        }
                        _ => {}
                    }

                    if let Some(err) = outcome.error {
                        if !last_err.is_empty() {
                            last_err.push_str("; ");
                        }
                        last_err.push_str(&format!("{}: {}", outcome.source, err));
                    }
                }
            }
        }

        if last_err.is_empty() {
            last_err = format!(
                "fallback '{}' failed: no response from '{}' and '{}'",
                self.tag, self.primary_tag, self.secondary_tag
            );
        }

        Err(DnsError::plugin(last_err))
    }
}

#[derive(Debug, Clone)]
pub struct FallbackFactory;

register_plugin_factory!("fallback", FallbackFactory {});

impl PluginFactory for FallbackFactory {
    fn validate_config(&self, plugin_config: &PluginConfig) -> Result<()> {
        let cfg: FallbackConfig = serde_yml::from_value(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("fallback requires args"))?,
        )
        .map_err(|e| DnsError::plugin(format!("failed to parse fallback config: {}", e)))?;

        if cfg.primary.trim().is_empty() || cfg.secondary.trim().is_empty() {
            return Err(DnsError::plugin(
                "fallback requires non-empty 'primary' and 'secondary'",
            ));
        }

        Ok(())
    }

    fn get_dependencies(&self, plugin_config: &PluginConfig) -> Vec<String> {
        plugin_config
            .args
            .clone()
            .and_then(|args| serde_yml::from_value::<FallbackConfig>(args).ok())
            .map(|cfg| vec![cfg.primary, cfg.secondary])
            .unwrap_or_default()
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cfg: FallbackConfig = serde_yml::from_value(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("fallback requires args"))?,
        )
        .map_err(|e| DnsError::plugin(format!("failed to parse fallback config: {}", e)))?;

        let primary = registry.get_plugin(cfg.primary.as_str()).ok_or_else(|| {
            DnsError::plugin(format!("fallback primary '{}' not found", cfg.primary))
        })?;
        if !matches!(primary.plugin_type, PluginType::Executor) {
            return Err(DnsError::plugin(format!(
                "fallback primary '{}' is not an executor",
                cfg.primary
            )));
        }

        let secondary = registry.get_plugin(cfg.secondary.as_str()).ok_or_else(|| {
            DnsError::plugin(format!("fallback secondary '{}' not found", cfg.secondary))
        })?;
        if !matches!(secondary.plugin_type, PluginType::Executor) {
            return Err(DnsError::plugin(format!(
                "fallback secondary '{}' is not an executor",
                cfg.secondary
            )));
        }

        Ok(UninitializedPlugin::Executor(Box::new(FallbackExecutor {
            tag: plugin_config.tag.clone(),
            primary_tag: cfg.primary.clone(),
            secondary_tag: cfg.secondary.clone(),
            primary: primary.to_executor(),
            secondary: secondary.to_executor(),
            threshold: Duration::from_millis(if cfg.threshold == 0 {
                500
            } else {
                cfg.threshold
            }),
            always_standby: cfg.always_standby,
        })))
    }
}

async fn run_executor(
    executor: Arc<dyn Executor>,
    context: &mut DnsContext,
    source: &'static str,
) -> Outcome {
    match executor.execute_with_handle(context, None).await {
        Ok(_) => Outcome {
            response: context.response.clone(),
            source,
            error: if context.response.is_none() {
                Some("executor returned without response".to_string())
            } else {
                None
            },
        },
        Err(e) => Outcome {
            response: None,
            source,
            error: Some(e.to_string()),
        },
    }
}
