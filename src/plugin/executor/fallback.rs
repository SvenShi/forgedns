/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! `fallback` executor plugin.
//!
//! Runs a primary executor and falls back to a secondary executor on
//! failure/timeout.
//!
//! Scheduling model:
//! - `primary` starts immediately.
//! - `secondary` starts after `threshold` milliseconds, or starts immediately
//!   in standby mode (`always_standby = true`).
//! - first successful response wins; unfinished sibling tasks are cancelled.
//!
//! Result semantics:
//! - if either branch produces a response, plugin writes it to
//!   `DnsContext.response` and returns `Next`.
//! - if both branches fail (or return no response), plugin returns error so the
//!   server request handler can generate a failure response.

use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::error::{DnsError, Result};
use crate::plugin::dependency::DependencySpec;
use crate::plugin::executor::{ExecStep, Executor};
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use crate::register_plugin_factory;
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Deserialize)]
struct FallbackConfig {
    /// Executor tag used as the primary path.
    primary: String,
    /// Executor tag used as the standby path.
    secondary: String,
    /// Timeout threshold in milliseconds before primary is treated as slow.
    #[serde(default)]
    threshold: u64,
    /// Always run standby path in parallel regardless of primary latency.
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

struct Outcome {
    context: Option<DnsContext>,
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

    async fn init(&mut self) -> Result<()> {
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Executor for FallbackExecutor {
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let mut join_set = JoinSet::new();
        let (primary_state_tx, primary_state_rx) = watch::channel(PrimaryState::Running);

        let primary = self.primary.clone();
        let primary_ctx = context.copy_for_subquery();
        join_set.spawn(async move {
            let outcome = run_executor(primary, primary_ctx, "primary").await;
            let state = if outcome.context.is_some() {
                PrimaryState::Success
            } else {
                PrimaryState::Failed
            };
            let _ = primary_state_tx.send(state);
            outcome
        });

        let secondary = self.secondary.clone();
        let secondary_ctx = context.copy_for_subquery();
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
                                    // Primary already won before threshold; skip secondary execution
                                    // and return an empty outcome just to unblock join loop.
                                    return Outcome {
                                        context: None,
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
            run_executor(secondary, secondary_ctx, "secondary").await
        });

        let mut last_err = String::new();
        let mut buffered_secondary: Option<DnsContext> = None;
        let mut threshold_reached = !self.always_standby;
        let standby_timer = tokio::time::sleep(self.threshold);
        tokio::pin!(standby_timer);
        loop {
            tokio::select! {
                _ = &mut standby_timer, if self.always_standby && !threshold_reached => {
                    threshold_reached = true;
                    // In standby mode, secondary can finish early but should not win until
                    // the threshold elapses. Flush buffered response once timer fires.
                    if let Some(secondary_ctx) = buffered_secondary.take() {
                        context.apply_subquery_result(secondary_ctx);
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
                            if let Some(primary_ctx) = outcome.context {
                                context.apply_subquery_result(primary_ctx);
                                join_set.abort_all();
                                return Ok(ExecStep::Next);
                            }
                            if let Some(secondary_ctx) = buffered_secondary.take() {
                                context.apply_subquery_result(secondary_ctx);
                                join_set.abort_all();
                                return Ok(ExecStep::Next);
                            }
                        }
                        "secondary" => {
                            if let Some(secondary_ctx) = outcome.context {
                                if !self.always_standby || threshold_reached {
                                    context.apply_subquery_result(secondary_ctx);
                                    join_set.abort_all();
                                    return Ok(ExecStep::Next);
                                }
                                // Standby mode before threshold: keep secondary result as backup
                                // and still wait for primary to finish or timer to fire.
                                buffered_secondary = Some(secondary_ctx);
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
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        plugin_config
            .args
            .clone()
            .and_then(|args| serde_yml::from_value::<FallbackConfig>(args).ok())
            .map(|cfg| {
                vec![
                    DependencySpec::executor("args.primary", cfg.primary),
                    DependencySpec::executor("args.secondary", cfg.secondary),
                ]
            })
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

        let primary = registry.get_executor_dependency(
            &plugin_config.tag,
            "args.primary",
            cfg.primary.as_str(),
        )?;
        let secondary = registry.get_executor_dependency(
            &plugin_config.tag,
            "args.secondary",
            cfg.secondary.as_str(),
        )?;

        Ok(UninitializedPlugin::Executor(Box::new(FallbackExecutor {
            tag: plugin_config.tag.clone(),
            primary_tag: cfg.primary.clone(),
            secondary_tag: cfg.secondary.clone(),
            primary,
            secondary,
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
    mut context: DnsContext,
    source: &'static str,
) -> Outcome {
    match executor.execute_with_next(&mut context, None).await {
        Ok(step) => {
            let has_response = context.response().is_some();
            Outcome {
                context: if has_response { Some(context) } else { None },
                source,
                error: if has_response {
                    None
                } else {
                    Some(format!("executor returned {:?} without response", step))
                },
            }
        }
        Err(e) => Outcome {
            context: None,
            source,
            error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::test_context;
    use crate::plugin::test_utils::{plugin_config, test_registry};
    use async_trait::async_trait;

    #[test]
    fn test_fallback_factory_requires_args() {
        let factory = FallbackFactory;
        let cfg = plugin_config("fb", "fallback", None);
        assert!(factory.create(&cfg, test_registry()).is_err());
    }

    #[derive(Debug)]
    struct StubExecutor {
        tag: String,
        should_fail: bool,
        produce_response: bool,
        refused_with_next: bool,
    }

    #[async_trait]
    impl Plugin for StubExecutor {
        fn tag(&self) -> &str {
            &self.tag
        }

        async fn init(&mut self) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for StubExecutor {
        fn with_next(&self) -> bool {
            self.refused_with_next
        }

        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            if self.should_fail {
                return Err(DnsError::plugin("stub failed"));
            }
            if self.produce_response {
                context.set_response(crate::proto::Message::new());
            }
            Ok(ExecStep::Next)
        }

        async fn execute_with_next(
            &self,
            context: &mut DnsContext,
            next: Option<crate::plugin::executor::ExecutorNext>,
        ) -> Result<ExecStep> {
            if self.refused_with_next {
                let _ = next;
                context.set_response(context.request.response(crate::proto::Rcode::Refused));
                return Ok(ExecStep::Next);
            }
            self.execute(context).await
        }
    }

    #[tokio::test]
    async fn test_run_executor_reports_success_and_errors() {
        let success = run_executor(
            Arc::new(StubExecutor {
                tag: "ok".to_string(),
                should_fail: false,
                produce_response: true,
                refused_with_next: false,
            }),
            test_context(),
            "primary",
        )
        .await;
        assert!(success.context.is_some());
        assert!(success.error.is_none());

        let no_response = run_executor(
            Arc::new(StubExecutor {
                tag: "noresp".to_string(),
                should_fail: false,
                produce_response: false,
                refused_with_next: false,
            }),
            test_context(),
            "secondary",
        )
        .await;
        assert!(no_response.context.is_none());
        assert!(
            no_response
                .error
                .as_deref()
                .is_some_and(|e| e.contains("without response"))
        );

        let failed = run_executor(
            Arc::new(StubExecutor {
                tag: "err".to_string(),
                should_fail: true,
                produce_response: false,
                refused_with_next: false,
            }),
            test_context(),
            "primary",
        )
        .await;
        assert!(failed.context.is_none());
        assert!(
            failed
                .error
                .as_deref()
                .is_some_and(|e| e.contains("stub failed"))
        );
    }

    #[tokio::test]
    async fn test_run_executor_supports_with_next_executor() {
        let outcome = run_executor(
            Arc::new(StubExecutor {
                tag: "with_next".to_string(),
                should_fail: false,
                produce_response: false,
                refused_with_next: true,
            }),
            test_context(),
            "primary",
        )
        .await;

        let context = outcome
            .context
            .expect("with-next executor should produce a response");
        assert_eq!(
            context
                .response()
                .expect("with-next executor should set response")
                .rcode(),
            crate::proto::Rcode::Refused
        );
        assert!(outcome.error.is_none());
    }
}
