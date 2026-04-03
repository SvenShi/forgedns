/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Foreground application runtime entry used by the CLI `start` command.
//!
//! This module owns the non-service startup path:
//!
//! - applies CLI overrides such as working directory and log level;
//! - loads and validates configuration;
//! - builds the Tokio runtime;
//! - assembles the API hub and plugin registry; and
//! - coordinates shutdown and reload flows for the live process.
//!
//! The goal is to keep process-level concerns here so the lower-level modules
//! (`config`, `plugin`, `network`, `api`) stay focused on their own domains.

pub mod bootstrap;
pub mod cli;
pub mod export_dat;
mod logging;

use crate::api::control::{AppController, ControlCommand};
use crate::app::bootstrap::AppAssembly;
use crate::app::cli::StartOptions;
use crate::config;
use crate::config::types::Config;
use crate::core;
use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result};
use tokio::runtime;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};

/// Start ForgeDNS in the foreground using the provided CLI options.
pub fn run(start: StartOptions) -> Result<()> {
    AppClock::start();
    prepare_start_options(&start)?;
    let config = load_config(&start)?;
    init_runtime(start, config)
}

fn prepare_start_options(start: &StartOptions) -> Result<()> {
    if let Some(working_dir) = &start.working_dir {
        std::env::set_current_dir(working_dir).map_err(|err| {
            DnsError::runtime(format!(
                "Failed to switch working directory to {}: {}",
                working_dir.display(),
                err
            ))
        })?;
    }
    Ok(())
}

fn init_runtime(options: StartOptions, config: Config) -> Result<()> {
    let worker_threads = config.runtime.effective_worker_threads();
    let mut tokio_runtime = runtime::Builder::new_multi_thread();
    tokio_runtime
        .enable_all()
        .thread_name("forgedns-worker")
        .worker_threads(worker_threads);
    let tokio_runtime = tokio_runtime
        .build()
        .map_err(|err| DnsError::runtime(format!("Failed to initialize Tokio runtime: {err}")))?;
    tokio_runtime.block_on(run_async_main(options, config))
}

fn load_config(options: &StartOptions) -> Result<Config> {
    config::init(&options.config).map_err(|err| {
        DnsError::config(format!(
            "Configuration initialization failed for {}: {}",
            options.config.display(),
            err
        ))
    })
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ShutdownSignal {
    ApiRequest,
    #[cfg(unix)]
    SigInt,
    #[cfg(unix)]
    SigTerm,
    #[cfg(unix)]
    SigQuit,
    #[cfg(any(windows, not(any(unix, windows))))]
    CtrlC,
    #[cfg(windows)]
    CtrlBreak,
    #[cfg(windows)]
    CtrlClose,
    #[cfg(windows)]
    CtrlShutdown,
    #[cfg(windows)]
    CtrlLogoff,
}

impl ShutdownSignal {
    const fn as_str(self) -> &'static str {
        match self {
            ShutdownSignal::ApiRequest => "API_REQUEST",
            #[cfg(unix)]
            ShutdownSignal::SigInt => "SIGINT",
            #[cfg(unix)]
            ShutdownSignal::SigTerm => "SIGTERM",
            #[cfg(unix)]
            ShutdownSignal::SigQuit => "SIGQUIT",
            #[cfg(any(windows, not(any(unix, windows))))]
            ShutdownSignal::CtrlC => "CTRL_C",
            #[cfg(windows)]
            ShutdownSignal::CtrlBreak => "CTRL_BREAK",
            #[cfg(windows)]
            ShutdownSignal::CtrlClose => "CTRL_CLOSE",
            #[cfg(windows)]
            ShutdownSignal::CtrlShutdown => "CTRL_SHUTDOWN",
            #[cfg(windows)]
            ShutdownSignal::CtrlLogoff => "CTRL_LOGOFF",
        }
    }
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<ShutdownSignal> {
    use tokio::signal::unix::{SignalKind, signal as unix_signal};

    let mut sigint = unix_signal(SignalKind::interrupt())
        .map_err(|err| DnsError::runtime(format!("Failed to listen for SIGINT: {err}")))?;
    let mut sigterm = unix_signal(SignalKind::terminate())
        .map_err(|err| DnsError::runtime(format!("Failed to listen for SIGTERM: {err}")))?;
    let mut sigquit = unix_signal(SignalKind::quit())
        .map_err(|err| DnsError::runtime(format!("Failed to listen for SIGQUIT: {err}")))?;

    tokio::select! {
        _ = sigint.recv() => Ok(ShutdownSignal::SigInt),
        _ = sigterm.recv() => Ok(ShutdownSignal::SigTerm),
        _ = sigquit.recv() => Ok(ShutdownSignal::SigQuit),
    }
}

#[cfg(windows)]
async fn wait_for_shutdown_signal() -> Result<ShutdownSignal> {
    use tokio::signal::windows::{
        ctrl_break, ctrl_c as windows_ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown,
    };

    let mut ctrl_c = windows_ctrl_c()
        .map_err(|err| DnsError::runtime(format!("Failed to listen for CTRL_C: {err}")))?;
    let mut ctrl_break = ctrl_break()
        .map_err(|err| DnsError::runtime(format!("Failed to listen for CTRL_BREAK: {err}")))?;
    let mut ctrl_close = ctrl_close()
        .map_err(|err| DnsError::runtime(format!("Failed to listen for CTRL_CLOSE: {err}")))?;
    let mut ctrl_shutdown = ctrl_shutdown()
        .map_err(|err| DnsError::runtime(format!("Failed to listen for CTRL_SHUTDOWN: {err}")))?;
    let mut ctrl_logoff = ctrl_logoff()
        .map_err(|err| DnsError::runtime(format!("Failed to listen for CTRL_LOGOFF: {err}")))?;

    tokio::select! {
        _ = ctrl_c.recv() => Ok(ShutdownSignal::CtrlC),
        _ = ctrl_break.recv() => Ok(ShutdownSignal::CtrlBreak),
        _ = ctrl_close.recv() => Ok(ShutdownSignal::CtrlClose),
        _ = ctrl_shutdown.recv() => Ok(ShutdownSignal::CtrlShutdown),
        _ = ctrl_logoff.recv() => Ok(ShutdownSignal::CtrlLogoff),
    }
}

#[cfg(not(any(unix, windows)))]
async fn wait_for_shutdown_signal() -> Result<ShutdownSignal> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|err| DnsError::runtime(format!("Failed to listen for Ctrl+C: {err}")))?;
    Ok(ShutdownSignal::CtrlC)
}

async fn run_async_main(options: StartOptions, config: Config) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<Result<ShutdownSignal>>();
    tokio::spawn(async move {
        let _ = shutdown_tx.send(wait_for_shutdown_signal().await);
    });

    let (app_controller, mut control_rx) = AppController::new(options.config.clone());

    let worker_threads = config.runtime.effective_worker_threads();
    let options = options.clone();

    let mut log_config = config.log.clone();
    let configured_level = log_config.level.clone();
    if let Some(level) = options.log_level.clone() {
        log_config.level = level;
    }

    let effective_log_level = log_config.level.clone();
    let _log_guard = logging::start_logging(log_config);
    info!(
        config = %options.config.display(),
        plugins = config.plugins.len(),
        "Configuration loaded"
    );
    info!(
        tokio_worker_threads = worker_threads,
        "Tokio runtime configured"
    );
    if let Some(level) = options.log_level {
        info!(
            config_level = %configured_level,
            cli_level = %level,
            "Log level overridden by CLI option"
        );
    }
    info!(log_level = %effective_log_level, "ForgeDNS server initializing");

    let mut current_config = config;
    let mut assembly =
        match bootstrap::assemble(&current_config, Some(app_controller.clone())).await {
            Ok(assembly) => {
                info!("ForgeDNS server started successfully");
                assembly
            }
            Err(err) => {
                error!("Plugin initialization failed: {}", err);
                return Err(err);
            }
        };

    let shutdown_signal = wait_for_termination(
        &mut control_rx,
        shutdown_rx,
        &mut assembly,
        &mut current_config,
        app_controller.clone(),
    )
    .await?;
    info!(
        signal = shutdown_signal.as_str(),
        "Destroying plugins for shutdown"
    );
    bootstrap::stop(&assembly).await;
    core::task_center::stop_all().await;
    info!(
        signal = shutdown_signal.as_str(),
        "Graceful shutdown complete"
    );
    Ok(())
}

async fn wait_for_termination(
    control_rx: &mut mpsc::UnboundedReceiver<ControlCommand>,
    mut shutdown_rx: oneshot::Receiver<Result<ShutdownSignal>>,
    assembly: &mut AppAssembly,
    current_config: &mut Config,
    controller: std::sync::Arc<AppController>,
) -> Result<ShutdownSignal> {
    loop {
        tokio::select! {
            shutdown_signal = &mut shutdown_rx => {
                let shutdown_signal = shutdown_signal
                    .map_err(|_| DnsError::runtime("Shutdown signal task exited unexpectedly"))??;
                info!(
                    signal = shutdown_signal.as_str(),
                    "Received shutdown signal, initiating graceful shutdown"
                );
                return Ok(shutdown_signal);
            }
            command = control_rx.recv() => {
                match command {
                    Some(ControlCommand::Shutdown) => {
                        info!("Received shutdown request from management API");
                        return Ok(ShutdownSignal::ApiRequest);
                    }
                    Some(ControlCommand::Reload) => {
                        handle_reload_command(assembly, current_config, controller.clone()).await?;
                    }
                    None => return Err(DnsError::runtime("Control command channel closed unexpectedly")),
                }
            }
        }
    }
}

async fn handle_reload_command(
    assembly: &mut AppAssembly,
    current_config: &mut Config,
    controller: std::sync::Arc<AppController>,
) -> Result<()> {
    controller.mark_reload_started();

    let candidate_config = match load_config_from_path(controller.config_path()) {
        Ok(config) => config,
        Err(err) => {
            controller.mark_reload_failed(err.to_string());
            return Ok(());
        }
    };

    let previous_config = current_config.clone();
    info!(
        config = %controller.config_path().display(),
        "Reloading configuration from management API"
    );

    bootstrap::stop(assembly).await;
    core::task_center::stop_all().await;

    match bootstrap::assemble(&candidate_config, Some(controller.clone())).await {
        Ok(new_assembly) => {
            *assembly = new_assembly;
            *current_config = candidate_config;
            controller.mark_reload_succeeded();
            info!("Configuration reload completed successfully");
            Ok(())
        }
        Err(reload_err) => {
            error!("Configuration reload failed: {}", reload_err);
            match bootstrap::assemble(&previous_config, Some(controller.clone())).await {
                Ok(restored_assembly) => {
                    *assembly = restored_assembly;
                    controller.mark_reload_failed(format!(
                        "reload failed and previous configuration was restored: {}",
                        reload_err
                    ));
                    Ok(())
                }
                Err(rollback_err) => {
                    controller.mark_reload_failed(format!(
                        "reload failed: {}; rollback failed: {}",
                        reload_err, rollback_err
                    ));
                    Err(DnsError::runtime(format!(
                        "reload failed: {}; rollback failed: {}",
                        reload_err, rollback_err
                    )))
                }
            }
        }
    }
}

fn load_config_from_path(path: &std::path::Path) -> Result<Config> {
    let path = path.to_path_buf();
    let config = config::init(&path).map_err(|err| {
        DnsError::config(format!(
            "Configuration initialization failed for {}: {}",
            path.display(),
            err
        ))
    })?;
    crate::plugin::validate_configuration(&config)?;
    Ok(config)
}
