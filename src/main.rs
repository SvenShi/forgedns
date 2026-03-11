/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! ForgeDNS - A high-performance DNS server written in Rust
//!
//! This is the main entry point for the ForgeDNS server, which provides:
//! - Multi-threaded async DNS query handling
//! - Support for various DNS protocols (UDP, TCP, DoT, DoQ, DoH)
//! - Plugin-based architecture for extensibility
//! - Graceful shutdown handling

use forgedns::config::types::Config;
use forgedns::core::error::{DnsError, Result};
use forgedns::{config, core, plugin};
use tokio::runtime;
use tokio::sync::oneshot;
use tracing::{error, info};

/// Application entry point
fn main() -> Result<()> {
    let options = core::parse_options();
    let config = load_config(&options)?;
    init_runtime(options, config)
}

/// Initialize and run the Tokio runtime with multi-threading enabled
///
/// Uses `runtime.worker_threads` from config, defaulting to available CPU cores.
fn init_runtime(options: core::Options, config: Config) -> Result<()> {
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

fn load_config(options: &core::Options) -> Result<Config> {
    config::init(&options.config).map_err(|err| {
        DnsError::config(format!(
            "Configuration initialization failed for {}: {}",
            options.config.display(),
            err
        ))
    })
}

#[derive(Clone, Copy, Debug)]
enum ShutdownSignal {
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

/// Main async runtime loop
///
/// Sets up signal handlers and spawns the application task.
/// Waits for an OS shutdown signal for graceful shutdown.
#[hotpath::main(percentiles =[50,70,90])]
async fn run_async_main(options: core::Options, config: Config) -> Result<()> {
    // Create shutdown channel for graceful termination
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<Result<ShutdownSignal>>();

    // Spawn signal handler before plugin initialization so signals received
    // after the Tokio runtime is online are still observed during startup.
    tokio::spawn(async move {
        let _ = shutdown_tx.send(wait_for_shutdown_signal().await);
    });

    // Initialize and run the DNS server application
    let worker_threads = config.runtime.effective_worker_threads();
    let mut runtime = core::init_with_options(options);
    let options = runtime.options.clone();

    // Override log level from command line if provided
    let mut log_config = config.log.clone();
    let configured_level = log_config.level.clone();
    if let Some(level) = options.log_level.clone() {
        log_config.level = level;
    }

    // Initialize logging and save the guard to ensure logs are flushed
    let effective_log_level = log_config.level.clone();
    runtime.log_guard = Some(core::init_log(log_config));
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

    // Initialize plugins with dependency resolution
    // The registry is created and returned by init()
    let registry = match plugin::init(config).await {
        Ok(registry) => {
            info!("ForgeDNS server started successfully");
            // Registry is now available for the application lifetime
            registry
        }
        Err(e) => {
            error!("Plugin initialization failed: {}", e);
            return Err(e);
        }
    };

    // Wait for shutdown signal
    let shutdown_signal = shutdown_rx
        .await
        .map_err(|_| DnsError::runtime("Shutdown signal task exited unexpectedly"))??;
    info!(
        signal = shutdown_signal.as_str(),
        "Received shutdown signal, initiating graceful shutdown"
    );
    info!(
        signal = shutdown_signal.as_str(),
        "Destroying plugins for shutdown"
    );
    registry.destroy_plugins().await;
    core::task_center::stop_all().await;
    info!(
        signal = shutdown_signal.as_str(),
        "Graceful shutdown complete"
    );
    Ok(())
}
