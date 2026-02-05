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

use tokio::sync::oneshot;
use tokio::{runtime, signal};
use tracing::{error, info};

mod config;
mod core;
mod network;
mod plugin;

use core::error::{DnsError, Result};

/// Application entry point
fn main() -> Result<()> {
    init_runtime()
}

/// Initialize and run the Tokio runtime with multi-threading enabled
///
/// Creates an 8-worker-thread Tokio runtime optimized for DNS server workloads
fn init_runtime() -> Result<()> {
    let mut tokio_runtime = runtime::Builder::new_multi_thread();
    tokio_runtime
        .enable_all()
        .thread_name("forgedns-worker")
        .worker_threads(8);
    let tokio_runtime = tokio_runtime
        .build()
        .map_err(|err| DnsError::runtime(format!("Failed to initialize Tokio runtime: {err}")))?;
    tokio_runtime.block_on(run_async_main())
}

/// Main async runtime loop
///
/// Sets up signal handlers and spawns the application task.
/// Waits for Ctrl+C signal for graceful shutdown.
#[hotpath::main(percentiles =[50,70,90])]
async fn run_async_main() -> Result<()> {
    // Create shutdown channel for graceful termination
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Spawn signal handler task for Ctrl+C
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received Ctrl+C signal, initiating graceful shutdown");
        let _ = shutdown_tx.send(());
    });

    // Initialize and run the DNS server application
    let mut runtime = core::init();
    let options = runtime.options.clone();

    info!("Loading configuration from: {:?}", options.config);
    let config = match config::init(&options.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Configuration initialization failed: {}", e);
            std::process::exit(1);
        }
    };

    // Override log level from command line if provided
    let mut log_config = config.log.clone();
    if let Some(level) = options.log_level {
        info!("Overriding log level from config to: {}", level);
        log_config.level = level;
    }

    // Initialize logging and save the guard to ensure logs are flushed
    runtime.log_guard = Some(core::init_log(log_config));
    info!("ForgeDNS server initializing...");

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
            std::process::exit(1);
        }
    };

    // Wait for shutdown signal
    shutdown_rx.await.ok();
    info!("Destroying plugins for shutdown");
    registry.destroy_plugins().await;
    info!("Graceful shutdown complete");
    Ok(())
}
