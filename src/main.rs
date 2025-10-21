/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! RustDNS - A high-performance DNS server written in Rust
//!
//! This is the main entry point for the RustDNS server, which provides:
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

/// Application entry point
fn main() -> Result<(), String> {
    init_runtime()
}

/// Initialize and run the Tokio runtime with multi-threading enabled
///
/// Creates an 8-worker-thread Tokio runtime optimized for DNS server workloads
fn init_runtime() -> Result<(), String> {
    let mut tokio_runtime = runtime::Builder::new_multi_thread();
    tokio_runtime
        .enable_all()
        .thread_name("rustdns-worker")
        .worker_threads(8);
    let tokio_runtime = tokio_runtime
        .build()
        .map_err(|err| format!("Failed to initialize Tokio runtime: {err}"))?;
    tokio_runtime.block_on(run_async_main())
}

/// Main async runtime loop
///
/// Sets up signal handlers and spawns the application task.
/// Waits for Ctrl+C signal for graceful shutdown.
#[cfg_attr(feature = "hotpath", hotpath::main(percentiles =[50,70,90]))]
async fn run_async_main() -> Result<(), String> {
    // Create shutdown channel for graceful termination
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Spawn main application task
    tokio::spawn(run_app());

    // Spawn signal handler task for Ctrl+C
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received Ctrl+C signal, initiating graceful shutdown");
        let _ = shutdown_tx.send(());
    });

    // Wait for shutdown signal
    shutdown_rx.await.ok();
    info!("Graceful shutdown complete");
    Ok(())
}

/// Initialize and run the DNS server application
///
/// This function:
/// 1. Initializes the core runtime (command-line args, app clock)
/// 2. Loads configuration from file
/// 3. Sets up logging system
/// 4. Initializes all configured plugins
async fn run_app() {
    let mut runtime = core::init();
    let options = runtime.options.clone();

    info!("Loading configuration from: {:?}", options.config);
    let config = config::init(&options.config);

    // Override log level from command line if provided
    let mut log_config = config.log.clone();
    if let Some(level) = options.log_level {
        info!("Overriding log level from config to: {}", level);
        log_config.level = level;
    }

    // Initialize logging and save the guard to ensure logs are flushed
    runtime.log_guard = Some(core::init_log(log_config));
    info!("RustDNS server initializing...");

    // Initialize plugins with dependency resolution
    // The registry is created and returned by init()
    match plugin::init(config).await {
        Ok(_registry) => {
            info!("RustDNS server started successfully");
            // Registry is now available for the application lifetime
        }
        Err(e) => {
            error!("Plugin initialization failed: {}", e);
            std::process::exit(1);
        }
    }

    // Runtime (and log_guard) will be dropped here, ensuring logs are flushed
}
