/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Core functionality module
//!
//! Provides essential infrastructure including:
//! - Runtime initialization and command-line argument parsing
//! - Logging system setup with custom formatters
//! - Application clock for high-performance time tracking
//! - DNS request/response context management

use crate::config::types::LogConfig;
use crate::core::app_clock::AppClock;
use crate::core::log::ForgeDnsLogFormatter;
use crate::core::runtime::{Options, Runtime};
use clap::Parser;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry, fmt};

pub mod app_clock;
pub mod context;
pub mod error;

mod log;
mod runtime;

/// Initialize the core runtime system
///
/// Parses command-line options and starts the application clock.
/// The clock runs in the background to provide high-performance timestamps.
pub fn init() -> Runtime {
    let options = Options::parse();

    // Start background clock for efficient timestamp generation
    AppClock::start();

    eprintln!("Core runtime initialized (clock started)");

    Runtime {
        options,
        log_guard: None, // Will be set later during logging initialization
    }
}

/// Initialize the logging system with console and optional file output
///
/// Sets up a dual-layer logging system:
/// - Console output (always enabled)
/// - File output (optional, based on config)
///
/// Both use the custom ForgeDnsLogFormatter for consistent formatting.
/// Returns a WorkerGuard that must be kept alive to ensure log flushing.
pub fn init_log(log: LogConfig) -> WorkerGuard {
    // Create file appender if a file path is configured
    let (file_writer, guard) = if let Some(ref file_path) = log.file {
        eprintln!("Logging to file: {}", file_path);
        let file_appender = tracing_appender::rolling::never(
            std::path::Path::new(&file_path).parent().unwrap(),
            std::path::Path::new(&file_path).file_name().unwrap(),
        );
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    // Build console logging layer
    let console_layer = fmt::layer()
        .event_format(ForgeDnsLogFormatter)
        .with_writer(std::io::stdout);

    // Build file logging layer (if configured)
    let file_layer = file_writer.map(|writer| {
        fmt::layer()
            .event_format(ForgeDnsLogFormatter)
            .with_writer(writer)
    });

    let mut filter = EnvFilter::try_new(&log.level).unwrap_or_else(|_| {
        eprintln!("Invalid log level '{}', defaulting to 'info'", log.level);
        EnvFilter::new("info")
    });

    // Suppress noisy hickory_server logs
    filter = filter.add_directive("hickory_server::server=off".parse().unwrap());

    let subscriber = Registry::default().with(filter).with(console_layer);

    // Add file layer if it exists
    if let Some(file_layer) = file_layer {
        let subscriber = subscriber.with(file_layer);
        subscriber.init();
    } else {
        subscriber.init();
    };

    eprintln!("Logging system initialized with level: {}", log.level);

    // Return WorkerGuard to ensure logs are flushed before program exit
    guard.unwrap_or_else(|| {
        // If no file logging, return a dummy guard
        tracing_appender::non_blocking(std::io::sink()).1
    })
}
