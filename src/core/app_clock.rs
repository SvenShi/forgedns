/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! High-performance application clock
//!
//! Provides efficient timestamp access without syscall overhead.
//! A background task updates the time every millisecond, allowing
//! hot-path code to read time with just an atomic load operation.
//!
//! This is crucial for performance-sensitive paths like connection
//! timeout tracking and cache expiration checks.

use std::ops::Add;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Once, OnceLock};
use std::time::Duration;
use tokio::time::Instant;

/// Application start time (set once during initialization)
static START_INSTANT: OnceLock<Instant> = OnceLock::new();

/// Cached milliseconds since start (updated every 1ms by background task)
static GLOBAL_NOW: AtomicU64 = AtomicU64::new(0);

/// Ensures clock is initialized only once
static CLOCK_INIT: Once = Once::new();

/// High-performance clock implementation
///
/// Uses a background task to update time every millisecond.
/// All reads are lock-free atomic operations.
pub struct AppClock {}

#[allow(unused)]
impl AppClock {
    /// Start the background clock updater task
    ///
    /// Safe to call multiple times (only runs once via `Once`)
    pub(crate) fn start() {
        CLOCK_INIT.call_once(|| {
            START_INSTANT
                .set(Instant::now())
                .expect("Clock initialization should never fail");

            // Spawn background task to update time every millisecond
            tokio::spawn(async move {
                loop {
                    let base = START_INSTANT.get().unwrap();
                    GLOBAL_NOW.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            });
        })
    }

    /// Get current time as Instant (based on cached milliseconds)
    pub fn now() -> Instant {
        let base = START_INSTANT.get().unwrap();
        base.add(AppClock::elapsed())
    }

    /// Get milliseconds elapsed since application start
    ///
    /// This is a hot-path function used extensively for timeout checks.
    /// Uses relaxed atomic load for maximum performance.
    pub fn elapsed_millis() -> u64 {
        GLOBAL_NOW.load(Ordering::Relaxed)
    }

    /// Get duration since application start
    pub fn elapsed() -> Duration {
        Duration::from_millis(Self::elapsed_millis())
    }
}

#[tokio::test]
async fn test() {
    AppClock::start();

    for _ in 0..5 {
        println!("ms = {}", AppClock::elapsed_millis());
        println!("dur = {:?}", AppClock::elapsed());
        println!("now = {:?}", AppClock::now());

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
