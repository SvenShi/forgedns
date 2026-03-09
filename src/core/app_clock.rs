/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! High-performance application clock
//!
//! Provides efficient timestamp access without syscall overhead.
//! A background task updates the time periodically (default: 1ms), allowing
//! hot-path code to read time with just an atomic load operation.
//!
//! This is crucial for performance-sensitive paths like connection
//! timeout tracking and cache expiration checks.

use std::ops::Add;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Once, OnceLock};
use std::time::Duration;
use tokio::time::{Instant, MissedTickBehavior};

const CLOCK_TICK_ENV: &str = "FORGEDNS_CLOCK_TICK_MS";
const DEFAULT_CLOCK_TICK_MS: u64 = 10;
const MIN_CLOCK_TICK_MS: u64 = 1;

/// Application start time (set once during initialization)
static START_INSTANT: OnceLock<Instant> = OnceLock::new();

/// Cached milliseconds since start (updated by background task)
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
    #[inline]
    fn read_tick_ms() -> u64 {
        std::env::var(CLOCK_TICK_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= MIN_CLOCK_TICK_MS)
            .unwrap_or(DEFAULT_CLOCK_TICK_MS)
    }

    /// Start the background clock updater task
    ///
    /// Safe to call multiple times (only runs once via `Once`)
    #[cold]
    pub fn start() {
        CLOCK_INIT.call_once(|| {
            START_INSTANT
                .set(Instant::now())
                .expect("Clock initialization should never fail");

            // Ensure readers do not observe stale default value after startup.
            GLOBAL_NOW.store(0, Ordering::Relaxed);

            // Spawn background task to update time periodically.
            // Uses interval + Skip to avoid accumulating drift under scheduler delay.
            let tick_ms = Self::read_tick_ms();
            tokio::spawn(async move {
                let base = START_INSTANT
                    .get()
                    .expect("Clock base instant must be initialized");
                let mut ticker = tokio::time::interval(Duration::from_millis(tick_ms));
                ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

                loop {
                    GLOBAL_NOW.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                    ticker.tick().await;
                }
            });
        })
    }

    /// Get current high-precision time.
    ///
    /// This can be slower than `now()` and should be used outside hot paths.
    #[inline]
    pub fn now_precise() -> Instant {
        Instant::now()
    }

    /// Get current time as `Instant` based on cached elapsed milliseconds.
    #[inline(always)]
    pub fn now() -> Instant {
        let base = START_INSTANT
            .get()
            .expect("AppClock::start() must be called before now()");
        base.add(Self::elapsed())
    }

    /// Get milliseconds elapsed since application start.
    ///
    /// Uses relaxed atomic load for maximum performance.
    #[inline(always)]
    pub fn elapsed_millis() -> u64 {
        GLOBAL_NOW.load(Ordering::Relaxed)
    }

    /// Get duration since application start
    #[inline(always)]
    pub fn elapsed() -> Duration {
        Duration::from_millis(Self::elapsed_millis())
    }
}

#[tokio::test(start_paused = true)]
async fn test_elapsed_millis_advances_with_runtime_time() {
    AppClock::start();
    tokio::task::yield_now().await;

    let initial = AppClock::elapsed_millis();
    let initial_now = AppClock::now();

    tokio::time::sleep(Duration::from_millis(35)).await;
    tokio::task::yield_now().await;

    let advanced = AppClock::elapsed_millis();
    assert!(advanced >= initial.saturating_add(DEFAULT_CLOCK_TICK_MS * 2));
    assert!(AppClock::elapsed() >= Duration::from_millis(advanced));
    assert!(AppClock::now() >= initial_now);
}
