/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Application monotonic clock.
//!
//! ForgeDNS mainly needs elapsed-time reads relative to process start for
//! metrics, cache expiry, and connection lifetime tracking. The previous
//! version maintained a dedicated updater task and cached elapsed time in an
//! atomic, but the measured gain did not justify an always-running runtime
//! task. The current design keeps only a lazily initialized monotonic base
//! instant and computes elapsed time directly from it.

use std::sync::OnceLock;
use std::time::Duration;
use tokio::time::Instant;

/// Application start time (set once during initialization)
static START_INSTANT: OnceLock<Instant> = OnceLock::new();

/// Process-wide monotonic clock helper.
pub struct AppClock {}

#[allow(unused)]
impl AppClock {
    #[inline]
    fn base() -> &'static Instant {
        START_INSTANT.get_or_init(Instant::now)
    }

    /// Initialize the process clock eagerly.
    ///
    /// Startup code can call this to make the zero point explicit, but all read
    /// APIs also initialize the clock lazily on first use.
    #[cold]
    pub fn start() {
        let _ = Self::base();
    }

    /// Get the current monotonic time.
    #[inline(always)]
    pub fn now() -> Instant {
        Instant::now()
    }

    /// Get milliseconds elapsed since application start.
    #[inline(always)]
    pub fn elapsed_millis() -> u64 {
        Self::base().elapsed().as_millis() as u64
    }

    /// Get duration since application start
    #[inline(always)]
    pub fn elapsed() -> Duration {
        Self::base().elapsed()
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
    assert!(advanced >= initial.saturating_add(35));
    assert!(AppClock::elapsed() >= Duration::from_millis(advanced));
    assert!(AppClock::now() >= initial_now);
}
