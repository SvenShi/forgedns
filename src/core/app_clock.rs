//! Application monotonic clock.
//!
//! ForgeDNS mainly needs elapsed-time reads relative to process start for
//! metrics, cache expiry, and connection lifetime tracking. The previous
//! version maintained a dedicated updater task and cached elapsed time in an
//! atomic, but the measured gain did not justify an always-running runtime
//! task. The current design keeps only a lazily initialized monotonic base
//! instant and computes elapsed time directly from it.
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Application start time, set once during initialization.
static START_INSTANT: OnceLock<Instant> = OnceLock::new();
static START_UNIX_TIMESTAMP_MS: OnceLock<u64> = OnceLock::new();

/// Process-wide monotonic clock helper.
pub struct AppClock;

#[allow(unused)]
impl AppClock {
    #[inline]
    fn base() -> &'static Instant {
        START_INSTANT
            .get()
            .expect("AppClock::start() must be called before using AppClock")
    }

    #[inline]
    fn base_timestamp_ms() -> u64 {
        *START_UNIX_TIMESTAMP_MS
            .get()
            .expect("AppClock::start() must be called before using AppClock")
    }

    /// Initialize the process clock eagerly.
    ///
    /// Must be called once during startup before using other AppClock APIs.
    #[cold]
    pub fn start() {
        let unix_timestamp_ms = unix_timestamp_ms();
        let instant = Instant::now();

        let _ = START_UNIX_TIMESTAMP_MS.set(unix_timestamp_ms);
        let _ = START_INSTANT.set(instant);
    }

    /// Get the current monotonic instant.
    #[inline(always)]
    pub fn now() -> Instant {
        Instant::now()
    }

    /// Estimated Unix timestamp in milliseconds.
    ///
    /// Computed as:
    ///
    /// startup_unix_timestamp_ms + monotonic_elapsed_ms
    ///
    /// This is monotonic and fast, but does not track wall-clock adjustments
    /// after application startup.
    #[inline(always)]
    pub fn now_timestamp() -> u64 {
        Self::base_timestamp_ms().saturating_add(Self::elapsed_millis())
    }

    /// Get milliseconds elapsed since application start.
    #[inline(always)]
    pub fn elapsed_millis() -> u64 {
        duration_millis_u64(Self::base().elapsed())
    }

    /// Get duration since application start.
    #[inline(always)]
    pub fn elapsed() -> Duration {
        Self::base().elapsed()
    }
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(duration_millis_u64)
        .unwrap_or(0)
}

fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
