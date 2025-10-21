/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use std::ops::Add;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Once, OnceLock};
use std::time::Duration;
use tokio::time::Instant;

static START_INSTANT: OnceLock<Instant> = OnceLock::new();
static GLOBAL_NOW: AtomicU64 = AtomicU64::new(0);
static CLOCK_INIT: Once = Once::new();

pub struct AppClock {}

#[allow(unused)]
impl AppClock {
    pub(crate) fn run() {
        CLOCK_INIT.call_once(|| {
            START_INSTANT.set(Instant::now()).expect("never throw");

            tokio::spawn(async move {
                loop {
                    let base = START_INSTANT.get().unwrap();
                    GLOBAL_NOW.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            });
        })
    }

    pub fn now() -> Instant {
        let base = START_INSTANT.get().unwrap();
        base.add(AppClock::run_dur())
    }

    pub fn run_millis() -> u64 {
        GLOBAL_NOW.load(Ordering::Relaxed)
    }

    pub fn run_dur() -> Duration {
        Duration::from_millis(Self::run_millis())
    }
}

#[tokio::test]
async fn test() {
    AppClock::run();

    for _ in 0..5 {
        println!("ms = {}", AppClock::run_millis());
        println!("dur = {:?}", AppClock::run_dur());
        println!("now = {:?}", AppClock::now());

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
