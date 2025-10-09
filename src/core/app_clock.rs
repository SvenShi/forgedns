/*
 * Copyright 2025 Sven Shi
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
impl AppClock {
    pub(crate) fn run() {
        CLOCK_INIT.call_once(|| {
            START_INSTANT.set(Instant::now()).expect("never throw");

            tokio::spawn(async move {
                loop {
                    let base = START_INSTANT.get().unwrap();
                    GLOBAL_NOW.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(10)).await;
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
