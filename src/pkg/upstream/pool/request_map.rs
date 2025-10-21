/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Lock-free request/response correlation map
//!
//! Maps DNS query IDs to response channels using lock-free atomic operations.
//! This is a hot path - all operations are wait-free for maximum performance.
//!
//! # Performance Characteristics
//! - Store operation: O(1) average case with random retry
//! - Take operation: O(1) atomic swap
//! - No locks or async operations
//! - Cache-friendly: slots are inline in the array

use hickory_proto::xfer::DnsResponse;
use rand::random;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU16, Ordering};
use tokio::sync::oneshot::Sender;

/// Maximum number of concurrent requests (DNS ID space is u16)
const MAX_IDS: usize = u16::MAX as usize;

/// Lock-free request correlation map
///
/// Uses atomic pointers to map DNS query IDs to response channels.
/// All operations are wait-free for hot-path performance.
#[derive(Debug)]
pub struct RequestMap {
    /// Array of atomic pointers to response senders
    /// Index = DNS query ID
    slots: Vec<AtomicPtr<Sender<DnsResponse>>>,
    
    /// Current number of active requests
    size: AtomicU16,
}

impl RequestMap {
    /// Create a new empty request map
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(MAX_IDS);
        for _ in 0..MAX_IDS + 1 {
            slots.push(AtomicPtr::new(ptr::null_mut()));
        }
        Self {
            slots,
            size: AtomicU16::new(0),
        }
    }

    /// Store a response sender and get a unique query ID
    ///
    /// Uses randomized probing to find an empty slot.
    /// This is wait-free - never blocks or yields.
    ///
    /// # Returns
    /// A unique u16 query ID that can be used to retrieve the sender later
    #[inline(always)]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn store(&self, tx: Sender<DnsResponse>) -> u16 {
        let ptr = Box::into_raw(Box::new(tx));

        loop {
            let id = random::<u16>() as usize;
            // Try to claim this slot with compare-and-swap
            if self.slots[id]
                .compare_exchange(ptr::null_mut(), ptr, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.size.fetch_add(1, Ordering::Relaxed);
                return id as u16;
            }
        }
    }

    /// Take a response sender by query ID
    ///
    /// Atomically removes and returns the sender for the given ID.
    /// Returns None if no sender exists for this ID.
    ///
    /// # Arguments
    /// * `id` - The DNS query ID
    ///
    /// # Returns
    /// The response sender if it exists, None otherwise
    #[inline(always)]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn take(&self, id: u16) -> Option<Sender<DnsResponse>> {
        let slot = &self.slots[id as usize];
        let ptr = slot.swap(ptr::null_mut(), Ordering::AcqRel);
        if ptr.is_null() {
            None
        } else {
            self.size.fetch_sub(1, Ordering::Relaxed);
            unsafe { Some(*Box::from_raw(ptr)) }
        }
    }

    /// Get the current number of active requests
    pub fn size(&self) -> u16 {
        self.size.load(Ordering::Relaxed)
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.size.load(Ordering::Relaxed) == 0
    }
}

#[cfg(test)]
mod test {
    use crate::pkg::upstream::pool::request_map::RequestMap;
    use hickory_proto::xfer::DnsResponse;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::task::JoinSet;
    use tokio::time::{Instant, sleep};

    #[tokio::test]
    async fn test() {
        // Test store performance
        for _ in 0..5 {
            let map = Arc::new(RequestMap::new());
            let mut set = JoinSet::new();
            for _ in 0..1000 {
                let map = map.clone();
                set.spawn(async move {
                    let mut nanos = 0;
                    for _ in 0..100 {
                        let sender = tokio::sync::oneshot::channel::<DnsResponse>();
                        let instant = Instant::now();
                        let id = map.store(sender.0);
                        nanos += instant.elapsed().as_nanos();
                        sleep(Duration::from_millis(30)).await;
                        map.take(id);
                    }
                    nanos / 100
                });
            }
            println!(
                "avg store using time {}ns",
                set.join_all().await.iter().sum::<u128>() / 1000
            )
        }

        // Test take performance
        for _ in 0..5 {
            let map = Arc::new(RequestMap::new());
            let mut set = JoinSet::new();
            for _ in 0..1000 {
                let map = map.clone();
                set.spawn(async move {
                    let mut nanos = 0;
                    for _ in 0..100 {
                        let sender = tokio::sync::oneshot::channel::<DnsResponse>();
                        let id = map.store(sender.0);
                        sleep(Duration::from_millis(30)).await;
                        let instant = Instant::now();
                        map.take(id);
                        nanos += instant.elapsed().as_nanos();
                    }
                    nanos / 100
                });
            }
            println!(
                "avg take using time {}ns",
                set.join_all().await.iter().sum::<u128>() / 1000
            )
        }
    }
}
