/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Lock-free request/response correlation map
//!
//! Maps DNS query IDs to response channels using lock-free atomic operations.
//! This is a hot path with lock-free operations and low contention under load.
//!
//! # Performance Characteristics
//! - Store operation: expected O(1) at normal load, worst-case O(n) when saturated
//! - Take operation: O(1) atomic swap
//! - No locks or async operations
//! - Cache-friendly: slots are inline in the array

use crate::message::Message;
use rand::random;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU16, Ordering};
use tokio::sync::oneshot::Sender;

/// Maximum number of concurrent requests (DNS ID space is u16)
const MAX_IDS: usize = u16::MAX as usize;

/// Lock-free request correlation map
///
/// Uses atomic pointers to map DNS query IDs to response channels.
/// Designed for hot-path performance without locks.
#[derive(Debug)]
pub struct RequestMap {
    /// Array of atomic pointers to response senders
    /// Index = DNS query ID
    slots: Vec<AtomicPtr<Sender<Message>>>,

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
    /// Uses quadratic probing for better cache locality and faster collision resolution.
    /// Falls back to linear probing if quadratic probing fails.
    ///
    /// # Returns
    /// A unique u16 query ID that can be used to retrieve the sender later
    ///
    /// # Panics
    /// Panics if all slots are occupied (extremely rare in practice)
    #[inline(always)]
    #[hotpath::measure]
    pub fn store(&self, tx: Sender<Message>) -> u16 {
        let ptr = Box::into_raw(Box::new(tx));
        let start = random::<u16>() as usize;

        // Phase 1: Quadratic probing for better cache locality
        // h(i) = (start + i^2) mod MAX_IDS
        for i in 0..256 {
            let offset = (i * i) % MAX_IDS;
            let id = (start + offset) % MAX_IDS;

            if self.slots[id]
                .compare_exchange(ptr::null_mut(), ptr, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.size.fetch_add(1, Ordering::Relaxed);
                return id as u16;
            }
        }

        // Phase 2: Linear probing with limited range
        // More cache-friendly than random probing
        for offset in 256..2048 {
            let id = (start + offset) % MAX_IDS;

            if self.slots[id]
                .compare_exchange(ptr::null_mut(), ptr, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.size.fetch_add(1, Ordering::Relaxed);
                return id as u16;
            }
        }

        // Phase 3: Full linear scan as last resort
        for offset in 2048..MAX_IDS {
            let id = (start + offset) % MAX_IDS;

            if self.slots[id]
                .compare_exchange(ptr::null_mut(), ptr, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.size.fetch_add(1, Ordering::Relaxed);
                return id as u16;
            }
        }

        // All slots occupied - clean up and panic
        // This should be extremely rare in practice (requires 65535 concurrent requests)
        unsafe {
            let _ = Box::from_raw(ptr);
        }
        panic!("RequestMap exhausted: all {} slots are occupied", MAX_IDS);
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
    #[hotpath::measure]
    pub fn take(&self, id: u16) -> Option<Sender<Message>> {
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
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    fn make_message(id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message
    }

    #[test]
    fn test_store_returns_retrievable_sender_and_updates_size() {
        let map = RequestMap::new();
        let (tx, rx) = oneshot::channel();

        let id = map.store(tx);

        assert_eq!(map.size(), 1);
        let sender = map.take(id).expect("stored sender should be retrievable");
        assert_eq!(map.size(), 0);
        assert!(sender.send(make_message(7)).is_ok());
        let received = rx.blocking_recv().expect("receiver should get the message");
        assert_eq!(received.id(), 7);
    }

    #[test]
    fn test_take_missing_id_returns_none_without_changing_size() {
        let map = RequestMap::new();

        assert!(map.take(42).is_none());
        assert_eq!(map.size(), 0);
        assert!(map.is_empty());
    }

    #[test]
    fn test_take_twice_only_returns_sender_once() {
        let map = RequestMap::new();
        let (tx, _rx) = oneshot::channel();
        let id = map.store(tx);

        assert!(map.take(id).is_some());
        assert!(map.take(id).is_none());
        assert!(map.is_empty());
    }

    #[test]
    fn test_store_after_take_keeps_map_usable() {
        let map = RequestMap::new();
        let (tx1, _rx1) = oneshot::channel();
        let id1 = map.store(tx1);
        let _ = map.take(id1);

        let (tx2, rx2) = oneshot::channel();
        let id2 = map.store(tx2);
        let sender = map.take(id2).expect("second sender should be retrievable");

        assert!(sender.send(make_message(9)).is_ok());
        assert_eq!(
            rx2.blocking_recv()
                .expect("receiver should get the second message")
                .id(),
            9
        );
    }
}
