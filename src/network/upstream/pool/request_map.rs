/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Lock-free request/response correlation map.
//!
//! The upstream connection pool already bounds per-connection inflight queries,
//! so mapping the entire u16 DNS ID space for every connection wastes memory.
//! This implementation keeps the wire ID space intact while storing only the
//! active requests in a fixed-capacity sparse table.
//!
//! # Slot State Machine
//!
//! Each slot is described by a compact `meta` word plus inline sender storage.
//! The high bits of `meta` encode a small state machine:
//!
//! - `EMPTY`
//!   The slot has no live request and no probe-chain history that matters.
//!   Lookup can stop when it sees this state because linear probing guarantees
//!   the target key cannot exist later in the chain.
//! - `RESERVED`
//!   A transient hand-off state used while a thread is publishing or removing a
//!   slot. Other threads must treat it as occupied and retry/skip so they never
//!   observe a half-written sender pointer or race a concurrent detach.
//! - `FULL`
//!   The slot contains a stable `query_id -> Sender<Message>` mapping and can be
//!   matched by `take()` or `remove()`.
//! - `TOMBSTONE`
//!   The slot used to hold an entry but was deleted. We cannot collapse it to
//!   `EMPTY` immediately because older probe chains may still need to continue
//!   past this position. Insertions may reuse tombstones, and the table resets
//!   them back to `EMPTY` when the map becomes empty.
//!
//! The resulting lifecycle is:
//!
//! - insert: `EMPTY/TOMBSTONE -> RESERVED -> FULL`
//! - remove/take: `FULL -> RESERVED -> TOMBSTONE`
//! - reset/clear: `TOMBSTONE -> EMPTY`
//!
//! # Concurrency Notes
//!
//! - `store()` first claims a slot by moving `meta` to `RESERVED`, then writes
//!   the inline sender, then publishes the final `FULL` state with `Release`.
//! - `take()` and `remove()` first move a `FULL` slot back to `RESERVED`, then
//!   move the inline sender out, then leave a `TOMBSTONE`.
//! - `clear()` is the shutdown path. It forcibly drops every sender and rewrites
//!   all slots back to `EMPTY` so connection close can promptly unblock waiters.

use crate::core::error::{DnsError, Result};
use crate::proto::Message;
use std::cell::UnsafeCell;
use std::hint::spin_loop;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use tokio::sync::oneshot::Sender;

const ID_SPACE_SIZE: u32 = u16::MAX as u32 + 1;
const MIN_SLOT_COUNT: usize = 8;
const SLOT_FACTOR: usize = 4;

/// Slot has never been used or has been fully reset.
const STATE_EMPTY: u32 = 0;
/// Slot is being published or removed and is not safe to consume.
const STATE_RESERVED: u32 = 1;
/// Slot contains a live `query_id -> sender` mapping.
const STATE_FULL: u32 = 2;
/// Slot was removed but must keep probe-chain continuity until reset.
const STATE_TOMBSTONE: u32 = 3;

const ID_MASK: u32 = 0x0000_FFFF;
const META_EMPTY: u32 = pack_meta(STATE_EMPTY, 0);
const META_TOMBSTONE: u32 = pack_meta(STATE_TOMBSTONE, 0);

const fn pack_meta(state: u32, id: u16) -> u32 {
    (state << 16) | id as u32
}

const fn meta_state(meta: u32) -> u32 {
    meta >> 16
}

const fn meta_id(meta: u32) -> u16 {
    (meta & ID_MASK) as u16
}

#[derive(Debug)]
struct Slot {
    meta: AtomicU32,
    sender: UnsafeCell<MaybeUninit<Sender<Message>>>,
}

impl Slot {
    fn empty() -> Self {
        Self {
            meta: AtomicU32::new(META_EMPTY),
            sender: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

// Safety: the slot state machine guarantees that only the thread that owns a
// slot in RESERVED state may read, write, or drop the inline sender storage.
unsafe impl Sync for Slot {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreResult {
    Stored(u16),
    Retry,
    Exhausted,
}

/// Lock-free request correlation map with bounded sparse storage.
///
/// The table is deliberately overprovisioned relative to `max_inflight` so the
/// average probe chain stays short while the per-connection memory footprint
/// remains in the KB range instead of scaling with all 65536 DNS IDs.
#[derive(Debug)]
pub struct RequestMap {
    slots: Box<[Slot]>,
    mask: usize,
    next_id: AtomicU16,
    size: AtomicU16,
}

impl RequestMap {
    /// Create a new sparse request map sized for the expected max inflight load.
    pub fn with_capacity(max_inflight: u16) -> Self {
        // Keep the table sparse on purpose. At the default inflight limit of 64,
        // we allocate 256 slots, which is still tiny but keeps linear probing
        // short even under bursty request churn.
        let desired = usize::from(max_inflight).saturating_mul(SLOT_FACTOR);
        let slot_count = desired.max(MIN_SLOT_COUNT).next_power_of_two();
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            slots.push(Slot::empty());
        }
        Self {
            slots: slots.into_boxed_slice(),
            mask: slot_count - 1,
            next_id: AtomicU16::new(0),
            size: AtomicU16::new(0),
        }
    }

    #[inline(always)]
    pub fn store(&self, tx: Sender<Message>) -> Result<u16> {
        let start = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut tx = Some(tx);

        for offset in 0..ID_SPACE_SIZE {
            let id = start.wrapping_add(offset as u16);
            match self.try_store_candidate(id, &mut tx) {
                StoreResult::Stored(id) => return Ok(id),
                StoreResult::Retry => continue,
                StoreResult::Exhausted => break,
            }
        }

        Err(DnsError::protocol(format!(
            "request map exhausted: table full (slots={}, active={})",
            self.slots.len(),
            self.size()
        )))
    }

    #[inline(always)]
    pub fn take(&self, id: u16) -> Option<Sender<Message>> {
        self.detach(id)
    }

    #[inline(always)]
    pub fn remove(&self, id: u16) -> bool {
        let Some(sender) = self.detach(id) else {
            return false;
        };
        drop(sender);
        true
    }

    /// Remove and drop every pending sender currently tracked by this map.
    pub fn clear(&self) -> u16 {
        let mut removed = 0u16;
        for slot in &self.slots {
            loop {
                let meta = slot.meta.load(Ordering::Acquire);
                match meta_state(meta) {
                    STATE_EMPTY => break,
                    STATE_TOMBSTONE => {
                        let _ = slot.meta.compare_exchange(
                            meta,
                            META_EMPTY,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                        break;
                    }
                    STATE_RESERVED => {
                        spin_loop();
                    }
                    STATE_FULL => {
                        if slot
                            .meta
                            .compare_exchange(
                                meta,
                                pack_meta(STATE_RESERVED, meta_id(meta)),
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_err()
                        {
                            continue;
                        }

                        unsafe {
                            (*slot.sender.get()).assume_init_drop();
                        }
                        removed = removed.saturating_add(1);
                        slot.meta.store(META_EMPTY, Ordering::Release);
                        break;
                    }
                    _ => unreachable!("invalid request map slot state"),
                }
            }
        }
        self.size.store(0, Ordering::Relaxed);
        removed
    }

    pub fn size(&self) -> u16 {
        self.size.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.size() == 0
    }

    #[inline(always)]
    fn try_store_candidate(&self, id: u16, tx: &mut Option<Sender<Message>>) -> StoreResult {
        let mut tombstone = None;

        for step in 0..self.slots.len() {
            let idx = self.probe_index(id, step);
            let meta = self.slots[idx].meta.load(Ordering::Acquire);
            match meta_state(meta) {
                STATE_EMPTY => {
                    // We can stop probing at the first EMPTY slot. If we saw an
                    // earlier TOMBSTONE, reuse it; otherwise insert here.
                    let target = tombstone.unwrap_or(idx);
                    return if self.claim_slot(target, id, tx.take().expect("sender present")) {
                        StoreResult::Stored(id)
                    } else {
                        StoreResult::Retry
                    };
                }
                STATE_TOMBSTONE => {
                    // Keep the earliest tombstone so we preserve the usual
                    // linear-probing insertion rule while still recycling old
                    // slots as soon as possible.
                    if tombstone.is_none() {
                        tombstone = Some(idx);
                    }
                }
                STATE_RESERVED | STATE_FULL => {
                    if meta_id(meta) == id {
                        return StoreResult::Retry;
                    }
                }
                _ => unreachable!("invalid request map slot state"),
            }
        }

        if let Some(target) = tombstone {
            if self.claim_slot(target, id, tx.take().expect("sender present")) {
                StoreResult::Stored(id)
            } else {
                StoreResult::Retry
            }
        } else {
            StoreResult::Exhausted
        }
    }

    #[inline(always)]
    fn claim_slot(&self, idx: usize, id: u16, tx: Sender<Message>) -> bool {
        let slot = &self.slots[idx];

        loop {
            let meta = slot.meta.load(Ordering::Acquire);
            match meta_state(meta) {
                STATE_EMPTY | STATE_TOMBSTONE => {
                    // Claim the slot first, then publish the inline sender,
                    // then mark the slot FULL. Readers treat RESERVED as busy
                    // and will never observe a half-published entry.
                    if slot
                        .meta
                        .compare_exchange(
                            meta,
                            pack_meta(STATE_RESERVED, id),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    unsafe {
                        (*slot.sender.get()).write(tx);
                    }
                    slot.meta
                        .store(pack_meta(STATE_FULL, id), Ordering::Release);
                    self.size.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                STATE_RESERVED | STATE_FULL => return false,
                _ => unreachable!("invalid request map slot state"),
            }
        }
    }

    #[inline(always)]
    fn detach(&self, id: u16) -> Option<Sender<Message>> {
        for step in 0..self.slots.len() {
            let idx = self.probe_index(id, step);
            let slot = &self.slots[idx];
            let meta = slot.meta.load(Ordering::Acquire);
            match meta_state(meta) {
                STATE_EMPTY => return None,
                STATE_RESERVED => continue,
                STATE_TOMBSTONE => continue,
                STATE_FULL => {
                    if meta_id(meta) != id {
                        continue;
                    }

                    // Move the slot back to RESERVED to become the sole owner
                    // of the inline sender before moving it out.
                    if slot
                        .meta
                        .compare_exchange(
                            meta,
                            pack_meta(STATE_RESERVED, id),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    let sender = unsafe { (*slot.sender.get()).assume_init_read() };
                    slot.meta.store(META_TOMBSTONE, Ordering::Release);
                    self.size.fetch_sub(1, Ordering::Relaxed);
                    if self.is_empty() {
                        // Once the map drains completely, we can safely turn all
                        // tombstones back into empty slots and restore short
                        // probe chains for the next burst of traffic.
                        self.reset_tombstones();
                    }
                    return Some(sender);
                }
                _ => unreachable!("invalid request map slot state"),
            }
        }
        None
    }

    fn reset_tombstones(&self) {
        if !self.is_empty() {
            return;
        }

        for slot in &self.slots {
            let meta = slot.meta.load(Ordering::Relaxed);
            if meta_state(meta) == STATE_TOMBSTONE {
                let _ = slot.meta.compare_exchange(
                    meta,
                    META_EMPTY,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
            }
        }
    }

    #[inline(always)]
    fn probe_index(&self, id: u16, step: usize) -> usize {
        let hash = usize::from(id).wrapping_mul(0x9E37_79B1usize);
        (hash.wrapping_add(step)) & self.mask
    }
}

impl Drop for RequestMap {
    fn drop(&mut self) {
        let _ = self.clear();
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
    fn test_with_capacity_uses_sparse_slot_count() {
        let map = RequestMap::with_capacity(64);

        assert_eq!(map.slots.len(), 256);
        assert_eq!(map.mask, 255);
    }

    #[test]
    fn test_store_returns_retrievable_sender_and_updates_size() {
        let map = RequestMap::with_capacity(8);
        let (tx, rx) = oneshot::channel();

        let id = map.store(tx).expect("store should succeed");

        assert_eq!(map.size(), 1);
        let sender = map.take(id).expect("stored sender should be retrievable");
        assert_eq!(map.size(), 0);
        assert!(sender.send(make_message(7)).is_ok());
        let received = rx.blocking_recv().expect("receiver should get the message");
        assert_eq!(received.id(), 7);
    }

    #[test]
    fn test_take_missing_id_returns_none_without_changing_size() {
        let map = RequestMap::with_capacity(8);

        assert!(map.take(42).is_none());
        assert_eq!(map.size(), 0);
        assert!(map.is_empty());
    }

    #[test]
    fn test_take_twice_only_returns_sender_once() {
        let map = RequestMap::with_capacity(8);
        let (tx, _rx) = oneshot::channel();
        let id = map.store(tx).expect("store should succeed");

        assert!(map.take(id).is_some());
        assert!(map.take(id).is_none());
        assert!(map.is_empty());
    }

    #[test]
    fn test_store_after_take_keeps_map_usable() {
        let map = RequestMap::with_capacity(8);
        let (tx1, _rx1) = oneshot::channel();
        let id1 = map.store(tx1).expect("store should succeed");
        let _ = map.take(id1);

        let (tx2, rx2) = oneshot::channel();
        let id2 = map.store(tx2).expect("store should succeed");
        let sender = map.take(id2).expect("second sender should be retrievable");

        assert!(sender.send(make_message(9)).is_ok());
        assert_eq!(
            rx2.blocking_recv()
                .expect("receiver should get the second message")
                .id(),
            9
        );
    }

    #[test]
    fn test_remove_drops_sender_and_updates_size() {
        let map = RequestMap::with_capacity(8);
        let (tx, rx) = oneshot::channel::<Message>();
        let id = map.store(tx).expect("store should succeed");

        assert!(map.remove(id));
        assert_eq!(map.size(), 0);
        assert!(map.is_empty());
        assert!(map.take(id).is_none());
        assert!(rx.blocking_recv().is_err());
    }

    #[test]
    fn test_drop_releases_pending_senders() {
        let (tx, rx) = oneshot::channel::<Message>();
        let map = RequestMap::with_capacity(8);
        let _id = map.store(tx).expect("store should succeed");

        drop(map);

        assert!(rx.blocking_recv().is_err());
    }

    #[test]
    fn test_remove_missing_id_returns_false_without_changing_size() {
        let map = RequestMap::with_capacity(8);
        let (tx, _rx) = oneshot::channel();
        let _id = map.store(tx).expect("store should succeed");

        assert!(!map.remove(42));
        assert_eq!(map.size(), 1);
    }

    #[test]
    fn test_clear_drops_all_pending_senders() {
        let map = RequestMap::with_capacity(8);
        let (tx1, rx1) = oneshot::channel::<Message>();
        let (tx2, rx2) = oneshot::channel::<Message>();
        let _ = map.store(tx1).expect("store should succeed");
        let _ = map.store(tx2).expect("store should succeed");

        assert_eq!(map.clear(), 2);
        assert_eq!(map.size(), 0);
        assert!(map.is_empty());
        assert!(rx1.blocking_recv().is_err());
        assert!(rx2.blocking_recv().is_err());
    }

    #[test]
    fn test_wraparound_ids_remain_reusable() {
        let map = RequestMap::with_capacity(8);
        map.next_id.store(u16::MAX - 1, Ordering::Relaxed);

        let (tx1, _rx1) = oneshot::channel();
        let first = map.store(tx1).expect("store should succeed");
        let (tx2, _rx2) = oneshot::channel();
        let second = map.store(tx2).expect("store should succeed");
        let (tx3, _rx3) = oneshot::channel();
        let third = map.store(tx3).expect("store should succeed");

        assert_eq!(first, u16::MAX - 1);
        assert_eq!(second, u16::MAX);
        assert_eq!(third, 0);
        assert!(map.remove(first));
        assert!(map.remove(second));
        assert!(map.remove(third));
    }

    #[test]
    fn test_tombstones_reset_when_map_becomes_empty() {
        let map = RequestMap::with_capacity(1);
        let (tx, _rx) = oneshot::channel();
        let id = map.store(tx).expect("store should succeed");

        assert!(map.remove(id));
        assert!(map.is_empty());
        assert!(
            map.slots
                .iter()
                .all(|slot| meta_state(slot.meta.load(Ordering::Relaxed)) == STATE_EMPTY)
        );
    }

    #[test]
    fn test_store_returns_error_when_table_is_full() {
        let map = RequestMap::with_capacity(1);
        for _ in 0..map.slots.len() {
            let (tx, _rx) = oneshot::channel::<Message>();
            let _ = map
                .store(tx)
                .expect("store should succeed while capacity remains");
        }

        let (tx, _rx) = oneshot::channel::<Message>();
        let err = map
            .store(tx)
            .expect_err("store should fail after table is full");

        assert!(err.to_string().contains("request map exhausted"));
    }
}
