/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared wire buffer pooling for short-lived network payloads.
//!
//! ForgeDNS encodes DNS messages on several hot paths, especially UDP reply
//! writes where each request may need a fresh `Vec<u8>` only for the duration
//! of one send call. A global fixed-capacity pool lets these transient buffers
//! be reused across tasks without tying reuse to a specific server worker
//! model.
//!
//! The pool is intentionally focused on wire-format payload buffers:
//!
//! - it stores `Vec<u8>` only;
//! - it always returns buffers with the same DNS-oriented capacity;
//! - callers borrow buffers via an RAII wrapper; and
//! - buffers that grew beyond the fixed capacity are replaced on return.

use crossbeam_queue::ArrayQueue;
use std::ops::{Deref, DerefMut};
use std::sync::LazyLock;

const DEFAULT_WIRE_BUFFER_CAPACITY: usize = 8191;
const DEFAULT_WIRE_BUFFER_POOL_SIZE: usize = 256;

/// Global wire buffer pool used by short-lived network encoding paths.
#[derive(Debug)]
pub struct WireBufferPool {
    buffer_capacity: usize,
    buffers: ArrayQueue<Vec<u8>>,
}

/// RAII guard for a pooled wire buffer.
///
/// The wrapped `Vec<u8>` can be used like a normal buffer through
/// `Deref/DerefMut`. Dropping the guard returns the buffer to the originating
/// pool when its capacity fits one of the configured size classes.
pub struct PooledWireBuffer<'a> {
    pool: &'a WireBufferPool,
    buffer: Option<Vec<u8>>,
}

impl WireBufferPool {
    fn new(buffer_capacity: usize, pool_size: usize) -> Self {
        let pool_size = pool_size.max(1);
        let buffers = ArrayQueue::new(pool_size);
        for _ in 0..pool_size {
            let _ = buffers.push(Vec::with_capacity(buffer_capacity.max(1)));
        }

        Self {
            buffer_capacity: buffer_capacity.max(1),
            buffers,
        }
    }

    pub fn new_default() -> Self {
        Self::new(DEFAULT_WIRE_BUFFER_CAPACITY, DEFAULT_WIRE_BUFFER_POOL_SIZE)
    }

    #[inline]
    pub fn acquire(&self) -> PooledWireBuffer<'_> {
        PooledWireBuffer {
            pool: self,
            buffer: Some(self.acquire_vec()),
        }
    }

    #[inline]
    fn acquire_vec(&self) -> Vec<u8> {
        self.buffers
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.buffer_capacity))
    }

    #[inline]
    fn release_vec(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        if buffer.capacity() != self.buffer_capacity {
            buffer = Vec::with_capacity(self.buffer_capacity);
        }
        let _ = self.buffers.push(buffer);
    }

    #[cfg(test)]
    fn available(&self) -> usize {
        self.buffers.len()
    }
}

impl Default for WireBufferPool {
    fn default() -> Self {
        Self::new_default()
    }
}

impl<'a> PooledWireBuffer<'a> {
    #[inline]
    pub fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        self.buffer
            .as_mut()
            .expect("pooled wire buffer should always hold a buffer")
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buffer
            .as_ref()
            .expect("pooled wire buffer should always hold a buffer")
            .capacity()
    }
}

impl AsRef<[u8]> for PooledWireBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
            .as_ref()
            .expect("pooled wire buffer should always hold a buffer")
            .as_slice()
    }
}

impl AsMut<[u8]> for PooledWireBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer
            .as_mut()
            .expect("pooled wire buffer should always hold a buffer")
            .as_mut_slice()
    }
}

impl Deref for PooledWireBuffer<'_> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.buffer
            .as_ref()
            .expect("pooled wire buffer should always hold a buffer")
    }
}

impl DerefMut for PooledWireBuffer<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer
            .as_mut()
            .expect("pooled wire buffer should always hold a buffer")
    }
}

impl Drop for PooledWireBuffer<'_> {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.release_vec(buffer);
        }
    }
}

static GLOBAL_WIRE_BUFFER_POOL: LazyLock<WireBufferPool> =
    LazyLock::new(WireBufferPool::new_default);

#[inline]
pub fn wire_buffer_pool() -> &'static WireBufferPool {
    &GLOBAL_WIRE_BUFFER_POOL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_reuses_buffer_from_matching_bucket() {
        let pool = WireBufferPool::new(8191, 1);
        assert_eq!(pool.available(), 1);

        let capacity = {
            let buffer = pool.acquire();
            assert_eq!(buffer.capacity(), 8191);
            assert_eq!(pool.available(), 0);
            buffer.capacity()
        };

        assert_eq!(pool.available(), 1);

        let reused = pool.acquire();
        assert_eq!(reused.capacity(), capacity);
    }

    #[test]
    fn test_release_replaces_grown_buffer_with_fixed_capacity() {
        let pool = WireBufferPool::new(8191, 1);
        assert_eq!(pool.available(), 1);

        {
            let mut buffer = pool.acquire();
            assert_eq!(pool.available(), 0);
            buffer.resize(16_384, 0);
            assert!(buffer.capacity() > 8191);
            drop(buffer);
        }

        assert_eq!(pool.available(), 1);
        let buffer = pool.acquire();
        assert_eq!(buffer.capacity(), 8191);
    }

    #[test]
    fn test_acquire_ignores_requested_min_capacity() {
        let pool = WireBufferPool::new(8191, 2);

        let small = pool.acquire();
        let large = pool.acquire();

        assert_eq!(small.capacity(), 8191);
        assert_eq!(large.capacity(), 8191);
    }
}
