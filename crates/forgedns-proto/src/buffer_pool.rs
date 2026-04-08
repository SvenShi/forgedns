/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared wire buffer pooling for short-lived network payloads.
//!
//! ForgeDNS encodes DNS messages on several hot paths, especially UDP reply
//! writes where each request may need a fresh `Vec<u8>` only for the duration
//! of one send call. A global, size-classed pool lets these transient buffers
//! be reused across tasks without tying reuse to a specific server worker
//! model.
//!
//! The pool is intentionally focused on wire-format payload buffers:
//!
//! - it stores `Vec<u8>` only;
//! - it groups buffers into a few DNS-oriented capacity classes;
//! - callers borrow buffers via an RAII wrapper; and
//! - buffers larger than the configured classes are dropped instead of being
//!   retained indefinitely.

use crossbeam_queue::ArrayQueue;
use std::ops::{Deref, DerefMut};
use std::sync::LazyLock;

const DEFAULT_WIRE_BUFFER_CLASSES: &[(usize, usize)] =
    &[(512, 128), (1232, 256), (2048, 128), (4096, 64), (8192, 32)];

#[derive(Debug)]
struct BufferBucket {
    max_capacity: usize,
    buffers: ArrayQueue<Vec<u8>>,
}

/// Global wire buffer pool used by short-lived network encoding paths.
#[derive(Debug)]
pub struct WireBufferPool {
    buckets: Box<[BufferBucket]>,
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
    fn from_size_classes(size_classes: &[(usize, usize)]) -> Self {
        let buckets = size_classes
            .iter()
            .map(|&(max_capacity, pool_size)| {
                let queue = ArrayQueue::new(pool_size.max(1));
                for _ in 0..pool_size.max(1) {
                    let _ = queue.push(Vec::with_capacity(max_capacity));
                }
                BufferBucket {
                    max_capacity,
                    buffers: queue,
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self { buckets }
    }

    pub fn new_default() -> Self {
        Self::from_size_classes(DEFAULT_WIRE_BUFFER_CLASSES)
    }

    #[inline]
    pub fn acquire(&self, min_capacity: usize) -> PooledWireBuffer<'_> {
        PooledWireBuffer {
            pool: self,
            buffer: Some(self.acquire_vec(min_capacity)),
        }
    }

    #[inline]
    fn acquire_vec(&self, min_capacity: usize) -> Vec<u8> {
        if let Some(bucket) = self.bucket_for_capacity(min_capacity) {
            bucket
                .buffers
                .pop()
                .unwrap_or_else(|| Vec::with_capacity(bucket.max_capacity))
        } else {
            Vec::with_capacity(min_capacity.max(1))
        }
    }

    #[inline]
    fn release_vec(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        let Some(bucket) = self.bucket_for_capacity(buffer.capacity()) else {
            return;
        };
        let _ = bucket.buffers.push(buffer);
    }

    #[inline]
    fn bucket_for_capacity(&self, min_capacity: usize) -> Option<&BufferBucket> {
        self.buckets
            .iter()
            .find(|bucket| bucket.max_capacity >= min_capacity)
    }

    #[cfg(test)]
    fn available_in_bucket(&self, bucket_index: usize) -> usize {
        self.buckets[bucket_index].buffers.len()
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
        let pool = WireBufferPool::from_size_classes(&[(512, 1)]);
        assert_eq!(pool.available_in_bucket(0), 1);

        let capacity = {
            let buffer = pool.acquire(200);
            assert!(buffer.capacity() >= 512);
            assert_eq!(pool.available_in_bucket(0), 0);
            buffer.capacity()
        };

        assert_eq!(pool.available_in_bucket(0), 1);

        let reused = pool.acquire(200);
        assert_eq!(reused.capacity(), capacity);
    }

    #[test]
    fn test_release_moves_grown_buffer_to_larger_bucket() {
        let pool = WireBufferPool::from_size_classes(&[(512, 1), (2048, 1)]);
        assert_eq!(pool.available_in_bucket(0), 1);
        assert_eq!(pool.available_in_bucket(1), 1);

        {
            let mut buffer = pool.acquire(200);
            let larger = pool.acquire(1000);
            assert_eq!(pool.available_in_bucket(0), 0);
            assert_eq!(pool.available_in_bucket(1), 0);
            buffer.resize(1500, 0);
            assert!(buffer.capacity() > 512);
            drop(buffer);
            assert_eq!(pool.available_in_bucket(0), 0);
            assert_eq!(pool.available_in_bucket(1), 1);
            drop(larger);
        }

        assert_eq!(pool.available_in_bucket(0), 0);
        assert_eq!(pool.available_in_bucket(1), 1);
    }

    #[test]
    fn test_oversized_buffer_is_not_retained() {
        let pool = WireBufferPool::from_size_classes(&[(512, 1)]);
        assert_eq!(pool.available_in_bucket(0), 1);

        {
            let mut buffer = pool.acquire(5000);
            buffer.resize(5000, 0);
            assert!(buffer.capacity() >= 5000);
        }

        assert_eq!(pool.available_in_bucket(0), 1);
    }
}
