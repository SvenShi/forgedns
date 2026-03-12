/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Reusable byte buffers for hot-path DNS message encoding.
//!
//! The benchmark pack exercises UDP/TCP response serialization heavily. Reusing
//! encoding buffers removes a large number of short-lived `Vec<u8>` allocations
//! from that path without changing protocol behavior.

use crossbeam_queue::SegQueue;
use lazy_static::lazy_static;

const DEFAULT_BUFFER_CAPACITY: usize = 512;
const MAX_RETAINED_CAPACITY: usize = 64 * 1024;

lazy_static! {
    static ref BYTE_BUFFER_POOL: SegQueue<Vec<u8>> = SegQueue::new();
}

#[derive(Debug)]
pub(crate) struct ReusableBuffer {
    buf: Vec<u8>,
}

impl ReusableBuffer {
    #[inline]
    pub(crate) fn with_capacity(min_capacity: usize) -> Self {
        let mut buf = BYTE_BUFFER_POOL.pop().unwrap_or_default();
        buf.clear();

        let target_capacity = min_capacity.max(DEFAULT_BUFFER_CAPACITY);
        if buf.capacity() < target_capacity {
            buf.reserve(target_capacity - buf.capacity());
        }

        Self { buf }
    }

    #[inline]
    pub(crate) fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl Drop for ReusableBuffer {
    fn drop(&mut self) {
        if self.buf.capacity() > MAX_RETAINED_CAPACITY {
            return;
        }

        let mut buf = std::mem::take(&mut self.buf);
        buf.clear();
        BYTE_BUFFER_POOL.push(buf);
    }
}
