/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS name compression helpers for wire encoding and length estimation.

use crate::message::Name;
use ahash::{AHashMap, AHashSet};

const MAX_COMPRESSION_POINTER_OFFSET: usize = 0x4000;

#[derive(Default)]
pub(crate) struct LenCompressionMap<'a> {
    enabled: bool,
    set: AHashSet<&'a [u8]>,
}

impl<'a> LenCompressionMap<'a> {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            set: AHashSet::with_capacity(32),
        }
    }
}

pub(crate) fn domain_name_len<'a>(
    name: &'a Name,
    off: usize,
    compression: &mut LenCompressionMap<'a>,
    compress: bool,
) -> usize {
    if name.is_root() {
        return 1;
    }

    if name.bytes_len() > 255 {
        return name.wire().len();
    }

    if !compression.enabled {
        return name.wire().len();
    }

    let mut prefix_len = 0usize;
    for index in 0..name.label_count() {
        let suffix = name.wire_suffix_from(index);

        if compress && compression.set.contains(suffix) {
            return prefix_len + 2;
        }

        if off + prefix_len < MAX_COMPRESSION_POINTER_OFFSET {
            compression.set.insert(suffix);
        }

        prefix_len += 1 + name.wire_label_at(index).len();
    }

    prefix_len + 1
}

#[derive(Debug, Default)]
pub(crate) struct CompressionState<'a> {
    enabled: bool,
    suffix_map: Option<AHashMap<&'a [u8], u16>>,
}

impl<'a> CompressionState<'a> {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            suffix_map: None,
        }
    }

    pub(crate) fn pointer_for(&self, name: &Name) -> Option<(usize, u16)> {
        if !self.enabled {
            return None;
        }
        let map = self.suffix_map.as_ref()?;
        for index in 0..name.label_count() {
            let suffix = name.wire_suffix_from(index);
            if let Some(&offset) = map.get(suffix) {
                return Some((index, offset));
            }
        }
        None
    }

    pub(crate) fn insert_suffix(&mut self, suffix: &'a [u8], position: u16) {
        if !self.enabled {
            return;
        }
        if usize::from(position) >= MAX_COMPRESSION_POINTER_OFFSET {
            return;
        }
        let map = self
            .suffix_map
            .get_or_insert_with(|| AHashMap::with_capacity(32));
        map.entry(suffix).or_insert(position);
    }
}
