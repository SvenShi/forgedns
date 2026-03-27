use crate::proto::Name;
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
            set: if enabled {
                AHashSet::with_capacity(32)
            } else {
                AHashSet::default()
            },
        }
    }

    /// Stop recording new suffixes once the trailer-length calculation reaches the
    /// detached signature block. This mirrors the limited encoder, where trailer names
    /// are intentionally emitted without compression.
    pub(crate) fn disable(&mut self) {
        self.enabled = false;
    }
}

pub(crate) fn domain_name_len<'a>(
    name: &'a Name,
    compression: &mut LenCompressionMap<'a>,
    compress: bool,
) -> usize {
    if name.is_root() {
        return 1;
    }

    let wire_len = name.bytes_len();
    if wire_len > 255 || !compression.enabled {
        return wire_len;
    }

    let label_count = name.label_count();
    let mut prefix_len = 0usize;

    for index in 0..label_count {
        let (label_len, suffix) = name.wire_label_len_and_suffix_at(index);

        if compress && compression.set.contains(suffix) {
            return prefix_len + 2;
        }

        compression.set.insert(suffix);

        prefix_len += 1 + label_len as usize;
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
        let label_count = name.label_count();

        for index in 0..label_count {
            let (_, suffix) = name.wire_label_len_and_suffix_at(index);
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

    /// Disable name compression for all subsequent encodes.
    ///
    /// The limited UDP path switches compression off before writing the trailer so the
    /// detached signature block cannot reference names introduced by truncated RR data.
    pub(crate) fn disable(&mut self) {
        self.enabled = false;
    }
}
