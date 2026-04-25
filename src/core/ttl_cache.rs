// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared TTL cache component.
//!
//! This module provides a reusable concurrent cache with:
//! - per-entry expiration timestamp
//! - last-access timestamp for sampled LRU eviction
//! - lightweight helpers for periodic cleanup tasks
//!
//! It is designed for plugin-level caches where each plugin keeps its own key
//! and value types but shares the same cache behavior.

use std::hash::Hash;
use std::sync::Arc;

use ahash::RandomState as AHashBuilder;
use dashmap::{DashMap, Entry};

/// Snapshot of one cached entry with metadata.
#[derive(Debug, Clone)]
pub struct TtlCacheEntry<V> {
    /// User data stored in cache.
    pub value: V,
    /// Insert/update timestamp in milliseconds.
    pub cache_time_ms: u64,
    /// Expiration timestamp in milliseconds.
    pub expire_at_ms: u64,
    /// Last access timestamp in milliseconds.
    pub last_access_ms: u64,
}

/// Shared concurrent TTL cache.
#[derive(Debug)]
pub struct TtlCache<K, V>
where
    K: Eq + Hash,
{
    map: Arc<DashMap<K, TtlCacheEntry<V>, AHashBuilder>>,
}

impl<K, V> Clone for TtlCache<K, V>
where
    K: Eq + Hash,
{
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }
}

#[allow(dead_code)]
impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash,
{
    /// Create cache using AHash hasher with expected capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: Arc::new(DashMap::with_capacity_and_hasher(
                capacity,
                AHashBuilder::default(),
            )),
        }
    }

    /// Current number of cached entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns true when cache has no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash,
{
    /// Insert or update one entry using "now" for cache and access timestamps.
    #[inline]
    pub fn insert_or_update(&self, key: K, value: V, now_ms: u64, expire_at_ms: u64) {
        self.insert_or_update_with_meta(key, value, now_ms, expire_at_ms, now_ms);
    }

    /// Insert or update one entry with explicit metadata.
    pub fn insert_or_update_with_meta(
        &self,
        key: K,
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
    ) {
        match self.map.entry(key) {
            Entry::Occupied(mut e) => {
                let existing = e.get_mut();
                existing.value = value;
                existing.cache_time_ms = cache_time_ms;
                existing.expire_at_ms = expire_at_ms;
                existing.last_access_ms = last_access_ms;
            }
            Entry::Vacant(e) => {
                e.insert(TtlCacheEntry {
                    value,
                    cache_time_ms,
                    expire_at_ms,
                    last_access_ms,
                });
            }
        }
    }

    /// Get one retained, non-expired entry and optionally refresh its access
    /// timestamp.
    ///
    /// This method only enforces the shared cache-retention deadline
    /// (`expire_at_ms`). Callers that need a fresh/stale split can apply their
    /// own semantics using the returned metadata.
    #[inline]
    pub fn get_retained_cloned(
        &self,
        key: &K,
        now_ms: u64,
        touch_interval_ms: u64,
    ) -> Option<TtlCacheEntry<V>>
    where
        V: Clone,
    {
        let entry = self.map.get(key)?;
        if entry.expire_at_ms <= now_ms {
            drop(entry);
            let _ = self
                .map
                .remove_if(key, |_, existing| existing.expire_at_ms <= now_ms);
            return None;
        }

        let snapshot = TtlCacheEntry {
            value: entry.value.clone(),
            cache_time_ms: entry.cache_time_ms,
            expire_at_ms: entry.expire_at_ms,
            last_access_ms: entry.last_access_ms,
        };
        drop(entry);

        if touch_interval_ms > 0
            && now_ms.saturating_sub(snapshot.last_access_ms) >= touch_interval_ms
            && let Some(mut existing) = self.map.get_mut(key)
            && existing.expire_at_ms > now_ms
            && existing.last_access_ms < now_ms
        {
            existing.last_access_ms = now_ms;
        }

        Some(snapshot)
    }

    /// Remove one entry only when already expired at `now_ms`.
    #[inline]
    pub fn remove_if_expired(&self, key: &K, now_ms: u64) -> bool {
        self.map
            .remove_if(key, |_, existing| existing.expire_at_ms <= now_ms)
            .is_some()
    }

    /// Remove one entry by key.
    #[inline]
    pub fn remove(&self, key: &K) -> bool {
        self.map.remove(key).is_some()
    }

    /// Remove all cached entries.
    #[inline]
    pub fn clear(&self) {
        self.map.clear();
    }
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone,
{
    /// Remove at most `batch` expired entries and return removed count.
    #[inline]
    pub fn remove_expired_batch(&self, now_ms: u64, batch: usize) -> usize {
        if batch == 0 {
            return 0;
        }

        let mut expired_keys = Vec::with_capacity(batch);
        for item in self.map.iter() {
            if item.value().expire_at_ms <= now_ms {
                expired_keys.push(item.key().clone());
                if expired_keys.len() >= batch {
                    break;
                }
            }
        }

        let mut removed = 0usize;
        for key in expired_keys {
            if self
                .map
                .remove_if(&key, |_, existing| existing.expire_at_ms <= now_ms)
                .is_some()
            {
                removed += 1;
            }
        }

        removed
    }

    /// Collect up to `limit` key + last-access pairs for sampled LRU eviction.
    #[inline]
    pub fn sample_last_access(&self, limit: usize) -> Vec<(K, u64)> {
        let cap = self.map.len().min(limit);
        let mut sample = Vec::with_capacity(cap);
        for item in self.map.iter().take(limit) {
            sample.push((item.key().clone(), item.value().last_access_ms));
        }
        sample
    }

    /// Snapshot all entries (key + metadata + cloned value).
    #[inline]
    pub fn iter_entries_cloned(&self) -> Vec<(K, TtlCacheEntry<V>)>
    where
        V: Clone,
    {
        let mut entries = Vec::with_capacity(self.map.len());
        for item in self.map.iter() {
            let value = item.value();
            entries.push((
                item.key().clone(),
                TtlCacheEntry {
                    value: value.value.clone(),
                    cache_time_ms: value.cache_time_ms,
                    expire_at_ms: value.expire_at_ms,
                    last_access_ms: value.last_access_ms,
                },
            ));
        }
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_get_and_remove_if_expired() {
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update("k", 1u32, 100, 200);

        let hit = cache
            .get_retained_cloned(&"k", 150, 0)
            .expect("entry should exist");
        assert_eq!(hit.value, 1);

        assert!(cache.remove_if_expired(&"k", 250));
        assert!(cache.get_retained_cloned(&"k", 260, 0).is_none());
    }

    #[test]
    fn test_remove_expired_batch_and_sample_last_access() {
        let cache = TtlCache::with_capacity(8);
        cache.insert_or_update_with_meta("a", 1u32, 10, 20, 11);
        cache.insert_or_update_with_meta("b", 2u32, 10, 200, 12);
        cache.insert_or_update_with_meta("c", 3u32, 10, 15, 13);

        let removed = cache.remove_expired_batch(30, 10);
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 1);

        let sample = cache.sample_last_access(10);
        assert_eq!(sample.len(), 1);
        assert_eq!(sample[0].0, "b");
    }

    #[test]
    fn test_get_retained_cloned_refreshes_last_access_after_touch_interval() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);

        // Act
        let hit = cache
            .get_retained_cloned(&"k", 25, 10)
            .expect("entry should exist");
        let (_, stored) = cache
            .iter_entries_cloned()
            .into_iter()
            .next()
            .expect("entry should remain cached");

        // Assert
        assert_eq!(hit.last_access_ms, 10);
        assert_eq!(stored.last_access_ms, 25);
    }

    #[test]
    fn test_get_retained_cloned_does_not_refresh_last_access_before_touch_interval() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);

        // Act
        let _ = cache
            .get_retained_cloned(&"k", 15, 10)
            .expect("entry should exist");
        let (_, stored) = cache
            .iter_entries_cloned()
            .into_iter()
            .next()
            .expect("entry should remain cached");

        // Assert
        assert_eq!(stored.last_access_ms, 10);
    }

    #[test]
    fn test_get_retained_cloned_removes_expired_entry() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 20, 10);

        // Act
        let hit = cache.get_retained_cloned(&"k", 20, 10);

        // Assert
        assert!(hit.is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_insert_or_update_replaces_existing_entry_without_growing_cache() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 20, 11);

        // Act
        cache.insert_or_update_with_meta("k", 2u32, 30, 40, 31);
        let (_, stored) = cache
            .iter_entries_cloned()
            .into_iter()
            .next()
            .expect("entry should exist");

        // Assert
        assert_eq!(cache.len(), 1);
        assert_eq!(stored.value, 2);
        assert_eq!(stored.cache_time_ms, 30);
        assert_eq!(stored.expire_at_ms, 40);
        assert_eq!(stored.last_access_ms, 31);
    }
}
