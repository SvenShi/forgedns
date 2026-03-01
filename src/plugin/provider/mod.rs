use std::any::Any;
use std::net::IpAddr;

/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;

use crate::plugin::Plugin;

pub mod domain_set;
pub mod ip_set;

#[async_trait]
#[allow(dead_code)]
pub trait Provider: Plugin {
    /// Type-erased view for provider-specific downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Fast-path domain membership check for hot matcher paths.
    fn contains_domain(&self, _domain: &str) -> bool {
        false
    }

    /// Domain membership check with pre-normalized domain and pre-split labels.
    ///
    /// `domain` is expected to be lowercased and without trailing dot.
    /// `labels_rev` is expected to be reverse labels of `domain`.
    #[inline]
    fn contains_domain_prepared(&self, domain: &str, _labels_rev: &[&str]) -> bool {
        self.contains_domain(domain)
    }

    /// Whether this provider has suffix-domain(trie) rules and can use `labels_rev`.
    #[inline]
    fn has_trie_domain_rules(&self) -> bool {
        false
    }

    /// Fast-path IP membership check for hot matcher paths.
    fn contains_ip(&self, _ip: IpAddr) -> bool {
        false
    }
}
