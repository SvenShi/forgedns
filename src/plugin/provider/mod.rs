/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Provider plugin category.
//!
//! Providers expose reusable datasets to other plugins, especially matchers and
//! executors that need fast membership checks without duplicating parsing or
//! storage logic.
//!
//! Common use cases include:
//!
//! - domain-set membership for qname and CNAME decisions;
//! - IP-set membership for client IP, response IP, or routing behavior; and
//! - typed provider-specific access via downcasting when a plugin needs richer
//!   capabilities than the generic membership helpers.
//!
//! Providers are initialized once, then shared through the plugin registry.
//! Their per-request API should stay read-only and cheap.
use std::any::Any;
use std::net::IpAddr;

use async_trait::async_trait;

use crate::plugin::Plugin;
use crate::proto::Name;

pub mod domain_set;
pub mod ip_set;
pub(crate) mod provider_utils;

#[async_trait]
#[allow(dead_code)]
pub trait Provider: Plugin {
    /// Type-erased view for provider-specific downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Domain membership check using an owned DNS name.
    #[inline]
    fn contains_name(&self, _name: &Name) -> bool {
        false
    }

    /// Fast-path IP membership check for hot matcher paths.
    fn contains_ip(&self, _ip: IpAddr) -> bool {
        false
    }
}
