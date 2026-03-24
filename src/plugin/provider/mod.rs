use std::any::Any;
use std::net::IpAddr;

/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;

use crate::message::Name;
use crate::plugin::Plugin;

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
