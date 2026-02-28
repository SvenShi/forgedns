use std::any::Any;
use std::net::IpAddr;

/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;

use crate::plugin::Plugin;

pub mod domain_set;

#[allow(dead_code)]
pub enum CheckTarget {
    IP(IpAddr),
    DOMAIN(String),
}

#[async_trait]
#[allow(dead_code)]
pub trait Provider: Plugin {
    /// Type-erased view for provider-specific downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Execute the plugin's logic on a generic target.
    async fn contains(&self, check_target: CheckTarget) -> bool {
        match check_target {
            CheckTarget::IP(ip) => self.contains_ip(ip),
            CheckTarget::DOMAIN(domain) => self.contains_domain(&domain),
        }
    }

    /// Fast-path domain membership check for hot matcher paths.
    fn contains_domain(&self, _domain: &str) -> bool {
        false
    }

    /// Fast-path IP membership check for hot matcher paths.
    fn contains_ip(&self, _ip: IpAddr) -> bool {
        false
    }
}
