use std::net::IpAddr;

/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use async_trait::async_trait;

use crate::plugin::Plugin;

#[allow(dead_code)]
pub enum CheckTarget {
    IP(IpAddr),
    DOMAIN(String),
}

#[async_trait]
#[allow(dead_code)]
pub trait Provider: Plugin {
    /// Execute the plugin's logic on a DNS request context
    async fn contains(&self, check_target: CheckTarget) -> bool;
}
