/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Cache key composition helpers.

use crate::core::context::DnsContext;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::{DNSClass, RecordType};
use std::net::IpAddr;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(super) struct EcsScopeDigest {
    pub(super) family: u16,
    pub(super) source_prefix: u8,
    pub(super) scope_prefix: u8,
    pub(super) network_len: u8,
    pub(super) network: [u8; 16],
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(super) struct CacheKey {
    pub(super) domain: String,
    pub(super) record_type: RecordType,
    pub(super) dns_class: DNSClass,
    pub(super) do_bit: bool,
    pub(super) cd_bit: bool,
    pub(super) ecs_scope: Option<EcsScopeDigest>,
}

#[inline]
pub(super) fn normalize_domain_key(raw: &str) -> String {
    let mut normalized = raw.trim().to_ascii_lowercase();
    if normalized.ends_with('.') {
        normalized.pop();
    }
    normalized
}

#[inline]
fn write_truncated_prefix(src: &[u8], prefix: u8, out: &mut [u8; 16]) -> u8 {
    let max_bits = (src.len() * 8) as u8;
    let prefix = prefix.min(max_bits);
    if prefix == 0 {
        return 0;
    }

    let full_bytes = (prefix / 8) as usize;
    let remaining_bits = prefix % 8;

    if full_bytes > 0 {
        out[..full_bytes].copy_from_slice(&src[..full_bytes]);
    }

    if remaining_bits == 0 {
        full_bytes as u8
    } else {
        let mask = 0xFFu8 << (8 - remaining_bits);
        out[full_bytes] = src[full_bytes] & mask;
        (full_bytes as u8).saturating_add(1)
    }
}

#[inline]
fn build_ecs_scope_digest(subnet: &ClientSubnet) -> EcsScopeDigest {
    let mut network = [0u8; 16];
    let (family, max_prefix, network_len) = match subnet.addr() {
        IpAddr::V4(v4) => {
            let len =
                write_truncated_prefix(&v4.octets(), subnet.source_prefix().min(32), &mut network);
            (1u16, 32u8, len)
        }
        IpAddr::V6(v6) => {
            let len =
                write_truncated_prefix(&v6.octets(), subnet.source_prefix().min(128), &mut network);
            (2u16, 128u8, len)
        }
    };

    let source_prefix = subnet.source_prefix().min(max_prefix);
    let scope_prefix = subnet.scope_prefix().min(max_prefix);

    EcsScopeDigest {
        family,
        source_prefix,
        scope_prefix,
        network_len,
        network,
    }
}

#[inline]
fn extract_do_bit(request: &Message) -> bool {
    request
        .extensions()
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok)
}

#[inline]
fn extract_ecs_scope(request: &Message) -> Option<EcsScopeDigest> {
    let edns = request.extensions().as_ref()?;
    let option = edns.option(EdnsCode::Subnet)?;
    let EdnsOption::Subnet(subnet) = option else {
        return None;
    };

    Some(build_ecs_scope_digest(subnet))
}

#[inline]
pub(super) fn build_cache_key(context: &mut DnsContext, ecs_in_key: bool) -> Option<CacheKey> {
    let (record_type, dns_class) = context
        .request
        .query()
        .map(|query| (query.query_type, query.query_class))?;

    let domain = context.query_view()?.normalized_name().to_string();

    Some(CacheKey {
        domain,
        record_type,
        dns_class,
        do_bit: extract_do_bit(&context.request),
        cd_bit: context.request.checking_disabled(),
        ecs_scope: if ecs_in_key {
            extract_ecs_scope(&context.request)
        } else {
            None
        },
    })
}
