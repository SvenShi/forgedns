// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cache key composition helpers.

use std::net::IpAddr;

use crate::core::context::DnsContext;
use crate::proto::{ClientSubnet, DNSClass, EdnsCode, EdnsOption, Message, RecordType};

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
fn extract_any_ecs_scope(request: &Message) -> Option<EcsScopeDigest> {
    request
        .edns()
        .as_ref()
        .and_then(|edns| match edns.option(EdnsCode::Subnet) {
            Some(EdnsOption::Subnet(subnet)) => Some(subnet),
            _ => None,
        })
        .map(build_ecs_scope_digest)
}

#[inline]
pub(super) fn build_cache_key(context: &mut DnsContext, ecs_in_key: bool) -> Option<CacheKey> {
    let question = context.request.first_question()?;
    let domain = question.name().normalized().to_string();
    let record_type = question.qtype();
    let dns_class = question.qclass();
    let do_bit = context
        .request
        .edns()
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok);
    let cd_bit = context.request.checking_disabled();

    Some(CacheKey {
        domain,
        record_type,
        dns_class,
        do_bit,
        cd_bit,
        ecs_scope: if ecs_in_key {
            extract_any_ecs_scope(&context.request)
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::plugin::test_utils::test_registry;
    use crate::proto::{DNSClass, Edns, EdnsOption, Message, Name, Question, RecordType};

    fn make_context(name: &str) -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii(name).expect("query name should be valid"),
            RecordType::A,
            DNSClass::IN,
        ));
        DnsContext::new(
            SocketAddr::from(([127, 0, 0, 1], 5300)),
            request,
            test_registry(),
        )
    }

    #[test]
    fn test_normalize_domain_key_trims_lowercases_and_strips_dot() {
        let normalized = normalize_domain_key("  WWW.Example.COM.  ");

        assert_eq!(normalized, "www.example.com");
    }

    #[test]
    fn test_write_truncated_prefix_masks_partial_byte() {
        let mut out = [0u8; 16];

        let network_len = write_truncated_prefix(&[0b1111_0000, 0b1010_1010], 12, &mut out);

        assert_eq!(network_len, 2);
        assert_eq!(out[0], 0b1111_0000);
        assert_eq!(out[1], 0b1010_0000);
    }

    #[test]
    fn test_build_ecs_scope_digest_clamps_prefix_and_truncates_network() {
        let subnet = ClientSubnet::new(IpAddr::from([192, 0, 2, 129]), 40, 48);

        let digest = build_ecs_scope_digest(&subnet);

        assert_eq!(digest.family, 1);
        assert_eq!(digest.source_prefix, 32);
        assert_eq!(digest.scope_prefix, 32);
        assert_eq!(digest.network_len, 4);
        assert_eq!(&digest.network[..4], &[192, 0, 2, 129]);
    }

    #[test]
    fn test_build_cache_key_uses_normalized_query_and_flags() {
        let mut context = make_context("WWW.Example.COM.");
        context.request.set_checking_disabled(true);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        context.request.set_edns(edns);

        let cache_key = build_cache_key(&mut context, false).expect("cache key should exist");

        assert_eq!(cache_key.domain, "www.example.com");
        assert_eq!(cache_key.record_type, RecordType::A);
        assert!(cache_key.do_bit);
        assert!(cache_key.cd_bit);
        assert_eq!(cache_key.ecs_scope, None);
    }

    #[test]
    fn test_build_cache_key_includes_ecs_when_enabled() {
        let mut context = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            20,
            24,
        )));
        context.request.set_edns(edns);

        let cache_key = build_cache_key(&mut context, true).expect("cache key should exist");

        let ecs = cache_key.ecs_scope.expect("ecs should be present");
        assert_eq!(ecs.family, 1);
        assert_eq!(ecs.source_prefix, 20);
        assert_eq!(ecs.scope_prefix, 24);
        assert_eq!(ecs.network_len, 3);
        assert_eq!(&ecs.network[..3], &[203, 0, 112]);
    }

    #[test]
    fn test_build_cache_key_returns_none_without_query() {
        let mut context = DnsContext::new(
            SocketAddr::from(([127, 0, 0, 1], 5300)),
            Message::new(),
            test_registry(),
        );

        let cache_key = build_cache_key(&mut context, true);

        assert_eq!(cache_key, None);
    }
}
