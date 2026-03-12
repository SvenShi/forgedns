/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS response values and packet-level response helpers.

mod build;
mod rewrite;
mod scan;
mod value;

#[cfg(test)]
mod tests;

pub use build::{
    build_address_response_packet, build_response_message_from_request, build_response_packet,
};
pub(crate) use rewrite::{collect_response_ttl_offsets, rewrite_response_id_and_ttls};
pub use rewrite::{rewrite_response_id, rewrite_response_ttls};
pub(crate) use scan::{ResponseScanSummary, ResponseTtlOffsets, scan_response};
pub use scan::{
    response_answer_any_ip, response_answer_ip_ttls, response_answer_ips, response_cnames,
    response_has_answer_type, response_ips, response_min_answer_ttl,
    response_negative_ttl_from_soa, response_rcode,
};
pub use value::Response;
