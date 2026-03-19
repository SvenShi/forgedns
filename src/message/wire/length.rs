/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Wire-length helpers for DNS message encoding.

use crate::message::{Edns, EdnsOption};
use std::net::IpAddr;

pub(crate) fn edns_record_len(edns: &Edns) -> usize {
    let mut rdlen = 0usize;
    for option in edns.options() {
        rdlen += edns_option_len(option);
    }
    1 + 2 + 2 + 4 + 2 + rdlen
}

/// Return the full encoded size of one EDNS option:
/// `[code:2][length:2][data:N]`.
fn edns_option_len(option: &EdnsOption) -> usize {
    match option {
        EdnsOption::Subnet(value) => {
            let max_prefix = match value.addr() {
                IpAddr::V4(_) => 32u8,
                IpAddr::V6(_) => 128u8,
            };
            let source_prefix = value.source_prefix().min(max_prefix);
            let required_len = usize::from(source_prefix).div_ceil(8);
            2 + 2 + 2 + 1 + 1 + required_len
        }
        EdnsOption::Unknown(_, data) => 2 + 2 + data.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{ClientSubnet, Edns};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    // Mirrors the exact wire accounting used by OPT packing so reserve/truncate logic
    // cannot drift from the encoder.
    fn edns_option_len_matches_wire_layout() {
        let subnet = EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 123)),
            24,
            0,
        ));
        assert_eq!(edns_option_len(&subnet), 11);

        let unknown = EdnsOption::Unknown(65001, vec![1, 2, 3]);
        assert_eq!(edns_option_len(&unknown), 7);
    }

    #[test]
    // Guards the shared length helper used by truncate and by size prediction.
    fn edns_record_len_matches_encoded_opt_rr_size() {
        let mut edns = Edns::new();
        edns.set_udp_payload_size(1400);
        edns.insert(EdnsOption::Unknown(65001, vec![1, 2, 3]));

        assert_eq!(edns_record_len(&edns), 11 + 7);
    }
}
