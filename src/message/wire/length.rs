/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Wire-length helpers for DNS message encoding.

use crate::message::{Edns, EdnsOption};

pub(crate) fn edns_record_len(edns: &Edns) -> usize {
    let mut rdlen = 0usize;
    for option in edns.options() {
        rdlen += edns_option_len(option);
    }
    1 + 2 + 2 + 4 + 2 + rdlen
}

/// Return the full encoded size of one EDNS option:
/// `[code:2][length:2][data:N]`.
pub(crate) fn edns_option_len(option: &EdnsOption) -> usize {
    2 + 2 + option.payload_len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{ClientSubnet, Edns};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    // Verifies that the shared helper stays aligned with the actual OPT option
    // wire layout used by the encoder.
    fn edns_option_len_matches_wire_layout() {
        let subnet = EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 123)),
            24,
            0,
        ));
        assert_eq!(edns_option_len(&subnet), 11);

        let local = EdnsOption::Local(crate::message::EdnsLocal::new(65001, vec![1, 2, 3]));
        assert_eq!(edns_option_len(&local), 7);
    }

    #[test]
    // Guards the shared length helper used by truncate and by size prediction.
    fn edns_record_len_matches_encoded_opt_rr_size() {
        let mut edns = Edns::new();
        edns.set_udp_payload_size(1400);
        edns.insert(EdnsOption::Local(crate::message::EdnsLocal::new(
            65001,
            vec![1, 2, 3],
        )));

        assert_eq!(edns_record_len(&edns), 11 + 7);
    }
}
