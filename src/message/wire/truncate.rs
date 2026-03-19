/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! DNS message truncation helpers.

use crate::message::Record;
use crate::message::codec::LenCompressionMap;

pub(crate) fn truncate_loop<'a>(
    records: &'a [Record],
    size: usize,
    len: &mut usize,
    compression: &mut LenCompressionMap<'a>,
) -> usize {
    for (index, record) in records.iter().enumerate() {
        *len += record.bytes_len(*len, compression);
        if *len > size {
            // Clamp to the caller's budget so subsequent section passes see a stable
            // "already full" state and do not keep accumulating past the limit.
            *len = size;
            return index;
        }
        if *len == size {
            return index + 1;
        }
    }
    records.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Name, RData};

    #[test]
    // Exact-fit behavior matters because Message::truncate walks Answer, Authority,
    // then Additional in order and uses this helper as its cut point.
    fn truncate_loop_returns_prefix_that_fits() {
        let records = vec![
            Record::from_rdata(
                Name::from_ascii("a.example.com.").unwrap(),
                300,
                RData::A(crate::message::A::new(1, 2, 3, 4)),
            ),
            Record::from_rdata(
                Name::from_ascii("bbbbbbbbbbbb.example.com.").unwrap(),
                300,
                RData::A(crate::message::A::new(5, 6, 7, 8)),
            ),
        ];

        let mut compression = LenCompressionMap::new(true);
        let mut len = crate::message::codec::DNS_HEADER_LEN;
        let count = truncate_loop(
            &records,
            len + records[0].bytes_len(len, &mut compression),
            &mut len,
            &mut compression,
        );

        assert_eq!(count, 1);
    }
}
