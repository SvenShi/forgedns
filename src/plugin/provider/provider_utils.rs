/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared helpers for provider plugins.

use crate::core::error::{DnsError, Result as DnsResult};
use ahash::AHashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;

fn for_each_nonempty_rule_line_reader<R, F, G>(
    mut reader: R,
    mut on_line: F,
    mut on_read_error: G,
) -> DnsResult<()>
where
    R: BufRead,
    F: FnMut(&str, usize) -> DnsResult<()>,
    G: FnMut(usize, std::io::Error) -> DnsError,
{
    // Reuse one line buffer to reduce allocations for large files.
    let mut line = String::with_capacity(256);
    let mut line_no = 0usize;
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| on_read_error(line_no + 1, e))?;
        if n == 0 {
            break;
        }
        line_no += 1;

        let raw = line.trim();
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        on_line(raw, line_no)?;
    }

    Ok(())
}

/// Read non-empty rule lines from a text file.
///
/// Empty lines and lines prefixed with `#` are skipped.
pub(crate) fn for_each_nonempty_rule_line<F>(
    path: &str,
    file_kind: &str,
    mut on_line: F,
) -> DnsResult<()>
where
    F: FnMut(&str, usize) -> DnsResult<()>,
{
    if path.trim().is_empty() {
        return Ok(());
    }

    let file = File::open(path).map_err(|e| {
        DnsError::plugin(format!(
            "failed to open {} file '{}': {}",
            file_kind, path, e
        ))
    })?;
    let reader = BufReader::with_capacity(256 * 1024, file);

    for_each_nonempty_rule_line_reader(
        reader,
        |raw, line_no| on_line(raw, line_no),
        |line_no, e| {
            DnsError::plugin(format!(
                "failed to read {} file '{}' at line {}: {}",
                file_kind, path, line_no, e
            ))
        },
    )
}

#[cfg(test)]
pub(crate) fn for_each_nonempty_rule_text<F>(content: &str, on_line: F) -> DnsResult<()>
where
    F: FnMut(&str, usize) -> DnsResult<()>,
{
    let reader = BufReader::new(content.as_bytes());
    for_each_nonempty_rule_line_reader(reader, on_line, |line_no, e| {
        DnsError::plugin(format!(
            "failed to read rule input at line {}: {}",
            line_no, e
        ))
    })
}

/// Push matcher into `matchers` if its Arc pointer has not been seen.
#[inline]
pub(crate) fn push_unique_matcher<T>(
    matchers: &mut Vec<Arc<T>>,
    seen: &mut AHashSet<usize>,
    matcher: Arc<T>,
) {
    let ptr = Arc::as_ptr(&matcher) as usize;
    if seen.insert(ptr) {
        matchers.push(matcher);
    }
}
