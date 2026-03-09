/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Custom log formatter for ForgeDNS
//!
//! Provides a structured log format with timestamp, level, target, and span information.
//! Format: `UTC_ISO8601 T+SECONDS.MILLISECONDS LEVEL TARGET:LINE:SPAN{fields}:message`

use crate::core::app_clock::AppClock;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields, format};
use tracing_subscriber::registry::LookupSpan;

/// Custom log formatter for ForgeDNS
///
/// Produces logs in the format:
/// `2026-03-04T16:02:01.123Z T+12.345 INFO forgedns::plugin::server::udp:54:message content`
pub struct ForgeDnsLogFormatter;

#[inline]
fn civil_from_days(days_since_epoch: i64) -> (i32, u8, u8) {
    // Convert days since 1970-01-01 to proleptic Gregorian date.
    // Reference: Howard Hinnant's "civil_from_days".
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let mut year = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let month = (mp + if mp < 10 { 3 } else { -9 }) as u8; // [1, 12]
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[inline]
fn write_utc_iso8601(writer: &mut format::Writer<'_>, unix_secs: u64, millis: u32) -> fmt::Result {
    let days = (unix_secs / 86_400) as i64;
    let sod = (unix_secs % 86_400) as u32;
    let hour = sod / 3_600;
    let minute = (sod % 3_600) / 60;
    let second = sod % 60;
    let (year, month, day) = civil_from_days(days);

    write!(
        writer,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, millis
    )
}

impl<S, N> FormatEvent<S, N> for ForgeDnsLogFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        // Write timestamp, log level, and target module
        let metadata = event.metadata();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let wall_secs = wall.as_secs();
        let wall_millis = wall.subsec_millis();
        let elapsed_ms = AppClock::elapsed_millis();
        let elapsed_secs = elapsed_ms / 1000;
        let elapsed_sub_ms = elapsed_ms % 1000;
        write_utc_iso8601(&mut writer, wall_secs, wall_millis)?;
        write!(
            &mut writer,
            " T+{}.{:03} {} {}",
            elapsed_secs,
            elapsed_sub_ms,
            metadata.level(),
            metadata.target()
        )?;

        // Append line number if available
        if let Some(line) = metadata.line() {
            write!(&mut writer, ":{line}")?;
        }

        // Write span context hierarchy (if any)
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, ":{}", span.name())?;

                let ext = span.extensions();
                let fields = &ext
                    .get::<FormattedFields<N>>()
                    .expect("Formatted fields should always exist");

                // Include span fields if present
                if !fields.is_empty() {
                    write!(writer, "{{{fields}}}")?;
                }
            }
        }

        // Write the actual log message fields
        write!(writer, ":")?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::fmt::format;

    #[test]
    fn test_civil_from_days_converts_unix_epoch() {
        let date = civil_from_days(0);

        assert_eq!(date, (1970, 1, 1));
    }

    #[test]
    fn test_write_utc_iso8601_formats_expected_timestamp() {
        let mut output = String::new();
        let mut writer = format::Writer::new(&mut output);

        write_utc_iso8601(&mut writer, 86_400 + 3661, 234)
            .expect("timestamp formatting should succeed");

        assert_eq!(output, "1970-01-02T01:01:01.234Z");
    }
}
