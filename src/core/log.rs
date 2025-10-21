/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Custom log formatter for RustDNS
//!
//! Provides a structured log format with timestamp, level, target, and span information.
//! Format: `TIMESTAMP LEVEL TARGET:LINE:SPAN{fields}:message`

use chrono::Local;
use std::fmt;
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields, format};
use tracing_subscriber::registry::LookupSpan;

/// Custom log formatter for RustDNS
///
/// Produces logs in the format:
/// `2025-01-15T10:30:45.123456 INFO rustdns::plugin::server::udp:54:message content`
pub struct RustDnsLogFormatter;

impl<S, N> FormatEvent<S, N> for RustDnsLogFormatter
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
        write!(
            &mut writer,
            "{} {} {}",
            Local::now().format("%FT%T%.6f"),
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
