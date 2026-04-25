// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Application logging bootstrap and formatter.

use std::path::Path;
use std::{fmt as std_fmt, fs};

use tracing::{Event, Subscriber, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::{
    self as tracing_fmt, FmtContext, FormatEvent, FormatFields, FormattedFields, format,
};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use crate::config::types::{LogConfig, LogRotation};
use crate::core::app_clock::AppClock;
use crate::core::system_utils::unix_time;

/// Initialize the logging system with console and optional file output.
pub fn start_logging(log: LogConfig) -> WorkerGuard {
    let (file_writer, guard) = if let Some(ref file_path) = log.file {
        let file_appender = build_file_appender(file_path, &log.rotation)
            .unwrap_or_else(|err| panic!("failed to initialize log file appender: {err}"));
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    let console_layer = tracing_fmt::layer()
        .event_format(ForgeDnsLogFormatter)
        .with_writer(std::io::stdout);
    let file_layer = file_writer.map(|writer| {
        tracing_fmt::layer()
            .with_ansi(false)
            .event_format(ForgeDnsLogFormatter)
            .with_writer(writer)
    });

    let (filter, invalid_level) = match EnvFilter::try_new(&log.level) {
        Ok(filter) => (filter, false),
        Err(_) => (EnvFilter::new("info"), true),
    };

    let subscriber = Registry::default().with(filter).with(console_layer);
    if let Some(file_layer) = file_layer {
        subscriber.with(file_layer).init();
    } else {
        subscriber.init();
    };

    if invalid_level {
        warn!(
            requested_level = %log.level,
            effective_level = "info",
            "Invalid log level from config, fallback applied"
        );
    }

    if let Some(file_path) = log.file.as_deref() {
        info!(
            level = %log.level,
            file = %file_path,
            "Logging system initialized"
        );
    } else {
        info!(level = %log.level, "Logging system initialized");
    }

    guard.unwrap_or_else(|| tracing_appender::non_blocking(std::io::sink()).1)
}

fn build_file_appender(path: &str, rotation: &LogRotation) -> std::io::Result<RollingFileAppender> {
    let path = Path::new(path);
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let filename = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "log file path must include a file name",
        )
    })?;
    let filename = filename.to_string_lossy().into_owned();

    fs::create_dir_all(directory)?;

    let appender = match rotation {
        LogRotation::Never => build_official_appender(Rotation::NEVER, directory, &filename, None)?,
        LogRotation::Minutely { max_files } => {
            build_official_appender(Rotation::MINUTELY, directory, &filename, *max_files)?
        }
        LogRotation::Hourly { max_files } => {
            build_official_appender(Rotation::HOURLY, directory, &filename, *max_files)?
        }
        LogRotation::Daily { max_files } => {
            build_official_appender(Rotation::DAILY, directory, &filename, *max_files)?
        }
        LogRotation::Weekly { max_files } => {
            build_official_appender(Rotation::WEEKLY, directory, &filename, *max_files)?
        }
    };

    Ok(appender)
}

fn build_official_appender(
    rotation: Rotation,
    directory: &Path,
    filename: &str,
    max_files: Option<usize>,
) -> std::io::Result<RollingFileAppender> {
    let mut builder = RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(filename);
    if let Some(max_files) = max_files {
        builder = builder.max_log_files(max_files);
    }
    builder
        .build(directory)
        .map_err(|err| std::io::Error::other(err.to_string()))
}

/// Custom log formatter for ForgeDNS.
pub struct ForgeDnsLogFormatter;

#[inline]
fn civil_from_days(days_since_epoch: i64) -> (i32, u8, u8) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = (yoe + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = (mp + if mp < 10 { 3 } else { -9 }) as u8;
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[inline]
fn write_utc_iso8601(
    writer: &mut format::Writer<'_>,
    unix_secs: u64,
    millis: u32,
) -> std_fmt::Result {
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
    ) -> std_fmt::Result {
        let metadata = event.metadata();
        let wall = unix_time();
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

        if let Some(line) = metadata.line() {
            write!(&mut writer, ":{line}")?;
        }

        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, ":{}", span.name())?;

                let ext = span.extensions();
                let fields = &ext
                    .get::<FormattedFields<N>>()
                    .expect("Formatted fields should always exist");

                if !fields.is_empty() {
                    write!(writer, "{{{fields}}}")?;
                }
            }
        }

        write!(writer, ":")?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}
