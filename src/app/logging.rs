// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Application logging bootstrap and formatter.

use std::path::Path;
use std::{fmt as std_fmt, fs};

use jiff::Zoned;
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
        let elapsed_ms = AppClock::elapsed_millis();
        let elapsed_secs = elapsed_ms / 1000;
        let elapsed_sub_ms = elapsed_ms % 1000;
        let zoned = Zoned::now();
        write!(
            &mut writer,
            "{} T+{}.{:03} {} {}",
            zoned.strftime("%Y-%m-%dT%H:%M:%S%:z"),
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
