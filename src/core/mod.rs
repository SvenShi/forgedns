/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::config::config::LogConfig;
use crate::core::app_clock::AppClock;
use crate::core::log::RustDnsLogFormatter;
use crate::core::runtime::{Options, Runtime};
use clap::Parser;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry, fmt};

pub mod app_clock;
pub mod context;

mod log;
mod runtime;

/// 初始化核心包
pub fn init() -> Runtime {
    let options = Options::parse();

    AppClock::run();

    Runtime { options }
}

///初始化log
pub fn log_init(log: LogConfig) -> WorkerGuard {
    // 创建文件appender（如果配置了文件路径）
    let (file_writer, guard) = if let Some(file_path) = log.file {
        let file_appender = tracing_appender::rolling::never(
            std::path::Path::new(&file_path).parent().unwrap(),
            std::path::Path::new(&file_path).file_name().unwrap(),
        );
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    // 构建控制台layer
    let console_layer = fmt::layer()
        .event_format(RustDnsLogFormatter)
        .with_writer(std::io::stdout);

    // 构建文件layer（如果配置了文件路径）
    let file_layer = file_writer.map(|writer| {
        fmt::layer()
            .event_format(RustDnsLogFormatter)
            .with_writer(writer)
    });

    let mut filter = EnvFilter::try_new(&log.level).unwrap_or_else(|_| EnvFilter::new("info"));

    // 屏蔽 hickory_server::server
    filter = filter.add_directive("hickory_server::server=off".parse().unwrap());

    let subscriber = Registry::default().with(filter).with(console_layer);

    // 添加文件layer（如果存在）
    if let Some(file_layer) = file_layer {
        let subscriber = subscriber.with(file_layer);
        // 设置全局默认subscriber
        subscriber.init();
    } else {
        subscriber.init();
    };

    // 返回WorkerGuard以确保日志在程序退出前被刷新
    guard.unwrap_or_else(|| {
        // 如果没有文件日志，返回一个空的guard
        tracing_appender::non_blocking(std::io::sink()).1
    })
}
