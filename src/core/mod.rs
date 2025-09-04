/*
 * Copyright 2025 Sven Shi
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use crate::config::config::LogConfig;
use crate::core::log::RustDnsLogFormatter;
use crate::core::runtime::{Options, Runtime};
use clap::Parser;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Registry};

pub mod context;
pub mod handler;
mod log;
mod runtime;

/// 初始化核心包
pub fn init() -> Runtime {
    let options = Options::parse();

    Runtime {
        options,
    }
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

    let mut filter = EnvFilter::try_new(&log.level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // 屏蔽 hickory_server::server
    filter = filter.add_directive("hickory_server::server=off".parse().unwrap());

    let subscriber = Registry::default()
        .with(filter)
        .with(console_layer);

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
