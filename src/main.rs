/*
 * Copyright 2025 Sven Shi
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::future;

use tokio::sync::oneshot;
use tokio::{runtime, signal};
use tracing::info;

mod config;
mod core;
mod pkg;
mod plugin;

fn main() -> Result<(), String> {
    tokio_run()
}

fn tokio_run() -> Result<(), String> {
    // info!("RustDNS {} starting...", hickory_client::version());
    let mut tokio_runtime = runtime::Builder::new_multi_thread();
    tokio_runtime
        .enable_all()
        .thread_name("rustdns-worker")
        .worker_threads(8);
    let tokio_runtime = tokio_runtime
        .build()
        .map_err(|err| format!("failed to initialize Tokio runtime: {err}"))?;
    tokio_runtime.block_on(async_run())
}

#[cfg_attr(feature = "hotpath", hotpath::main(percentiles =[50,70,90]))]
async fn async_run() -> Result<(), String> {
    // 创建一个 shutdown 通道
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // 启动 app_run 任务
    tokio::spawn(app_run());

    // 启动一个监听信号的任务
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("failed to listen for Ctrl+C");
        info!("Received Ctrl+C, shutting down...");
        let _ = shutdown_tx.send(());
    });

    // 等待关闭信号
    shutdown_rx.await.ok();
    info!("Graceful shutdown complete.");
    Ok(())
}

async fn app_run() {
    let runtime = core::init();
    let options = runtime.options;
    let config = config::init(&options.config);
    let mut log_config = config.log.clone();
    match options.log_level {
        None => {}
        Some(level) => log_config.level = level,
    }
    let _ = core::log_init(log_config);
    plugin::init(config).await;
}
