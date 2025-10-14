// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

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
