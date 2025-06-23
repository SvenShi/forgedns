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

use hickory_client::client::Client;
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::udp::UdpClientStream;
use tokio::sync::Mutex;

use crate::core::handler::DnsRequestHandler;
use crate::plugin::executable::forward::SequentialDnsForwarder;
use hickory_server::ServerFuture;
use log::info;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::runtime;

mod config;
mod core;
mod plugin;

fn main() -> Result<(), String> {
    tokio_run()
}

async fn app_init() {
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

fn tokio_run() -> Result<(), String> {
    info!("RustDNS {} starting...", hickory_client::version());
    let mut tokio_runtime = runtime::Builder::new_multi_thread();
    tokio_runtime
        .enable_all()
        .thread_name("rustdns-worker")
        .worker_threads(4);
    let tokio_runtime = tokio_runtime
        .build()
        .map_err(|err| format!("failed to initialize Tokio runtime: {err}"))?;
    tokio_runtime.block_on(async_run())
}

async fn async_run() -> Result<(), String> {
    app_init().await;
    Ok(())
}
