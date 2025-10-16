/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

mod request_map;

mod utils;

pub(crate) mod pipeline;
pub(crate) mod reuse;
pub(crate) mod udp_conn;
pub(crate) mod tcp_conn;
pub(crate) mod h2_conn;
pub(crate) mod h3_conn;
pub(crate) mod quic_conn;

use async_trait::async_trait;
use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::yield_now;

#[async_trait]
pub trait Connection: Send + Sized + Debug + Sync + 'static {
    /// Mark this connection as closed and notify listeners
    fn close(&self);

    async fn query(&self, request: Message) -> Result<DnsResponse, ProtoError>;

    fn using_count(&self) -> u16;

    fn available(&self) -> bool;

    fn last_used(&self) -> u64;
}

#[async_trait]
pub trait ConnectionBuilder<C: Connection>: Send + Sync + Debug + 'static {
    async fn new_conn(&self, conn_id: u16) -> Result<Arc<C>, ProtoError>;
}

#[async_trait]
pub trait ConnectionPool<C: Connection>: Send + Sync + Debug + 'static {
    async fn query(&self, request: Message) -> Result<DnsResponse, ProtoError>;

    async fn scan_pool(&self);
}

const MAINTENANCE_DURATION: Duration = Duration::from_secs(5);

/// Periodically remove idle connections
#[inline]
fn start_maintenance<C: Connection>(pool: Arc<dyn ConnectionPool<C>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(MAINTENANCE_DURATION).await;
            // run scan in background (not awaiting here would drop errors), we await to ensure fairness
            pool.scan_pool().await;
            // small yield to let other tasks run
            yield_now().await;
        }
    });
}
