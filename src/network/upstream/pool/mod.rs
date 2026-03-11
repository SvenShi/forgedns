/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Connection pooling infrastructure for DNS upstreams
//!
//! Provides high-performance connection management with different pooling strategies:
//!
//! # Pool Types
//!
//! ## Pipeline Pool (`pipeline.rs`)
//! - Supports multiple concurrent requests per connection
//! - Ideal for TCP/TLS/QUIC/DoH where connections can handle parallel queries
//! - Automatic scaling based on load (min_size to max_size)
//! - Configurable max load per connection to prevent overloading
//!
//! ## Reuse Pool (`reuse.rs`)
//! - One request per connection at a time
//! - Connections are borrowed and returned to pool
//! - Ideal for UDP or when pipelining is disabled
//! - Automatic idle connection cleanup
//!
//! # Connection Types
//! - `udp_conn`: UDP connections with automatic TCP fallback
//! - `tcp_conn`: Plain TCP and DoT (DNS over TLS) connections
//! - `quic_conn`: DoQ (DNS over QUIC) connections
//! - `h2_conn`: DoH over HTTP/2 connections
//! - `h3_conn`: DoH over HTTP/3 connections
//!
//! # Performance Features
//! - Lock-free connection selection with atomic operations
//! - Background maintenance tasks for idle connection cleanup
//! - Request/response matching via lock-free request map
//! - Zero-copy message passing where possible
//! - Connection reuse to amortize handshake costs

mod request_map;

pub(crate) mod conn_h2;
pub(crate) mod conn_h3;
pub(crate) mod conn_quic;
pub(crate) mod conn_tcp;
pub(crate) mod conn_udp;
pub(crate) mod pool_pipeline;
pub(crate) mod pool_reuse;

use crate::core::error::Result;
use crate::core::task_center;
use async_trait::async_trait;
use hickory_proto::op::Message;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::task::yield_now;

/// Connection trait - represents a single persistent connection to an upstream DNS server
///
/// All connection types (UDP, TCP, QUIC, H2, H3) implement this trait.
/// Connections manage their own request/response correlation and lifecycle.
#[async_trait]
pub trait Connection: Send + Sized + Debug + Sync + 'static {
    /// Mark this connection as closed and notify listeners
    ///
    /// Should be idempotent - safe to call multiple times
    fn close(&self);

    /// Send a DNS query and asynchronously wait for the response
    ///
    /// This is a hot path - implementations should minimize overhead
    async fn query(&self, request: Message) -> Result<Message>;

    /// Get the number of queries currently in flight on this connection
    ///
    /// Used by pipeline pools to balance load across connections
    fn using_count(&self) -> u16;

    /// Check if the connection is available for use
    ///
    /// Returns false if the connection is closed or experiencing errors
    fn available(&self) -> bool;

    /// Get the timestamp of the last successful activity (in milliseconds)
    ///
    /// Used for idle connection detection and cleanup
    fn last_used(&self) -> u64;
}

/// Connection builder trait - creates new connections on demand
///
/// Each connection type has a corresponding builder that knows how to
/// establish connections with the appropriate protocol-specific handshakes.
#[async_trait]
pub trait ConnectionBuilder<C: Connection>: Send + Sync + Debug + 'static {
    /// Create a new connection with the given ID
    ///
    /// # Arguments
    /// * `conn_id` - Unique identifier for this connection (used for debugging/logging)
    ///
    /// # Returns
    /// Arc-wrapped connection on success, or error if connection establishment fails
    async fn create_connection(&self, conn_id: u16) -> Result<Arc<C>>;
}

/// Connection pool trait - manages a pool of connections for load balancing
///
/// Different pool implementations provide different strategies:
/// - Pipeline pools allow multiple concurrent requests per connection
/// - Reuse pools borrow/return connections for single requests
#[async_trait]
pub trait ConnectionPool<C: Connection>: Send + Sync + Debug + 'static {
    /// Execute a DNS query through the pool
    ///
    /// The pool automatically selects or creates an appropriate connection.
    /// This is the main hot path for DNS queries.
    async fn query(&self, request: Message) -> Result<Message>;

    /// Perform maintenance on the pool
    ///
    /// Called periodically by background task to:
    /// - Remove idle connections
    /// - Drop failed connections
    /// - Ensure minimum pool size
    async fn maintain(&self);
}

/// Pools that own a periodic maintenance task managed by the global task center.
pub trait ManagedMaintenanceTask {
    fn maintenance_task_id(&self) -> &Mutex<Option<u64>>;
    fn maintenance_task_name(&self) -> String;
}

/// Maintenance interval for pool cleanup
const MAINTENANCE_DURATION: Duration = Duration::from_secs(10);

/// Start background maintenance task for a connection pool
///
/// Periodically calls `maintain()` to clean up idle/dead connections.
/// The task runs for the lifetime of the pool.
#[inline]
fn start_maintenance<C, P>(pool: &Arc<P>)
where
    C: Connection,
    P: ConnectionPool<C> + ManagedMaintenanceTask + 'static,
{
    let weak_pool: Weak<P> = Arc::downgrade(pool);
    let task_id_slot = Arc::new(AtomicU64::new(0));
    let task_id_slot_task = task_id_slot.clone();
    let task_name = pool.maintenance_task_name();
    let task_id = task_center::spawn_fixed(task_name, MAINTENANCE_DURATION, move || {
        let weak_pool = weak_pool.clone();
        let task_id_slot_task = task_id_slot_task.clone();
        async move {
            let Some(pool) = weak_pool.upgrade() else {
                let task_id = task_id_slot_task.load(Ordering::Acquire);
                if task_id != 0 {
                    task_center::stop_task_detached(task_id);
                }
                return;
            };

            // Perform maintenance (awaiting ensures fairness and proper error handling)
            pool.maintain().await;
            // Yield to allow other tasks to run
            yield_now().await;
        }
    });
    task_id_slot.store(task_id, Ordering::Release);
    *pool
        .maintenance_task_id()
        .lock()
        .expect("maintenance_task_id poisoned") = Some(task_id);
}
