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

pub(crate) mod h2_conn;
pub(crate) mod h3_conn;
pub(crate) mod pipeline;
pub(crate) mod quic_conn;
pub(crate) mod reuse;
pub(crate) mod tcp_conn;
pub(crate) mod udp_conn;

use crate::core::error::Result;
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use std::fmt::Debug;
use std::sync::Arc;
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
    async fn query(&self, request: Message) -> Result<DnsResponse>;

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
    async fn query(&self, request: Message) -> Result<DnsResponse>;

    /// Perform maintenance on the pool
    ///
    /// Called periodically by background task to:
    /// - Remove idle connections
    /// - Drop failed connections
    /// - Ensure minimum pool size
    async fn maintain(&self);
}

/// Maintenance interval for pool cleanup
const MAINTENANCE_DURATION: Duration = Duration::from_secs(10);

/// Start background maintenance task for a connection pool
///
/// Periodically calls `maintain()` to clean up idle/dead connections.
/// The task runs for the lifetime of the pool.
#[inline]
fn start_maintenance<C: Connection>(pool: Arc<dyn ConnectionPool<C>>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(MAINTENANCE_DURATION).await;
            // Perform maintenance (awaiting ensures fairness and proper error handling)
            pool.maintain().await;
            // Yield to allow other tasks to run
            yield_now().await;
        }
    });
}
