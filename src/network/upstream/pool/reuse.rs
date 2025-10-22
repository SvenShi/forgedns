/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::app_clock::AppClock;
use crate::network::upstream::pool::utils::close_conns;
use crate::network::upstream::pool::{
    Connection, ConnectionBuilder, ConnectionPool, start_maintenance,
};
use async_trait::async_trait;
use crossbeam_queue::ArrayQueue;
use crate::core::error::Result;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

/// A reusable connection pool implementation
/// - Keeps a minimum number of active connections (`min_size`)
/// - Can expand up to `max_size` when needed
/// - Reuses idle connections, and drops those idle beyond `max_idle`
/// - Thread-safe, designed for async DNS request handling
#[derive(Debug)]
pub struct ReusePool<C: Connection> {
    /// Queue holding idle connections
    connections: ArrayQueue<Arc<C>>,
    /// Number of active connections in use or queued
    active_count: AtomicUsize,
    /// Maximum number of connections allowed
    max_size: usize,
    /// Minimum number of connections to keep alive
    min_size: usize,
    /// Maximum allowed idle duration before dropping a connection
    max_idle: Duration,
    /// Factory to create new connections
    connection_builder: Box<dyn ConnectionBuilder<C>>,
    /// Monotonic increasing connection id
    next_id: AtomicU16,
    /// Notify waiting threads when a connection becomes available
    release_notified: Notify,
}

#[async_trait]
impl<C: Connection> ConnectionPool<C> for ReusePool<C> {
    /// Obtain a connection, execute query, and release it back to the pool
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, request: Message) -> Result<DnsResponse> {
        let conn = self.get().await?;
        debug!(
            "Got connection from pool, using_count={}",
            conn.using_count()
        );
        let result = conn.query(request).await;
        self.release(conn);
        result
    }

    /// Periodic pool maintenance task
    /// - Removes idle/invalid connections
    /// - Ensures minimum connection count
    async fn maintain(&self) {
        let now = AppClock::elapsed_millis();
        let mut drop_vec = Vec::new();
        let mut invalid_vec = Vec::new();

        // Only log if there are connections to scan
        let check_count = self.connections.len();
        if check_count == 0 {
            return;
        }

        for _ in 0..check_count {
            if let Some(conn) = self.connections.pop() {
                if conn.available() {
                    let idle = now - conn.last_used();
                    if idle < self.max_idle.as_millis() as u64 {
                        // still valid
                        if let Err(conn) = self.connections.push(conn) {
                            drop_vec.push(conn);
                            self.active_count.fetch_sub(1, Ordering::Relaxed);
                        }
                    } else {
                        // idle timeout
                        drop_vec.push(conn);
                        self.active_count.fetch_sub(1, Ordering::Relaxed);
                    }
                } else {
                    warn!("Dropping invalid connection");
                    invalid_vec.push(conn);
                    self.active_count.fetch_sub(1, Ordering::Relaxed);
                }
            } else {
                break;
            }
        }

        // Maintain minimum connection count
        while self.active_count.load(Ordering::Relaxed) < self.min_size {
            if !drop_vec.is_empty() {
                if let Err(conn) = self.connections.push(drop_vec.pop().unwrap()) {
                    drop_vec.push(conn);
                    break;
                } else {
                    self.active_count.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                break;
            }
        }

        // Close dropped/invalid connections
        close_conns(&drop_vec);
        close_conns(&invalid_vec);

        // Log maintenance results if significant
        if !drop_vec.is_empty() || !invalid_vec.is_empty() {
            debug!(
                "Reuse pool maintenance: dropped {} idle, {} invalid, {} active",
                drop_vec.len(),
                invalid_vec.len(),
                self.active_count.load(Ordering::Relaxed)
            );
        }

        // Expand if below min_size
        if self.active_count.load(Ordering::Relaxed) < self.min_size {
            debug!("Reuse pool expanding to maintain minimum size");
            let _ = self.expand().await;
        }
    }
}

impl<C: Connection> ReusePool<C> {
    /// Create a new reusable connection pool
    pub fn new(
        min_size: usize,
        max_size: usize,
        connection_builder: Box<dyn ConnectionBuilder<C>>,
    ) -> Arc<ReusePool<C>> {
        info!(
            "Creating ReusePool (min_size={}, max_size={})",
            min_size, max_size
        );

        let pool = Arc::new(Self {
            connections: ArrayQueue::new(max_size),
            min_size,
            max_size,
            connection_builder,
            max_idle: Duration::from_secs(10),
            active_count: AtomicUsize::new(0),
            next_id: AtomicU16::new(1),
            release_notified: Notify::new(),
        });

        start_maintenance(pool.clone());

        if min_size > 0 {
            let arc = pool.clone();
            tokio::spawn(async move {
                if let Err(e) = arc.expand().await {
                    warn!("Failed to prefill ReusePool: {:?}", e);
                }
            });
        }

        pool
    }

    /// Borrow a connection from the pool or create a new one if needed
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn get(&self) -> Result<Arc<C>> {
        loop {
            if let Some(conn) = self.connections.pop() {
                if conn.available() {
                    debug!("Reusing existing connection");
                    return Ok(conn);
                } else {
                    warn!("Detected unavailable connection, closing it");
                    conn.close();
                    self.active_count.fetch_sub(1, Ordering::Relaxed);
                }
            }

            if self.active_count.load(Ordering::Relaxed) < self.max_size {
                let _ = self.expand().await;
            } else {
                debug!("Pool is full, waiting for release...");
                while self.connections.is_empty() {
                    self.release_notified.notified().await;
                }
            }
        }
    }

    /// Return a connection back to the pool or close it if invalid
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn release(&self, conn: Arc<C>) {
        if !conn.available() || self.connections.push(conn.clone()).is_err() {
            warn!("Releasing invalid or overflowed connection, closing it");
            conn.close();
            self.active_count.fetch_sub(1, Ordering::Relaxed);
        } else {
            debug!("Connection released back to pool");
            self.release_notified.notify_one();
        }
    }

    /// Expand pool by creating new connections up to desired size
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn expand(&self) -> Result<()> {
        let conns_len = self.active_count.load(Ordering::Relaxed);
        if conns_len >= self.max_size {
            debug!("Pool already at max capacity ({})", self.max_size);
            return Ok(());
        }

        let mut want = if conns_len >= self.min_size {
            1
        } else {
            self.min_size - conns_len
        };
        if conns_len + want > self.max_size {
            want = self.max_size - conns_len;
        }
        if want == 0 {
            return Ok(());
        }

        self.active_count.fetch_add(want, Ordering::SeqCst);

        let actually_reserved = {
            let after = self.active_count.load(Ordering::SeqCst);
            if after > self.max_size {
                let overflow = after - self.max_size;
                self.active_count.fetch_sub(overflow, Ordering::SeqCst);
                want - overflow
            } else {
                want
            }
        };

        if actually_reserved == 0 {
            return Ok(());
        }

        let mut created = Vec::with_capacity(actually_reserved);
        for _ in 0..actually_reserved {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            match self.connection_builder.create_connection(id).await {
                Ok(conn) => {
                    if self.connections.push(conn.clone()).is_ok() {
                        created.push(conn);
                        self.release_notified.notify_one();
                    } else {
                        debug!("Pool queue is full while expanding, closing new connection");
                        conn.close();
                        self.active_count.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    debug!("Failed to create new connection: {:?}", e);
                    self.active_count.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }

        let created_len = created.len();

        if created_len > 0 {
            debug!(
                "Reuse pool expanded: +{} connections (total={}/{})",
                created_len,
                self.active_count.load(Ordering::Relaxed),
                self.max_size
            );
        }

        Ok(())
    }
}
