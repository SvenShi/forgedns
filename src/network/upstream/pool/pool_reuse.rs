/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::app_clock::AppClock;
use crate::core::error::Result;
use crate::core::task_center;
use crate::message::Message;
use crate::network::upstream::pool::{
    Connection, ConnectionBuilder, ConnectionPool, ManagedMaintenanceTask, start_maintenance,
};
use crate::network::upstream::utils::close_conns;
use async_trait::async_trait;
use crossbeam_queue::ArrayQueue;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;
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
    /// Background maintenance task registered in task center.
    maintenance_task_id: Mutex<Option<u64>>,
}

#[async_trait]
impl<C: Connection> ConnectionPool<C> for ReusePool<C> {
    /// Obtain a connection, execute query, and release it back to the pool
    #[hotpath::measure]
    async fn query(&self, request: Message) -> Result<Message> {
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
        idle_time: u64,
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
            max_idle: Duration::from_secs(idle_time),
            active_count: AtomicUsize::new(0),
            next_id: AtomicU16::new(1),
            release_notified: Notify::new(),
            maintenance_task_id: Mutex::new(None),
        });

        start_maintenance(&pool);

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
    #[hotpath::measure]
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
    #[hotpath::measure]
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
    #[hotpath::measure]
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

impl<C: Connection> ManagedMaintenanceTask for ReusePool<C> {
    fn maintenance_task_id(&self) -> &Mutex<Option<u64>> {
        &self.maintenance_task_id
    }

    fn maintenance_task_name(&self) -> String {
        "upstream_reuse_pool:maintenance".to_string()
    }
}

impl<C: Connection> Drop for ReusePool<C> {
    fn drop(&mut self) {
        let task_id = self
            .maintenance_task_id
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(task_id) = task_id {
            task_center::stop_task_detached(task_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::{DnsError, Result};
    use crate::message::Message;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    #[derive(Debug)]
    struct MockConnection {
        available: AtomicBool,
        using_count: AtomicU16,
        last_used: AtomicU64,
        close_calls: AtomicUsize,
        query_calls: AtomicUsize,
    }

    impl MockConnection {
        fn new(available: bool, using_count: u16, last_used: u64) -> Self {
            Self {
                available: AtomicBool::new(available),
                using_count: AtomicU16::new(using_count),
                last_used: AtomicU64::new(last_used),
                close_calls: AtomicUsize::new(0),
                query_calls: AtomicUsize::new(0),
            }
        }

        fn close_calls(&self) -> usize {
            self.close_calls.load(Ordering::Relaxed)
        }

        fn query_calls(&self) -> usize {
            self.query_calls.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        fn close(&self) {
            self.close_calls.fetch_add(1, Ordering::Relaxed);
            self.available.store(false, Ordering::Relaxed);
        }

        async fn query(&self, request: Message) -> Result<Message> {
            self.query_calls.fetch_add(1, Ordering::Relaxed);
            Ok(request)
        }

        fn using_count(&self) -> u16 {
            self.using_count.load(Ordering::Relaxed)
        }

        fn available(&self) -> bool {
            self.available.load(Ordering::Relaxed)
        }

        fn last_used(&self) -> u64 {
            self.last_used.load(Ordering::Relaxed)
        }
    }

    #[derive(Debug)]
    struct MockBuilder {
        planned: Mutex<VecDeque<Result<Arc<MockConnection>>>>,
    }

    impl MockBuilder {
        fn new(planned: Vec<Result<Arc<MockConnection>>>) -> Self {
            Self {
                planned: Mutex::new(planned.into()),
            }
        }
    }

    #[async_trait]
    impl ConnectionBuilder<MockConnection> for MockBuilder {
        async fn create_connection(&self, _conn_id: u16) -> Result<Arc<MockConnection>> {
            self.planned
                .lock()
                .expect("builder plan lock should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| Err(DnsError::runtime("no planned connection")))
        }
    }

    fn make_pool(
        min_size: usize,
        max_size: usize,
        idle_secs: u64,
        builder: MockBuilder,
    ) -> ReusePool<MockConnection> {
        ReusePool {
            connections: ArrayQueue::new(max_size.max(1)),
            active_count: AtomicUsize::new(0),
            max_size,
            min_size,
            max_idle: Duration::from_secs(idle_secs),
            connection_builder: Box::new(builder),
            next_id: AtomicU16::new(1),
            release_notified: Notify::new(),
            maintenance_task_id: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn test_get_reuses_available_connection_from_queue() {
        let pool = make_pool(0, 2, 10, MockBuilder::new(vec![]));
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        pool.connections
            .push(conn.clone())
            .expect("queue should accept connection");
        pool.active_count.store(1, Ordering::Relaxed);

        let selected = pool
            .get()
            .await
            .expect("get should reuse queued connection");

        assert!(Arc::ptr_eq(&selected, &conn));
        assert_eq!(pool.active_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_get_closes_unavailable_connection_and_expands_replacement() {
        let replacement = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(0, 2, 10, MockBuilder::new(vec![Ok(replacement.clone())]));
        let stale = Arc::new(MockConnection::new(false, 0, 0));
        pool.connections
            .push(stale.clone())
            .expect("queue should accept stale connection");
        pool.active_count.store(1, Ordering::Relaxed);

        let selected = pool
            .get()
            .await
            .expect("get should expand a replacement connection");

        assert!(Arc::ptr_eq(&selected, &replacement));
        assert_eq!(stale.close_calls(), 1);
        assert_eq!(pool.active_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_release_closes_unavailable_connection_instead_of_requeueing() {
        let pool = make_pool(0, 2, 10, MockBuilder::new(vec![]));
        let conn = Arc::new(MockConnection::new(false, 0, 0));
        pool.active_count.store(1, Ordering::Relaxed);

        pool.release(conn.clone());

        assert_eq!(conn.close_calls(), 1);
        assert_eq!(pool.connections.len(), 0);
        assert_eq!(pool.active_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_maintain_drops_idle_and_invalid_connections() {
        let pool = make_pool(0, 4, 0, MockBuilder::new(vec![]));
        let idle = Arc::new(MockConnection::new(true, 0, 0));
        let invalid = Arc::new(MockConnection::new(false, 0, 0));
        pool.connections
            .push(idle.clone())
            .expect("queue should accept idle connection");
        pool.connections
            .push(invalid.clone())
            .expect("queue should accept invalid connection");
        pool.active_count.store(2, Ordering::Relaxed);

        pool.maintain().await;

        assert_eq!(idle.close_calls(), 1);
        assert_eq!(invalid.close_calls(), 1);
        assert_eq!(pool.connections.len(), 0);
        assert_eq!(pool.active_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_maintain_reuses_idle_connection_to_preserve_min_size() {
        let pool = make_pool(1, 1, 0, MockBuilder::new(vec![]));
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        pool.connections
            .push(conn.clone())
            .expect("queue should accept connection");
        pool.active_count.store(1, Ordering::Relaxed);

        pool.maintain().await;

        assert_eq!(conn.close_calls(), 0);
        assert_eq!(pool.connections.len(), 1);
        assert_eq!(pool.active_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_query_releases_connection_back_to_pool_after_success() {
        let pool = make_pool(0, 1, 10, MockBuilder::new(vec![]));
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        pool.connections
            .push(conn.clone())
            .expect("queue should accept connection");
        pool.active_count.store(1, Ordering::Relaxed);
        let mut request = Message::new();
        request.set_id(21);

        let response = pool
            .query(request)
            .await
            .expect("query should return the mock response");

        assert_eq!(response.id(), 21);
        assert_eq!(conn.query_calls(), 1);
        assert_eq!(pool.connections.len(), 1);
    }
}
