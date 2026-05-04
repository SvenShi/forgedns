// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt::Debug;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio::task::yield_now;
use tracing::debug;

use crate::core::app_clock::AppClock;
use crate::core::error::{DnsError, Result};
use crate::core::task_center;
use crate::network::upstream::pool::{
    Connection, ConnectionBuilder, ConnectionPool, ManagedMaintenanceTask, start_maintenance,
};
use crate::network::upstream::utils::close_conns;
use crate::proto::Message;

#[derive(Debug)]
pub struct PipelinePool<C: Connection> {
    /// Round-robin index for load balancing across connections
    index: AtomicUsize,
    /// List of active connections (lock-free with ArcSwap)
    connections: ArcSwap<Vec<Arc<C>>>,
    /// Maximum number of connections allowed
    max_size: usize,
    /// Minimum number of connections to maintain
    min_size: usize,
    /// Maximum number of concurrent queries per connection
    max_load: u16,
    /// Maximum allowed idle time before a connection is dropped
    max_idle: Duration,
    /// Connection builder, build new connections
    connection_builder: Box<dyn ConnectionBuilder<C>>,
    /// The Next connection id
    next_id: AtomicU16,
    /// Background maintenance task registered in task center.
    maintenance_task_id: Mutex<Option<u64>>,
}

#[async_trait]
impl<C: Connection> ConnectionPool<C> for PipelinePool<C> {
    async fn query(&self, request: Message) -> Result<Message> {
        self.get().await?.query(request).await
    }

    async fn maintain(&self) {
        let now = AppClock::elapsed_millis();
        let mut new_vec = Vec::new();
        let mut drop_vec = Vec::new();
        let mut invalid_vec = Vec::new();

        // Lock-free read of current connections
        let conns = self.connections.load();
        for conn in conns.iter() {
            if conn.available() {
                let idle = now - conn.last_used();
                if idle < self.max_idle.as_millis() as u64 || conn.using_count() > 0 {
                    new_vec.push(conn.clone());
                } else {
                    drop_vec.push(conn.clone());
                }
            } else {
                invalid_vec.push(conn.clone());
            }
        }

        // Try to keep min_size
        while new_vec.len() < self.min_size {
            if !drop_vec.is_empty() {
                new_vec.push(drop_vec.pop().unwrap());
            } else {
                break;
            }
        }

        let new_len = new_vec.len();

        // attempt atomic swap
        if !Arc::ptr_eq(
            &conns,
            &self.connections.compare_and_swap(&conns, Arc::new(new_vec)),
        ) {
            close_conns(&drop_vec);
            close_conns(&invalid_vec);
            return;
        }

        // Close removed connections
        close_conns(&drop_vec);
        close_conns(&invalid_vec);

        if !drop_vec.is_empty() || !invalid_vec.is_empty() {
            debug!(
                "Pipeline pool maintenance: dropped {} idle, {} invalid, {} active",
                drop_vec.len(),
                invalid_vec.len(),
                new_len
            );
        }

        // Try to keep min_size connections
        if new_len < self.min_size {
            let _ = self.expand().await;
        }
    }
}

impl<C: Connection> PipelinePool<C> {
    pub fn new(
        min_size: usize,
        max_size: usize,
        max_load: u16,
        idle_time: Duration,
        connection_builder: Box<dyn ConnectionBuilder<C>>,
    ) -> Arc<PipelinePool<C>> {
        let pool = Arc::new(Self {
            index: AtomicUsize::new(0),
            connections: ArcSwap::from_pointee(Vec::new()),
            max_size,
            min_size,
            max_load,
            max_idle: idle_time,
            connection_builder,
            next_id: AtomicU16::new(0),
            maintenance_task_id: Mutex::new(None),
        });
        start_maintenance(&pool);
        if min_size > 0 {
            let arc = pool.clone();
            // Fire-and-forget async expand to prefill pool
            tokio::spawn(async move {
                let _ = arc.expand().await;
            });
        }
        pool
    }

    async fn get(&self) -> Result<Arc<C>> {
        loop {
            // Lock-free fast path with ArcSwap
            let conns = self.connections.load();

            if conns.is_empty() {
                self.expand().await?;
                yield_now().await;
                continue;
            }

            let len = conns.len();

            let start_idx = self.index.fetch_add(1, Ordering::Relaxed) % len;

            for offset in 0..len {
                let idx = (start_idx + offset) % len;
                let conn = &conns[idx];
                if conn.available() && conn.using_count() < self.max_load {
                    return Ok(conn.clone());
                }
            }

            // Check if we can expand
            if self.connections.load().len() < self.max_size {
                if self.expand().await.is_err() {
                    yield_now().await;
                }
            } else {
                // All connections are at max_load, yield to allow active queries to finish
                yield_now().await;
            }
        }
    }

    /// Expand the pool by creating new connections
    async fn expand(&self) -> Result<()> {
        // Determine how many connections to create (lock-free read)
        let new_conns_count = {
            let conns = self.connections.load();
            let conns_len = conns.len();

            if conns_len >= self.max_size {
                debug!("Connection pool already at max size");
                return Err(DnsError::protocol(
                    "Connection pool already at maximum size",
                ));
            }

            let target = if conns_len >= self.min_size {
                1
            } else {
                self.min_size - conns_len
            };

            std::cmp::min(target, self.max_size - conns_len)
        };

        if new_conns_count == 0 {
            return Ok(());
        }

        // Create new connections concurrently
        let mut futures = FuturesUnordered::new();
        for _ in 0..new_conns_count {
            let builder = &self.connection_builder;
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            futures.push(async move { builder.create_connection(id).await });
        }

        // Collect results
        let mut created: Vec<Arc<C>> = Vec::with_capacity(new_conns_count);
        while let Some(res) = futures.next().await {
            match res {
                Ok(conn) => created.push(conn),
                Err(e) => {
                    debug!("Failed to create new connection: {:?}", e);
                }
            }
        }

        if created.is_empty() {
            return Ok(());
        }

        // Lock-free atomic update with RCU pattern. arc-swap returns the previous
        // value from `rcu`, so track the number of inserted connections explicitly.
        let inserted_count = AtomicUsize::new(0);
        self.connections.rcu(|old_conns| {
            let current_len = old_conns.len();
            if current_len >= self.max_size {
                inserted_count.store(0, Ordering::Relaxed);
                return old_conns.clone();
            }

            let space = self.max_size - current_len;
            let to_add = created.len().min(space);
            inserted_count.store(to_add, Ordering::Relaxed);

            let mut new_vec = Vec::with_capacity(current_len + to_add);
            new_vec.extend_from_slice(old_conns);
            new_vec.extend(created.iter().take(to_add).cloned());

            debug!(
                "Pipeline pool expanded: +{} connections (total={}/{})",
                to_add,
                new_vec.len(),
                self.max_size
            );

            Arc::new(new_vec)
        });
        let added_count = inserted_count.load(Ordering::Relaxed);

        // Close any leftover connections
        if created.len() > added_count {
            let leftover: Vec<_> = created.into_iter().skip(added_count).collect();
            close_conns(&leftover);
        }

        Ok(())
    }
}

impl<C: Connection> ManagedMaintenanceTask for PipelinePool<C> {
    fn maintenance_task_id(&self) -> &Mutex<Option<u64>> {
        &self.maintenance_task_id
    }

    fn maintenance_task_name(&self) -> String {
        "upstream_pipeline_pool:maintenance".to_string()
    }
}

impl<C: Connection> Drop for PipelinePool<C> {
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
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    use super::*;

    #[derive(Debug)]
    struct MockConnection {
        available: AtomicBool,
        using_count: AtomicU16,
        last_used: AtomicU64,
        close_calls: AtomicUsize,
    }

    impl MockConnection {
        fn new(available: bool, using_count: u16, last_used: u64) -> Self {
            Self {
                available: AtomicBool::new(available),
                using_count: AtomicU16::new(using_count),
                last_used: AtomicU64::new(last_used),
                close_calls: AtomicUsize::new(0),
            }
        }

        fn close_calls(&self) -> usize {
            self.close_calls.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        fn close(&self) {
            self.close_calls.fetch_add(1, Ordering::Relaxed);
            self.available.store(false, Ordering::Relaxed);
        }

        async fn query(&self, request: Message) -> Result<Message> {
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
        max_load: u16,
        idle_secs: u64,
        builder: MockBuilder,
        initial_connections: Vec<Arc<MockConnection>>,
    ) -> PipelinePool<MockConnection> {
        PipelinePool {
            index: AtomicUsize::new(0),
            connections: ArcSwap::from_pointee(initial_connections),
            max_size,
            min_size,
            max_load,
            max_idle: Duration::from_secs(idle_secs),
            connection_builder: Box::new(builder),
            next_id: AtomicU16::new(1),
            maintenance_task_id: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn test_get_uses_round_robin_across_connections() {
        let first = Arc::new(MockConnection::new(true, 0, 0));
        let second = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(
            0,
            2,
            4,
            10,
            MockBuilder::new(vec![]),
            vec![first.clone(), second.clone()],
        );

        let selected_first = pool.get().await.expect("first get should succeed");
        let selected_second = pool.get().await.expect("second get should succeed");

        assert!(Arc::ptr_eq(&selected_first, &first));
        assert!(Arc::ptr_eq(&selected_second, &second));
    }

    #[tokio::test]
    async fn test_get_expands_when_pool_is_empty() {
        let created = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(
            0,
            1,
            4,
            10,
            MockBuilder::new(vec![Ok(created.clone())]),
            vec![],
        );

        let selected = tokio::time::timeout(Duration::from_millis(100), pool.get())
            .await
            .expect("get should not hang on empty-pool expansion")
            .expect("get should expand an empty pool");

        assert!(Arc::ptr_eq(&selected, &created));
        assert_eq!(pool.connections.load().len(), 1);
    }

    #[tokio::test]
    async fn test_get_skips_saturated_connections_and_uses_expanded_one() {
        let saturated_a = Arc::new(MockConnection::new(true, 2, 0));
        let saturated_b = Arc::new(MockConnection::new(true, 2, 0));
        let created = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(
            0,
            3,
            2,
            10,
            MockBuilder::new(vec![Ok(created.clone())]),
            vec![saturated_a, saturated_b],
        );

        let selected = tokio::time::timeout(Duration::from_millis(100), pool.get())
            .await
            .expect("get should not hang when expanding under saturation")
            .expect("get should expand when all connections are saturated");

        assert!(Arc::ptr_eq(&selected, &created));
        assert_eq!(pool.connections.load().len(), 3);
    }

    #[tokio::test]
    async fn test_maintain_drops_idle_and_invalid_connections() {
        AppClock::start();
        let idle = Arc::new(MockConnection::new(true, 0, 0));
        let invalid = Arc::new(MockConnection::new(false, 0, 0));
        let pool = make_pool(
            0,
            4,
            4,
            0,
            MockBuilder::new(vec![]),
            vec![idle.clone(), invalid.clone()],
        );

        pool.maintain().await;

        assert_eq!(idle.close_calls(), 1);
        assert_eq!(invalid.close_calls(), 1);
        assert!(pool.connections.load().is_empty());
    }

    #[tokio::test]
    async fn test_maintain_reuses_idle_connection_to_preserve_min_size() {
        AppClock::start();
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(1, 1, 4, 0, MockBuilder::new(vec![]), vec![conn.clone()]);

        pool.maintain().await;

        assert_eq!(conn.close_calls(), 0);
        assert_eq!(pool.connections.load().len(), 1);
    }

    #[tokio::test]
    async fn test_maintain_keeps_idle_connection_with_inflight_queries() {
        AppClock::start();
        let conn = Arc::new(MockConnection::new(true, 1, 0));
        let pool = make_pool(0, 1, 4, 0, MockBuilder::new(vec![]), vec![conn.clone()]);

        pool.maintain().await;

        assert_eq!(conn.close_calls(), 0);
        assert_eq!(pool.connections.load().len(), 1);
    }
}
