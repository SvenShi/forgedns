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
use crate::core::app_clock::AppClock;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hickory_proto::op::Query;
use hickory_proto::xfer::DnsResponse;
use hickory_proto::ProtoError;
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

/// A pool of UDP connections used for DNS queries
#[derive(Debug)]
pub struct ConnectionPool<C: Connection> {
    /// Round-robin index for load balancing across connections
    index: AtomicUsize,
    /// List of active UDP connections
    connections: ArcSwap<Vec<Arc<ConnectionWrapper<C>>>>,
    /// Maximum number of UDP connections allowed
    max_size: usize,
    /// Minimum number of UDP connections to maintain
    min_size: usize,
    /// Maximum number of concurrent queries per connection
    max_load: u16,
    /// Maximum allowed idle time before a connection is dropped
    max_idle: Duration,
    /// Connection builder, build new connections
    connection_builder: Box<dyn ConnectionBuilder<C>>,
}

impl<C: Connection> ConnectionPool<C> {
    pub fn new(
        min_size: usize,
        max_size: usize,
        connection_builder: Box<dyn ConnectionBuilder<C>>,
    ) -> Arc<Self> {
        info!(
            "Initializing UDP connection pool: min_size={}, max_size={}",
            min_size, max_size
        );
        let pool = Arc::new(Self {
            index: AtomicUsize::new(0),
            connections: ArcSwap::from_pointee(Vec::new()),
            max_size,
            min_size,
            max_load: 64,
            max_idle: Duration::from_secs(60),
            connection_builder,
        });

        pool.clone().start_maintenance();

        if min_size > 0 {
            let arc = pool.clone();
            tokio::spawn(async move {
                arc.expand().await;
            });
        }
        pool
    }

    /// Send DNS request and wait for the response or timeout
    pub async fn query(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        let conn = self.get().await;
        let result = conn.query(query).await;
        self.release(conn);
        result
    }

    /// Get a connection from the pool with load balancing
    async fn get(&'_ self) -> Arc<ConnectionWrapper<C>> {
        loop {
            let conns = self.connections.load();
            let len = conns.len();

            if len == 0 {
                warn!("No available connections, expanding pool...");
                self.expand().await;
                continue;
            }

            let mut idx = self.index.fetch_add(1, Ordering::Relaxed) % len;

            for _ in 0..len {
                let conn = &conns[idx];
                if conn.using_count() < self.max_load {
                    return conn.clone();
                }
                idx = (idx + 1) % len;
            }

            trace!("All connections overloaded, attempting to expand pool...");
            self.expand().await;
        }
    }

    /// Release a connection back to the pool
    fn release(&self, connection: Arc<ConnectionWrapper<C>>) {
        if connection.using_count() == 0 && connection.dropped.load(Ordering::Acquire) {
            connection.close();
            return;
        }
    }

    /// Expand the pool by creating new UDP connections
    async fn expand(&self) {
        let conns_len = self.connections.load().len();
        if conns_len >= self.max_size {
            debug!("Connection pool already at max size");
            return;
        }

        let new_conns_count = if conns_len >= self.min_size {
            1
        } else {
            self.min_size - conns_len
        };

        debug!(
            "Expanding connection pool by {} connections",
            new_conns_count
        );
        let mut new_conns = Vec::with_capacity(new_conns_count);

        for _ in 0..new_conns_count {
            let conn = self.connection_builder.new_conn();
            let connection: ConnectionWrapper<C> = ConnectionWrapper::new(conn);
            let conn = Arc::new(connection);
            new_conns.push(conn);
        }

        loop {
            let conns = self.connections.load().clone();
            let mut new_vec = (*conns).clone();
            new_vec.append(&mut new_conns);
            let new_len = new_vec.len();
            if Arc::ptr_eq(
                &conns,
                &self.connections.compare_and_swap(&conns, Arc::new(new_vec)),
            ) {
                debug!("UDP connections pool expanded, new total: {}", new_len);
                break;
            }
        }
    }

    /// Periodically remove idle connections
    fn start_maintenance(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;

                let now = AppClock::run_millis();
                let mut new_vec = Vec::new();
                let mut drop_vec = Vec::new();
                let conns = self.connections.load();

                for conn in conns.iter() {
                    let last_use = conn.last_use.load(Ordering::Relaxed);
                    let idle = now - last_use;
                    if idle < self.max_idle.as_millis() as u64 {
                        new_vec.push(conn.clone());
                    } else {
                        drop_vec.push(conn.clone());
                    }
                }

                while new_vec.len() < self.min_size {
                    if !drop_vec.is_empty() {
                        new_vec.push(drop_vec.pop().unwrap());
                    } else {
                        break;
                    }
                }

                let new_len = new_vec.len();

                if !Arc::ptr_eq(
                    &conns,
                    &self.connections.compare_and_swap(&conns, Arc::new(new_vec)),
                ) {
                    break;
                }

                drop_vec.iter().for_each(|conn| conn.close());

                debug!(
                    "UDP connection pool maintenance: dropped {} idle connections, active={}",
                    drop_vec.len(),
                    new_len
                );
            }
        });
    }
}

#[derive(Debug)]
pub struct ConnectionWrapper<C: Connection> {
    /// Underlying connection
    pub connection: Arc<C>,
    /// Timestamp (ms, monotonic) of the last usage
    pub last_use: AtomicU64,
    /// Whether this connection has been marked as dropped
    pub dropped: AtomicBool,
}

impl<C: Connection> ConnectionWrapper<C> {
    pub fn new(connection: Arc<C>) -> Self {
        Self {
            connection,
            last_use: AtomicU64::new(AppClock::run_millis()),
            dropped: AtomicBool::new(false),
        }
    }

    pub fn using_count(&self) -> u16 {
        self.connection.using_count()
    }

    pub async fn query(&self, query: Query) -> Result<DnsResponse, ProtoError> {
        self.touch();
        self.connection.query(query).await
    }

    /// Mark this connection as closed and notify listeners
    pub fn close(&self) {
        if self.dropped.swap(true, Ordering::SeqCst) {
            return;
        }
        self.connection.close();
    }

    #[inline]
    pub fn touch(&self) {
        self.last_use
            .store(AppClock::run_millis(), Ordering::Relaxed);
    }
}

#[async_trait]
pub trait Connection: Send + Sized + Sync + 'static {
    /// Mark this connection as closed and notify listeners
    fn close(&self);

    async fn query(&self, query: Query) -> Result<DnsResponse, ProtoError>;

    fn using_count(&self) -> u16;
}

pub trait ConnectionBuilder<C: Connection>: Send + Sync + Debug + 'static {
    fn new_conn(&self) -> Arc<C>;
}
