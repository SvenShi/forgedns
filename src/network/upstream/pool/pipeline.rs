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
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::yield_now;
use tracing::debug;

#[derive(Debug)]
pub struct PipelinePool<C: Connection> {
    /// Round-robin index for load balancing across connections
    index: AtomicUsize,
    /// List of active connections (protected by RwLock)
    connections: RwLock<Vec<Arc<C>>>,
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
}

#[async_trait]
impl<C: Connection> ConnectionPool<C> for PipelinePool<C> {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, request: Message) -> Result<DnsResponse, ProtoError> {
        self.get().await?.query(request).await
    }

    async fn maintain(&self) {
        let now = AppClock::elapsed_millis();
        let mut new_vec = Vec::new();
        let mut drop_vec = Vec::new();
        let mut invalid_vec = Vec::new();

        // Read connections
        {
            let conns = self.connections.read().await;
            for conn in conns.iter() {
                if conn.available() {
                    let idle = now - conn.last_used();
                    if idle < self.max_idle.as_millis() as u64 {
                        new_vec.push(conn.clone());
                    } else {
                        drop_vec.push(conn.clone());
                    }
                } else {
                    invalid_vec.push(conn.clone());
                }
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

        // Update connections (short write lock)
        {
            let mut conns = self.connections.write().await;
            *conns = new_vec;
        }

        // Close removed connections (outside lock)
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
        connection_builder: Box<dyn ConnectionBuilder<C>>,
    ) -> Arc<PipelinePool<C>> {
        let pool = Arc::new(Self {
            index: AtomicUsize::new(0),
            connections: RwLock::new(Vec::new()),
            max_size,
            min_size,
            max_load,
            max_idle: Duration::from_secs(10),
            connection_builder,
            next_id: AtomicU16::new(0),
        });
        start_maintenance(pool.clone());
        if min_size > 0 {
            let arc = pool.clone();
            // Fire-and-forget async expand to prefill pool
            tokio::spawn(async move {
                let _ = arc.expand().await;
            });
        }
        pool
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn get(&self) -> Result<Arc<C>, ProtoError> {
        loop {
            // Fast read path
            {
                let conns = self.connections.read().await;
                if conns.is_empty() {
                    drop(conns);
                    self.expand().await?;
                    yield_now().await;
                    continue;
                }

                let len = conns.len();
                let mut idx = self.index.load(Ordering::Relaxed) % len;
                let raw_idx = idx;

                for _ in 0..len {
                    let conn = &conns[idx];
                    if conn.available() && conn.using_count() < self.max_load {
                        if raw_idx != idx {
                            self.index.store(idx, Ordering::Relaxed);
                        }
                        return Ok(conn.clone());
                    }
                    idx = (idx + 1) % len;
                }

                // All connections at max load
            }

            // Check if we can expand
            let current_len = self.connections.read().await.len();
            if current_len < self.max_size {
                if let Err(_) = self.expand().await {
                    yield_now().await;
                }
            } else {
                // All connections are at max_load, yield to allow active queries to finish
                yield_now().await;
            }
        }
    }

    /// Expand the pool by creating new connections
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn expand(&self) -> Result<(), ProtoError> {
        // Determine how many connections to create (outside lock)
        let new_conns_count = {
            let conns = self.connections.read().await;
            let conns_len = conns.len();

            if conns_len >= self.max_size {
                debug!("Connection pool already at max size");
                return Err(ProtoError::from("Connection pool already at maximum size"));
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

        // Create new connections (outside lock)
        let mut futs = FuturesUnordered::new();
        for _ in 0..new_conns_count {
            let builder = &self.connection_builder;
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            futs.push(async move { builder.create_connection(id).await });
        }

        // Collect results
        let mut created: Vec<Arc<C>> = Vec::with_capacity(new_conns_count);
        while let Some(res) = futs.next().await {
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

        // Add new connections (short write lock, no retry loop)
        {
            let mut conns = self.connections.write().await;
            if conns.len() < self.max_size {
                let space = self.max_size - conns.len();
                let to_add = created.len().min(space);

                for conn in created.drain(..to_add) {
                    conns.push(conn);
                }

                // Set index near the end for round robin fairness
                self.index
                    .store(conns.len().saturating_sub(1), Ordering::Relaxed);

                debug!(
                    "Pipeline pool expanded: +{} connections (total={}/{})",
                    to_add,
                    conns.len(),
                    self.max_size
                );
            }
        }

        // Close any leftover connections (outside lock)
        if !created.is_empty() {
            close_conns(&created);
        }

        Ok(())
    }
}
