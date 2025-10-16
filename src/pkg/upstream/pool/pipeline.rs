/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::app_clock::AppClock;
use crate::pkg::upstream::pool::utils::close_conns;
use crate::pkg::upstream::pool::{
    Connection, ConnectionBuilder, ConnectionPool, start_maintenance,
};
use arc_swap::ArcSwap;
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
use tokio::task::yield_now;
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct PipelinePool<C: Connection> {
    /// Round-robin index for load balancing across connections
    index: AtomicUsize,
    /// List of active connections
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
}

#[async_trait]
impl<C: Connection> ConnectionPool<C> for PipelinePool<C> {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn query(&self, request: Message) -> Result<DnsResponse, ProtoError> {
        self.get().await?.query(request).await
    }

    async fn scan_pool(&self) {
        let now = AppClock::run_millis();
        let mut new_vec = Vec::new();
        let mut drop_vec = Vec::new();
        let mut invalid_vec = Vec::new();
        let conns = self.connections.load();

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

        // try to keep min_size
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
            // lost race, nothing to do
            return;
        }

        // now actually close those we removed
        close_conns(&drop_vec);
        close_conns(&invalid_vec);

        debug!(
            "connection pool maintenance: dropped {} idle connections, dropped {} invalid connections, active={}",
            drop_vec.len(),
            invalid_vec.len(),
            new_len
        );

        // try to keep min_size connections
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
            connections: ArcSwap::from_pointee(Vec::new()),
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
            // fire-and-forget async expand to prefill pool
            tokio::spawn(async move {
                let _ = arc.expand().await;
            });
        }
        pool
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn get(&self) -> Result<Arc<C>, ProtoError> {
        loop {
            let conns = self.connections.load();
            let len = conns.len();
            if len == 0 {
                self.expand().await?;
                // yield to allow expand to make progress
                yield_now().await;
                continue;
            }
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

            if len < self.max_size {
                if let Err(_) = self.expand().await {
                    yield_now().await;
                }
            } else {
                // all connections are at max_load, yield to allow active queries to finish
                yield_now().await;
            }
        }
    }

    /// Expand the pool by creating new connections
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn expand(&self) -> Result<(), ProtoError> {
        let mut conns_len = self.connections.load().len();
        if conns_len >= self.max_size {
            debug!("Connection pool already at max size");
            return Err(ProtoError::from("Connection pool already at maximum size"));
        }

        let mut new_conns_count = if conns_len >= self.min_size {
            1
        } else {
            self.min_size - conns_len
        };

        conns_len = self.connections.load().len();
        // clamp to not exceed max_size
        if conns_len + new_conns_count > self.max_size {
            new_conns_count = self.max_size - conns_len;
        }

        if new_conns_count == 0 {
            return Ok(());
        }

        let mut futs = FuturesUnordered::new();

        for _ in 0..new_conns_count {
            let builder = &self.connection_builder;
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            // spawn per-connection creation in a task so we don't block current task if creation has internal awaits
            futs.push(async move {
                // call builder.new_conn — builder must be Sync so it's safe to call concurrently
                builder.new_conn(id).await
            });
        }

        // collect results
        let mut created: Vec<Arc<C>> = Vec::with_capacity(new_conns_count);
        while let Some(res) = futs.next().await {
            match res {
                Ok(conn) => created.push(conn),
                Err(e) => {
                    // close any already created connections, return error
                    debug!("Failed to create new connection: {:?}", e);
                }
            }
        }

        if created.is_empty() {
            // nothing created (race or other), just return
            return Ok(());
        }
        let new_conns_len = created.len();

        loop {
            let conns = self.connections.load().clone();
            if conns.len() >= self.max_size {
                close_conns(&created);
                return Ok(());
            }
            let mut new_vec = (*conns).clone();
            new_vec.reserve(created.len());
            // move created into new_vec
            new_vec.extend(created.drain(..));
            let new_len = new_vec.len();
            let new_arc = Arc::new(new_vec);
            if Arc::ptr_eq(
                &conns,
                &self.connections.compare_and_swap(&conns, new_arc.clone()),
            ) {
                // set index near the end to give round robin fairness
                self.index.store(new_len - 1, Ordering::Relaxed);
                debug!(
                    "Expanding pool: creating {} new connections (current={}/{})",
                    new_conns_len, new_len, self.max_size
                );
                break Ok(());
            } else {
                // lost the race (someone else updated), retry: reload conns and try again, but re-use any remaining created (should be none)
                // If compare_and_swap fails, our `created` Vec is empty (drained). To be safe, break.
                // However to avoid leaks, if created still has elements, close them
                if !created.is_empty() {
                    close_conns(&created);
                    created.clear();
                }
                // reload snapshot and check if now satisfied
                let cur_len = self.connections.load().len();
                if cur_len >= self.max_size {
                    break Ok(());
                } else {
                    // try one more time to add a single conn (fallback)
                    break Ok(());
                }
            }
        }
    }
}
