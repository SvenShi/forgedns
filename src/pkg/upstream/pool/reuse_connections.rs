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
use crate::pkg::upstream::pool::{Connection, ConnectionBuilder, ConnectionFetcher};
use async_trait::async_trait;
use crossbeam_queue::ArrayQueue;
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
use tracing::debug;

#[derive(Debug)]
pub struct ConnectionGuard<C: Connection> {
    connection: Arc<C>,
    fetcher: Arc<ReuseConnectionFetcher<C>>,
}

impl<C: Connection> Drop for ConnectionGuard<C> {
    fn drop(&mut self) {
        self.fetcher.release(self.connection.clone());
    }
}

#[async_trait]
impl<C: Connection> Connection for ConnectionGuard<C> {
    fn close(&self) {
        self.connection.close()
    }

    async fn query(&self, request: Message) -> Result<DnsResponse, ProtoError> {
        self.connection.query(request).await
    }

    fn using_count(&self) -> u16 {
        self.connection.using_count()
    }

    fn available(&self) -> bool {
        self.connection.available()
    }

    fn last_used(&self) -> u64 {
        self.connection.last_used()
    }
}

#[derive(Debug)]
pub struct ReuseConnectionFetcher<C: Connection> {
    /// List of active connections
    connections: ArrayQueue<Arc<C>>,
    active_count: AtomicUsize,
    /// Maximum number of connections allowed
    max_size: usize,
    /// Minimum number of connections to maintain
    min_size: usize,
    /// Maximum allowed idle time before a connection is dropped
    max_idle: Duration,
    /// Connection builder, build new connections
    connection_builder: Box<dyn ConnectionBuilder<C>>,
    /// The Next connection id
    next_id: AtomicU16,
}

#[async_trait]
impl<C: Connection> ConnectionFetcher<C> for ReuseConnectionFetcher<C> {
    async fn get(&self) -> Result<Arc<C>, ProtoError> {
        loop {
            if let Some(conn) = self.connections.pop() {
                if conn.available() {
                    return Ok(conn);
                } else {
                    self.active_count.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }
}

impl<C: Connection> ReuseConnectionFetcher<C> {
    pub fn new(
        min_size: usize,
        max_size: usize,
        connection_builder: Box<dyn ConnectionBuilder<C>>,
    ) -> Arc<ReuseConnectionFetcher<C>> {
        todo!()
    }

    fn release(&self, connection: Arc<C>) {
        if !connection.available() || self.connections.push(connection).is_err() {
            self.active_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Expand the pool by creating new connections
    async fn expand(&self) -> Result<(), ProtoError> {
        let conns_len = self.active_count.load(Ordering::Relaxed);
        if conns_len >= self.max_size {
            debug!("Connection pool already at max size");
            return Err(ProtoError::from("Connection pool already at maximum size"));
        }

        let mut new_conns_count = if conns_len >= self.min_size {
            1
        } else {
            self.min_size - conns_len
        };

        // clamp to not exceed max_size
        if conns_len + new_conns_count > self.max_size {
            new_conns_count = self.max_size - conns_len;
        }

        debug!(
            "Expanding connection pool by {} connections",
            new_conns_count
        );

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
        while let Some(res) = futs.next().await {
            match res {
                Ok(conn) => {
                    if self.active_count.load(Ordering::Relaxed) < self.max_size
                        && self.connections.push(conn).is_ok()
                    {
                        self.active_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    // close any already created connections, return error
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    const MAINTENANCE_DURATION: Duration = Duration::from_secs(30);

    /// Periodically remove idle connections
    fn start_maintenance(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Self::MAINTENANCE_DURATION).await;
                // run scan in background (not awaiting here would drop errors), we await to ensure fairness
                self.clone().scan_pool().await;
                // small yield to let other tasks run
                yield_now().await;
            }
        });
    }

    async fn scan_pool(self: Arc<Self>) {
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

/// Synchronous close helper (close() is sync)
#[inline]
fn close_conns<C: Connection>(conns: &Vec<Arc<C>>) {
    for conn in conns {
        // it's fine if close() is sync: call directly
        conn.close();
    }
}
