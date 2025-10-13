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

mod pipeline_connections;
mod reuse_connections;

mod request_map;
pub(crate) mod tcp;
pub(crate) mod udp;

use crate::pkg::upstream::pool::pipeline_connections::PipelineConnectionFetcher;
use async_trait::async_trait;
use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::xfer::DnsResponse;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::info;

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
pub trait ConnectionFetcher<C: Connection>: Send + Sync + Debug + 'static {
    async fn get(&self) -> Result<Arc<C>, ProtoError>;
}

/// A pool of connections used for DNS queries
#[derive(Debug)]
pub struct ConnectionPool<C: Connection> {
    conn_fetcher: Arc<dyn ConnectionFetcher<C>>,
}

impl<C: Connection> ConnectionPool<C> {
    pub fn new_reuse(
        min_size: usize,
        max_size: usize,
        connection_builder: Box<dyn ConnectionBuilder<C>>,
    ) -> Self {
        todo!()
    }

    pub fn new_pipeline(
        min_size: usize,
        max_size: usize,
        max_load: u16,
        connection_builder: Box<dyn ConnectionBuilder<C>>,
    ) -> Self {
        info!(
            "new pipeline connection pool, min_size:{}, max_size:{}, max_load:{}",
            min_size, max_size, max_load
        );
        Self {
            conn_fetcher: PipelineConnectionFetcher::new(
                min_size,
                max_size,
                max_load,
                connection_builder,
            ),
        }
    }

    /// Send DNS request and wait for the response or timeout
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn query(&self, request: Message) -> Result<DnsResponse, ProtoError> {
        let conn = self.get().await?;
        conn.query(request).await
    }

    /// Get a connection from the pool with load balancing
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn get(&'_ self) -> Result<Arc<C>, ProtoError> {
        self.conn_fetcher.get().await
    }
}
