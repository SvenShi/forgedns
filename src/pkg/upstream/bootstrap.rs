/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::context::DnsContext;
use crate::pkg::upstream::{UpStream, UpStreamBuilder, UpstreamConfig};
use arc_swap::ArcSwap;
use chrono::{DateTime, Duration, Local};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tokio::task::yield_now;
use tracing::{debug, error, info, warn};

#[derive(Clone, Debug)]
enum CacheState {
    None,
    Querying,
    Cached(IpAddr),
    Failed,
}

pub(crate) struct Bootstrap {
    upstream: Box<dyn UpStream>,
    next_update: RwLock<DateTime<Local>>,
    cache_state: RwLock<CacheState>,
    domain: String,
}

impl Bootstrap {
    pub fn new(bootstrap_server: &str, domain: &str) -> Self {
        let config = UpstreamConfig {
            addr: bootstrap_server.to_string(),
            port: None,
            socks5: None,
            bootstrap: None,
            dial_addr: None,
            insecure_skip_verify: None,
            timeout: None,
            enable_pipeline: None,
            enable_http3: None,
        };

        Bootstrap {
            upstream: UpStreamBuilder::with_upstream_config(&config),
            next_update: RwLock::new(Local::now()),
            cache_state: RwLock::new(CacheState::None),
            domain: domain.to_string(),
        }
    }

    pub async fn get(&self) -> Result<IpAddr, String> {
        let mut failed_count = 0;

        loop {
            let state = { self.cache_state.read().await.clone() };

            match state {
                CacheState::None => {
                    self.query().await;
                }
                CacheState::Querying => {
                    yield_now().await;
                }
                CacheState::Cached(result) => {
                    let next_update = *self.next_update.read().await;
                    if Local::now() > next_update {
                        debug!("Bootstrap cache expired for {}, refreshing", self.domain);
                        self.query().await;
                        continue;
                    }
                    return Ok(result);
                }
                CacheState::Failed => {
                    if failed_count > 3 {
                        return Err(format!("Bootstrap query failed for {}", self.domain));
                    }
                    failed_count += 1;
                    self.query().await;
                }
            }
        }
    }

    async fn query(&self) {
        let mut state = self.cache_state.write().await;
        *state = CacheState::Querying;
        drop(state); // 释放锁，避免在查询过程中长时间持有锁

        // 创建DNS查询
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        // 添加查询记录
        let name = match Name::from_str(&self.domain) {
            Ok(name) => name,
            Err(e) => {
                error!("Failed to parse domain name {}: {}", self.domain, e);
                let mut state = self.cache_state.write().await;
                *state = CacheState::Failed;
                return;
            }
        };

        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 执行查询
        let mut context = DnsContext::new(message);
        match self.upstream.query(&mut context).await {
            Ok(response) => {
                // 处理响应
                let answers = response.answers();
                if !answers.is_empty() {
                    for answer in answers {
                        if answer.record_type() == RecordType::A {
                            if let Some(ip) = answer.data().and_then(|data| data.as_a().ok()) {
                                let ip_addr = IpAddr::from(*ip);
                                info!("Resolved {} to {}", self.domain, ip_addr);
                                
                                let mut state = self.cache_state.write().await;
                                *state = CacheState::Cached(ip_addr);
                                
                                let mut next_update = self.next_update.write().await;
                                *next_update = Local::now() + Duration::minutes(10);
                                return;
                            }
                        }
                    }
                }
                
                warn!("No A records found for {}", self.domain);
                let mut state = self.cache_state.write().await;
                *state = CacheState::Failed;
            }
            Err(e) => {
                error!("Failed to query DNS for {}: {}", self.domain, e);
                let mut state = self.cache_state.write().await;
                *state = CacheState::Failed;
            }
        }
    }
}
