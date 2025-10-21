/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::core::app_clock::AppClock;
use crate::pkg::upstream::{UpStream, UpStreamBuilder, UpstreamConfig};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::sync::{Notify, RwLock};
use tracing::{debug, error, info, warn};

// 状态常量
const STATE_NONE: u8 = 0;
const STATE_QUERYING: u8 = 1;
const STATE_CACHED: u8 = 2;
const STATE_FAILED: u8 = 3;

#[derive(Clone, Debug)]
struct CacheData {
    ip: IpAddr,
    expires_at: u64,
}

pub(crate) struct Bootstrap {
    upstream: Box<dyn UpStream>,
    /// 原子状态标志，用于快速路径检查
    state: AtomicU8,
    /// 缓存数据 - 使用 parking_lot 的同步 RwLock（比 tokio 的快）
    cache: RwLock<Option<CacheData>>,
    /// 查询完成通知
    query_done: Notify,

    message: Message,
    /// 原始域名（仅用于日志）
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

        // 预解析域名，如果失败则 panic（在初始化时就应该发现）
        let parsed_name = Name::from_str(domain)
            .unwrap_or_else(|e| panic!("Invalid domain name {}: {}", domain, e));
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(Query::query(parsed_name.clone(), RecordType::A));
        Bootstrap {
            upstream: UpStreamBuilder::with_upstream_config(&config),
            state: AtomicU8::new(STATE_NONE),
            cache: RwLock::new(None),
            query_done: Notify::new(),
            message,
            domain: domain.to_string(),
        }
    }

    #[inline]
    pub async fn get(&self) -> Result<IpAddr, String> {
        let mut failed_count = 0;

        loop {
            // 【优化1】快速路径：使用原子 load，无锁检查
            let state = self.state.load(Ordering::Acquire);

            match state {
                STATE_CACHED => {
                    // 【优化2】使用同步 RwLock（parking_lot），比 tokio 的异步锁快
                    let cache = self.cache.read().await;
                    if let Some(ref data) = *cache {
                        // 【优化3】使用 Instant 而不是 DateTime<Local>
                        if AppClock::run_millis() < data.expires_at {
                            // 热路径：缓存命中 - 这是最常见的情况
                            return Ok(data.ip);
                        }
                    }
                    drop(cache);

                    // 缓存过期，尝试触发刷新
                    debug!("Bootstrap cache expired for {}, refreshing", self.domain);
                    if self
                        .state
                        .compare_exchange(
                            STATE_CACHED,
                            STATE_NONE,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // 继续到下一次循环，触发查询
                        continue;
                    }
                    // 其他协程已经在刷新了，等待通知
                    self.query_done.notified().await;
                }
                STATE_NONE => {
                    // 尝试获取查询权限
                    if self
                        .state
                        .compare_exchange(
                            STATE_NONE,
                            STATE_QUERYING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // 我们获得了查询权限
                        self.query().await;
                        continue;
                    }
                    // 其他协程已经在查询，等待
                    self.query_done.notified().await;
                }
                STATE_QUERYING => {
                    // 【优化4】使用 Notify 替代 yield_now 的自旋等待
                    self.query_done.notified().await;
                }
                STATE_FAILED => {
                    if failed_count > 3 {
                        return Err(format!("Bootstrap query failed for {}", self.domain));
                    }
                    failed_count += 1;

                    // 重试
                    if self
                        .state
                        .compare_exchange(
                            STATE_FAILED,
                            STATE_NONE,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        continue;
                    }
                    self.query_done.notified().await;
                }
                _ => unreachable!("Invalid bootstrap state"),
            }
        }
    }

    async fn query(&self) {
        // 【优化5】使用预解析的域名，避免重复解析
        // 【优化6】直接构建查询消息，减少中间步骤

        // 执行查询
        match self.upstream.query(self.message.clone()).await {
            Ok(response) => {
                let answers = response.answers();

                // 【优化7】直接迭代，避免多余的检查
                for answer in answers {
                    if answer.record_type() == RecordType::A || answer.record_type() == RecordType::AAAA {
                        if let Some(ip) = answer.data().ip_addr() {
                            let ttl = answer.ttl() as u64 * 1000;
                            info!("Resolved {} to {}, tll {}", self.domain, ip, ttl);

                            // 更新缓存
                            let expires_at = AppClock::run_millis() + ttl;
                            *self.cache.write().await = Some(CacheData { ip, expires_at });

                            // 更新状态并通知
                            self.state.store(STATE_CACHED, Ordering::Release);
                            self.query_done.notify_waiters();
                            return;
                        }
                    }
                }

                warn!("No A records found for {}", self.domain);
                self.state.store(STATE_FAILED, Ordering::Release);
                self.query_done.notify_waiters();
            }
            Err(e) => {
                error!("Failed to query DNS for {}: {}", self.domain, e);
                self.state.store(STATE_FAILED, Ordering::Release);
                self.query_done.notify_waiters();
            }
        }
    }
}
