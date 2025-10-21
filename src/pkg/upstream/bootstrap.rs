/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Bootstrap DNS resolver for domain name resolution
//!
//! Provides efficient hostname-to-IP resolution for upstream servers.
//! Implements a lock-free caching mechanism with automatic refresh.
//!
//! # Performance Optimizations
//! - Lock-free state machine using atomic operations
//! - Cached results with TTL-based expiration
//! - Single resolver instance for multiple concurrent queries
//! - Pre-parsed DNS queries to avoid repeated allocations

use crate::core::app_clock::AppClock;
use crate::pkg::upstream::{UpStream, UpStreamBuilder, UpstreamConfig};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::sync::{Notify, RwLock};
use tracing::{debug, error, info, warn};

// State machine constants for atomic state transitions
const STATE_NONE: u8 = 0; // Initial state, needs query
const STATE_QUERYING: u8 = 1; // Currently performing DNS lookup
const STATE_CACHED: u8 = 2; // Valid cached result available
const STATE_FAILED: u8 = 3; // Previous query failed

/// Cached DNS resolution result
#[derive(Clone, Debug)]
struct CacheData {
    /// Resolved IP address
    ip: IpAddr,
    /// Expiration time in milliseconds since app start
    expires_at: u64,
}

/// Bootstrap DNS resolver for upstream hostname resolution
///
/// Uses a lock-free state machine to coordinate multiple concurrent
/// resolution requests efficiently. Only one query is performed at a time,
/// with other requests waiting for the result.
#[derive(Debug)]
pub(crate) struct Bootstrap {
    /// Upstream resolver for DNS queries
    upstream: Box<dyn UpStream>,

    /// Atomic state flag for lock-free fast path
    state: AtomicU8,

    /// Cached resolution data with TTL
    cache: RwLock<Option<CacheData>>,

    /// Notifier for query completion (wakes waiting tasks)
    query_done: Notify,

    /// Pre-built DNS query message (optimization)
    message: Message,

    /// Domain name being resolved (for logging only)
    domain: String,
}

impl Bootstrap {
    /// Create a new bootstrap resolver
    ///
    /// # Arguments
    /// * `bootstrap_server` - DNS server address for resolution (e.g., "8.8.8.8")
    /// * `domain` - Domain name to resolve
    ///
    /// # Panics
    /// Panics if the domain name is invalid (should be caught during init)
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

        // Pre-parse domain name (fail fast during initialization)
        let parsed_name = Name::from_str(domain)
            .unwrap_or_else(|e| panic!("Invalid domain name '{}': {}", domain, e));

        // Pre-build DNS query message (optimization: avoid repeated allocations)
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

    /// Get the resolved IP address, using cache or triggering a new query
    ///
    /// This is the hot path - optimized for minimal overhead when cache is valid.
    /// Uses a lock-free state machine for coordination.
    #[inline]
    pub async fn get(&self) -> Result<IpAddr, String> {
        let mut failed_count = 0;

        loop {
            // Fast path: atomic load without locking
            let state = self.state.load(Ordering::Acquire);

            match state {
                STATE_CACHED => {
                    // Hot path: check cache validity
                    let cache = self.cache.read().await;
                    if let Some(ref data) = *cache {
                        if AppClock::run_millis() < data.expires_at {
                            // Cache hit - most common case
                            return Ok(data.ip);
                        }
                    }
                    drop(cache);

                    // Cache expired, try to trigger refresh
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
                        // Successfully transitioned to NONE, loop to trigger query
                        continue;
                    }
                    // Someone else is already refreshing, wait for result
                    self.query_done.notified().await;
                }
                STATE_NONE => {
                    // Try to acquire query permission
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
                        // We won the race, perform the query
                        self.query().await;
                        continue;
                    }
                    // Someone else is querying, wait for result
                    self.query_done.notified().await;
                }
                STATE_QUERYING => {
                    // Wait for query to complete
                    self.query_done.notified().await;
                }
                STATE_FAILED => {
                    if failed_count > 3 {
                        return Err(format!("Bootstrap query failed for {}", self.domain));
                    }
                    failed_count += 1;

                    // Retry by transitioning back to NONE
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

    /// Perform DNS query for the domain
    ///
    /// Uses pre-built query message for efficiency.
    /// Updates cache and notifies waiting tasks on completion.
    async fn query(&self) {
        // Execute DNS query using pre-built message
        match self.upstream.query(self.message.clone()).await {
            Ok(response) => {
                let answers = response.answers();

                // Find first A or AAAA record
                for answer in answers {
                    if answer.record_type() == RecordType::A
                        || answer.record_type() == RecordType::AAAA
                    {
                        if let Some(ip) = answer.data().ip_addr() {
                            let ttl = answer.ttl() as u64 * 1000; // Convert to milliseconds
                            info!(
                                "Bootstrap resolved {} to {} (TTL: {}s)",
                                self.domain,
                                ip,
                                ttl / 1000
                            );

                            // Update cache
                            let expires_at = AppClock::run_millis() + ttl;
                            *self.cache.write().await = Some(CacheData { ip, expires_at });

                            // Transition to CACHED and wake waiting tasks
                            self.state.store(STATE_CACHED, Ordering::Release);
                            self.query_done.notify_waiters();
                            return;
                        }
                    }
                }

                // No A/AAAA records found
                warn!("No A/AAAA records found for {}", self.domain);
                self.state.store(STATE_FAILED, Ordering::Release);
                self.query_done.notify_waiters();
            }
            Err(e) => {
                // DNS query failed
                error!("Failed to query DNS for {}: {}", self.domain, e);
                self.state.store(STATE_FAILED, Ordering::Release);
                self.query_done.notify_waiters();
            }
        }
    }
}
