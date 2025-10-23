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
use crate::core::error::{DnsError, Result};
use crate::network::upstream::{ConnectionInfo, Upstream, UpstreamBuilder};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};
use rand::random;
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
    upstream: Box<dyn Upstream>,

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
    /// * `bootstrap_server` - DNS server address for resolution (e.g., "8.8.8.8:53")
    /// * `domain` - Domain name to resolve (FQDN format)
    /// * `ip_version` - IP version preference: Some(6) for IPv6, None or Some(4) for IPv4
    ///
    /// # Panics
    /// Panics if the domain name is invalid (validation happens at initialization time)
    ///
    /// # Performance
    /// Pre-builds the DNS query message to avoid repeated allocations on each query
    pub fn new(bootstrap_server: &str, domain: &str, ip_version: Option<u8>) -> Self {
        // Pre-parse domain name (fail-fast strategy during initialization)
        let parsed_name = Name::from_str(domain)
            .unwrap_or_else(|e| panic!("Invalid domain name '{}': {}", domain, e));

        // Pre-build DNS query message to optimize hot path performance
        // This message template will be cloned for each actual query
        let mut message = Message::new();
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        // Set query type based on IP version: AAAA for IPv6, A for IPv4
        message.add_query(Query::query(
            parsed_name.clone(),
            match ip_version {
                Some(6) => RecordType::AAAA,
                _ => RecordType::A,
            },
        ));

        Bootstrap {
            upstream: UpstreamBuilder::with_connection_info(ConnectionInfo::with_addr(
                bootstrap_server,
            )),
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
    /// Uses a lock-free state machine for coordination among multiple concurrent callers.
    ///
    /// # Returns
    /// - `Ok(IpAddr)` if resolution succeeds (from cache or fresh query)
    /// - `Err(DnsError)` if all resolution attempts fail after retries
    ///
    /// # Performance
    /// - Fast path: single atomic load when cache is valid
    /// - Only one concurrent query at a time (others wait for result)
    /// - Automatic retry on transient failures
    #[inline]
    pub async fn get(&self) -> Result<IpAddr> {
        let mut failed_count = 0;

        loop {
            // Fast path: atomic load without locking (most common case)
            let state = self.state.load(Ordering::Acquire);

            match state {
                STATE_CACHED => {
                    // Hot path: check cache validity
                    let cache = self.cache.read().await;
                    if let Some(ref data) = *cache
                        && AppClock::elapsed_millis() < data.expires_at
                    {
                        // Cache hit - most common case
                        return Ok(data.ip);
                    }
                    drop(cache);

                    // Cache expired, trigger refresh
                    debug!(
                        domain = %self.domain,
                        "Bootstrap cache expired, triggering refresh"
                    );
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
                    // Limit retry attempts to prevent infinite loops
                    if failed_count > 3 {
                        return Err(DnsError::protocol(format!(
                            "Bootstrap DNS resolution failed for '{}' after {} attempts",
                            self.domain, failed_count
                        )));
                    }
                    failed_count += 1;

                    // Retry by transitioning back to NONE state
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
    ///
    /// # State Transitions
    /// - Success: STATE_QUERYING -> STATE_CACHED
    /// - Failure: STATE_QUERYING -> STATE_FAILED
    ///
    /// # Concurrency
    /// This method is called by only one task at a time (enforced by state machine).
    /// Other tasks wait via `query_done` notification.
    async fn query(&self) {
        // Execute DNS query using pre-built message template
        // Randomize query ID to prevent response spoofing
        let mut message = self.message.clone();
        message.set_id(random());
        match self.upstream.query(message).await {
            Ok(response) => {
                let answers = response.answers();

                // Find the first matching A (IPv4) or AAAA (IPv6) record
                for answer in answers {
                    if answer.record_type() == RecordType::A
                        || answer.record_type() == RecordType::AAAA
                    {
                        if let Some(ip) = answer.data().ip_addr() {
                            let ttl = answer.ttl() as u64 * 1000; // Convert seconds to milliseconds
                            info!(
                                domain = %self.domain,
                                ip = %ip,
                                ttl_seconds = ttl / 1000,
                                record_type = ?answer.record_type(),
                                "Bootstrap DNS resolution successful"
                            );

                            // Update cache with new IP and expiration time
                            let expires_at = AppClock::elapsed_millis() + ttl;
                            *self.cache.write().await = Some(CacheData { ip, expires_at });

                            // Transition to CACHED state and wake all waiting tasks
                            self.state.store(STATE_CACHED, Ordering::Release);
                            self.query_done.notify_waiters();
                            return;
                        }
                    }
                }

                // No matching A/AAAA records found in response
                warn!(
                    domain = %self.domain,
                    answer_count = answers.len(),
                    "No A/AAAA records found in bootstrap DNS response"
                );
                self.state.store(STATE_FAILED, Ordering::Release);
                self.query_done.notify_waiters();
            }
            Err(e) => {
                // DNS query failed (network error, timeout, etc.)
                error!(
                    domain = %self.domain,
                    error = %e,
                    "Bootstrap DNS query failed"
                );
                self.state.store(STATE_FAILED, Ordering::Release);
                self.query_done.notify_waiters();
            }
        }
    }
}
