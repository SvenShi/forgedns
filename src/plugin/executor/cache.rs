/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

use crate::config::types::PluginConfig;
use crate::core::app_clock::AppClock;
use crate::core::context::DnsContext;
use crate::core::error::Result;
use crate::plugin::executor::Executor;
use crate::plugin::executor::sequence::chain::ChainNode;
use crate::plugin::{Plugin, PluginFactory, PluginRegistry, UninitializedPlugin};
use async_trait::async_trait;
use dashmap::DashMap;
use hickory_proto::op::Message;
use serde::Deserialize;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time::sleep;
use tracing::info;

const DEFAULT_CACHE_SIZE: usize = 1024;

#[derive(Clone, Debug, Deserialize)]
pub struct CacheConfig {
    size: Option<usize>,

    lazy_cache_ttl: Option<u64>,

    dump_file: Option<String>,

    dump_interval: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CacheItem {
    resp: Message,
    cache_time: u64,
    ttl: u32,
    expire_time: u64,
}

#[derive(Debug)]
pub struct Cache {
    domain_map: OnceCell<Arc<DashMap<String, CacheItem>>>,
    tag: String,
    config: CacheConfig,
}

#[async_trait]
impl Plugin for Cache {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self) {
        // init cache plugin
        // 根据配置初始化
        let domain_map = Arc::from(DashMap::with_capacity(
            self.config.size.unwrap_or_else(|| DEFAULT_CACHE_SIZE),
        ));
        let _domain_map = domain_map.clone();
        let _ = self.domain_map.set(domain_map);

        // load dump file to cache
        if let Some(_dump_file) = &self.config.dump_file {
            todo!("not implemented yet")
        }

        // cache clean job
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(300)).await;
                let now = AppClock::elapsed_millis();
                _domain_map.retain(|_, item| item.expire_time > now);
            }
        });
    }

    async fn destroy(&mut self) {
        if let Some(_dump_file) = &self.config.dump_file {
            //     dump file here
        }
    }
}

#[async_trait]
impl Executor for Cache {
    async fn execute(&self, context: &mut DnsContext, next: Option<&Arc<ChainNode>>) {
        // 1. find query result from cache
        if let Some(query) = context.request.query() {
            let domain = query.name().to_string();
            if let Some(item) = self.domain_map.get().unwrap().get(&domain) {
                let now = AppClock::elapsed_millis();
                if now < item.expire_time {
                    // cache hit
                    context.response = Some(item.resp.clone());
                    info!(
                        "cache hit query:{}, response:{:?}",
                        query.name(),
                        item.resp.answers()
                    );
                } else {
                    self.domain_map.get().unwrap().remove(&domain);
                }
            } else {
                info!("cache miss query:{}, domain:{:?}", self.tag, domain);
            }
        }

        // 2. execute next
        continue_next!(next, context);

        // 3. If present, set the response to cache
        if context.response.is_some() {
            // async save response to cache
            let query = context.request.query().cloned();
            let response = context.response.clone();
            let domain_map = self.domain_map.clone();

            tokio::spawn(async move {
                if let Some(query) = query {
                    let domain = query.name().to_string();
                    if let Some(response) = response {
                        let now = AppClock::elapsed_millis();
                        //  Maybe the default TTL is needed here
                        let ttl = response
                            .answers()
                            .first()
                            .map(|answer| answer.ttl())
                            .unwrap_or_else(|| 5);

                        let cache_item = CacheItem {
                            resp: response.clone(),
                            cache_time: now,
                            ttl,
                            expire_time: now + (ttl as u64 * 1000),
                        };
                        info!("cached cache item:{:?}", cache_item);
                        // save response to cache
                        domain_map.get().unwrap().insert(domain, cache_item);
                    }
                }
            });
        }
    }
}

#[derive(Debug)]
pub struct CacheFactory;
impl PluginFactory for CacheFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _registry: Arc<PluginRegistry>,
    ) -> Result<UninitializedPlugin> {
        let cache_config = if let Some(args) = &plugin_config.args {
            serde_yml::from_value::<CacheConfig>(args.clone())?
        } else {
            CacheConfig {
                size: None,
                lazy_cache_ttl: None,
                dump_file: None,
                dump_interval: None,
            }
        };

        Ok(UninitializedPlugin::Executor(Box::new(Cache {
            domain_map: OnceCell::new(),
            tag: plugin_config.tag.clone(),
            config: cache_config,
        })))
    }
}
