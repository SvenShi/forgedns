/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Provider plugin category.
//!
//! Providers expose reusable datasets to other plugins, especially matchers and
//! executors that need fast membership checks without duplicating parsing or
//! storage logic.
//!
//! Common use cases include:
//!
//! - domain-set membership for qname and CNAME decisions;
//! - IP-set membership for client IP, response IP, or routing behavior; and
//! - typed provider-specific access via downcasting when a plugin needs richer
//!   capabilities than the generic membership helpers.
//!
//! Providers are initialized once, then shared through the plugin registry.
//! Their per-request API should stay read-only and cheap.
use std::any::Any;
use std::net::IpAddr;
use std::sync::Arc;

use crate::api::{ApiHandler, ApiRegister, json_error, json_ok};
use crate::core::error::{DnsError, Result as DnsResult};
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode};
use serde::Serialize;

use crate::plugin::Plugin;
use crate::plugin::PluginRegistry;
use crate::proto::{Name, Question};

pub mod adguard_rule;
pub mod domain_set;
pub mod geoip;
pub mod geosite;
pub mod ip_set;
pub(crate) mod provider_utils;
pub(crate) mod v2ray_dat;

#[async_trait]
#[allow(dead_code)]
pub trait Provider: Plugin {
    /// Type-erased view for provider-specific downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Domain membership check using an owned DNS name.
    #[inline]
    fn contains_name(&self, _name: &Name) -> bool {
        false
    }

    /// Question-level membership check for providers that need request question context.
    #[inline]
    fn contains_question(&self, _question: &Question) -> bool {
        false
    }

    /// Fast-path IP membership check for hot matcher paths.
    fn contains_ip(&self, _ip: IpAddr) -> bool {
        false
    }

    /// Reload the provider's internal data using the same startup config.
    async fn reload(&self) -> DnsResult<()> {
        Err(DnsError::plugin(format!(
            "provider '{}' does not support reload",
            self.tag()
        )))
    }

    #[inline]
    fn supports_ip_matching(&self) -> bool {
        false
    }

    #[inline]
    fn supports_domain_matching(&self) -> bool {
        false
    }
}

#[derive(Debug, Serialize)]
struct ProviderReloadResponse {
    ok: bool,
    action: &'static str,
    provider: String,
    status: &'static str,
}

#[derive(Debug)]
struct ProviderReloadHandler {
    tag: String,
    registry: Arc<PluginRegistry>,
}

#[async_trait]
impl ApiHandler for ProviderReloadHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        match self.registry.reload_provider(&self.tag).await {
            Ok(()) => json_ok(
                StatusCode::OK,
                &ProviderReloadResponse {
                    ok: true,
                    action: "reload_provider",
                    provider: self.tag.clone(),
                    status: "reloaded",
                },
            ),
            Err(err) => json_error(
                StatusCode::BAD_REQUEST,
                "provider_reload_failed",
                err.to_string(),
            ),
        }
    }
}

pub(crate) fn register_reload_api_route(
    api_register: Option<&ApiRegister>,
    registry: Arc<PluginRegistry>,
    tag: &str,
) -> DnsResult<()> {
    let Some(api_register) = api_register else {
        return Ok(());
    };

    api_register.register_plugin_post(
        tag,
        "/reload",
        Arc::new(ProviderReloadHandler {
            tag: tag.to_string(),
            registry,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiHub;
    use crate::config::types::{ApiConfig, ApiHttpConfig, PluginConfig};
    use crate::plugin::dependency::DependencyKind;
    use crate::plugin::matcher::qname::QnameFactory;
    use crate::plugin::{PluginFactory, UninitializedPlugin};
    use async_trait::async_trait;
    use http::{Method, Request as HttpRequest, StatusCode, Uri};
    use http_body_util::{BodyExt, Empty};
    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioExecutor;
    use std::net::{SocketAddr, TcpListener as StdTcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn reserve_local_addr() -> SocketAddr {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        addr
    }

    #[derive(Debug)]
    struct ReloadableProvider {
        tag: String,
        reload_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Plugin for ReloadableProvider {
        fn tag(&self) -> &str {
            &self.tag
        }

        async fn init(&mut self) -> DnsResult<()> {
            Ok(())
        }

        async fn destroy(&self) -> DnsResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Provider for ReloadableProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn contains_name(&self, _name: &Name) -> bool {
            false
        }

        async fn reload(&self) -> DnsResult<()> {
            self.reload_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn supports_domain_matching(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct ReloadableProviderFactory {
        reload_count: Arc<AtomicUsize>,
    }

    impl PluginFactory for ReloadableProviderFactory {
        fn create(
            &self,
            plugin_config: &PluginConfig,
            _registry: Arc<PluginRegistry>,
            _context: &crate::plugin::PluginCreateContext,
        ) -> DnsResult<UninitializedPlugin> {
            Ok(UninitializedPlugin::Provider(Box::new(
                ReloadableProvider {
                    tag: plugin_config.tag.clone(),
                    reload_count: self.reload_count.clone(),
                },
            )))
        }
    }

    #[tokio::test]
    async fn provider_reload_api_calls_targeted_reload() -> DnsResult<()> {
        let listen = reserve_local_addr();
        let hub = ApiHub::from_config(&ApiConfig {
            http: Some(ApiHttpConfig::Listen(listen.to_string())),
        })?
        .expect("api hub should be created");
        let reload_count = Arc::new(AtomicUsize::new(0));

        let mut registry = PluginRegistry::with_api(Some(ApiRegister::new(hub.clone())));
        registry.register_factory("qname", DependencyKind::Matcher, Box::new(QnameFactory {}));
        registry.register_factory(
            "reloadable_provider",
            DependencyKind::Provider,
            Box::new(ReloadableProviderFactory {
                reload_count: reload_count.clone(),
            }),
        );
        let registry = Arc::new(registry);

        let configs = vec![
            PluginConfig {
                tag: "reloadable".to_string(),
                plugin_type: "reloadable_provider".to_string(),
                args: None,
            },
            PluginConfig {
                tag: "match_qname".to_string(),
                plugin_type: "qname".to_string(),
                args: Some(serde_yaml_ng::from_str("- \"$reloadable\"").unwrap()),
            },
        ];

        registry
            .clone()
            .init_plugins(configs)
            .await
            .expect("plugin init should succeed");
        hub.start().await.expect("api hub should start");

        let client: Client<HttpConnector, Empty<bytes::Bytes>> =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());
        let uri: Uri = format!("http://{listen}/plugins/reloadable/reload")
            .parse()
            .expect("uri should parse");
        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Empty::new())
            .expect("request should build");
        let response = client
            .request(request)
            .await
            .expect("request should succeed");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body should collect")
            .to_bytes();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(reload_count.load(Ordering::Relaxed), 1);
        let payload = serde_json::from_slice::<serde_json::Value>(&body)
            .expect("response should be valid json");
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["action"], "reload_provider");
        assert_eq!(payload["provider"], "reloadable");

        hub.stop().await;
        registry.destory().await;
        Ok(())
    }
}
