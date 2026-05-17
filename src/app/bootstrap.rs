// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Application assembly helpers for wiring API and plugin runtime components.

use std::sync::Arc;

use crate::api::control::AppController;
use crate::api::{self, ApiHub, ApiRegister, clear_global_api_register, set_global_api_register};
use crate::config::types::Config;
use crate::core::error::Result;
use crate::plugin::{self, PluginRegistry};

#[derive(Debug)]
pub struct AppAssembly {
    pub api_hub: Option<Arc<ApiHub>>,
    pub registry: Arc<PluginRegistry>,
}

pub async fn assemble(
    config: &Config,
    controller: Option<Arc<AppController>>,
) -> Result<AppAssembly> {
    let api_hub = ApiHub::from_config(&config.api)?;
    if let Some(api_hub) = &api_hub {
        api::register_builtin_routes(api_hub)?;
        if let Some(controller) = &controller {
            api::register_control_routes(api_hub, controller.clone())?;
        }
    }

    set_global_api_register(api_hub.as_ref().map(|hub| ApiRegister::new(hub.clone())));
    let registry = match plugin::init(config.clone()).await {
        Ok(registry) => registry,
        Err(err) => {
            clear_global_api_register();
            return Err(err);
        }
    };
    if let Some(controller) = controller {
        registry.set_controller(controller);
    }

    if let Some(api_hub) = &api_hub {
        api_hub.mark_plugins_initialized(registry.plugin_count(), registry.server_plugin_count());
        if let Err(err) = api_hub.start().await {
            registry.destory().await;
            clear_global_api_register();
            return Err(err);
        }
    }

    Ok(AppAssembly { api_hub, registry })
}

pub async fn stop(assembly: &AppAssembly) {
    clear_global_api_register();
    if let Some(api_hub) = &assembly.api_hub {
        api_hub.stop().await;
    }
    assembly.registry.destory().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        ApiHub, ApiRegister, global_api_register, global_api_test_guard, set_global_api_register,
    };
    use crate::config::types::{ApiConfig, ApiHttpConfig, LogConfig, RuntimeConfig};
    use crate::core::app_clock::AppClock;

    #[tokio::test]
    async fn assemble_without_api_config_does_not_register_api() {
        let _guard = global_api_test_guard().await;
        AppClock::start();
        let stale_hub = ApiHub::from_config(&ApiConfig {
            http: Some(ApiHttpConfig::Listen("127.0.0.1:0".to_string())),
        })
        .expect("stale api config should parse")
        .expect("stale api hub should exist");
        set_global_api_register(Some(ApiRegister::new(stale_hub)));

        let assembly = assemble(
            &Config {
                include: Vec::new(),
                runtime: RuntimeConfig::default(),
                api: ApiConfig::default(),
                log: LogConfig::default(),
                plugins: Vec::new(),
            },
            None,
        )
        .await
        .expect("empty config should assemble");

        assert!(assembly.api_hub.is_none());
        assert!(global_api_register().is_none());

        stop(&assembly).await;
    }
}
