// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Application assembly helpers for wiring API and plugin runtime components.

use std::sync::Arc;

use crate::api::control::AppController;
use crate::api::{self, ApiHub, clear_global_api, install_global_api};
use crate::config::types::Config;
use crate::core::error::Result;
use crate::plugin;

#[derive(Debug)]
pub struct AppAssembly {
    pub api_hub: Option<Arc<ApiHub>>,
}

pub async fn assemble(
    config: &Config,
    controller: Option<Arc<AppController>>,
) -> Result<AppAssembly> {
    let api_hub = ApiHub::from_config(&config.api)?;
    if let Some(api_hub) = &api_hub {
        install_global_api(api_hub.clone());
        api::register_builtin_routes()?;
        if let Some(controller) = &controller {
            api::register_control_routes(controller.clone())?;
        }
    } else {
        clear_global_api();
    }

    if let Some(controller) = &controller {
        plugin::set_app_controller(controller.clone());
    } else {
        plugin::clear_app_controller();
    }

    let runtime = match plugin::init(config.clone()).await {
        Ok(runtime) => runtime,
        Err(err) => {
            clear_global_api();
            plugin::clear_app_controller();
            return Err(err);
        }
    };

    if let Some(api_hub) = &api_hub {
        api_hub.mark_plugins_initialized(runtime.plugin_count(), runtime.server_plugin_count());
        if let Err(err) = api_hub.start().await {
            plugin::destroy_runtime().await;
            clear_global_api();
            plugin::clear_app_controller();
            return Err(err);
        }
    }

    Ok(AppAssembly { api_hub })
}

pub async fn stop(assembly: &AppAssembly) {
    clear_global_api();
    if let Some(api_hub) = &assembly.api_hub {
        api_hub.stop().await;
    }
    plugin::destroy_runtime().await;
    plugin::clear_app_controller();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        ApiHub, ApiRegister, global_api_register, global_api_test_guard,
        set_global_api_register_for_test,
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
        set_global_api_register_for_test(Some(ApiRegister::new(stale_hub)));

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
