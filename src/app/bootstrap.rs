/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Application assembly helpers for wiring API and plugin runtime components.

use crate::api::control::{self, AppController};
use crate::api::{ApiHub, ApiRegister};
use crate::config::types::Config;
use crate::core::error::Result;
use crate::plugin::{self, PluginRegistry};
use std::sync::Arc;

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
    if let (Some(api_hub), Some(controller)) = (&api_hub, controller.as_ref()) {
        control::register_builtin_routes(&ApiRegister::new(api_hub.clone()), controller.clone())?;
    }

    let api_register = api_hub.as_ref().map(|hub| ApiRegister::new(hub.clone()));
    let registry = plugin::init(config.clone(), api_register).await?;
    if let Some(controller) = controller {
        registry.set_controller(controller);
    }

    if let Some(api_hub) = &api_hub {
        api_hub.mark_plugins_initialized(registry.plugin_count(), registry.server_plugin_count());
        if let Err(err) = api_hub.start().await {
            registry.destory().await;
            return Err(err);
        }
    }

    Ok(AppAssembly { api_hub, registry })
}

pub async fn stop(assembly: &AppAssembly) {
    if let Some(api_hub) = &assembly.api_hub {
        api_hub.stop().await;
    }
    assembly.registry.destory().await;
}
