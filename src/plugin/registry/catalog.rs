// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Process-wide plugin factory catalog backed by inventory registrations.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::core::error::{DnsError, Result};
use crate::plugin::dependency::DependencyKind;
use crate::plugin::{FactoryRegistration, PluginFactory, dependency_kind_from_module_path};

/// Process-wide immutable catalog of plugin factories.
#[derive(Debug)]
pub struct PluginCatalog {
    entries: HashMap<String, PluginCatalogEntry>,
}

#[derive(Debug, Clone, Copy)]
struct PluginCatalogEntry {
    kind: DependencyKind,
    constructor: fn() -> Box<dyn PluginFactory>,
}

impl PluginCatalog {
    fn from_inventory() -> Result<Self> {
        let mut entries = HashMap::new();
        let mut seen_plugin_types = HashSet::new();

        for registration in inventory::iter::<FactoryRegistration> {
            if !seen_plugin_types.insert(registration.plugin_type) {
                return Err(DnsError::plugin(format!(
                    "Duplicate plugin type '{}' registered in inventory",
                    registration.plugin_type
                )));
            }
            entries.insert(
                registration.plugin_type.to_string(),
                PluginCatalogEntry {
                    kind: dependency_kind_from_module_path(registration.module_path),
                    constructor: registration.constructor,
                },
            );
        }

        Ok(Self { entries })
    }

    pub fn factory(&self, plugin_type: &str) -> Option<Box<dyn PluginFactory>> {
        self.entries
            .get(plugin_type)
            .map(|entry| (entry.constructor)())
    }

    pub(super) fn iter_factories(
        &self,
    ) -> impl Iterator<Item = (&str, DependencyKind, Box<dyn PluginFactory>)> + '_ {
        self.entries
            .iter()
            .map(|(plugin_type, entry)| (plugin_type.as_str(), entry.kind, (entry.constructor)()))
    }
}

static GLOBAL_CATALOG: OnceLock<std::result::Result<PluginCatalog, String>> = OnceLock::new();

pub fn try_global_catalog() -> Result<&'static PluginCatalog> {
    match GLOBAL_CATALOG
        .get_or_init(|| PluginCatalog::from_inventory().map_err(|err| err.to_string()))
    {
        Ok(catalog) => Ok(catalog),
        Err(message) => Err(DnsError::plugin(format!(
            "plugin catalog inventory is invalid: {message}"
        ))),
    }
}

pub fn global_catalog() -> &'static PluginCatalog {
    try_global_catalog().expect("plugin catalog inventory should be valid")
}
