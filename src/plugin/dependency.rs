/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Plugin dependency resolution
//!
//! Provides automatic dependency resolution for plugins using topological sorting.
//! This ensures plugins are initialized in the correct order, even if they are
//! declared in any order in the configuration file.

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use std::collections::{HashMap, VecDeque};

/// Resolve plugin dependencies and return plugins in initialization order
///
/// Uses Kahn's algorithm for topological sorting to detect the correct
/// initialization order and detect circular dependencies.
///
/// # Arguments
/// * `configs` - Vector of plugin configurations
/// * `get_deps` - Function to extract dependencies from a plugin configuration
///
/// # Returns
/// * `Ok(Vec<PluginConfig>)` - Plugins sorted in dependency order
/// * `Err(DnsError)` - Error message if circular dependency detected
pub fn resolve_dependencies(
    configs: Vec<PluginConfig>,
    get_deps: &dyn Fn(&PluginConfig) -> Vec<String>,
) -> Result<Vec<PluginConfig>> {
    // Build dependency graph (tag -> list of tags that depend on it)
    let mut reverse_graph: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_degree: HashMap<String, usize> = HashMap::new();

    // Initialize all plugin tags
    for config in &configs {
        in_degree.insert(config.tag.clone(), 0);
        reverse_graph
            .entry(config.tag.clone())
            .or_insert_with(Vec::new);
    }

    // Build the reverse dependency graph and calculate in-degrees
    for config in &configs {
        let deps = get_deps(config);

        // Set in-degree to number of dependencies
        *in_degree.get_mut(&config.tag).unwrap() = deps.len();

        // Add reverse edges: dependency -> who depends on it
        for dep in deps {
            reverse_graph
                .entry(dep.clone())
                .or_insert_with(Vec::new)
                .push(config.tag.clone());
        }
    }

    // Kahn's algorithm: start with nodes that have no dependencies (in-degree 0)
    let mut queue: VecDeque<String> = in_degree
        .iter()
        .filter(|&(_, deg)| *deg == 0)
        .map(|(tag, _)| tag.clone())
        .collect();

    let mut sorted = Vec::new();
    let config_map: HashMap<_, _> = configs.into_iter().map(|c| (c.tag.clone(), c)).collect();

    while let Some(tag) = queue.pop_front() {
        if let Some(config) = config_map.get(&tag) {
            sorted.push(config.clone());
        }

        // For each plugin that depends on this one, decrease its in-degree
        if let Some(dependents) = reverse_graph.get(&tag) {
            for dependent in dependents {
                if let Some(degree) = in_degree.get_mut(dependent) {
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(dependent.clone());
                    }
                }
            }
        }
    }

    // Check for circular dependencies
    if sorted.len() != config_map.len() {
        return Err(DnsError::dependency(
            "Circular dependency detected in plugin configuration",
        ));
    }

    Ok(sorted)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock dependency extraction function for tests
    fn mock_get_deps(config: &PluginConfig) -> Vec<String> {
        match config.plugin_type.as_str() {
            "udp_server" | "tcp_server" => {
                if let Some(args) = &config.args {
                    if let Some(entry) = args.get("entry") {
                        if let Some(entry_str) = entry.as_str() {
                            return vec![entry_str.to_string()];
                        }
                    }
                }
                vec![]
            }
            _ => vec![],
        }
    }

    #[test]
    fn test_resolve_simple_dependency() {
        let configs = vec![
            PluginConfig {
                tag: "server".to_string(),
                plugin_type: "udp_server".to_string(),
                args: Some(
                    serde_yml::to_value(
                        vec![("entry", "forward")]
                            .into_iter()
                            .collect::<std::collections::HashMap<_, _>>(),
                    )
                    .unwrap(),
                ),
            },
            PluginConfig {
                tag: "forward".to_string(),
                plugin_type: "forward".to_string(),
                args: None,
            },
        ];

        let sorted = resolve_dependencies(configs, &mock_get_deps).unwrap();
        assert_eq!(sorted[0].tag, "forward");
        assert_eq!(sorted[1].tag, "server");
    }

    #[test]
    fn test_no_dependencies() {
        let configs = vec![PluginConfig {
            tag: "forward".to_string(),
            plugin_type: "forward".to_string(),
            args: None,
        }];

        let sorted = resolve_dependencies(configs, &mock_get_deps).unwrap();
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].tag, "forward");
    }
}
