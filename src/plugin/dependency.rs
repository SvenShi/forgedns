/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Plugin dependency resolution
//!
//! Provides startup-time dependency graph validation and topological sorting.

use crate::config::types::PluginConfig;
use crate::core::error::{DnsError, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Display;

/// Expected dependency kind used during startup structural validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyKind {
    Any,
    Server,
    Executor,
    Matcher,
    Provider,
    Unknown,
}

impl Display for DependencyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DependencyKind::Any => write!(f, "any"),
            DependencyKind::Server => write!(f, "server"),
            DependencyKind::Executor => write!(f, "executor"),
            DependencyKind::Matcher => write!(f, "matcher"),
            DependencyKind::Provider => write!(f, "provider"),
            DependencyKind::Unknown => write!(f, "unknown"),
        }
    }
}

/// One dependency edge from a source plugin to a target plugin tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencySpec {
    /// Field path in source config that references target tag.
    pub field: String,
    /// Referenced plugin tag.
    pub target_tag: String,
    /// Expected runtime plugin kind.
    pub expected_kind: DependencyKind,
    /// Optional concrete plugin type name (e.g. "ip_set", "domain_set").
    pub expected_plugin_type: Option<String>,
}

impl DependencySpec {
    pub fn new(field: impl Into<String>, target_tag: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            target_tag: target_tag.into(),
            expected_kind: DependencyKind::Any,
            expected_plugin_type: None,
        }
    }

    pub fn with_kind(
        field: impl Into<String>,
        target_tag: impl Into<String>,
        expected_kind: DependencyKind,
    ) -> Self {
        Self {
            field: field.into(),
            target_tag: target_tag.into(),
            expected_kind,
            expected_plugin_type: None,
        }
    }

    pub fn executor(field: impl Into<String>, target_tag: impl Into<String>) -> Self {
        Self::with_kind(field, target_tag, DependencyKind::Executor)
    }

    pub fn executor_type(
        field: impl Into<String>,
        target_tag: impl Into<String>,
        expected_plugin_type: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            target_tag: target_tag.into(),
            expected_kind: DependencyKind::Executor,
            expected_plugin_type: Some(expected_plugin_type.into()),
        }
    }

    pub fn matcher(field: impl Into<String>, target_tag: impl Into<String>) -> Self {
        Self::with_kind(field, target_tag, DependencyKind::Matcher)
    }

    pub fn provider_type(
        field: impl Into<String>,
        target_tag: impl Into<String>,
        expected_plugin_type: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            target_tag: target_tag.into(),
            expected_kind: DependencyKind::Provider,
            expected_plugin_type: Some(expected_plugin_type.into()),
        }
    }

    pub fn provider(field: impl Into<String>, target_tag: impl Into<String>) -> Self {
        Self::with_kind(field, target_tag, DependencyKind::Provider)
    }
}

/// Resolve plugin dependencies and return plugins in initialization order.
///
/// The function validates missing nodes, self references, type mismatches, then
/// performs topological sorting. All checks are startup-only and never on hot path.
pub fn resolve_dependencies(
    configs: Vec<PluginConfig>,
    get_deps: &dyn Fn(&PluginConfig) -> Vec<DependencySpec>,
    get_kind: &dyn Fn(&PluginConfig) -> DependencyKind,
) -> Result<Vec<PluginConfig>> {
    // Build dependency graph (tag -> list of tags that depend on it)
    let mut reverse_graph: HashMap<String, Vec<String>> = HashMap::new();
    let mut forward_graph: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut config_map: HashMap<String, &PluginConfig> = HashMap::new();
    let mut errors = Vec::new();

    // Initialize all plugin tags
    for config in &configs {
        if config_map.insert(config.tag.clone(), config).is_some() {
            return Err(DnsError::dependency(format!(
                "Duplicate plugin tag '{}' in dependency graph",
                config.tag
            )));
        }
        in_degree.insert(config.tag.clone(), 0);
        reverse_graph.entry(config.tag.clone()).or_default();
        forward_graph.entry(config.tag.clone()).or_default();
    }

    // Build the reverse dependency graph and calculate in-degrees.
    for config in &configs {
        let deps = get_deps(config);
        let mut unique_deps = HashSet::new();

        for dep in deps {
            let dep_tag = dep.target_tag.trim();
            if dep_tag.is_empty() {
                continue;
            }

            let field = if dep.field.trim().is_empty() {
                "<unknown>"
            } else {
                dep.field.trim()
            };

            if dep_tag == config.tag {
                errors.push(format!(
                    "plugin '{}' field '{}' references itself",
                    config.tag, field
                ));
                continue;
            }

            let dep_config = match config_map.get(dep_tag) {
                Some(dep_config) => dep_config,
                None => {
                    errors.push(format!(
                        "plugin '{}' field '{}' references missing plugin '{}'",
                        config.tag, field, dep_tag
                    ));
                    continue;
                }
            };

            let actual_kind = get_kind(dep_config);
            if dep.expected_kind != DependencyKind::Any && dep.expected_kind != actual_kind {
                errors.push(format!(
                    "plugin '{}' field '{}' expects {} plugin, but '{}' is {} (type '{}')",
                    config.tag,
                    field,
                    dep.expected_kind,
                    dep_tag,
                    actual_kind,
                    dep_config.plugin_type
                ));
            }

            if let Some(expected_plugin_type) = dep.expected_plugin_type.as_deref()
                && dep_config.plugin_type != expected_plugin_type
            {
                errors.push(format!(
                    "plugin '{}' field '{}' expects plugin type '{}', but '{}' has type '{}'",
                    config.tag, field, expected_plugin_type, dep_tag, dep_config.plugin_type
                ));
            }

            unique_deps.insert(dep_tag.to_string());
        }

        // Set in-degree to number of dependencies.
        *in_degree.get_mut(&config.tag).unwrap() = unique_deps.len();
        if let Some(forward) = forward_graph.get_mut(&config.tag) {
            forward.extend(unique_deps.iter().cloned());
        }

        // Add reverse edges: dependency -> who depends on it.
        for dep in unique_deps {
            reverse_graph
                .entry(dep.clone())
                .or_default()
                .push(config.tag.clone());
        }
    }

    if !errors.is_empty() {
        return Err(DnsError::dependency(format!(
            "Invalid plugin dependencies:\n  - {}",
            errors.join("\n  - ")
        )));
    }

    // Kahn's algorithm: start with nodes that have no dependencies (in-degree 0).
    let queue_sorted = {
        let mut queue = in_degree
            .iter()
            .filter(|&(_, degree)| *degree == 0)
            .map(|(tag, _)| tag.clone())
            .collect::<Vec<_>>();
        queue.sort();
        queue
    };
    let mut queue: VecDeque<String> = queue_sorted.into();

    let mut sorted_tags = Vec::with_capacity(in_degree.len());
    let mut owned_configs: HashMap<_, _> =
        configs.into_iter().map(|c| (c.tag.clone(), c)).collect();

    while let Some(tag) = queue.pop_front() {
        sorted_tags.push(tag.clone());

        // For each plugin that depends on this one, decrease its in-degree.
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

    // Check for circular dependencies.
    if sorted_tags.len() != owned_configs.len() {
        let remaining: HashSet<String> = in_degree
            .iter()
            .filter_map(|(tag, degree)| if *degree > 0 { Some(tag.clone()) } else { None })
            .collect();

        if let Some(cycle) = find_cycle_path(&forward_graph, &remaining) {
            return Err(DnsError::dependency(format!(
                "Circular dependency detected: {}",
                cycle.join(" -> ")
            )));
        }

        let mut unresolved: Vec<String> = remaining.into_iter().collect();
        unresolved.sort();
        return Err(DnsError::dependency(format!(
            "Circular dependency detected among plugins: {}",
            unresolved.join(", ")
        )));
    }

    let mut sorted = Vec::with_capacity(sorted_tags.len());
    for tag in sorted_tags {
        if let Some(config) = owned_configs.remove(&tag) {
            sorted.push(config);
        }
    }

    Ok(sorted)
}

fn find_cycle_path(
    forward_graph: &HashMap<String, Vec<String>>,
    remaining: &HashSet<String>,
) -> Option<Vec<String>> {
    let mut marks: HashMap<String, u8> = HashMap::new();
    let mut stack: Vec<String> = Vec::new();

    fn dfs(
        node: &str,
        forward_graph: &HashMap<String, Vec<String>>,
        remaining: &HashSet<String>,
        marks: &mut HashMap<String, u8>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        marks.insert(node.to_string(), 1);
        stack.push(node.to_string());

        if let Some(next_nodes) = forward_graph.get(node) {
            for next in next_nodes {
                if !remaining.contains(next) {
                    continue;
                }

                match marks.get(next).copied() {
                    None => {
                        if let Some(cycle) = dfs(next, forward_graph, remaining, marks, stack) {
                            return Some(cycle);
                        }
                    }
                    Some(1) => {
                        if let Some(pos) = stack.iter().position(|tag| tag == next) {
                            let mut cycle = stack[pos..].to_vec();
                            cycle.push(next.clone());
                            return Some(cycle);
                        }
                    }
                    Some(_) => {}
                }
            }
        }

        stack.pop();
        marks.insert(node.to_string(), 2);
        None
    }

    let mut candidates: Vec<String> = remaining.iter().cloned().collect();
    candidates.sort();
    for node in candidates {
        if marks.contains_key(&node) {
            continue;
        }
        if let Some(cycle) = dfs(&node, forward_graph, remaining, &mut marks, &mut stack) {
            return Some(cycle);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock dependency extraction function for tests.
    fn mock_get_deps(config: &PluginConfig) -> Vec<DependencySpec> {
        match config.plugin_type.as_str() {
            "udp_server" | "tcp_server" => {
                if let Some(args) = &config.args
                    && let Some(entry) = args.get("entry")
                    && let Some(entry_str) = entry.as_str()
                {
                    return vec![DependencySpec::executor(
                        "args.entry",
                        entry_str.to_string(),
                    )];
                }
                vec![]
            }
            _ => vec![],
        }
    }

    fn mock_get_kind(config: &PluginConfig) -> DependencyKind {
        match config.plugin_type.as_str() {
            "udp_server" | "tcp_server" => DependencyKind::Server,
            "forward" => DependencyKind::Executor,
            "domain_set" | "ip_set" => DependencyKind::Provider,
            "qname" => DependencyKind::Matcher,
            _ => DependencyKind::Unknown,
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

        let sorted = resolve_dependencies(configs, &mock_get_deps, &mock_get_kind).unwrap();
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

        let sorted = resolve_dependencies(configs, &mock_get_deps, &mock_get_kind).unwrap();
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].tag, "forward");
    }

    #[test]
    fn test_reports_missing_dependency_with_field_context() {
        let configs = vec![PluginConfig {
            tag: "server".to_string(),
            plugin_type: "udp_server".to_string(),
            args: Some(
                serde_yml::to_value(
                    vec![("entry", "missing_exec")]
                        .into_iter()
                        .collect::<std::collections::HashMap<_, _>>(),
                )
                .unwrap(),
            ),
        }];

        let err = resolve_dependencies(configs, &mock_get_deps, &mock_get_kind).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("server"));
        assert!(msg.contains("args.entry"));
        assert!(msg.contains("missing_exec"));
    }

    #[test]
    fn test_reports_type_mismatch_with_field_context() {
        let configs = vec![
            PluginConfig {
                tag: "server".to_string(),
                plugin_type: "udp_server".to_string(),
                args: Some(
                    serde_yml::to_value(
                        vec![("entry", "set1")]
                            .into_iter()
                            .collect::<std::collections::HashMap<_, _>>(),
                    )
                    .unwrap(),
                ),
            },
            PluginConfig {
                tag: "set1".to_string(),
                plugin_type: "domain_set".to_string(),
                args: None,
            },
        ];

        let err = resolve_dependencies(configs, &mock_get_deps, &mock_get_kind).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("expects executor plugin"));
        assert!(msg.contains("args.entry"));
        assert!(msg.contains("domain_set"));
    }

    #[test]
    fn test_reports_cycle_path() {
        fn get_cycle_deps(config: &PluginConfig) -> Vec<DependencySpec> {
            if let Some(args) = &config.args
                && let Some(dep) = args.get("dep").and_then(|value| value.as_str())
            {
                return vec![DependencySpec::new("args.dep", dep.to_string())];
            }
            vec![]
        }

        let configs = vec![
            PluginConfig {
                tag: "a".to_string(),
                plugin_type: "forward".to_string(),
                args: Some(
                    serde_yml::to_value(
                        vec![("dep", "b")]
                            .into_iter()
                            .collect::<std::collections::HashMap<_, _>>(),
                    )
                    .unwrap(),
                ),
            },
            PluginConfig {
                tag: "b".to_string(),
                plugin_type: "forward".to_string(),
                args: Some(
                    serde_yml::to_value(
                        vec![("dep", "a")]
                            .into_iter()
                            .collect::<std::collections::HashMap<_, _>>(),
                    )
                    .unwrap(),
                ),
            },
        ];

        let err = resolve_dependencies(configs, &get_cycle_deps, &mock_get_kind).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Circular dependency detected"));
        assert!(msg.contains("a -> b -> a") || msg.contains("b -> a -> b"));
    }
}
