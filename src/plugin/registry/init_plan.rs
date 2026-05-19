// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runtime initialization planning derived from dependency analysis.

use std::collections::{HashMap, HashSet};

use crate::plugin::dependency::{DependencyGraphEdge, DependencyGraphReport, DependencyKind};
use crate::plugin::{PluginCreateContext, PluginDependent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RuntimeInitPlan {
    pub(super) report: DependencyGraphReport,
    pub(super) skipped_providers: Vec<SkippedProvider>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SkippedProvider {
    pub(super) tag: String,
    pub(super) plugin_type: String,
}

pub(super) fn build_runtime_init_plan(report: &DependencyGraphReport) -> RuntimeInitPlan {
    let mut edges_by_source: HashMap<&str, Vec<&DependencyGraphEdge>> = HashMap::new();
    for edge in &report.edges {
        edges_by_source
            .entry(edge.source_tag.as_str())
            .or_default()
            .push(edge);
    }

    let mut live_tags = HashSet::new();
    let mut stack = Vec::new();

    for node in &report.nodes {
        if node.kind != DependencyKind::Provider && live_tags.insert(node.tag.clone()) {
            stack.push(node.tag.clone());
        }
    }

    while let Some(tag) = stack.pop() {
        if let Some(edges) = edges_by_source.get(tag.as_str()) {
            for edge in edges {
                if live_tags.insert(edge.target_tag.clone()) {
                    stack.push(edge.target_tag.clone());
                }
            }
        }
    }

    let mut skipped_providers = report
        .nodes
        .iter()
        .filter(|node| node.kind == DependencyKind::Provider && !live_tags.contains(&node.tag))
        .map(|node| SkippedProvider {
            tag: node.tag.clone(),
            plugin_type: node.plugin_type.clone(),
        })
        .collect::<Vec<_>>();
    skipped_providers.sort_by(|a, b| {
        a.tag
            .cmp(&b.tag)
            .then_with(|| a.plugin_type.cmp(&b.plugin_type))
    });

    RuntimeInitPlan {
        report: DependencyGraphReport {
            nodes: report
                .nodes
                .iter()
                .filter(|node| live_tags.contains(&node.tag))
                .cloned()
                .collect(),
            edges: report
                .edges
                .iter()
                .filter(|edge| {
                    live_tags.contains(&edge.source_tag) && live_tags.contains(&edge.target_tag)
                })
                .cloned()
                .collect(),
            init_order: report
                .init_order
                .iter()
                .filter(|tag| live_tags.contains(*tag))
                .cloned()
                .collect(),
            sequence_flows: report
                .sequence_flows
                .iter()
                .filter(|flow| live_tags.contains(&flow.tag))
                .cloned()
                .collect(),
        },
        skipped_providers,
    }
}

pub(super) fn build_create_contexts(
    report: &DependencyGraphReport,
) -> HashMap<String, PluginCreateContext> {
    let node_map = report
        .nodes
        .iter()
        .map(|node| (node.tag.as_str(), node))
        .collect::<HashMap<_, _>>();
    let mut dependents_by_target: HashMap<String, Vec<PluginDependent>> = HashMap::new();

    for edge in &report.edges {
        let Some(source_node) = node_map.get(edge.source_tag.as_str()) else {
            continue;
        };
        dependents_by_target
            .entry(edge.target_tag.clone())
            .or_default()
            .push(PluginDependent {
                tag: edge.source_tag.clone(),
                plugin_type: source_node.plugin_type.clone(),
                kind: source_node.kind,
                field: edge.field.clone(),
            });
    }

    dependents_by_target
        .into_iter()
        .map(|(tag, mut dependents)| {
            dependents.sort_by(|a, b| {
                a.tag
                    .cmp(&b.tag)
                    .then_with(|| a.field.cmp(&b.field))
                    .then_with(|| a.plugin_type.cmp(&b.plugin_type))
            });
            (tag, PluginCreateContext { dependents })
        })
        .collect()
}
