use std::collections::{HashMap, HashSet};

use crate::plugin::dependency::{
    DependencyGraphEdge, DependencyGraphNode, DependencyGraphReport, DependencyKind,
    SequenceFlowExpression, SequenceFlowExpressionKind, SequenceFlowReport,
};

pub(crate) fn render_dependency_graph(report: &DependencyGraphReport) -> String {
    let mut lines = vec!["Plugin dependency graph:".to_string()];
    let node_map = report
        .nodes
        .iter()
        .map(|node| (node.tag.as_str(), node))
        .collect::<HashMap<_, _>>();
    let flow_map = report
        .sequence_flows
        .iter()
        .map(|flow| (flow.tag.as_str(), flow))
        .collect::<HashMap<_, _>>();
    let init_index = report
        .init_order
        .iter()
        .enumerate()
        .map(|(idx, tag)| (tag.as_str(), idx))
        .collect::<HashMap<_, _>>();
    let mut dependency_map: HashMap<&str, Vec<_>> = HashMap::new();
    let mut referenced = HashSet::new();

    for edge in &report.edges {
        dependency_map
            .entry(edge.source_tag.as_str())
            .or_default()
            .push(edge);
        referenced.insert(edge.target_tag.as_str());
    }

    for deps in dependency_map.values_mut() {
        deps.sort_by(|a, b| {
            a.field
                .cmp(&b.field)
                .then_with(|| {
                    init_index
                        .get(a.target_tag.as_str())
                        .cmp(&init_index.get(b.target_tag.as_str()))
                })
                .then_with(|| a.target_tag.cmp(&b.target_tag))
        });
    }

    let mut roots = report
        .init_order
        .iter()
        .filter(|tag| !referenced.contains(tag.as_str()))
        .collect::<Vec<_>>();
    roots.sort_by(|a, b| {
        init_index
            .get(a.as_str())
            .cmp(&init_index.get(b.as_str()))
            .then_with(|| a.cmp(b))
    });

    for (idx, root) in roots.iter().enumerate() {
        if idx > 0 {
            lines.push(String::new());
        }
        let mut path = HashSet::new();
        render_dependency_tree(
            root,
            "",
            true,
            &node_map,
            &dependency_map,
            &flow_map,
            &mut path,
            &mut lines,
        );
    }
    lines.join("\n")
}

#[allow(clippy::too_many_arguments)]
fn render_dependency_tree<'a>(
    tag: &'a str,
    prefix: &str,
    is_last: bool,
    node_map: &HashMap<&'a str, &'a DependencyGraphNode>,
    dependency_map: &HashMap<&'a str, Vec<&'a DependencyGraphEdge>>,
    flow_map: &HashMap<&'a str, &'a SequenceFlowReport>,
    path: &mut HashSet<&'a str>,
    lines: &mut Vec<String>,
) {
    let Some(node) = node_map.get(tag) else {
        return;
    };

    let branch = if prefix.is_empty() {
        ""
    } else if is_last {
        "└─ "
    } else {
        "├─ "
    };
    lines.push(format!(
        "{}{}{} [{}:{}]",
        prefix,
        branch,
        node.tag,
        kind_label(node.kind),
        node.plugin_type
    ));

    if !path.insert(tag) {
        lines.push(format!("{prefix}   (already shown)"));
        return;
    }

    let child_prefix = if prefix.is_empty() {
        String::new()
    } else if is_last {
        format!("{prefix}   ")
    } else {
        format!("{prefix}│  ")
    };

    if let Some(flow) = flow_map.get(tag) {
        render_sequence_flow(
            flow,
            &child_prefix,
            node_map,
            dependency_map,
            flow_map,
            path,
            lines,
        );
        path.remove(tag);
        return;
    }

    let Some(deps) = dependency_map.get(tag) else {
        return;
    };

    for (idx, dep) in deps.iter().enumerate() {
        let last_dep = idx + 1 == deps.len();
        let edge_branch = if last_dep { "└─ " } else { "├─ " };
        let edge_label = match dep.expected_plugin_type.as_deref() {
            Some(expected_type) => format!(
                "{}{}{} [{}:{}]",
                child_prefix,
                edge_branch,
                dep.field,
                kind_label(dep.expected_kind),
                expected_type
            ),
            None => format!(
                "{}{}{} [{}]",
                child_prefix,
                edge_branch,
                dep.field,
                kind_label(dep.expected_kind)
            ),
        };
        lines.push(edge_label);

        let next_prefix = if last_dep {
            format!("{child_prefix}   ")
        } else {
            format!("{child_prefix}│  ")
        };
        render_dependency_tree(
            dep.target_tag.as_str(),
            &next_prefix,
            true,
            node_map,
            dependency_map,
            flow_map,
            path,
            lines,
        );
    }
    path.remove(tag);
}

fn render_sequence_flow<'a>(
    flow: &'a SequenceFlowReport,
    prefix: &str,
    node_map: &HashMap<&'a str, &'a DependencyGraphNode>,
    dependency_map: &HashMap<&'a str, Vec<&'a DependencyGraphEdge>>,
    flow_map: &HashMap<&'a str, &'a SequenceFlowReport>,
    path: &mut HashSet<&'a str>,
    lines: &mut Vec<String>,
) {
    if flow.rules.is_empty() {
        lines.push(format!("{prefix}(empty sequence)"));
        return;
    }

    lines.push(format!("{prefix}sequence:"));
    for (idx, rule) in flow.rules.iter().enumerate() {
        if idx > 0 {
            lines.push(format!("{prefix}   else continue"));
        }
        let matches = if rule.matches.is_empty() {
            "always".to_string()
        } else {
            rule.matches
                .iter()
                .map(render_sequence_expression)
                .collect::<Vec<_>>()
                .join(" AND ")
        };
        let exec = rule
            .exec
            .as_ref()
            .map(render_sequence_expression)
            .unwrap_or_else(|| "<no exec>".to_string());
        lines.push(format!("{prefix}  #{} IF {matches}", rule.index));
        if rule.matches.is_empty() {
            lines.push(format!("{prefix}     deps: none"));
        } else {
            for expression in &rule.matches {
                render_sequence_expression_dependencies(
                    expression,
                    flow.tag.as_str(),
                    node_map,
                    dependency_map,
                    flow_map,
                    path,
                    lines,
                    &format!("{prefix}     "),
                );
            }
        }
        lines.push(format!("{prefix}     THEN {exec}"));
        if let Some(exec) = &rule.exec {
            render_sequence_expression_dependencies(
                exec,
                flow.tag.as_str(),
                node_map,
                dependency_map,
                flow_map,
                path,
                lines,
                &format!("{prefix}       "),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_sequence_expression_dependencies<'a>(
    expression: &'a SequenceFlowExpression,
    source_tag: &'a str,
    node_map: &HashMap<&'a str, &'a DependencyGraphNode>,
    dependency_map: &HashMap<&'a str, Vec<&'a DependencyGraphEdge>>,
    flow_map: &HashMap<&'a str, &'a SequenceFlowReport>,
    path: &mut HashSet<&'a str>,
    lines: &mut Vec<String>,
    prefix: &str,
) {
    match expression.kind {
        SequenceFlowExpressionKind::Plugin => {
            let Some(target_tag) = expression.target_tag.as_deref() else {
                return;
            };
            render_dependency_tree(
                target_tag,
                prefix,
                true,
                node_map,
                dependency_map,
                flow_map,
                path,
                lines,
            );
        }
        SequenceFlowExpressionKind::Builtin => {
            let Some(target_tag) = expression.target_tag.as_deref() else {
                return;
            };
            render_dependency_tree(
                target_tag,
                prefix,
                true,
                node_map,
                dependency_map,
                flow_map,
                path,
                lines,
            );
        }
        SequenceFlowExpressionKind::QuickSetup => {
            let deps = dependency_map
                .get(source_tag)
                .into_iter()
                .flat_map(|deps| deps.iter())
                .filter(|edge| edge.field.starts_with(&format!("{} ->", expression.field)))
                .collect::<Vec<_>>();
            if deps.is_empty() {
                return;
            }
            lines.push(format!("{prefix}deps:"));
            for dep in deps {
                render_dependency_tree(
                    dep.target_tag.as_str(),
                    &format!("{prefix}  "),
                    true,
                    node_map,
                    dependency_map,
                    flow_map,
                    path,
                    lines,
                );
            }
        }
        SequenceFlowExpressionKind::Invalid => {}
    }
}

fn render_sequence_expression(expression: &SequenceFlowExpression) -> String {
    let not = if expression.inverted { "NOT " } else { "" };
    match expression.kind {
        SequenceFlowExpressionKind::Plugin => {
            let target = expression
                .target_tag
                .as_deref()
                .unwrap_or(expression.raw.as_str());
            format!("{not}${target} [{}]", expression.field)
        }
        SequenceFlowExpressionKind::QuickSetup => {
            let plugin_type = expression.plugin_type.as_deref().unwrap_or("quick_setup");
            let param = expression
                .param
                .as_deref()
                .filter(|param| !param.trim().is_empty())
                .map(|param| format!(" {param}"))
                .unwrap_or_default();
            format!(
                "{not}quick_setup({plugin_type}){param} [{}]",
                expression.field
            )
        }
        SequenceFlowExpressionKind::Builtin => {
            let builtin = expression
                .builtin
                .as_deref()
                .unwrap_or(expression.raw.as_str());
            let param = expression
                .param
                .as_deref()
                .filter(|param| !param.trim().is_empty())
                .map(|param| format!(" {param}"))
                .unwrap_or_default();
            format!("{builtin}{param} [{}]", expression.field)
        }
        SequenceFlowExpressionKind::Invalid => {
            format!("invalid '{}' [{}]", expression.raw, expression.field)
        }
    }
}

fn kind_label(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Any => "any",
        DependencyKind::Server => "server",
        DependencyKind::Executor => "executor",
        DependencyKind::Matcher => "matcher",
        DependencyKind::Provider => "provider",
        DependencyKind::Unknown => "unknown",
    }
}
