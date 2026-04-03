/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! CLI support for exporting selected rules from v2ray-rules-dat files.

use crate::app::cli::{DatKind, ExportDatOptions, ExportFormat};
use crate::core::error::{DnsError, Result};
use crate::plugin::provider::v2ray_dat::{
    GeoIpList, GeoSiteList, ParsedDat, cidr_to_rule, detect_dat_kind, geoip_code, geosite_code,
    geosite_domain_expression, geosite_domain_expression_original_with_attrs,
    geosite_domain_matches_selectors, matched_geosite_selectors, normalized_selectors,
    parse_geoip_dat, parse_geosite_dat, parse_geosite_selectors, unique_nonempty_selectors,
};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(options: ExportDatOptions) -> Result<()> {
    let selectors = unique_nonempty_selectors(&options.selectors);
    let merged_file = options
        .merged_file
        .as_deref()
        .map(validate_output_file_name)
        .transpose()?;
    let data = fs::read(&options.file).map_err(|err| {
        DnsError::runtime(format!(
            "failed to read dat file '{}': {}",
            options.file.display(),
            err
        ))
    })?;

    let export_plan = build_export_plan(&data, options.kind, options.format, &selectors)?;
    let output_files =
        write_output_content(&options.out_dir, &export_plan, merged_file.as_deref())?;
    validate_output_targets(&output_files, options.overwrite)?;
    fs::create_dir_all(&options.out_dir).map_err(|err| {
        DnsError::runtime(format!(
            "failed to create output directory '{}': {}",
            options.out_dir.display(),
            err
        ))
    })?;

    for (path, content) in output_files {
        write_output_file(&path, &content)?;
    }
    Ok(())
}

fn build_export_plan(
    data: &[u8],
    kind: DatKind,
    format: ExportFormat,
    selectors: &[String],
) -> Result<ExportPlan> {
    match kind {
        DatKind::Auto => match detect_dat_kind(data).map_err(DnsError::config)? {
            ParsedDat::GeoSite(list) => export_geosite(selectors, format, &list),
            ParsedDat::GeoIp(list) => export_geoip(selectors, format, &list),
        },
        DatKind::Geosite => export_geosite(
            selectors,
            format,
            &parse_geosite_dat(data).map_err(|e| {
                DnsError::config(format!("failed to decode geosite dat payload: {}", e))
            })?,
        ),
        DatKind::Geoip => export_geoip(
            selectors,
            format,
            &parse_geoip_dat(data).map_err(|e| {
                DnsError::config(format!("failed to decode geoip dat payload: {}", e))
            })?,
        ),
    }
}

fn export_geosite(
    selectors: &[String],
    format: ExportFormat,
    geosite: &GeoSiteList,
) -> Result<ExportPlan> {
    if matches!(format, ExportFormat::Original) {
        return export_geosite_original(selectors, geosite);
    }

    if selectors.is_empty() {
        let mut merged = Vec::new();
        for entry in &geosite.entry {
            for domain in &entry.domain {
                let rule = geosite_domain_expression(domain).map_err(|e| {
                    DnsError::config(format!(
                        "geosite full export code '{}' {}",
                        geosite_code(entry),
                        e
                    ))
                })?;
                merged.push(rule);
            }
        }
        if merged.is_empty() {
            return Err(DnsError::config("geosite dat produced no exportable rules"));
        }
        merged.insert(0, "# selector: all".to_string());
        return Ok(ExportPlan {
            default_output_file: "geosite.txt".to_string(),
            per_selector: Vec::new(),
            merged,
        });
    }

    let parsed_selectors = parse_geosite_selectors(selectors)
        .map_err(|e| DnsError::config(format!("failed to parse geosite selectors: {}", e)))?;
    let mut per_selector = Vec::with_capacity(selectors.len());
    let mut merged = Vec::new();

    for (raw_selector, selector) in selectors.iter().zip(parsed_selectors.iter()) {
        let mut rules = Vec::new();
        for entry in &geosite.entry {
            let matched = matched_geosite_selectors(entry, std::slice::from_ref(selector));
            if matched.is_empty() {
                continue;
            }
            for domain in &entry.domain {
                if !geosite_domain_matches_selectors(domain, &matched) {
                    continue;
                }
                let rule = geosite_domain_expression(domain).map_err(|e| {
                    DnsError::config(format!(
                        "geosite selector '{}' code '{}' {}",
                        raw_selector,
                        geosite_code(entry),
                        e
                    ))
                })?;
                rules.push(rule);
            }
        }
        if rules.is_empty() {
            return Err(DnsError::config(format!(
                "selector '{}' matched no geosite rules",
                raw_selector
            )));
        }
        rules.insert(0, format!("# selector: {}", raw_selector));
        append_unique(&mut merged, &rules);
        per_selector.push(SelectorExport {
            selector: raw_selector.clone(),
            lines: rules,
        });
    }

    Ok(ExportPlan {
        default_output_file: "geosite.txt".to_string(),
        per_selector,
        merged,
    })
}

fn export_geosite_original(selectors: &[String], geosite: &GeoSiteList) -> Result<ExportPlan> {
    if selectors.is_empty() {
        let mut merged = Vec::new();
        for entry in &geosite.entry {
            append_original_section(
                &mut merged,
                geosite_code(entry),
                entry.domain.iter(),
                "geosite full export",
                geosite_code(entry),
            )?;
        }
        if merged.is_empty() {
            return Err(DnsError::config("geosite dat produced no exportable rules"));
        }
        return Ok(ExportPlan {
            default_output_file: "geosite.txt".to_string(),
            per_selector: Vec::new(),
            merged,
        });
    }

    let parsed_selectors = parse_geosite_selectors(selectors)
        .map_err(|e| DnsError::config(format!("failed to parse geosite selectors: {}", e)))?;
    let mut per_selector = Vec::with_capacity(selectors.len());
    let mut merged = Vec::new();

    for (raw_selector, selector) in selectors.iter().zip(parsed_selectors.iter()) {
        let mut section_lines = Vec::new();
        for entry in &geosite.entry {
            let matched = matched_geosite_selectors(entry, std::slice::from_ref(selector));
            if matched.is_empty() {
                continue;
            }
            let matched_domains: Vec<_> = entry
                .domain
                .iter()
                .filter(|domain| geosite_domain_matches_selectors(domain, &matched))
                .collect();
            if matched_domains.is_empty() {
                continue;
            }
            append_original_section(
                &mut section_lines,
                geosite_code(entry),
                matched_domains.into_iter(),
                "geosite selector export",
                geosite_code(entry),
            )?;
        }
        if section_lines.is_empty() {
            return Err(DnsError::config(format!(
                "selector '{}' matched no geosite rules",
                raw_selector
            )));
        }
        append_section_block(&mut merged, &section_lines);
        per_selector.push(SelectorExport {
            selector: raw_selector.clone(),
            lines: section_lines,
        });
    }

    Ok(ExportPlan {
        default_output_file: "geosite.txt".to_string(),
        per_selector,
        merged,
    })
}

fn append_original_section<'a>(
    target: &mut Vec<String>,
    header: &str,
    domains: impl Iterator<Item = &'a crate::plugin::provider::v2ray_dat::Domain>,
    error_context: &str,
    code: &str,
) -> Result<()> {
    let mut lines = Vec::new();
    for domain in domains {
        let line = geosite_domain_expression_original_with_attrs(domain)
            .map_err(|e| DnsError::config(format!("{} code '{}' {}", error_context, code, e)))?;
        lines.push(line);
    }
    if lines.is_empty() {
        return Ok(());
    }
    if !target.is_empty() {
        target.push(String::new());
    }
    target.push(format!("[{}]", header));
    target.extend(lines);
    Ok(())
}

fn append_section_block(target: &mut Vec<String>, section: &[String]) {
    if !target.is_empty() && !section.is_empty() {
        target.push(String::new());
    }
    target.extend(section.iter().cloned());
}

fn export_geoip(
    selectors: &[String],
    format: ExportFormat,
    geoip: &GeoIpList,
) -> Result<ExportPlan> {
    if matches!(format, ExportFormat::Original) {
        return export_geoip_original(selectors, geoip);
    }

    if selectors.is_empty() {
        let mut merged = Vec::new();
        for entry in &geoip.entry {
            for cidr in &entry.cidr {
                let rule = cidr_to_rule(cidr).ok_or_else(|| {
                    DnsError::config(format!(
                        "geoip full export code '{}' contains invalid CIDR bytes",
                        geoip_code(entry)
                    ))
                })?;
                merged.push(rule);
            }
        }
        if merged.is_empty() {
            return Err(DnsError::config("geoip dat produced no exportable rules"));
        }
        merged.insert(0, "# selector: all".to_string());
        return Ok(ExportPlan {
            default_output_file: "geoip.txt".to_string(),
            per_selector: Vec::new(),
            merged,
        });
    }

    let normalized = normalized_selectors(selectors);
    let mut per_selector = Vec::with_capacity(selectors.len());
    let mut merged = Vec::new();

    for (raw_selector, wanted) in selectors.iter().zip(normalized.iter()) {
        let mut rules = Vec::new();
        for entry in &geoip.entry {
            if geoip_code(entry).to_ascii_lowercase() != *wanted {
                continue;
            }
            for cidr in &entry.cidr {
                let rule = cidr_to_rule(cidr).ok_or_else(|| {
                    DnsError::config(format!(
                        "geoip selector '{}' code '{}' contains invalid CIDR bytes",
                        raw_selector,
                        geoip_code(entry)
                    ))
                })?;
                rules.push(rule);
            }
        }
        if rules.is_empty() {
            return Err(DnsError::config(format!(
                "selector '{}' matched no geoip rules",
                raw_selector
            )));
        }
        rules.insert(0, format!("# selector: {}", raw_selector));
        append_unique(&mut merged, &rules);
        per_selector.push(SelectorExport {
            selector: raw_selector.clone(),
            lines: rules,
        });
    }

    Ok(ExportPlan {
        default_output_file: "geoip.txt".to_string(),
        per_selector,
        merged,
    })
}

fn export_geoip_original(selectors: &[String], geoip: &GeoIpList) -> Result<ExportPlan> {
    if selectors.is_empty() {
        let mut merged = Vec::new();
        for entry in &geoip.entry {
            append_geoip_original_section(
                &mut merged,
                geoip_code(entry),
                entry.cidr.iter(),
                "geoip full export",
                geoip_code(entry),
            )?;
        }
        if merged.is_empty() {
            return Err(DnsError::config("geoip dat produced no exportable rules"));
        }
        return Ok(ExportPlan {
            default_output_file: "geoip.txt".to_string(),
            per_selector: Vec::new(),
            merged,
        });
    }

    let normalized = normalized_selectors(selectors);
    let mut per_selector = Vec::with_capacity(selectors.len());
    let mut merged = Vec::new();

    for (raw_selector, wanted) in selectors.iter().zip(normalized.iter()) {
        let mut section_lines = Vec::new();
        for entry in &geoip.entry {
            if geoip_code(entry).to_ascii_lowercase() != *wanted {
                continue;
            }
            append_geoip_original_section(
                &mut section_lines,
                geoip_code(entry),
                entry.cidr.iter(),
                "geoip selector export",
                geoip_code(entry),
            )?;
        }
        if section_lines.is_empty() {
            return Err(DnsError::config(format!(
                "selector '{}' matched no geoip rules",
                raw_selector
            )));
        }
        append_section_block(&mut merged, &section_lines);
        per_selector.push(SelectorExport {
            selector: raw_selector.clone(),
            lines: section_lines,
        });
    }

    Ok(ExportPlan {
        default_output_file: "geoip.txt".to_string(),
        per_selector,
        merged,
    })
}

fn append_geoip_original_section<'a>(
    target: &mut Vec<String>,
    header: &str,
    cidrs: impl Iterator<Item = &'a crate::plugin::provider::v2ray_dat::Cidr>,
    error_context: &str,
    code: &str,
) -> Result<()> {
    let mut lines = Vec::new();
    for cidr in cidrs {
        let line = cidr_to_rule(cidr).ok_or_else(|| {
            DnsError::config(format!(
                "{} code '{}' contains invalid CIDR bytes",
                error_context, code
            ))
        })?;
        lines.push(line);
    }
    if lines.is_empty() {
        return Ok(());
    }
    if !target.is_empty() {
        target.push(String::new());
    }
    target.push(format!("[{}]", header));
    target.extend(lines);
    Ok(())
}

fn validate_output_targets(outputs: &[(PathBuf, String)], overwrite: bool) -> Result<()> {
    if overwrite {
        return Ok(());
    }
    for (path, _) in outputs {
        if path.exists() {
            return Err(DnsError::runtime(format!(
                "output file '{}' already exists; pass --overwrite to replace it",
                path.display()
            )));
        }
    }
    Ok(())
}

fn write_output_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).map_err(|err| {
        DnsError::runtime(format!(
            "failed to write output file '{}': {}",
            path.display(),
            err
        ))
    })
}

fn validate_output_file_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(DnsError::config("--merged-file must not be empty"));
    }
    if Path::new(trimmed).components().count() != 1 {
        return Err(DnsError::config(
            "--merged-file must be a plain file name inside --out-dir",
        ));
    }
    Ok(trimmed.to_string())
}

fn sanitize_selector_filename(selector: &str) -> String {
    let mut name = String::with_capacity(selector.len());
    for ch in selector.trim().chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '!' | '@') {
            name.push(ch);
        } else {
            name.push('_');
        }
    }
    let trimmed = name.trim_matches(['.', ' ']).to_string();
    if trimmed.is_empty() || matches!(trimmed.as_str(), "." | "..") {
        "selector".to_string()
    } else {
        trimmed
    }
}

fn append_unique(target: &mut Vec<String>, source: &[String]) {
    let mut seen = HashSet::with_capacity(target.len() + source.len());
    for item in target.iter() {
        seen.insert(item.clone());
    }
    for item in source {
        if seen.insert(item.clone()) {
            target.push(item.clone());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectorExport {
    selector: String,
    lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportPlan {
    default_output_file: String,
    per_selector: Vec<SelectorExport>,
    merged: Vec<String>,
}

fn write_output_content(
    out_dir: &Path,
    plan: &ExportPlan,
    merged_file: Option<&str>,
) -> Result<Vec<(PathBuf, String)>> {
    let mut outputs =
        Vec::with_capacity(plan.per_selector.len() + usize::from(merged_file.is_some()));
    for export in &plan.per_selector {
        let filename = format!("{}.txt", sanitize_selector_filename(&export.selector));
        outputs.push((out_dir.join(filename), join_lines(&export.lines)));
    }
    if let Some(merged_target) = merged_file {
        if !plan.merged.is_empty() {
            outputs.push((out_dir.join(merged_target), join_lines(&plan.merged)));
        }
    } else if plan.per_selector.is_empty() && !plan.merged.is_empty() {
        outputs.push((
            out_dir.join(plan.default_output_file.as_str()),
            join_lines(&plan.merged),
        ));
    }
    validate_unique_output_paths(&outputs)?;
    Ok(outputs)
}

fn join_lines(lines: &[String]) -> String {
    let mut content = lines.join("\n");
    content.push('\n');
    content
}

fn validate_unique_output_paths(outputs: &[(PathBuf, String)]) -> Result<()> {
    let mut seen = HashSet::new();
    for (path, _) in outputs {
        let key = path.to_string_lossy().to_ascii_lowercase();
        if !seen.insert(key) {
            return Err(DnsError::config(format!(
                "output file collision detected for '{}'",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn test_rule_path(relative_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("testdata")
            .join("rules")
            .join(relative_name)
    }

    #[test]
    fn sanitize_selector_keeps_readable_name() {
        assert_eq!(
            sanitize_selector_filename("geolocation-!cn"),
            "geolocation-!cn"
        );
        assert_eq!(sanitize_selector_filename("master/card"), "master_card");
    }

    #[test]
    fn export_geosite_and_merged_files() {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        run(ExportDatOptions {
            file: test_rule_path("geosite.dat"),
            kind: DatKind::Geosite,
            format: ExportFormat::Forgedns,
            selectors: vec!["cn".to_string(), "mastercard@cn".to_string()],
            out_dir: temp_dir.path().to_path_buf(),
            merged_file: Some("merged.txt".to_string()),
            overwrite: false,
        })
        .expect("export should succeed");

        let cn =
            fs::read_to_string(temp_dir.path().join("cn.txt")).expect("cn output should exist");
        let attr = fs::read_to_string(temp_dir.path().join("mastercard@cn.txt"))
            .expect("attribute output should exist");
        let merged = fs::read_to_string(temp_dir.path().join("merged.txt"))
            .expect("merged output should exist");

        assert!(cn.contains("full:265.com"));
        assert!(!attr.trim().is_empty());
        assert!(attr.lines().all(|line| merged.contains(line)));
    }

    #[test]
    fn export_geoip_selector() {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        run(ExportDatOptions {
            file: test_rule_path("geoip.dat"),
            kind: DatKind::Geoip,
            format: ExportFormat::Forgedns,
            selectors: vec!["cn".to_string()],
            out_dir: temp_dir.path().to_path_buf(),
            merged_file: None,
            overwrite: false,
        })
        .expect("export should succeed");

        let cn =
            fs::read_to_string(temp_dir.path().join("cn.txt")).expect("cn output should exist");
        let first_line = cn.lines().next().expect("content should not be empty");
        assert_eq!(first_line, "# selector: cn");
        assert!(cn.contains("1.0.1.0/24"));
    }

    #[test]
    fn export_geosite_without_selector_writes_full_union_file() {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        run(ExportDatOptions {
            file: test_rule_path("geosite.dat"),
            kind: DatKind::Geosite,
            format: ExportFormat::Forgedns,
            selectors: Vec::new(),
            out_dir: temp_dir.path().to_path_buf(),
            merged_file: None,
            overwrite: false,
        })
        .expect("export should succeed");

        let all = fs::read_to_string(temp_dir.path().join("geosite.txt"))
            .expect("full export output should exist");
        assert!(all.contains("full:265.com"));
        assert!(all.contains("full:a.ppy.sh"));
    }

    #[test]
    fn export_geoip_without_selector_writes_full_union_file() {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        run(ExportDatOptions {
            file: test_rule_path("geoip.dat"),
            kind: DatKind::Geoip,
            format: ExportFormat::Forgedns,
            selectors: Vec::new(),
            out_dir: temp_dir.path().to_path_buf(),
            merged_file: None,
            overwrite: false,
        })
        .expect("export should succeed");

        let all = fs::read_to_string(temp_dir.path().join("geoip.txt"))
            .expect("full export output should exist");
        let first_line = all.lines().next().expect("content should not be empty");
        assert_eq!(first_line, "# selector: all");
        assert!(all.contains("1.0.1.0/24"));
        assert!(all.contains("8.8.8.0/24"));
    }

    #[test]
    fn export_fails_when_output_exists_without_overwrite() {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        fs::write(temp_dir.path().join("cn.txt"), "old\n").expect("file should be created");

        let err = run(ExportDatOptions {
            file: test_rule_path("geosite.dat"),
            kind: DatKind::Geosite,
            format: ExportFormat::Forgedns,
            selectors: vec!["cn".to_string()],
            out_dir: temp_dir.path().to_path_buf(),
            merged_file: None,
            overwrite: false,
        })
        .expect_err("export should fail");

        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn export_geosite_original_format_uses_v2ray_type_names() {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        run(ExportDatOptions {
            file: test_rule_path("geosite.dat"),
            kind: DatKind::Geosite,
            format: ExportFormat::Original,
            selectors: vec!["cn".to_string()],
            out_dir: temp_dir.path().to_path_buf(),
            merged_file: None,
            overwrite: false,
        })
        .expect("export should succeed");

        let cn =
            fs::read_to_string(temp_dir.path().join("cn.txt")).expect("cn output should exist");
        let first_line = cn.lines().next().expect("content should not be empty");
        assert!(first_line.starts_with('[') && first_line.ends_with(']'));
        assert!(cn.contains("full:265.com"));
        assert!(!cn.contains("keyword:"));
    }

    #[test]
    fn export_geosite_original_format_groups_by_code_and_keeps_attrs() {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        run(ExportDatOptions {
            file: test_rule_path("geosite.dat"),
            kind: DatKind::Geosite,
            format: ExportFormat::Original,
            selectors: vec!["mastercard@cn".to_string()],
            out_dir: temp_dir.path().to_path_buf(),
            merged_file: None,
            overwrite: false,
        })
        .expect("export should succeed");

        let content = fs::read_to_string(temp_dir.path().join("mastercard@cn.txt"))
            .expect("attribute output should exist");
        let first_line = content.lines().next().expect("content should not be empty");
        assert!(first_line.starts_with('[') && first_line.ends_with(']'));
        assert!(content.contains("mastercard.cn"));
        assert!(content.contains("@cn"));
    }

    #[test]
    fn export_geoip_original_format_groups_by_code() {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        run(ExportDatOptions {
            file: test_rule_path("geoip.dat"),
            kind: DatKind::Geoip,
            format: ExportFormat::Original,
            selectors: vec!["cn".to_string()],
            out_dir: temp_dir.path().to_path_buf(),
            merged_file: None,
            overwrite: false,
        })
        .expect("export should succeed");

        let content =
            fs::read_to_string(temp_dir.path().join("cn.txt")).expect("cn output should exist");
        let first_line = content.lines().next().expect("content should not be empty");
        assert_eq!(first_line, "[CN]");
        assert!(content.contains("1.0.1.0/24"));
    }

    #[test]
    fn export_geoip_original_without_selector_groups_full_export_by_code() {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        run(ExportDatOptions {
            file: test_rule_path("geoip.dat"),
            kind: DatKind::Geoip,
            format: ExportFormat::Original,
            selectors: Vec::new(),
            out_dir: temp_dir.path().to_path_buf(),
            merged_file: None,
            overwrite: false,
        })
        .expect("export should succeed");

        let content = fs::read_to_string(temp_dir.path().join("geoip.txt"))
            .expect("full export output should exist");
        assert!(content.contains("[CN]"));
        assert!(content.contains("[GOOGLE]"));
        assert!(content.contains("1.0.1.0/24"));
        assert!(content.contains("8.8.8.0/24"));
    }
}
