/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Startup banner rendering and output helpers.

use crate::core::VERSION;
use crate::core::error::{DnsError, Result};
use std::io::{self, Write};

const STARTUP_BANNER_REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
const STARTUP_BANNER_MIN_INNER_WIDTH: usize = 67;
const STARTUP_BANNER_SIDE_PADDING: usize = 2;

pub(super) fn print_startup_banner() -> Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{}", render_startup_banner())
        .map_err(|err| DnsError::runtime(format!("Failed to write startup banner: {err}")))?;
    stdout
        .flush()
        .map_err(|err| DnsError::runtime(format!("Failed to flush startup banner: {err}")))
}

fn render_startup_banner() -> String {
    let art_lines = [
        " ███████████                                      ██████████   ██████   █████  █████████ ",
        "▒▒███▒▒▒▒▒▒                                      ▒▒███▒▒▒▒███ ▒▒██████ ▒▒███  ███▒▒▒▒▒███",
        " ▒███         ██████  ████████   ███████  ██████  ▒███   ▒▒███ ▒███▒███ ▒███ ▒███    ▒▒▒ ",
        " ▒███████    ███▒▒███▒▒███▒▒███ ███▒▒███ ███▒▒███ ▒███    ▒███ ▒███▒▒███▒███ ▒▒█████████ ",
        " ▒███▒▒▒    ▒███ ▒███ ▒███ ▒▒▒ ▒███ ▒███▒███████  ▒███    ▒███ ▒███ ▒▒██████  ▒▒▒▒▒▒▒▒███",
        " ▒███       ▒███ ▒███ ▒███     ▒███ ▒███▒███▒▒▒   ▒███    ███  ▒███  ▒▒█████  ███    ▒███",
        " █████      ▒▒██████  █████    ▒▒███████▒▒██████  ██████████   █████  ▒▒█████▒▒█████████ ",
        "▒▒▒▒▒        ▒▒▒▒▒▒  ▒▒▒▒▒      ▒▒▒▒▒███ ▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒    ▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒  ",
        "                                ███ ▒███                                                 ",
        "                               ▒▒██████                                                  ",
        "                                ▒▒▒▒▒▒                                                   ",
    ];
    let art_width = art_lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    let version_line = format!("ForgeDNS v{VERSION}");
    let inner_width = [
        STARTUP_BANNER_MIN_INNER_WIDTH,
        art_width + STARTUP_BANNER_SIDE_PADDING * 2,
        version_line.chars().count() + STARTUP_BANNER_SIDE_PADDING * 2,
        STARTUP_BANNER_REPOSITORY.chars().count() + STARTUP_BANNER_SIDE_PADDING * 2,
    ]
    .into_iter()
    .max()
    .unwrap_or(STARTUP_BANNER_MIN_INNER_WIDTH);
    let mut lines = Vec::with_capacity(art_lines.len() + 5);
    lines.push(render_banner_line("", inner_width));
    for line in art_lines {
        lines.push(render_banner_block_line(line, art_width, inner_width));
    }
    lines.push(render_banner_line("", inner_width));
    lines.push(render_banner_line(&version_line, inner_width));
    lines.push(render_banner_line(STARTUP_BANNER_REPOSITORY, inner_width));
    lines.push(render_banner_line("", inner_width));

    let border = format!("+{}+", "=".repeat(inner_width));
    let mut banner = String::with_capacity(1024);
    banner.push_str(&border);
    banner.push('\n');
    for line in lines {
        banner.push_str(&line);
        banner.push('\n');
    }
    banner.push_str(&border);
    banner
}

fn render_banner_block_line(text: &str, content_width: usize, inner_width: usize) -> String {
    let padded = format!("{text:<content_width$}");
    render_banner_line(&padded, inner_width)
}

fn render_banner_line(text: &str, inner_width: usize) -> String {
    let visible_len = text.chars().count();
    let total_padding = inner_width.saturating_sub(visible_len);
    let left_padding = total_padding / 2;
    let right_padding = total_padding - left_padding;

    format!(
        "|{}{}{}|",
        " ".repeat(left_padding),
        text,
        " ".repeat(right_padding)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_banner_includes_branding_version_and_repository() {
        let banner = render_startup_banner();
        assert!(banner.contains("ForgeDNS"));
        assert!(banner.contains(VERSION));
        assert!(banner.contains(STARTUP_BANNER_REPOSITORY));
        assert!(!banner.contains("\x1b["));
    }

    #[test]
    fn startup_banner_expands_to_fit_logo_width() {
        let banner = render_startup_banner();
        let lines = banner.lines().collect::<Vec<_>>();
        let border = lines.first().expect("banner should have top border");
        let first_art_line = lines.get(2).expect("banner should include art lines");
        let inner_width = border.chars().count().saturating_sub(2);

        assert!(inner_width > STARTUP_BANNER_MIN_INNER_WIDTH);
        assert!(first_art_line.starts_with("|  "));
        assert!(first_art_line.ends_with("  |"));
    }
}
