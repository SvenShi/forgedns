// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Heuristic location of config errors within YAML source text.
//!
//! The validation pipeline produces plain-text error messages. These helpers
//! extract a token from a message (e.g. an unknown plugin type name) and then
//! scan the YAML source for that token to return a 1-based (line, column,
//! end_column) triple. The result is intentionally approximate — it covers the
//! common cases without requiring a full YAML AST.

/// A located diagnostic for a config validation error.
#[derive(Debug)]
pub struct ConfigLocation {
    pub line: usize,
    pub column: usize,
    pub end_column: usize,
}

/// Try to locate the relevant token for `message` within `config_text`.
///
/// Returns `None` when no known pattern matches or the token cannot be found
/// in the source, which callers should treat as "no location available".
pub fn locate_in_config(config_text: &str, message: &str) -> Option<ConfigLocation> {
    let token = token_after(message, "Unknown plugin type: ")
        .or_else(|| quoted_after(message, "Unknown plugin type '"))
        .or_else(|| quoted_after(message, "Duplicate plugin tag '"))
        .or_else(|| quoted_after(message, "references missing plugin '"))
        .or_else(|| quoted_after(message, "but '"))
        .or_else(|| quoted_after(message, "plugin type '"))?;

    let (line, column, end_column) = locate_token(config_text, token)?;
    Some(ConfigLocation {
        line,
        column,
        end_column,
    })
}

fn quoted_after<'a>(message: &'a str, prefix: &str) -> Option<&'a str> {
    let start = message.find(prefix)? + prefix.len();
    let rest = &message[start..];
    let end = rest.find('\'')?;
    Some(&rest[..end])
}

fn token_after<'a>(message: &'a str, prefix: &str) -> Option<&'a str> {
    let start = message.find(prefix)? + prefix.len();
    let rest = &message[start..];
    rest.split_whitespace()
        .next()
        .map(|token| token.trim_matches(|ch| ch == '\'' || ch == '"' || ch == ',' || ch == '.'))
        .filter(|token| !token.is_empty())
}

fn locate_token(config_text: &str, token: &str) -> Option<(usize, usize, usize)> {
    let reference = format!("${token}");
    for (line_idx, line) in config_text.lines().enumerate() {
        for needle in [reference.as_str(), token] {
            if let Some(column_idx) = line.find(needle) {
                let column = column_idx + 1;
                return Some((line_idx + 1, column, column + needle.len()));
            }
        }
    }
    None
}
