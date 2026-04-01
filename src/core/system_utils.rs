/*
 * SPDX-FileCopyrightText: 2025 Sven Shi
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Shared helpers for parsing simple runtime values and reading wall-clock or
//! filesystem metadata.

use cronexpr::jiff::tz::TimeZone;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;

const KIB: u64 = 1024;
const MIB: u64 = KIB * 1024;
const GIB: u64 = MIB * 1024;
const TIB: u64 = GIB * 1024;

/// Read the current wall-clock time since the Unix epoch.
#[inline]
pub fn unix_time() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Read the current Unix timestamp in milliseconds.
#[inline]
pub fn unix_timestamp_millis() -> i64 {
    unix_time().as_millis().min(i64::MAX as u128) as i64
}

/// Resolve the current system IANA timezone name.
///
/// Returns `UTC` when the local timezone name is unavailable.
#[inline]
pub fn system_timezone_name() -> String {
    TimeZone::system()
        .iana_name()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "UTC".to_string())
}

/// Read file length if the path exists.
///
/// Returns `Ok(None)` when the file does not exist.
pub async fn file_len_if_exists(path: impl AsRef<Path>) -> std::io::Result<Option<u64>> {
    match fs::metadata(path).await {
        Ok(metadata) => Ok(Some(metadata.len())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Parse an integer duration string with a unit suffix.
///
/// Supported units:
/// - `ms`
/// - `s`
/// - `m`
/// - `h`
/// - `d`
pub fn parse_simple_duration(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("duration cannot be empty".to_string());
    }

    let unit_start = raw
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| "duration must include a unit".to_string())?;
    let value = raw[..unit_start]
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("invalid duration '{}': {}", raw, e))?;
    let unit = raw[unit_start..].trim().to_ascii_lowercase();

    let duration = match unit.as_str() {
        "ms" => Duration::from_millis(value),
        "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value.saturating_mul(60)),
        "h" => Duration::from_secs(value.saturating_mul(60 * 60)),
        "d" => Duration::from_secs(value.saturating_mul(60 * 60 * 24)),
        _ => return Err(format!("unsupported duration unit '{}' in '{}'", unit, raw)),
    };

    Ok(duration)
}

/// Parse a file-size string such as `1k`, `2m`, or `3g`.
///
/// Supported suffixes use binary multiples:
/// - `k` / `kb`
/// - `m` / `mb`
/// - `g` / `gb`
/// - `t` / `tb`
///
/// A plain integer is interpreted as raw bytes.
pub fn parse_byte_size(raw: &str) -> Result<u64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("byte size cannot be empty".to_string());
    }

    if raw.chars().all(|c| c.is_ascii_digit()) {
        return raw
            .parse::<u64>()
            .map_err(|e| format!("invalid byte size '{}': {}", raw, e));
    }

    let unit_start = raw
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| "byte size must include a valid integer prefix".to_string())?;
    let value = raw[..unit_start]
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("invalid byte size '{}': {}", raw, e))?;
    let unit = raw[unit_start..].trim().to_ascii_lowercase();

    let multiplier = match unit.as_str() {
        "k" | "kb" => KIB,
        "m" | "mb" => MIB,
        "g" | "gb" => GIB,
        "t" | "tb" => TIB,
        _ => {
            return Err(format!(
                "unsupported byte size unit '{}' in '{}'",
                unit, raw
            ));
        }
    };

    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("byte size '{}' is too large", raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_timestamp_millis_is_non_negative() {
        assert!(unix_timestamp_millis() >= 0);
    }

    #[test]
    fn test_system_timezone_name_is_non_empty() {
        assert!(!system_timezone_name().trim().is_empty());
    }

    #[test]
    fn test_parse_simple_duration() {
        assert_eq!(
            parse_simple_duration("250ms").unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(parse_simple_duration("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(
            parse_simple_duration("3m").unwrap(),
            Duration::from_secs(180)
        );
        assert_eq!(
            parse_simple_duration("4h").unwrap(),
            Duration::from_secs(14_400)
        );
        assert_eq!(
            parse_simple_duration("1d").unwrap(),
            Duration::from_secs(86_400)
        );
        assert!(parse_simple_duration("10").is_err());
        assert!(parse_simple_duration("10w").is_err());
    }

    #[test]
    fn test_parse_byte_size() {
        assert_eq!(parse_byte_size("128").unwrap(), 128);
        assert_eq!(parse_byte_size("1k").unwrap(), KIB);
        assert_eq!(parse_byte_size("2M").unwrap(), 2 * MIB);
        assert_eq!(parse_byte_size("3gb").unwrap(), 3 * GIB);
        assert!(parse_byte_size("5p").is_err());
    }
}
