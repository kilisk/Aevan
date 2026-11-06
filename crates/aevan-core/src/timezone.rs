//! Best-effort local UTC offset for the vendor login form's `tz_offset` field.
//!
//! `std::time` exposes UTC only, this workspace forbids `unsafe`, and no
//! timezone crate is a dependency. The vendor form wants the offset in
//! minutes, so this module asks the operating system once and caches the
//! answer:
//!
//! * Windows: `powershell.exe` reports
//!   `[TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).TotalMinutes`.
//! * Unix: `date +%z` reports the numeric offset (for example `+0800`).
//!
//! This is deliberately best-effort. The query can fail under a restricted
//! environment, and it observes the offset at the time of the first call, so a
//! DST transition during a long-running process is not picked up. Callers fall
//! back to UTC and document that the value is unknown rather than guessing a
//! timezone rule.

use std::process::Command;
use std::sync::OnceLock;

/// Local UTC offset in minutes east of UTC (for example `480` for UTC+8).
///
/// Returns `None` when the platform query or its output cannot be understood.
pub fn local_utc_offset_minutes() -> Option<i32> {
    static OFFSET: OnceLock<Option<i32>> = OnceLock::new();
    *OFFSET.get_or_init(query_utc_offset_minutes)
}

fn query_utc_offset_minutes() -> Option<i32> {
    #[cfg(windows)]
    {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[int]([TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).TotalMinutes)",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8(output.stdout).ok()?;
        parse_decimal_minutes(text.trim())
    }

    #[cfg(unix)]
    {
        let output = Command::new("date").arg("+%z").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8(output.stdout).ok()?;
        parse_numeric_offset(text.trim())
    }

    #[cfg(not(any(windows, unix)))]
    {
        None
    }
}

/// Parse the `tzi`-style decimal minute offset printed by Windows `tzutil`.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_decimal_minutes(text: &str) -> Option<i32> {
    text.parse::<i32>().ok()
}

/// Parse a `date +%z` value such as `+0800`, `-0530` or `Z`.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_numeric_offset(text: &str) -> Option<i32> {
    if text.eq_ignore_ascii_case("z") {
        return Some(0);
    }
    let (sign, digits) = match text.as_bytes().first() {
        Some(b'+') => (1, &text[1..]),
        Some(b'-') => (-1, &text[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let hours = digits[..2].parse::<i32>().ok()?;
    let minutes = digits[2..].parse::<i32>().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 60 + minutes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numeric_offsets() {
        assert_eq!(parse_numeric_offset("+0800"), Some(480));
        assert_eq!(parse_numeric_offset("-0530"), Some(-330));
        assert_eq!(parse_numeric_offset("+0000"), Some(0));
        assert_eq!(parse_numeric_offset("Z"), Some(0));
    }

    #[test]
    fn rejects_malformed_offsets() {
        for value in ["", "+08", "0800", "+ab00", "+2400", "+0870"] {
            assert_eq!(parse_numeric_offset(value), None, "{value:?}");
        }
    }

    #[test]
    fn parses_decimal_minutes() {
        assert_eq!(parse_decimal_minutes("480"), Some(480));
        assert_eq!(parse_decimal_minutes("-330"), Some(-330));
        assert_eq!(parse_decimal_minutes("+60"), Some(60));
        assert_eq!(parse_decimal_minutes("nope"), None);
    }
}
