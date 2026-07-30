//! What each subcommand does.
//!
//! Split by audience rather than by noun: [`record`] and [`zone`] edit and
//! inspect the config file, [`inspect`] talks to a running server.
//!
//! Two rules hold everywhere in here:
//!
//! * every command has a `--json` form, because agents and scripts should not
//!   have to scrape a table;
//! * a command that changes nothing says so, and exits 0 — idempotent edits are
//!   the normal case when configuration is generated.

// Date and serial literals here are grouped as YYYY_MM_DD(_nn) because that is
// how an operator reads a SOA serial; clippy would rather see 20_260_730.
#![allow(clippy::inconsistent_digit_grouping)]

pub mod inspect;
pub mod record;
pub mod zone;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{cli::CONFIG_SEARCH_PATH, editor::ConfigEditor};

/// Print a JSON value on one line, the way a pipe wants it.
pub fn emit_json(value: &serde_json::Value) {
    println!("{value}");
}

/// Open the config file for editing, with an error that says where we looked.
pub fn open_config(path: Option<&Path>) -> Result<ConfigEditor> {
    let path = require_config(path)?;
    ConfigEditor::open(path)
}

/// Resolve the config path, or explain that there isn't one.
pub fn require_config(path: Option<&Path>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path.to_path_buf()),
        None => anyhow::bail!(
            "no config file found (looked for {}); pass --config PATH or run `vega init`",
            CONFIG_SEARCH_PATH.join(", ")
        ),
    }
}

/// Today's date as a `YYYYMMDDnn` SOA serial, incrementing `previous` when it is
/// already from today.
///
/// RFC 1912 recommends this format; the counter matters because a zone can change
/// more than once a day and secondaries only refresh when the serial increases.
pub fn next_serial(previous: Option<u32>, today: u32) -> u32 {
    let base = today.saturating_mul(100);
    match previous {
        // Same day: bump the counter, saturating at 99 so we never go backwards.
        Some(prev) if prev >= base && prev < base + 99 => prev + 1,
        Some(prev) if prev >= base => prev,
        _ => base + 1,
    }
}

/// `YYYYMMDD` for the current UTC day.
pub fn today_utc() -> Result<u32> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the system clock is before the unix epoch")?
        .as_secs();
    Ok(ymd_from_unix_days(secs / 86_400))
}

/// Convert days-since-epoch into `YYYYMMDD`.
///
/// Implemented here rather than pulling in a date library: this is the only date
/// arithmetic in the crate. Algorithm from Howard Hinnant's `civil_from_days`.
fn ymd_from_unix_days(days: u64) -> u32 {
    #[allow(clippy::cast_possible_wrap)]
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let day_of_year = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let d = day_of_year - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let packed = (y as u32) * 10_000 + (m as u32) * 100 + (d as u32);
    packed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_day_zero_is_1970_01_01() {
        assert_eq!(ymd_from_unix_days(0), 1970_01_01);
    }

    #[test]
    fn known_dates_round_trip() {
        // 2000-03-01 is 11017 days after the epoch — just past a leap-year boundary,
        // which is where naive implementations break.
        assert_eq!(ymd_from_unix_days(11_017), 2000_03_01);
        // 2026-07-30
        assert_eq!(ymd_from_unix_days(20_664), 2026_07_30);
    }

    #[test]
    fn today_is_a_plausible_date() {
        let today = today_utc().unwrap();
        assert!(
            (1970_01_01..=2999_12_31).contains(&today),
            "implausible date: {today}"
        );
        let month = (today / 100) % 100;
        let day = today % 100;
        assert!((1..=12).contains(&month), "bad month in {today}");
        assert!((1..=31).contains(&day), "bad day in {today}");
    }

    #[test]
    fn first_serial_of_the_day_ends_in_01() {
        assert_eq!(next_serial(None, 2026_07_30), 2026_07_30_01);
        assert_eq!(next_serial(Some(1), 2026_07_30), 2026_07_30_01);
        assert_eq!(next_serial(Some(2026_07_29_04), 2026_07_30), 2026_07_30_01);
    }

    #[test]
    fn same_day_bumps_the_counter() {
        assert_eq!(next_serial(Some(2026_07_30_01), 2026_07_30), 2026_07_30_02);
        assert_eq!(next_serial(Some(2026_07_30_41), 2026_07_30), 2026_07_30_42);
    }

    #[test]
    fn serial_never_goes_backwards_at_the_daily_limit() {
        // 99 edits in one day is pathological; holding steady is safer than
        // rolling over into tomorrow's serial.
        let maxed = 2026_07_30_99;
        assert_eq!(next_serial(Some(maxed), 2026_07_30), maxed);
    }

    #[test]
    fn a_future_serial_is_left_alone() {
        let future = 2027_01_01_05;
        assert_eq!(next_serial(Some(future), 2026_07_30), future);
    }

    #[test]
    fn missing_config_error_lists_the_search_path() {
        let error = require_config(None).unwrap_err().to_string();
        assert!(error.contains("vega.toml"), "{error}");
        assert!(error.contains("--config"), "{error}");
    }

    #[test]
    fn explicit_config_path_is_returned_as_is() {
        let path = PathBuf::from("/tmp/x.toml");
        assert_eq!(require_config(Some(&path)).unwrap(), path);
    }
}
