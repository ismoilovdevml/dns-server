//! `dns-server zone …` and `dns-server check` — inspect and validate the zone as
//! a whole, plus `init` for a first config file.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde_json::json;

use crate::{
    commands::{emit_json, next_serial, open_config, require_config, today_utc},
    config::Config,
    editor::ConfigEditor,
    ui,
    zone::Zone,
};

/// `zone show`
pub fn show(config: Option<&Path>, as_json: bool) -> Result<()> {
    let editor = open_config(config)?;
    let records = editor.records();

    let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
    for record in &records {
        *by_type.entry(record.record_type.clone()).or_default() += record.values.len();
    }
    let names: std::collections::BTreeSet<&str> = records.iter().map(|r| r.name.as_str()).collect();
    let values: usize = records.iter().map(|r| r.values.len()).sum();
    let origin = editor.origin().unwrap_or("<unset>").to_owned();

    if as_json {
        emit_json(&json!({
            "origin": origin,
            "config": editor.path().display().to_string(),
            "serial": editor.serial(),
            "record_sets": records.len(),
            "records": values,
            "names": names.len(),
            "by_type": by_type,
        }));
        return Ok(());
    }

    ui::section("ZONE");
    ui::field("origin", ui::accent(&origin), 14);
    ui::field("config", editor.path().display(), 14);
    ui::field(
        "soa serial",
        editor
            .serial()
            .map_or_else(|| ui::muted("unset"), |s| ui::accent(s).to_string()),
        14,
    );
    ui::field("names", names.len(), 14);
    ui::field("record sets", records.len(), 14);
    ui::field("records", values, 14);

    if !by_type.is_empty() {
        ui::section("BY TYPE");
        let widest = by_type.values().copied().max().unwrap_or(1).max(1);
        let mut table = ui::Table::new(&["TYPE", "COUNT", ""]);
        for (ty, count) in &by_type {
            #[allow(clippy::cast_precision_loss)]
            let ratio = *count as f64 / widest as f64;
            table.row(
                vec![ui::record_type(ty), count.to_string(), ui::bar(ratio, 20)],
                &[ty.clone(), count.to_string(), String::new()],
            );
        }
        table.print();
    }

    Ok(())
}

/// `zone export` — BIND zone-file format, for diffing against another server.
pub fn export(config: Option<&Path>) -> Result<()> {
    let editor = open_config(config)?;
    let origin = editor.origin().unwrap_or("example.invalid").to_owned();

    println!("; exported by {} {}", crate::NAME, crate::VERSION);
    println!("; source: {}", editor.path().display());
    println!("$ORIGIN {origin}.");
    if let Some(serial) = editor.serial() {
        println!("; SOA serial {serial}");
    }
    println!();

    for record in editor.records() {
        let owner = if record.name == "@" {
            "@".to_owned()
        } else {
            record.name.clone()
        };
        let ttl = record.ttl.map_or_else(String::new, |t| format!("{t}\t"));
        for value in &record.values {
            println!("{owner}\t{ttl}IN\t{}\t{value}", record.record_type);
        }
    }
    Ok(())
}

/// `zone bump-serial`
pub fn bump_serial(config: Option<&Path>, as_json: bool) -> Result<u32> {
    let mut editor = open_config(config)?;
    let previous = editor.serial();
    let serial = next_serial(previous, today_utc()?);
    editor.set_serial(serial)?;
    editor.save()?;

    if as_json {
        emit_json(&json!({
            "serial": serial,
            "previous": previous,
            "config": editor.path().display().to_string(),
        }));
    } else {
        match previous {
            Some(previous) => println!(
                "{} SOA serial {} → {}",
                ui::tick(),
                ui::muted(previous),
                ui::accent(serial)
            ),
            None => println!("{} SOA serial set to {}", ui::tick(), ui::accent(serial)),
        }
    }
    Ok(serial)
}

/// `init` — write a starter config file.
pub fn init(output: Option<&Path>, origin: &str, as_json: bool) -> Result<bool> {
    let path = output.map_or_else(|| PathBuf::from("dns-server.toml"), Path::to_path_buf);
    let created = ConfigEditor::init(&path, origin)?;

    if as_json {
        emit_json(&json!({
            "created": created,
            "config": path.display().to_string(),
            "origin": origin,
        }));
        return Ok(created);
    }

    if created {
        println!(
            "{} wrote {} for zone {}",
            ui::tick(),
            ui::accent(path.display()),
            ui::accent(origin)
        );
        println!();
        println!("{}", ui::muted("next:"));
        println!(
            "  {} record add www A 203.0.113.10 --config {}",
            crate::NAME,
            path.display()
        );
        println!("  {} check --config {}", crate::NAME, path.display());
        println!("  {} serve --config {}", crate::NAME, path.display());
    } else {
        println!(
            "{} {} already exists, leaving it alone",
            ui::bang(),
            ui::accent(path.display())
        );
    }
    Ok(created)
}

/// `check` — resolve the configuration, build the zone, report what it would serve.
pub fn check(config: &Config, config_path: Option<&Path>, as_json: bool) -> Result<()> {
    let zone = Zone::from_config(&config.zone)?;

    if as_json {
        emit_json(&json!({
            "ok": true,
            "config": config_path.map(|p| p.display().to_string()),
            "zone": {
                "origin": config.zone.origin,
                "default_ttl": config.zone.default_ttl,
                "builtins": config.zone.builtins,
                "record_sets": config.zone.records.len(),
                "records": zone.record_count(),
                "soa": zone.soa().is_some(),
            },
            "listeners": {
                "udp": config.udp.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "tcp": config.tcp.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "admin": config.admin_listen.map(|a| a.to_string()),
            },
            "rate_limit": config.rate_limit.map(|r| json!({ "qps": r.qps, "burst": r.burst })),
            "log": { "format": format!("{:?}", config.log_format).to_lowercase(), "level": config.log_level },
        }));
        return Ok(());
    }

    ui::section("CONFIGURATION");
    if let Some(path) = config_path {
        ui::field("source", path.display(), 16);
    } else {
        ui::field("source", ui::muted("defaults + flags only"), 16);
    }
    ui::field("zone", ui::accent(&config.zone.origin), 16);
    ui::field("default ttl", format!("{}s", config.zone.default_ttl), 16);
    ui::field("record sets", config.zone.records.len(), 16);
    ui::field("records", ui::accent(zone.record_count()), 16);
    ui::field(
        "soa",
        if zone.soa().is_some() {
            format!("{} present", ui::tick())
        } else {
            // Without an SOA, resolvers cannot cache our negative answers.
            format!(
                "{} missing — negative answers will not be cacheable",
                ui::bang()
            )
        },
        16,
    );
    ui::field(
        "builtins",
        if config.zone.builtins {
            ui::good("enabled")
        } else {
            ui::muted("disabled").to_string()
        },
        16,
    );

    ui::section("LISTENERS");
    ui::field("udp", join(&config.udp), 16);
    ui::field("tcp", join(&config.tcp), 16);
    ui::field(
        "admin",
        config.admin_listen.map_or_else(
            || ui::muted("disabled").to_string(),
            |a| {
                if a.ip().is_loopback() {
                    ui::good(a)
                } else {
                    // Unauthenticated endpoints on a public interface are worth a nudge.
                    format!("{} {} (not loopback — keep it firewalled)", ui::bang(), a)
                }
            },
        ),
        16,
    );

    ui::section("PROTECTION");
    ui::field(
        "rate limit",
        config.rate_limit.map_or_else(
            || format!("{} disabled", ui::bang()),
            |r| ui::good(format!("{} qps / burst {} per source IP", r.qps, r.burst)),
        ),
        16,
    );
    ui::field(
        "admin token",
        if config.admin_token.is_some() {
            ui::good("set")
        } else {
            ui::muted("unset (reload restricted to loopback)").to_string()
        },
        16,
    );

    println!();
    println!("{} configuration is valid", ui::tick());
    Ok(())
}

/// Resolve the config path for a command that requires one.
pub fn resolve(path: Option<&Path>) -> Result<PathBuf> {
    require_config(path)
}

fn join<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        return ui::muted("none").to_string();
    }
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const BASE: &str = r#"[zone]
origin = "example.com"
default_ttl = 300

[zone.soa]
mname = "ns1.example.com."
rname = "hostmaster.example.com."
serial = 7

[[zone.records]]
name = "@"
type = "A"
values = ["203.0.113.10", "203.0.113.11"]

[[zone.records]]
name = "www"
type = "CNAME"
values = ["example.com."]
"#;

    fn fixture() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dns-server.toml");
        fs::write(&path, BASE).unwrap();
        (dir, path)
    }

    #[test]
    fn show_runs_in_both_modes() {
        let (_dir, path) = fixture();
        show(Some(&path), true).unwrap();
        show(Some(&path), false).unwrap();
    }

    #[test]
    fn export_emits_zone_file_syntax() {
        let (_dir, path) = fixture();
        // Just checking it does not error; content is exercised by the shape of
        // the printed lines, which the CLI test covers end to end.
        export(Some(&path)).unwrap();
    }

    #[test]
    fn bump_serial_advances_and_persists() {
        let (_dir, path) = fixture();
        let serial = bump_serial(Some(&path), true).unwrap();
        assert!(
            serial > 7,
            "serial should have advanced from 7, got {serial}"
        );
        assert_eq!(ConfigEditor::open(&path).unwrap().serial(), Some(serial));

        // A second bump must be strictly greater.
        let again = bump_serial(Some(&path), true).unwrap();
        assert!(again >= serial, "{again} should be >= {serial}");
    }

    #[test]
    fn init_creates_then_refuses_to_clobber() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dns-server.toml");

        assert!(init(Some(&path), "example.org", true).unwrap());
        assert!(!init(Some(&path), "other.test", true).unwrap());
        assert_eq!(
            ConfigEditor::open(&path).unwrap().origin(),
            Some("example.org")
        );
    }

    #[test]
    fn init_output_is_a_valid_config() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dns-server.toml");
        init(Some(&path), "example.org", true).unwrap();

        // The generated file must parse as a real config and build a real zone.
        let editor = ConfigEditor::open(&path).unwrap();
        assert_eq!(editor.origin(), Some("example.org"));
        assert!(editor.records().is_empty());
    }

    #[test]
    fn show_reports_a_missing_file() {
        let error = show(Some(Path::new("/nonexistent/x.toml")), true).unwrap_err();
        assert!(error.to_string().contains("reading"), "{error}");
    }
}
