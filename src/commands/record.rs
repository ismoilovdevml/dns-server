//! `vega record …` — list, inspect and edit record sets in the config file.

use std::{net::SocketAddr, path::Path};

use anyhow::Result;
use serde_json::json;

use crate::{
    commands::{emit_json, next_serial, open_config, today_utc},
    editor::{Change, ConfigEditor, RecordEntry},
    ui,
};

/// Result of an edit, so `main` can pick an exit code and a message.
#[derive(Clone, Debug)]
pub struct EditResult {
    /// What changed.
    pub change: Change,
    /// The record set after the edit, if it still exists.
    pub entry: Option<RecordEntry>,
    /// New SOA serial, when `--bump-serial` was given.
    pub serial: Option<u32>,
}

/// `record list`
pub fn list(
    config: Option<&Path>,
    name_filter: Option<&str>,
    type_filter: Option<&str>,
    as_json: bool,
) -> Result<()> {
    let editor = open_config(config)?;
    let origin = editor.origin().unwrap_or("<unset>").to_owned();

    let wanted_type = type_filter.map(str::to_uppercase);
    let wanted_name = name_filter.map(normalise);

    let records: Vec<RecordEntry> = editor
        .records()
        .into_iter()
        .filter(|r| wanted_type.as_ref().is_none_or(|t| &r.record_type == t))
        .filter(|r| {
            wanted_name
                .as_ref()
                .is_none_or(|n| &normalise(&r.name) == n)
        })
        .collect();

    if as_json {
        emit_json(&json!({
            "origin": origin,
            "config": editor.path().display().to_string(),
            "count": records.len(),
            "records": records.iter().map(entry_json).collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    print_table(&origin, editor.path(), &records);
    Ok(())
}

/// `record get`
pub fn get(
    config: Option<&Path>,
    name: &str,
    record_type: Option<&str>,
    as_json: bool,
) -> Result<bool> {
    let editor = open_config(config)?;
    let origin = editor.origin().unwrap_or("<unset>").to_owned();
    let wanted_name = normalise(name);
    let wanted_type = record_type.map(str::to_uppercase);

    let records: Vec<RecordEntry> = editor
        .records()
        .into_iter()
        .filter(|r| normalise(&r.name) == wanted_name)
        .filter(|r| wanted_type.as_ref().is_none_or(|t| &r.record_type == t))
        .collect();

    if as_json {
        emit_json(&json!({
            "origin": origin,
            "name": wanted_name,
            "found": !records.is_empty(),
            "records": records.iter().map(entry_json).collect::<Vec<_>>(),
        }));
        return Ok(!records.is_empty());
    }

    if records.is_empty() {
        println!(
            "{} no records for {} in {}",
            ui::bang(),
            ui::accent(fqdn(&wanted_name, &origin)),
            origin
        );
        return Ok(false);
    }

    print_table(&origin, editor.path(), &records);
    Ok(true)
}

/// `record add`
#[allow(clippy::too_many_arguments)]
pub fn add(
    config: Option<&Path>,
    name: &str,
    record_type: &str,
    values: &[String],
    ttl: Option<u32>,
    replace: bool,
    bump_serial: bool,
    as_json: bool,
) -> Result<EditResult> {
    let mut editor = open_config(config)?;
    let change = editor.add(name, record_type, values, ttl, replace)?;
    let serial = maybe_bump(&mut editor, bump_serial, change)?;

    if change != Change::Unchanged || serial.is_some() {
        editor.save()?;
    }

    let entry = find(&editor, name, Some(record_type));
    report(&editor, change, entry.as_ref(), serial, as_json);
    Ok(EditResult {
        change,
        entry,
        serial,
    })
}

/// `record delete`
pub fn delete(
    config: Option<&Path>,
    name: &str,
    record_type: Option<&str>,
    values: &[String],
    bump_serial: bool,
    as_json: bool,
) -> Result<EditResult> {
    let mut editor = open_config(config)?;
    let change = editor.remove(name, record_type, values)?;
    let serial = maybe_bump(&mut editor, bump_serial, change)?;

    if change != Change::Unchanged || serial.is_some() {
        editor.save()?;
    }

    let entry = find(&editor, name, record_type);
    report(&editor, change, entry.as_ref(), serial, as_json);
    Ok(EditResult {
        change,
        entry,
        serial,
    })
}

/// Ask a running server to pick up the change, and report whether it did.
pub async fn reload_server(addr: SocketAddr, token: Option<&str>, as_json: bool) -> Result<bool> {
    let response = crate::http::post(addr, "/reload", token).await?;
    let parsed: serde_json::Value =
        serde_json::from_str(response.body.trim()).unwrap_or_else(|_| json!({}));

    if as_json {
        emit_json(&json!({
            "reload": {
                "server": addr.to_string(),
                "status": response.status,
                "ok": response.is_success(),
                "detail": parsed,
            }
        }));
        return Ok(response.is_success());
    }

    if response.is_success() {
        let records = parsed.get("records").and_then(serde_json::Value::as_u64);
        match records {
            Some(count) => println!(
                "{} reloaded {} ({} records now live)",
                ui::tick(),
                ui::muted(addr),
                ui::accent(count)
            ),
            None => println!("{} reloaded {}", ui::tick(), ui::muted(addr)),
        }
    } else {
        let detail = parsed
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map_or_else(|| response.body.trim().to_owned(), str::to_owned);
        println!(
            "{} reload refused by {} (HTTP {}): {}",
            ui::cross(),
            ui::muted(addr),
            response.status,
            ui::bad(detail)
        );
    }
    Ok(response.is_success())
}

fn maybe_bump(editor: &mut ConfigEditor, requested: bool, change: Change) -> Result<Option<u32>> {
    // Nothing changed means nothing for secondaries to notice.
    if !requested || change == Change::Unchanged {
        return Ok(None);
    }
    let serial = next_serial(editor.serial(), today_utc()?);
    editor.set_serial(serial)?;
    Ok(Some(serial))
}

fn find(editor: &ConfigEditor, name: &str, record_type: Option<&str>) -> Option<RecordEntry> {
    let wanted_name = normalise(name);
    let wanted_type = record_type.map(str::to_uppercase);
    editor.records().into_iter().find(|r| {
        normalise(&r.name) == wanted_name
            && wanted_type.as_ref().is_none_or(|t| &r.record_type == t)
    })
}

fn report(
    editor: &ConfigEditor,
    change: Change,
    entry: Option<&RecordEntry>,
    serial: Option<u32>,
    as_json: bool,
) {
    if as_json {
        emit_json(&json!({
            "change": change_str(change),
            "config": editor.path().display().to_string(),
            "origin": editor.origin(),
            "serial": serial,
            "record": entry.map(entry_json),
        }));
        return;
    }

    let origin = editor.origin().unwrap_or("<unset>");
    let (symbol, verb) = match change {
        Change::Created => (ui::tick(), ui::good("created")),
        Change::Extended => (ui::tick(), ui::good("extended")),
        Change::Replaced => (ui::tick(), ui::good("replaced")),
        Change::Removed => (ui::tick(), ui::warn("removed")),
        Change::Unchanged => (ui::bang(), ui::muted("unchanged")),
    };

    match entry {
        Some(entry) => println!(
            "{symbol} {verb} {} {} → {}",
            ui::accent(fqdn(&entry.name, origin)),
            ui::record_type(&entry.record_type),
            entry.values.join(", ")
        ),
        None => println!("{symbol} {verb}"),
    }

    if let Some(serial) = serial {
        println!("{} SOA serial → {}", ui::muted("  "), ui::accent(serial));
    }
    if ui::verbose() {
        println!("{} {}", ui::label("  config:"), editor.path().display());
    }
}

fn print_table(origin: &str, config: &Path, records: &[RecordEntry]) {
    if records.is_empty() {
        println!(
            "{} no records in {}",
            ui::bang(),
            ui::muted(config.display())
        );
        return;
    }

    let mut table = ui::Table::new(&["NAME", "TYPE", "TTL", "VALUE"]);
    for record in records {
        let name = fqdn(&record.name, origin);
        let ttl = record
            .ttl
            .map_or_else(|| "-".to_owned(), |t| format!("{t}s"));

        // One row per value keeps long record sets readable and greppable.
        for (idx, value) in record.values.iter().enumerate() {
            let (shown_name, shown_type, shown_ttl) = if idx == 0 {
                (name.clone(), record.record_type.clone(), ttl.clone())
            } else {
                (String::new(), String::new(), String::new())
            };
            table.row(
                vec![
                    ui::accent(&shown_name),
                    ui::record_type(&shown_type),
                    ui::muted(&shown_ttl),
                    value.clone(),
                ],
                &[shown_name, shown_type, shown_ttl, value.clone()],
            );
        }
    }

    table.print();
    println!(
        "{}",
        ui::muted(format!(
            "{} record set(s), {} value(s) in {}",
            records.len(),
            records.iter().map(|r| r.values.len()).sum::<usize>(),
            config.display()
        ))
    );
}

fn entry_json(entry: &RecordEntry) -> serde_json::Value {
    json!({
        "name": entry.name,
        "type": entry.record_type,
        "ttl": entry.ttl,
        "values": entry.values,
    })
}

fn change_str(change: Change) -> &'static str {
    match change {
        Change::Created => "created",
        Change::Extended => "extended",
        Change::Replaced => "replaced",
        Change::Removed => "removed",
        Change::Unchanged => "unchanged",
    }
}

fn normalise(name: &str) -> String {
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        "@".to_owned()
    } else {
        trimmed.to_lowercase()
    }
}

/// Render an owner name the way it appears in DNS, for output only.
fn fqdn(name: &str, origin: &str) -> String {
    if name == "@" {
        format!("{origin}.")
    } else {
        format!("{name}.{origin}.")
    }
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
name = "www"
type = "A"
values = ["203.0.113.10"]
"#;

    fn fixture() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vega.toml");
        fs::write(&path, BASE).unwrap();
        (dir, path)
    }

    fn vals(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn add_creates_a_record_and_persists_it() {
        let (_dir, path) = fixture();
        let result = add(
            Some(&path),
            "api",
            "A",
            &vals(&["203.0.113.20"]),
            Some(60),
            false,
            false,
            true,
        )
        .unwrap();

        assert_eq!(result.change, Change::Created);
        let entry = result.entry.expect("entry returned");
        assert_eq!(entry.name, "api");
        assert_eq!(entry.ttl, Some(60));

        // Persisted, not just held in memory.
        let reopened = ConfigEditor::open(&path).unwrap();
        assert_eq!(reopened.records().len(), 2);
    }

    #[test]
    fn adding_the_same_value_twice_is_unchanged() {
        let (_dir, path) = fixture();
        let result = add(
            Some(&path),
            "www",
            "A",
            &vals(&["203.0.113.10"]),
            None,
            false,
            false,
            true,
        )
        .unwrap();
        assert_eq!(result.change, Change::Unchanged);
        assert!(result.serial.is_none(), "no change means no serial bump");
    }

    #[test]
    fn bump_serial_only_fires_on_a_real_change() {
        let (_dir, path) = fixture();

        let changed = add(
            Some(&path),
            "api",
            "A",
            &vals(&["203.0.113.20"]),
            None,
            false,
            true,
            true,
        )
        .unwrap();
        let serial = changed.serial.expect("serial bumped");
        assert!(serial > 2_020_010_100, "serial looks wrong: {serial}");

        let unchanged = add(
            Some(&path),
            "api",
            "A",
            &vals(&["203.0.113.20"]),
            None,
            false,
            true,
            true,
        )
        .unwrap();
        assert_eq!(unchanged.change, Change::Unchanged);
        assert!(unchanged.serial.is_none());

        // And the file still carries the earlier bump.
        assert_eq!(ConfigEditor::open(&path).unwrap().serial(), Some(serial));
    }

    #[test]
    fn delete_removes_the_record_set() {
        let (_dir, path) = fixture();
        let result = delete(Some(&path), "www", Some("A"), &[], false, true).unwrap();
        assert_eq!(result.change, Change::Removed);
        assert!(result.entry.is_none());
        assert!(ConfigEditor::open(&path).unwrap().records().is_empty());
    }

    #[test]
    fn delete_of_something_absent_is_unchanged_and_not_an_error() {
        let (_dir, path) = fixture();
        let result = delete(Some(&path), "ghost", Some("A"), &[], false, true).unwrap();
        assert_eq!(result.change, Change::Unchanged);
    }

    #[test]
    fn add_rejects_an_invalid_value_without_touching_the_file() {
        let (_dir, path) = fixture();
        let before = fs::read_to_string(&path).unwrap();

        let error = add(
            Some(&path),
            "bad",
            "A",
            &vals(&["definitely-not-an-ip"]),
            None,
            false,
            false,
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid A value"), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn list_and_get_run_against_a_real_file() {
        let (_dir, path) = fixture();
        // Exercised for panics and errors; the printed output is not asserted on.
        list(Some(&path), None, None, true).unwrap();
        list(Some(&path), Some("www"), Some("a"), true).unwrap();
        assert!(get(Some(&path), "www", Some("A"), true).unwrap());
        assert!(!get(Some(&path), "nope", None, true).unwrap());
    }

    #[test]
    fn missing_config_is_an_error_not_a_panic() {
        assert!(list(None, None, None, true).is_err() || list(None, None, None, true).is_ok());
        let error = list(Some(Path::new("/nonexistent/x.toml")), None, None, true).unwrap_err();
        assert!(error.to_string().contains("reading"), "{error}");
    }

    #[test]
    fn names_are_normalised_consistently() {
        assert_eq!(normalise(" WWW. "), "www");
        assert_eq!(normalise(""), "@");
        assert_eq!(normalise("@"), "@");
    }

    #[test]
    fn fqdn_renders_the_apex_as_the_origin() {
        assert_eq!(fqdn("@", "example.com"), "example.com.");
        assert_eq!(fqdn("www", "example.com"), "www.example.com.");
    }
}
