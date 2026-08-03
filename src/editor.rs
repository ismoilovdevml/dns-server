//! Format-preserving edits to the config file, so `vega record add` can be
//! scripted without destroying an operator's comments and layout.
//!
//! Everything goes through a [`crate::tomlparse::Document`], which keeps the
//! original document and only rewrites the parts that changed. Writes are
//! atomic: we render to a temporary file in the same directory and rename over
//! the original, so a crash mid-write cannot leave a truncated config behind.
//!
//! The parse itself belongs to [`crate::tomlparse`] and not to this module. It
//! used to live here, and a broken config printed its offending source line —
//! `admin_token = "…` — to the terminal of anyone who ran `vega record add` or
//! `vega zone show` (VEGA-089, the sibling of VEGA-082 on the server path).

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use hickory_proto::rr::RecordType;
use toml_edit::{Array, ArrayOfTables, Item, Table, Value};

use crate::{
    rdata::{self, ValueError},
    tomlparse::{self, Document},
};

/// One record set as it appears in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordEntry {
    /// Owner name relative to the origin (`@` for the apex).
    pub name: String,
    /// Record type, upper-cased.
    pub record_type: String,
    /// Explicit TTL, if the entry sets one.
    pub ttl: Option<u32>,
    /// Presentation-format values.
    pub values: Vec<String>,
}

/// What an edit actually did, so the caller can report it honestly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// A new record set was appended.
    Created,
    /// Values were added to an existing record set.
    Extended,
    /// An existing record set was overwritten.
    Replaced,
    /// Values or a whole record set were removed.
    Removed,
    /// The file already said exactly this.
    Unchanged,
}

/// An open config document.
#[derive(Debug)]
pub struct ConfigEditor {
    path: PathBuf,
    doc: Document,
}

impl ConfigEditor {
    /// Read and parse the config file.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let raw =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        // `tomlparse::ParseError` is safe to keep as a `source`: it carries the
        // position and not the line, so `{:#}` and `{:?}` say where the file is
        // broken without saying what is on that line.
        let doc =
            tomlparse::document(&raw).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Self { path, doc })
    }

    /// Create a minimal config file for `origin` if none exists yet.
    ///
    /// Returns `false` when the file was already there and nothing was written.
    pub fn init(path: impl AsRef<Path>, origin: &str) -> Result<bool> {
        let path = path.as_ref();
        if path.exists() {
            return Ok(false);
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }

        let contents = format!(
            "# vega configuration. See vega.example.toml for every option.\n\
             \n\
             [server]\n\
             udp = [\"0.0.0.0:53\"]\n\
             tcp = [\"0.0.0.0:53\"]\n\
             admin_listen = \"127.0.0.1:9100\"\n\
             log_format = \"json\"\n\
             \n\
             [zone]\n\
             origin = \"{origin}\"\n\
             default_ttl = 300\n\
             builtins = true\n\
             \n\
             [zone.soa]\n\
             mname = \"ns1.{origin}.\"\n\
             rname = \"hostmaster.{origin}.\"\n\
             serial = 1\n\
             minimum = 60\n\
             \n\
             # RFC 1034 §4.2.1 requires an NS record set at the apex, and the \
             server refuses\n\
             # to start without one: it names the servers authoritative for \
             this zone, and\n\
             # every delegation checker and every secondary reads it. Point it \
             at this host.\n\
             [[zone.records]]\n\
             name = \"@\"\n\
             type = \"NS\"\n\
             values = [\"ns1.{origin}.\"]\n\
             \n\
             [[zone.records]]\n\
             name = \"ns1\"\n\
             type = \"A\"\n\
             values = [\"127.0.0.1\"]        # replace with this server's \
             public address\n"
        );
        write_atomically(path, &contents)?;
        Ok(true)
    }

    /// Path this editor is bound to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The configured zone origin, if the file sets one.
    pub fn origin(&self) -> Option<&str> {
        self.doc
            .get("zone")?
            .as_table_like()?
            .get("origin")?
            .as_str()
    }

    /// Every record set in the file, in document order.
    pub fn records(&self) -> Vec<RecordEntry> {
        let Some(tables) = self
            .doc
            .get("zone")
            .and_then(Item::as_table_like)
            .and_then(|zone| zone.get("records"))
            .and_then(Item::as_array_of_tables)
        else {
            return Vec::new();
        };

        tables
            .iter()
            .map(|table| RecordEntry {
                name: table
                    .get("name")
                    .and_then(Item::as_str)
                    .unwrap_or("@")
                    .to_owned(),
                record_type: table
                    .get("type")
                    .and_then(Item::as_str)
                    .unwrap_or_default()
                    .to_uppercase(),
                ttl: table
                    .get("ttl")
                    .and_then(Item::as_integer)
                    .and_then(|v| u32::try_from(v).ok()),
                values: table
                    .get("values")
                    .and_then(Item::as_array)
                    .map(|array| {
                        array
                            .iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect()
    }

    /// Add `values` to the `name`/`record_type` record set.
    ///
    /// With `replace`, the existing values are discarded first. Without it,
    /// values already present are skipped rather than duplicated.
    pub fn add(
        &mut self,
        name: &str,
        record_type: &str,
        values: &[String],
        ttl: Option<u32>,
        replace: bool,
    ) -> Result<Change> {
        let record_type = normalise_type(record_type)?;
        let name = normalise_name(name);
        if values.is_empty() {
            bail!("no values given");
        }
        for value in values {
            validate_value(record_type, &name, value)?;
        }

        let tables = self.records_mut()?;
        let existing = tables
            .iter_mut()
            .find(|t| matches(t, &name, record_type.to_string().as_str()));

        if let Some(table) = existing {
            let current_ttl = ttl_of(table);
            let current_values = value_array_mut(table).map(|a| array_values(a))?;

            if replace {
                if current_values == values && current_ttl == ttl {
                    return Ok(Change::Unchanged);
                }
                *value_array_mut(table)? = build_array(values);
                set_ttl(table, ttl);
                return Ok(Change::Replaced);
            }

            let missing: Vec<&String> = values
                .iter()
                .filter(|value| !current_values.iter().any(|v| v == *value))
                .collect();
            let rettl = ttl.is_some() && current_ttl != ttl;

            if missing.is_empty() && !rettl {
                return Ok(Change::Unchanged);
            }

            let array = value_array_mut(table)?;
            for value in missing {
                array.push(value.as_str());
            }
            if rettl {
                set_ttl(table, ttl);
            }
            return Ok(Change::Extended);
        }

        let mut table = Table::new();
        table.insert("name", toml_edit::value(name.as_str()));
        table.insert("type", toml_edit::value(record_type.to_string()));
        if let Some(ttl) = ttl {
            table.insert("ttl", toml_edit::value(i64::from(ttl)));
        }
        table.insert("values", Item::Value(Value::Array(build_array(values))));
        tables.push(table);
        Ok(Change::Created)
    }

    /// Remove a record set, or just some of its values.
    ///
    /// `record_type` of `None` removes every type at `name`. A non-empty `values`
    /// removes only those values, deleting the record set if none are left.
    pub fn remove(
        &mut self,
        name: &str,
        record_type: Option<&str>,
        values: &[String],
    ) -> Result<Change> {
        let name = normalise_name(name);
        let wanted_type = record_type.map(normalise_type).transpose()?;

        let Some(tables) = self.existing_records_mut() else {
            return Ok(Change::Unchanged);
        };

        let mut changed = false;
        let mut drop_indices = Vec::new();

        for (idx, table) in tables.iter_mut().enumerate() {
            let type_matches = match wanted_type {
                Some(ty) => matches(table, &name, ty.to_string().as_str()),
                None => name_of(table) == name,
            };
            if !type_matches {
                continue;
            }

            if values.is_empty() {
                drop_indices.push(idx);
                changed = true;
                continue;
            }

            let array = value_array_mut(table)?;
            let before = array_values(array);
            let kept: Vec<String> = before
                .iter()
                .filter(|v| !values.iter().any(|drop| drop == *v))
                .cloned()
                .collect();
            if kept.len() != before.len() {
                changed = true;
                if kept.is_empty() {
                    drop_indices.push(idx);
                } else {
                    *array = build_array(&kept);
                }
            }
        }

        // Remove from the back so earlier indices stay valid.
        for idx in drop_indices.into_iter().rev() {
            tables.remove(idx);
        }

        Ok(if changed {
            Change::Removed
        } else {
            Change::Unchanged
        })
    }

    /// Set the SOA serial, e.g. after a batch of record edits.
    pub fn set_serial(&mut self, serial: u32) -> Result<()> {
        let soa = self
            .doc
            .entry("zone")
            .or_insert(Item::Table(Table::new()))
            .as_table_like_mut()
            .context("[zone] is not a table")?
            .entry("soa")
            .or_insert(Item::Table(Table::new()));
        soa.as_table_like_mut()
            .context("[zone.soa] is not a table")?
            .insert("serial", toml_edit::value(i64::from(serial)));
        Ok(())
    }

    /// The current SOA serial, if set.
    pub fn serial(&self) -> Option<u32> {
        self.doc
            .get("zone")?
            .as_table_like()?
            .get("soa")?
            .as_table_like()?
            .get("serial")?
            .as_integer()
            .and_then(|v| u32::try_from(v).ok())
    }

    /// The document as it would be written.
    pub fn to_toml(&self) -> String {
        self.doc.to_string()
    }

    /// Write the document back to disk, atomically.
    pub fn save(&self) -> Result<()> {
        write_atomically(&self.path, &self.doc.to_string())
    }

    fn records_mut(&mut self) -> Result<&mut ArrayOfTables> {
        let zone = self
            .doc
            .entry("zone")
            .or_insert(Item::Table(Table::new()))
            .as_table_like_mut()
            .context("[zone] is not a table")?;

        // `entry` on a table-like gives us an Item; make sure it is the array of
        // tables that `[[zone.records]]` produces.
        if zone.get("records").is_none() {
            zone.insert("records", Item::ArrayOfTables(ArrayOfTables::new()));
        }
        zone.get_mut("records")
            .and_then(Item::as_array_of_tables_mut)
            .context("[[zone.records]] is not an array of tables")
    }

    fn existing_records_mut(&mut self) -> Option<&mut ArrayOfTables> {
        self.doc
            .get_mut("zone")?
            .as_table_like_mut()?
            .get_mut("records")?
            .as_array_of_tables_mut()
    }
}

/// Render to a sibling temp file, fsync, then rename over the target.
fn write_atomically(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;

    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp = match dir {
        Some(dir) => dir.join(format!(
            ".{}.tmp",
            path.file_name().map_or_else(
                || "vega.toml".to_owned(),
                |n| n.to_string_lossy().into_owned(),
            )
        )),
        None => PathBuf::from(".vega.toml.tmp"),
    };

    {
        let mut file =
            fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        // Without the sync, a crash after the rename can leave an empty file.
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
    }

    fs::rename(&tmp, path)
        .with_context(|| format!("replacing {} with {}", path.display(), tmp.display()))?;
    Ok(())
}

fn normalise_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        "@".to_owned()
    } else {
        trimmed.to_lowercase()
    }
}

fn normalise_type(record_type: &str) -> Result<RecordType> {
    record_type
        .trim()
        .to_uppercase()
        .parse()
        .map_err(|e| anyhow::anyhow!("unknown record type {record_type:?}: {e}"))
}

/// Reject bad values here rather than letting the server fail to start later.
///
/// Goes through [`crate::rdata::parse_value`] rather than calling the parser
/// directly: the length bound that keeps hickory's lexer from aborting the
/// process lives there, and this path is `vega record add`, i.e. an argument
/// straight off an operator's command line.
fn validate_value(record_type: RecordType, owner: &str, value: &str) -> Result<()> {
    match rdata::parse_value(record_type, owner, value) {
        Ok(_) => Ok(()),
        // Reworded rather than passed through: the operator is looking at the
        // value they just typed, not at a file, so the parser's own message
        // needs the value attached to be worth anything.
        Err(ValueError::Unparsable(e)) => Err(anyhow::anyhow!(
            "invalid {record_type} value {value:?}: {e}"
        )),
        Err(too_long @ ValueError::TooLong { .. }) => Err(anyhow::Error::new(too_long)),
    }
}

fn matches(table: &Table, name: &str, record_type: &str) -> bool {
    name_of(table) == name
        && table
            .get("type")
            .and_then(Item::as_str)
            .map(str::to_uppercase)
            .as_deref()
            == Some(record_type)
}

fn name_of(table: &Table) -> String {
    normalise_name(table.get("name").and_then(Item::as_str).unwrap_or("@"))
}

fn ttl_of(table: &Table) -> Option<u32> {
    table
        .get("ttl")
        .and_then(Item::as_integer)
        .and_then(|v| u32::try_from(v).ok())
}

fn set_ttl(table: &mut Table, ttl: Option<u32>) {
    match ttl {
        Some(ttl) => {
            table.insert("ttl", toml_edit::value(i64::from(ttl)));
        }
        None => {
            table.remove("ttl");
        }
    }
}

fn value_array_mut(table: &mut Table) -> Result<&mut Array> {
    if table.get("values").is_none() {
        table.insert("values", Item::Value(Value::Array(Array::new())));
    }
    table
        .get_mut("values")
        .and_then(Item::as_array_mut)
        .context("`values` is not an array")
}

fn array_values(array: &Array) -> Vec<String> {
    array
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

fn build_array(values: &[String]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(value.as_str());
    }
    array
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const BASE: &str = r#"# A comment we must not lose.
[server]
udp = ["0.0.0.0:53"]

[zone]
origin = "example.com"   # trailing comment
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

    fn editor(contents: &str) -> (TempDir, ConfigEditor) {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("vega.toml");
        fs::write(&path, contents).expect("write fixture");
        let editor = ConfigEditor::open(&path).expect("open fixture");
        (dir, editor)
    }

    fn vals(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn reads_existing_records() {
        let (_dir, editor) = editor(BASE);
        let records = editor.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "www");
        assert_eq!(records[0].record_type, "A");
        assert_eq!(records[0].values, vals(&["203.0.113.10"]));
        assert_eq!(editor.origin(), Some("example.com"));
        assert_eq!(editor.serial(), Some(7));
    }

    #[test]
    fn adding_a_new_record_set_preserves_comments() {
        let (_dir, mut editor) = editor(BASE);
        let change = editor
            .add("api", "A", &vals(&["203.0.113.20"]), Some(30), false)
            .unwrap();
        assert_eq!(change, Change::Created);

        let rendered = editor.to_toml();
        assert!(rendered.contains("# A comment we must not lose."));
        assert!(rendered.contains("# trailing comment"));
        assert!(rendered.contains("name = \"api\""));
        assert!(rendered.contains("ttl = 30"));
    }

    #[test]
    fn adding_to_an_existing_set_appends_without_duplicating() {
        let (_dir, mut editor) = editor(BASE);

        let change = editor
            .add("www", "A", &vals(&["203.0.113.11"]), None, false)
            .unwrap();
        assert_eq!(change, Change::Extended);
        assert_eq!(
            editor.records()[0].values,
            vals(&["203.0.113.10", "203.0.113.11"])
        );

        // Same value again is a no-op, not a duplicate.
        let change = editor
            .add("www", "A", &vals(&["203.0.113.11"]), None, false)
            .unwrap();
        assert_eq!(change, Change::Unchanged);
        assert_eq!(editor.records()[0].values.len(), 2);
    }

    #[test]
    fn replace_overwrites_the_value_list() {
        let (_dir, mut editor) = editor(BASE);
        let change = editor
            .add("www", "A", &vals(&["198.51.100.1"]), None, true)
            .unwrap();
        assert_eq!(change, Change::Replaced);
        assert_eq!(editor.records()[0].values, vals(&["198.51.100.1"]));
    }

    #[test]
    fn replace_with_identical_content_is_unchanged() {
        let (_dir, mut editor) = editor(BASE);
        let change = editor
            .add("www", "A", &vals(&["203.0.113.10"]), None, true)
            .unwrap();
        assert_eq!(change, Change::Unchanged);
    }

    #[test]
    fn apex_names_are_normalised() {
        let (_dir, mut editor) = editor(BASE);
        editor
            .add("", "TXT", &vals(&["\"hi\""]), None, false)
            .unwrap();
        assert_eq!(editor.records()[1].name, "@");

        // "" and "@" must land in the same record set.
        let change = editor
            .add("@", "TXT", &vals(&["\"hi\""]), None, false)
            .unwrap();
        assert_eq!(change, Change::Unchanged);
    }

    #[test]
    fn type_matching_is_case_insensitive() {
        let (_dir, mut editor) = editor(BASE);
        let change = editor
            .add("WWW", "a", &vals(&["203.0.113.10"]), None, true)
            .unwrap();
        assert_eq!(
            change,
            Change::Unchanged,
            "should have matched the existing set"
        );
    }

    #[test]
    fn invalid_values_are_rejected_before_writing() {
        let (_dir, mut editor) = editor(BASE);
        let error = editor
            .add("bad", "A", &vals(&["not-an-ip"]), None, false)
            .unwrap_err();
        assert!(error.to_string().contains("invalid A value"), "{error}");
        assert_eq!(editor.records().len(), 1, "nothing should have been added");
    }

    /// A TXT value of exactly `n` characters, quotes included — quoted because
    /// that is what an operator types and what the parser expects, and the
    /// quotes count towards the length the lexer walks.
    fn txt_of(n: usize) -> String {
        format!("\"{}\"", "a".repeat(n - 2))
    }

    /// Scenario: A record value of exactly the maximum length is accepted
    /// features/cli-record-editing.feature
    ///
    /// The bound is inclusive. Without this, `chars > MAX` could be tightened to
    /// `>=` — or the constant dropped to something arbitrarily small — and the
    /// rejection test alone would not notice.
    #[test]
    fn a_record_value_at_the_length_limit_is_accepted() {
        let (_dir, mut editor) = editor(BASE);
        let value = txt_of(rdata::MAX_VALUE_CHARS);
        assert_eq!(value.chars().count(), rdata::MAX_VALUE_CHARS);

        let change = editor
            .add("big", "TXT", &vals(&[&value]), None, false)
            .expect("a value at the limit must be accepted");
        assert_eq!(change, Change::Created);
    }

    /// Scenario: A record value one character over the maximum is rejected
    /// features/cli-record-editing.feature
    ///
    /// One character over the limit, so an off-by-one in the guard fails here.
    /// Before the fix this did not fail — it aborted the process inside
    /// hickory's lexer, which under `panic = "abort"` is exit 134 for anyone
    /// scripting `vega record add`.
    #[test]
    fn a_record_value_one_character_over_the_limit_is_rejected_not_aborted() {
        let (_dir, mut editor) = editor(BASE);
        let value = txt_of(rdata::MAX_VALUE_CHARS + 1);

        let error = editor
            .add("big", "TXT", &vals(&[&value]), None, false)
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains(&format!("is {} characters", rdata::MAX_VALUE_CHARS + 1)),
            "{message}"
        );
        assert!(
            message.contains(&format!("the maximum is {}", rdata::MAX_VALUE_CHARS)),
            "{message}"
        );
        assert_eq!(editor.records().len(), 1, "nothing should have been added");
    }

    /// A long value in the *second* position must be caught too: `add` loops,
    /// and a guard applied only to the first value would leave the rest to the
    /// lexer. The first value is valid so the loop has to reach the second.
    #[test]
    fn every_value_in_the_list_is_length_checked_not_just_the_first() {
        let (_dir, mut editor) = editor(BASE);
        let good = txt_of(16);
        let bad = txt_of(rdata::MAX_VALUE_CHARS + 1);

        let error = editor
            .add("big", "TXT", &vals(&[&good, &bad]), None, false)
            .unwrap_err();
        assert!(error.to_string().contains("the maximum is"), "{error}");
        assert_eq!(editor.records().len(), 1, "nothing should have been added");
    }

    #[test]
    fn unknown_types_are_rejected() {
        let (_dir, mut editor) = editor(BASE);
        let error = editor
            .add("x", "NOPE", &vals(&["y"]), None, false)
            .unwrap_err();
        assert!(error.to_string().contains("unknown record type"), "{error}");
    }

    #[test]
    fn removing_a_single_value_keeps_the_rest() {
        let (_dir, mut editor) = editor(BASE);
        editor
            .add("www", "A", &vals(&["203.0.113.11"]), None, false)
            .unwrap();

        let change = editor
            .remove("www", Some("A"), &vals(&["203.0.113.10"]))
            .unwrap();
        assert_eq!(change, Change::Removed);
        assert_eq!(editor.records()[0].values, vals(&["203.0.113.11"]));
    }

    #[test]
    fn removing_the_last_value_drops_the_record_set() {
        let (_dir, mut editor) = editor(BASE);
        let change = editor
            .remove("www", Some("A"), &vals(&["203.0.113.10"]))
            .unwrap();
        assert_eq!(change, Change::Removed);
        assert!(editor.records().is_empty());
    }

    #[test]
    fn removing_without_a_type_drops_every_type_at_the_name() {
        let (_dir, mut editor) = editor(BASE);
        editor
            .add("www", "TXT", &vals(&["\"hello\""]), None, false)
            .unwrap();
        assert_eq!(editor.records().len(), 2);

        let change = editor.remove("www", None, &[]).unwrap();
        assert_eq!(change, Change::Removed);
        assert!(editor.records().is_empty());
    }

    #[test]
    fn removing_something_absent_is_unchanged() {
        let (_dir, mut editor) = editor(BASE);
        let change = editor.remove("ghost", Some("A"), &[]).unwrap();
        assert_eq!(change, Change::Unchanged);
        assert_eq!(editor.records().len(), 1);
    }

    #[test]
    fn removing_from_a_file_with_no_records_is_unchanged() {
        let (_dir, mut editor) = editor("[zone]\norigin = \"example.com\"\n");
        let change = editor.remove("www", Some("A"), &[]).unwrap();
        assert_eq!(change, Change::Unchanged);
    }

    #[test]
    fn adding_to_a_file_with_no_zone_table_creates_one() {
        let (_dir, mut editor) = editor("[server]\nudp = [\"0.0.0.0:53\"]\n");
        editor
            .add("www", "A", &vals(&["203.0.113.10"]), None, false)
            .unwrap();
        let rendered = editor.to_toml();
        assert!(rendered.contains("[[zone.records]]"), "{rendered}");
        assert_eq!(editor.records().len(), 1);
    }

    #[test]
    fn serial_can_be_set_and_read_back() {
        let (_dir, mut editor) = editor(BASE);
        editor.set_serial(2_026_073_001).unwrap();
        assert_eq!(editor.serial(), Some(2_026_073_001));
    }

    #[test]
    fn set_serial_creates_the_soa_table_when_missing() {
        let (_dir, mut editor) = editor("[zone]\norigin = \"example.com\"\n");
        editor.set_serial(5).unwrap();
        assert_eq!(editor.serial(), Some(5));
        assert!(editor.to_toml().contains("serial = 5"));
    }

    #[test]
    fn save_round_trips_through_the_filesystem() {
        let (dir, mut editor) = editor(BASE);
        editor
            .add("api", "AAAA", &vals(&["2001:db8::1"]), None, false)
            .unwrap();
        editor.save().unwrap();

        let reopened = ConfigEditor::open(dir.path().join("vega.toml")).unwrap();
        assert_eq!(reopened.records().len(), 2);
        assert!(reopened.to_toml().contains("# A comment we must not lose."));

        // The temp file must not be left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| Path::new(n).extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    #[test]
    fn init_creates_a_usable_config_and_never_clobbers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("vega.toml");

        assert!(ConfigEditor::init(&path, "example.org").unwrap());
        let editor = ConfigEditor::open(&path).unwrap();
        assert_eq!(editor.origin(), Some("example.org"));

        // Second call must leave the file alone.
        assert!(!ConfigEditor::init(&path, "other.test").unwrap());
        assert_eq!(
            ConfigEditor::open(&path).unwrap().origin(),
            Some("example.org")
        );
    }

    #[test]
    fn open_reports_a_missing_file_clearly() {
        let error = ConfigEditor::open("/nonexistent/vega.toml").unwrap_err();
        assert!(error.to_string().contains("reading"), "{error}");
    }

    #[test]
    fn open_reports_broken_toml_clearly() {
        let (_dir, _) = editor(BASE);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("broken.toml");
        fs::write(&path, "[zone\norigin =").unwrap();
        let error = ConfigEditor::open(&path).unwrap_err();
        assert!(error.to_string().contains("parsing"), "{error}");
    }

    /// Scenario: No command echoes the admin_token line from a broken config
    /// features/config-precedence.feature:481
    ///
    /// VEGA-089. This is the unit-level half of the CLI round in
    /// `tests/cli.rs::no_command_that_reads_the_config_echoes_the_admin_token_line`:
    /// every editing command reaches an operator's terminal through this one
    /// function, and it used to hand back `toml_edit`'s rendering, which quotes
    /// the line it stopped on — usually the one with the token on it.
    #[test]
    fn open_does_not_quote_the_offending_line_back() {
        const SECRET: &str = "SUPER-SECRET-TOKEN-1";
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("broken.toml");
        fs::write(&path, format!("[server]\nadmin_token = \"{SECRET}\n")).unwrap();

        let error = ConfigEditor::open(&path).unwrap_err();
        // Three renderings, because each is a separate way out of the process:
        // `{}` is what a `bail!` prints, `{:#}` is what `report` prints, and
        // `{:?}` is what a `tracing` field would.
        for rendering in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            assert!(
                !rendering.contains(SECRET),
                "the offending config line came back with the token on it: {rendering}"
            );
        }
        // The position is the half that makes it actionable, and it is only in
        // the chain, so assert on the rendering `report` actually uses.
        let full = format!("{error:#}");
        assert!(full.contains("line 2"), "{full}");
        assert!(full.contains("column"), "{full}");
    }

    // -----------------------------------------------------------------------
    // Regression tests from mutation testing.
    // -----------------------------------------------------------------------

    #[test]
    fn adding_the_same_value_with_a_new_ttl_retimes_the_set() {
        // Kills `ttl.is_some() && current_ttl != ttl` -> `||` and -> `==`, plus
        // `set_ttl with ()` and `ttl_of -> None`. Nothing covered the TTL side
        // of a non-replacing add.
        let (_dir, mut editor) = editor(BASE);
        assert_eq!(editor.records()[0].ttl, None);

        let change = editor
            .add("www", "A", &vals(&["203.0.113.10"]), Some(60), false)
            .unwrap();
        assert_eq!(change, Change::Extended, "a new TTL is a change");
        assert_eq!(editor.records()[0].ttl, Some(60));
        assert_eq!(
            editor.records()[0].values,
            vals(&["203.0.113.10"]),
            "re-timing must not duplicate the value"
        );

        // Same value, same TTL: nothing to do.
        let change = editor
            .add("www", "A", &vals(&["203.0.113.10"]), Some(60), false)
            .unwrap();
        assert_eq!(change, Change::Unchanged);

        // No TTL given: the existing one is left alone rather than cleared.
        let change = editor
            .add("www", "A", &vals(&["203.0.113.10"]), None, false)
            .unwrap();
        assert_eq!(change, Change::Unchanged);
        assert_eq!(editor.records()[0].ttl, Some(60));
    }

    #[test]
    fn replacing_with_no_ttl_removes_an_existing_one() {
        // Kills `set_ttl with ()` on the replace path.
        let (_dir, mut editor) = editor(BASE);
        editor
            .add("www", "A", &vals(&["203.0.113.10"]), Some(60), true)
            .unwrap();
        assert_eq!(editor.records()[0].ttl, Some(60));

        let change = editor
            .add("www", "A", &vals(&["203.0.113.10"]), None, true)
            .unwrap();
        assert_eq!(change, Change::Replaced);
        assert_eq!(editor.records()[0].ttl, None);
        // `default_ttl = 300` lives in [zone]; only a bare `ttl =` key is ours.
        assert!(
            !editor.to_toml().contains("\nttl ="),
            "{}",
            editor.to_toml()
        );
    }

    #[test]
    fn the_saved_file_is_reopenable_and_keeps_its_comments() {
        // An atomic replace only works when the temp file is on the same
        // filesystem as the target, which in practice means the same
        // directory. A rename across devices fails at runtime, on the
        // operator's machine, part-way through a config write.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vega.toml");
        fs::write(&path, BASE).unwrap();
        let mut editor = ConfigEditor::open(&path).unwrap();
        editor
            .add("api", "A", &vals(&["203.0.113.20"]), None, false)
            .unwrap();
        editor.save().unwrap();

        assert_eq!(ConfigEditor::open(&path).unwrap().records().len(), 2);
        assert!(fs::read_to_string(&path)
            .unwrap()
            .contains("# A comment we must not lose."));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "BUG: an atomic write drops the config's permission bits, exposing admin_token (0640 -> 0644)"]
    fn saving_preserves_the_config_file_permissions() {
        // `write_atomically` creates a brand new temp file with
        // `fs::File::create` — mode 0666 & ~umask, so 0644 under the usual
        // umask 022 — and renames it over the original. The original's mode is
        // discarded.
        //
        // That matters because vega.toml holds `admin_token`, the shared
        // secret guarding the mutating `/reload` endpoint, and install.sh
        // deliberately sets the file to 0640 and its directory to 0750. Any
        // subsequent `vega record add` silently widens it to 0644 and the
        // token becomes readable by every local user.
        //
        // Reproduced with the release binary:
        //   chmod 600 c.toml && vega -c c.toml record add www A 203.0.113.10
        //   -> "OK created", and the file is left -rw-r--r--
        //
        // The fix is to stat the target first and re-apply its mode to the temp
        // file before the rename.
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vega.toml");
        fs::write(&path, BASE).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let mut editor = ConfigEditor::open(&path).unwrap();
        editor
            .add("api", "A", &vals(&["203.0.113.20"]), None, false)
            .unwrap();
        editor.save().unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "saving widened the config from 0600 to {mode:o}; it may hold admin_token"
        );
    }

    #[test]
    #[ignore = "BUG: write_atomically uses a fixed temp filename, so two concurrent writers to the same config corrupt each other"]
    fn two_concurrent_writers_do_not_corrupt_the_config() {
        // `write_atomically` derives the temp path purely from the target name
        // (`.vega.toml.tmp`), with no pid, no randomness and no O_EXCL.
        // Two `vega record add` processes editing the same file therefore
        // open, truncate and write the *same* temp file concurrently: one
        // truncates the other mid-write, then both rename it into place. The
        // survivor can be a torn document, and it is not even guaranteed to be
        // either writer's intended content.
        use std::sync::{Arc, Barrier};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vega.toml");
        fs::write(&path, BASE).unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for worker in 0..2 {
            let (path, barrier) = (path.clone(), Arc::clone(&barrier));
            handles.push(std::thread::spawn(move || {
                // A big payload widens the window between create and rename.
                let values: Vec<String> = (0..400)
                    .map(|i| format!("203.0.{worker}.{}", i % 256))
                    .collect();
                barrier.wait();
                for _ in 0..40 {
                    let mut e = ConfigEditor::open(&path).unwrap();
                    e.add(&format!("host{worker}"), "A", &values, None, true)
                        .unwrap();
                    e.save().unwrap();
                }
            }));
        }
        for h in handles {
            h.join().expect("worker finishes");
        }

        let raw = fs::read_to_string(&path).unwrap();
        tomlparse::document(&raw)
            .unwrap_or_else(|e| panic!("config was corrupted by concurrent writers: {e}\n{raw}"));
        assert!(
            raw.contains("# A comment we must not lose."),
            "the original document was lost:\n{raw}"
        );
    }
}
