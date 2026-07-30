//! Terminal output: colour, symbols, tables and key/value panels.
//!
//! Colour is decided once, at startup, and every helper here routes through that
//! decision. The rules are the ones users expect:
//!
//! * `NO_COLOR` set (any value) → no colour, per <https://no-color.org>.
//! * `TERM=dumb` → no colour.
//! * `--json`, or stdout is not a terminal (a pipe, a file, CI) → no colour.
//! * `CLICOLOR_FORCE` set → colour anyway.
//!
//! Nothing here writes to stderr; diagnostics stay on the tracing side.

use std::{
    fmt::Display,
    io::{IsTerminal as _, Write as _},
    sync::atomic::{AtomicBool, Ordering},
};

use owo_colors::OwoColorize as _;

/// Whether ANSI styling is enabled. Set once by [`init`].
static COLOR: AtomicBool = AtomicBool::new(false);

/// Whether `--verbose` was requested.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Decide whether to colour output, and record the verbosity level.
///
/// `structured` should be true when the caller is emitting JSON, which must never
/// contain escape sequences.
pub fn init(structured: bool, verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
    COLOR.store(should_colour(structured), Ordering::Relaxed);
}

fn should_colour(structured: bool) -> bool {
    if structured {
        return false;
    }
    if std::env::var_os("CLICOLOR_FORCE").is_some() {
        return true;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|term| term == "dumb") {
        return false;
    }
    std::io::stdout().is_terminal()
}

/// True when colour is enabled.
pub fn colour() -> bool {
    COLOR.load(Ordering::Relaxed)
}

/// True when `--verbose` was requested.
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Apply a style only when colour is on.
macro_rules! styled {
    ($value:expr, $method:ident) => {{
        let value = $value;
        if colour() {
            value.$method().to_string()
        } else {
            value.to_string()
        }
    }};
}

/// Section heading, e.g. `ZONE`.
pub fn heading(text: &str) -> String {
    styled!(text, bold)
}

/// A label in a key/value pair.
pub fn label(text: &str) -> String {
    styled!(text, dimmed)
}

/// Something that worked.
pub fn good(text: impl Display) -> String {
    styled!(text, green)
}

/// Something that needs attention.
pub fn warn(text: impl Display) -> String {
    styled!(text, yellow)
}

/// Something that failed.
pub fn bad(text: impl Display) -> String {
    styled!(text, red)
}

/// A value worth drawing the eye to.
pub fn accent(text: impl Display) -> String {
    styled!(text, cyan)
}

/// Secondary detail.
pub fn muted(text: impl Display) -> String {
    styled!(text, dimmed)
}

/// A DNS record type, coloured by family so a long listing is scannable.
pub fn record_type(ty: &str) -> String {
    if !colour() {
        return ty.to_owned();
    }
    match ty {
        // Address records: the common case.
        "A" | "AAAA" => ty.green().to_string(),
        // Delegation and aliasing: the ones that redirect a lookup elsewhere.
        "CNAME" | "NS" | "SOA" | "DNAME" => ty.magenta().to_string(),
        // Mail and service discovery.
        "MX" | "SRV" | "SVCB" | "HTTPS" => ty.blue().to_string(),
        // Free-form policy data.
        "TXT" | "CAA" => ty.yellow().to_string(),
        _ => ty.cyan().to_string(),
    }
}

/// A DNS response code, coloured by severity.
pub fn rcode(code: &str) -> String {
    if !colour() {
        return code.to_owned();
    }
    match code {
        "NOERROR" => code.green().bold().to_string(),
        "NXDOMAIN" => code.yellow().bold().to_string(),
        _ => code.red().bold().to_string(),
    }
}

/// `✔` when colour and unicode are welcome, `OK` otherwise.
pub fn tick() -> String {
    if colour() {
        "✔".green().to_string()
    } else {
        "OK".to_owned()
    }
}

/// `✘` / `FAIL`.
pub fn cross() -> String {
    if colour() {
        "✘".red().to_string()
    } else {
        "FAIL".to_owned()
    }
}

/// `!` / `WARN`.
pub fn bang() -> String {
    if colour() {
        "!".yellow().to_string()
    } else {
        "WARN".to_owned()
    }
}

/// Print a top-level section heading with a rule under it.
pub fn section(title: &str) {
    println!();
    println!("{}", heading(title));
    println!("{}", muted("─".repeat(title.chars().count().max(8))));
}

/// Print a `label  value` line, with the label padded to `width` visible columns.
///
/// Padding is measured on the unstyled text: a styled label carries escape
/// sequences that `{:<width$}` would count as printable and mis-align.
pub fn field(name: &str, value: impl Display, width: usize) {
    let styled = label(name);
    let pad = width.saturating_sub(name.chars().count());
    println!("{styled}{} {value}", " ".repeat(pad));
}

/// A simple left-aligned table with a dimmed header row.
///
/// Column widths come from the content, so a listing of one record does not get
/// padded to the width of a listing of a hundred.
#[derive(Debug, Default)]
pub struct Table {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
    /// Plain-text widths, tracked separately because styled cells contain escape
    /// sequences that would break `{:<width$}`.
    widths: Vec<usize>,
}

impl Table {
    /// Start a table with these column headings.
    pub fn new(header: &[&str]) -> Self {
        Self {
            header: header.iter().map(|h| (*h).to_owned()).collect(),
            rows: Vec::new(),
            widths: header.iter().map(|h| h.chars().count()).collect(),
        }
    }

    /// Append a row. `cells` may be styled; `plain` is the same text unstyled and
    /// is what column widths are measured from.
    pub fn row(&mut self, cells: Vec<String>, plain: &[String]) {
        for (idx, text) in plain.iter().enumerate() {
            let width = text.chars().count();
            match self.widths.get_mut(idx) {
                Some(current) => *current = (*current).max(width),
                None => self.widths.push(width),
            }
        }
        self.rows.push(cells);
    }

    /// Number of data rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when there is nothing to show.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Render to stdout.
    pub fn print(&self) {
        let mut out = std::io::stdout().lock();
        let last = self.header.len().saturating_sub(1);

        let header: Vec<String> = self
            .header
            .iter()
            .enumerate()
            .map(|(idx, cell)| pad(cell, self.width(idx), idx == last))
            .collect();
        let _ = writeln!(out, "{}", label(&header.join("  ")));

        for row in &self.rows {
            let cells: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(idx, cell)| pad_styled(cell, self.width(idx), idx == last))
                .collect();
            let _ = writeln!(out, "{}", cells.join("  "));
        }
    }

    fn width(&self, idx: usize) -> usize {
        self.widths.get(idx).copied().unwrap_or(0)
    }
}

fn pad(text: &str, width: usize, last: bool) -> String {
    if last {
        text.to_owned()
    } else {
        format!("{text:<width$}")
    }
}

/// Pad a possibly-styled cell to `width` visible characters.
fn pad_styled(text: &str, width: usize, last: bool) -> String {
    if last {
        return text.to_owned();
    }
    let visible = visible_width(text);
    let mut out = text.to_owned();
    if visible < width {
        out.push_str(&" ".repeat(width - visible));
    }
    out
}

/// Count printable characters, skipping ANSI escape sequences.
fn visible_width(text: &str) -> usize {
    let mut width = 0;
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            // Consume up to and including the terminating letter of the sequence.
            for esc in chars.by_ref() {
                if esc.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            width += 1;
        }
    }
    width
}

/// Render a duration the way an operator reads it.
/// `u64::MAX` rounded to the nearest f64. Any float at or above this cannot be
/// represented as a `u64`, so it is the right clamp ceiling.
#[allow(clippy::cast_precision_loss)]
const U64_MAX_AS_F64: f64 = u64::MAX as f64;

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn duration(secs: f64) -> String {
    if secs < 1.0 {
        return format!("{:.0}ms", secs * 1000.0);
    }
    // Saturating rather than `as`: an absurd uptime should render oddly, not wrap.
    let total = secs.trunc().clamp(0.0, U64_MAX_AS_F64) as u64;
    let (days, rest) = (total / 86_400, total % 86_400);
    let (hours, rest) = (rest / 3_600, rest % 3_600);
    let (minutes, seconds) = (rest / 60, rest % 60);

    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// A fixed-width bar for a 0..=1 ratio, for at-a-glance proportions.
pub fn bar(ratio: f64, width: usize) -> String {
    let clamped = ratio.clamp(0.0, 1.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let filled = (clamped * width as f64).round() as usize;
    let filled = filled.min(width);
    let glyphs = format!("{}{}", "█".repeat(filled), "░".repeat(width - filled));
    if colour() {
        glyphs.cyan().to_string()
    } else {
        glyphs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Colour state is global, so tests that touch it must restore it.
    fn with_colour<T>(on: bool, f: impl FnOnce() -> T) -> T {
        let previous = COLOR.swap(on, Ordering::Relaxed);
        let result = f();
        COLOR.store(previous, Ordering::Relaxed);
        result
    }

    #[test]
    fn styling_is_a_no_op_when_colour_is_off() {
        with_colour(false, || {
            assert_eq!(good("yes"), "yes");
            assert_eq!(bad("no"), "no");
            assert_eq!(record_type("A"), "A");
            assert_eq!(rcode("NOERROR"), "NOERROR");
            assert_eq!(tick(), "OK");
            assert_eq!(cross(), "FAIL");
        });
    }

    #[test]
    fn styling_emits_escapes_when_colour_is_on() {
        with_colour(true, || {
            assert!(good("yes").contains('\u{1b}'));
            assert!(record_type("A").contains('\u{1b}'));
            assert!(rcode("SERVFAIL").contains('\u{1b}'));
        });
    }

    #[test]
    fn json_output_never_gets_colour() {
        assert!(!should_colour(true));
    }

    #[test]
    fn visible_width_ignores_escape_sequences() {
        with_colour(true, || {
            let styled = record_type("AAAA");
            assert!(styled.len() > 4, "expected escapes in {styled:?}");
            assert_eq!(visible_width(&styled), 4);
        });
        assert_eq!(visible_width("plain"), 5);
        assert_eq!(visible_width(""), 0);
    }

    #[test]
    fn table_pads_columns_to_the_widest_cell() {
        with_colour(false, || {
            let mut table = Table::new(["NAME", "TYPE"].as_slice());
            table.row(
                vec!["www".to_owned(), "A".to_owned()],
                &["www".to_owned(), "A".to_owned()],
            );
            table.row(
                vec!["very-long-name".to_owned(), "AAAA".to_owned()],
                &["very-long-name".to_owned(), "AAAA".to_owned()],
            );
            assert_eq!(table.len(), 2);
            assert!(!table.is_empty());
            assert_eq!(table.width(0), "very-long-name".len());
        });
    }

    #[test]
    fn table_starts_empty() {
        let table = Table::new(["A"].as_slice());
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn durations_read_the_way_operators_expect() {
        assert_eq!(duration(0.004), "4ms");
        assert_eq!(duration(42.0), "42s");
        assert_eq!(duration(90.0), "1m 30s");
        assert_eq!(duration(3_725.0), "1h 2m 5s");
        assert_eq!(duration(90_000.0), "1d 1h 0m");
    }

    #[test]
    fn field_pads_by_visible_width_not_byte_length() {
        with_colour(true, || {
            let styled = label("origin");
            // The escape codes must not be counted towards the column width.
            assert_eq!(visible_width(&styled), 6);
            assert!(styled.len() > 6);
        });
    }

    #[test]
    fn bar_clamps_out_of_range_ratios() {
        with_colour(false, || {
            assert_eq!(bar(0.0, 4), "░░░░");
            assert_eq!(bar(1.0, 4), "████");
            assert_eq!(bar(2.0, 4), "████");
            assert_eq!(bar(-1.0, 4), "░░░░");
            assert_eq!(bar(0.5, 4), "██░░");
        });
    }
}
