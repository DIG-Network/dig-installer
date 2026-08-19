//! **No shipping sentence carries a run of spaces.**
//!
//! dig_ecosystem#3117. A string literal wrapped across two source lines with a trailing `\`
//! ships as one sentence. Lose that `\` — a reflow, a hand edit, a `cargo fmt` pass over a
//! continuation — and the source still compiles, still reads plausibly in review, and now ships
//! the wrapping indentation verbatim to the user:
//!
//! ```text
//! v9.9.9 is NEWER than the latest release v1.0.0 — left as                              is
//! ```
//!
//! The damage is invisible to the tests around it, because a test that asserts a message
//! *contains* "NEWER" is satisfied by a mangled one. dig-app shipped seven corrupted offer
//! sentences this way before a human reading a diff caught them, and dig-installer shipped
//! fourteen. So this asserts the shape of the copy itself rather than any one sentence.

use std::path::{Path, PathBuf};

/// A run this long cannot be deliberate mid-sentence, and is the shortest run the observed
/// corruptions produced.
const RUN_LIMIT: usize = 4;

/// Every `.rs` file under `src/`, deepest first, so a new module is covered the day it lands.
fn crate_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("the crate's own source tree is readable");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    found.sort();
    found
}

/// The part of a file that reaches a user: everything before the first `#[cfg(test)]`.
///
/// Test modules hold captured `sc.exe`, `whoami` and `systemctl` output, whose column alignment is
/// the fixture's whole point. Including them would force the guard to be loosened until it could
/// no longer see the defect it exists to catch.
fn shipping_source(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(cut) => &source[..cut],
        None => source,
    }
}

/// Where the scanner stands between two characters.
enum Ctx {
    /// Ordinary Rust code, outside any literal.
    Code,
    /// Inside a `"..."` string literal — the copy a user reads.
    Str,
    /// Inside a `r#"..."#` raw literal, holding the count of hashes that will close it.
    Raw(usize),
}

/// Walks a whole source file, carrying literal state ACROSS line boundaries.
///
/// The line boundary is the entire point. A string literal wrapped over two source lines with a
/// trailing `\` ships as one sentence, and losing that `\` is the corruption's FIRST state — the
/// run that reaches the user then LEADS the continuation line, where a per-line scan reads it as
/// harmless indentation because it has forgotten that a sentence is already open.
///
/// So the scanner distinguishes the two ends of a line that stops inside a literal:
///
/// - it ends with an unescaped `\` — Rust swallows the newline and the next line's indentation,
///   nothing reaches the user, and the next line starts as if fresh;
/// - it ends with anything else — the newline and the next line's indentation are shipped
///   verbatim, so that indentation is mid-sentence text and counts toward a run.
///
/// Three legitimate space runs stay invisible to it:
///
/// - **leading indentation** — nothing precedes it on the line, so no run is open yet;
/// - **indentation deliberately written just inside an opening quote** (a log bullet's `"    · "`)
///   — an opening quote closes any run and reopens the line, so that indentation leads too;
/// - **a raw literal's body** — those are file templates (a plist, a unit file) whose column
///   alignment is the template's whole point, exactly like the test fixtures cut away above.
///
/// A trailing `//` comment is not sentence text either, so scanning stops at one that falls
/// outside a literal — column-aligned end-of-line comments are a style, not a defect.
struct Scan {
    ctx: Ctx,
    seen_text: bool,
    run: usize,
}

impl Scan {
    fn new() -> Self {
        Self {
            ctx: Ctx::Code,
            seen_text: false,
            run: 0,
        }
    }

    /// Whether `line` carries a run of spaces with sentence text on both sides, advancing the
    /// scanner's state to the start of the next line.
    fn line_carries_a_space_run(&mut self, line: &str) -> bool {
        if !matches!(self.ctx, Ctx::Str) {
            // Only an open sentence survives a line break; everything else starts the line fresh,
            // so ordinary code indentation leads and cannot be read as a mid-sentence run.
            self.seen_text = false;
            self.run = 0;
        }
        if matches!(self.ctx, Ctx::Code)
            && (line.trim_start().starts_with("//") || !line.contains('"'))
        {
            // Neither a comment nor a quoteless line can open a literal, so the state is unchanged
            // and there is nothing shipping on it to measure.
            return false;
        }

        let chars: Vec<char> = line.chars().collect();
        let mut at = 0usize;
        let mut found = false;
        let mut continued = false;
        while at < chars.len() {
            let ch = chars[at];
            let mut step = 1usize;
            match self.ctx {
                Ctx::Code => {
                    if ch == '/' && chars.get(at + 1) == Some(&'/') {
                        break;
                    } else if ch == '\'' && chars.get(at + 1) == Some(&'"') {
                        // A `'"'` char literal: one quote that opens nothing.
                        step = 3;
                    } else if let Some(hashes) = raw_literal_opening(&chars, at) {
                        self.ctx = Ctx::Raw(hashes);
                        step = hashes + 2;
                    } else if ch == '"' {
                        self.ctx = Ctx::Str;
                        self.seen_text = false;
                        self.run = 0;
                    } else {
                        found |= self.take(ch);
                    }
                }
                Ctx::Str => {
                    if ch == '\\' {
                        // An escape: the next character is data, and a `\` ending the line
                        // swallows the newline together with the next line's indentation.
                        continued = at + 1 == chars.len();
                        self.seen_text = true;
                        self.run = 0;
                        step = 2;
                    } else if ch == '"' {
                        self.ctx = Ctx::Code;
                        self.seen_text = false;
                        self.run = 0;
                    } else {
                        found |= self.take(ch);
                    }
                }
                Ctx::Raw(hashes) => {
                    if closes_raw_literal(&chars, at, hashes) {
                        self.ctx = Ctx::Code;
                        self.seen_text = false;
                        self.run = 0;
                        step = hashes + 1;
                    }
                }
            }
            at += step;
        }

        if matches!(self.ctx, Ctx::Str) {
            // A sentence stays open across the boundary. Its indentation on the next line ships
            // verbatim unless a `\` swallowed it.
            self.seen_text = !continued;
            self.run = 0;
        }
        found
    }

    /// Feeds one character of shipping text, reporting whether it completes a mid-sentence run.
    fn take(&mut self, ch: char) -> bool {
        if ch == ' ' {
            self.run += usize::from(self.seen_text);
            return false;
        }
        if self.seen_text && self.run >= RUN_LIMIT {
            return true;
        }
        self.seen_text = true;
        self.run = 0;
        false
    }
}

/// The hash count of a raw literal opening at `at` (`r"` is zero, `r#"` is one), if one opens there.
fn raw_literal_opening(chars: &[char], at: usize) -> Option<usize> {
    if chars[at] != 'r' {
        return None;
    }
    let hashes = chars[at + 1..].iter().take_while(|ch| **ch == '#').count();
    (chars.get(at + 1 + hashes) == Some(&'"')).then_some(hashes)
}

/// Whether a raw literal closed by `hashes` hashes ends at `at`.
fn closes_raw_literal(chars: &[char], at: usize, hashes: usize) -> bool {
    chars[at] == '"'
        && chars[at + 1..]
            .iter()
            .take(hashes)
            .filter(|ch| **ch == '#')
            .count()
            == hashes
}

/// Every 1-based line number in `source` whose shipping copy carries a mid-sentence space run.
fn space_runs_in(source: &str) -> Vec<usize> {
    let mut scan = Scan::new();
    let mut found = Vec::new();
    for (offset, line) in source.lines().enumerate() {
        if scan.line_carries_a_space_run(line) {
            found.push(offset + 1);
        }
    }
    found
}

#[test]
fn no_shipping_literal_carries_a_space_run() {
    let mut scanned = 0usize;
    let mut damaged: Vec<String> = Vec::new();
    for path in crate_sources() {
        let source = std::fs::read_to_string(&path).expect("a listed source file is readable");
        let shipping = shipping_source(&source);
        scanned += shipping.lines().count();
        let lines: Vec<&str> = shipping.lines().collect();
        for number in space_runs_in(shipping) {
            let name = path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy();
            damaged.push(format!("{name}:{number}: {}", lines[number - 1].trim()));
        }
    }
    assert!(
        scanned > 20_000,
        "the scan saw only {scanned} lines, so it is measuring itself rather than the crate"
    );
    assert!(
        damaged.is_empty(),
        "a literal carries a run of {RUN_LIMIT}+ spaces mid-sentence, which reaches the user \
         verbatim — collapse it, and restore the `\\` if a continuation lost one: {damaged:#?}"
    );
}

/// Shape A — the corruption after something has reflowed it onto ONE line.
const JOINED_ONTO_ONE_LINE: &str = r##"
    let note = format!("v{new} is NEWER than v{old} — left as                    is");
"##;

/// Shape B — the corruption's FIRST state: the `\` was lost, so the literal now spans two
/// source lines and ships the newline plus the wrapping indentation verbatim.
const LOST_ITS_CONTINUATION: &str = r##"
    let note = format!("v{new} is NEWER than v{old} — left as
                        is");
"##;

/// Shape C — the same loss where the literal also carries an escaped newline of its own, so the
/// sentence looks deliberately multi-line in review.
const LOST_ITS_CONTINUATION_AFTER_AN_ESCAPE: &str = r##"
    let note = format!("installed {name}\n\nleft as
                        is");
"##;

/// The intact original: the `\` swallows the newline and the wrapping indentation, so nothing
/// reaches the user, and the guard must stay silent.
const INTACT_CONTINUATION: &str = r##"
    let note = format!("v{new} is NEWER than v{old} — left as \
                        is");
"##;

/// A log bullet's indentation, written just inside the opening quote on purpose.
const DELIBERATE_BULLET_INDENT: &str = r##"
    println!("    · {name} installed");
"##;

/// A configuration template, whose column alignment is the template's whole point — and whose
/// inner quotes must not desynchronise the scan of everything after it.
const RAW_STRING_TEMPLATE: &str = r##"
    let plist = r#"
<plist version="1.0">
    <key>Label</key>
    <string>net.dig.node</string>
</plist>
"#;
    let note = "all good";
"##;

/// A `'"'` char literal in shipping code: one quote, and not a literal opening.
const CHAR_LITERAL_QUOTE: &str = r##"
    let head = text.split([',', '"', '\n']).next();
    let note = "all good";
"##;

#[test]
fn a_run_joined_onto_one_line_is_caught() {
    assert_eq!(space_runs_in(JOINED_ONTO_ONE_LINE), vec![2]);
}

#[test]
fn a_literal_that_lost_its_continuation_is_caught_on_the_wrapped_line() {
    assert_eq!(space_runs_in(LOST_ITS_CONTINUATION), vec![3]);
}

#[test]
fn a_literal_that_lost_its_continuation_after_an_escape_is_caught() {
    assert_eq!(
        space_runs_in(LOST_ITS_CONTINUATION_AFTER_AN_ESCAPE),
        vec![3]
    );
}

#[test]
fn an_intact_continuation_ships_nothing_and_is_not_caught() {
    let caught = space_runs_in(INTACT_CONTINUATION);
    assert!(caught.is_empty(), "{caught:?}");
}

#[test]
fn indentation_written_inside_an_opening_quote_is_not_caught() {
    let caught = space_runs_in(DELIBERATE_BULLET_INDENT);
    assert!(caught.is_empty(), "{caught:?}");
}

#[test]
fn a_raw_string_template_is_not_caught_and_does_not_desynchronise_the_scan() {
    let caught = space_runs_in(RAW_STRING_TEMPLATE);
    assert!(caught.is_empty(), "{caught:?}");
}

#[test]
fn a_char_literal_quote_does_not_desynchronise_the_scan() {
    let caught = space_runs_in(CHAR_LITERAL_QUOTE);
    assert!(caught.is_empty(), "{caught:?}");
}
