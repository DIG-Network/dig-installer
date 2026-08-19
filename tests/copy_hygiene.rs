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

/// Whether `line` carries a run of spaces with sentence text on both sides.
///
/// Walked character by character rather than by index so the three legitimate space runs stay
/// invisible to it:
///
/// - **leading indentation** — nothing precedes it on the line, so no run is open yet;
/// - **the indentation after a `\` continuation** — likewise line-leading;
/// - **indentation deliberately written just inside an opening quote** (a log bullet's `"    · "`)
///   — an opening quote closes any run and reopens the line, so that indentation leads too.
///
/// A trailing `//` comment is not sentence text either, so scanning stops at one that falls
/// outside a literal — column-aligned end-of-line comments are a style, not a defect.
fn carries_a_space_run(line: &str) -> bool {
    let mut seen_text = false;
    let mut run = 0usize;
    let mut inside_literal = false;
    let mut previous = '\0';
    let mut was_slash = false;
    for ch in line.chars() {
        if ch == '"' && previous != '\\' {
            inside_literal = !inside_literal;
            seen_text = false;
            run = 0;
        } else if ch == '/' && was_slash && !inside_literal {
            return false;
        } else if ch == ' ' {
            run += usize::from(seen_text);
        } else if seen_text && run >= RUN_LIMIT {
            return true;
        } else {
            seen_text = true;
            run = 0;
        }
        was_slash = ch == '/';
        previous = ch;
    }
    false
}

#[test]
fn no_shipping_literal_carries_a_space_run() {
    let mut scanned = 0usize;
    let mut damaged: Vec<String> = Vec::new();
    for path in crate_sources() {
        let source = std::fs::read_to_string(&path).expect("a listed source file is readable");
        for (offset, line) in shipping_source(&source).lines().enumerate() {
            scanned += 1;
            if line.trim_start().starts_with("//") || !line.contains('"') {
                continue;
            }
            if carries_a_space_run(line) {
                let name = path
                    .file_name()
                    .unwrap_or(path.as_os_str())
                    .to_string_lossy();
                damaged.push(format!("{name}:{}: {}", offset + 1, line.trim()));
            }
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
