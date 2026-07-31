//! The headless uninstall entrypoint for the GUI executable (#854).
//!
//! Windows' Add/Remove Programs runs the persisted installer with `--uninstall`.
//! That persisted binary is THIS Tauri executable, which is built with
//! `windows_subsystem = "windows"` and therefore has no console to print to — so
//! the run is transcribed to a log file and its outcome is carried by the
//! process exit code.
//!
//! The teardown itself is not reimplemented here: it delegates to the CLI
//! library's already-tested [`dig_installer::uninstall_all`], so both entrypoints
//! share one orchestration rather than drifting into two.

use std::io::Write;
use std::path::PathBuf;

use crate::cli::Intent;

/// Run the whole-stack teardown described by `intent` and return the process
/// exit code: success only when every step reached its end-state AND the
/// post-run inventory found no residue.
///
/// Never panics — a log-file failure degrades to a silent-but-correct uninstall
/// rather than aborting the teardown the user asked for.
pub fn run_uninstall(intent: Intent) -> i32 {
    let Intent::Uninstall { dry_run } = intent else {
        return 0;
    };

    let mut transcript = Transcript::open();
    let bin_dir = dig_installer::paths::default_bin_dir();
    let browser_ids: Vec<String> = dig_installer::browsers::detect_installed()
        .into_iter()
        .map(|b| b.id)
        .collect();

    let report = dig_installer::uninstall_all(&bin_dir, &browser_ids, dry_run, &mut |line| {
        transcript.write_line(line);
    });

    if report.complete() {
        transcript.write_line("uninstall: complete — no residue");
        return 0;
    }
    for item in &report.residue {
        transcript.write_line(&format!("uninstall: residue {item}"));
    }
    1
}

/// A best-effort log file for a windowed process that has nowhere to print.
///
/// Written under the OS temp directory, which on an elevated ARP-launched run is
/// the administrator/SYSTEM temp. It is only ever WRITTEN to and never executed
/// or read back as input, so it introduces no exec-from-writable-path exposure
/// (the #1748 class).
struct Transcript(Option<std::fs::File>);

impl Transcript {
    fn open() -> Self {
        let path: PathBuf =
            std::env::temp_dir().join(format!("dig-uninstall-{}.log", std::process::id()));
        Self(std::fs::File::create(path).ok())
    }

    fn write_line(&mut self, line: &str) {
        if let Some(file) = self.0.as_mut() {
            let _ = writeln!(file, "{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `run_uninstall` is the teardown entrypoint; handed the GUI intent it must
    /// do nothing at all. Without this arm a `run_uninstall` that unconditionally
    /// tore the machine down would still satisfy every caller-side test.
    #[test]
    fn the_gui_intent_tears_nothing_down_and_succeeds() {
        assert_eq!(run_uninstall(Intent::Gui), 0);
    }
}
