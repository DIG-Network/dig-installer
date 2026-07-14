//! Post-install PATH verification (#496): confirm each required DIG CLI —
//! `digstore`, `dig-node`, `dig-dns` — actually RESOLVES by bare name from a
//! fresh shell, so a user can run e.g. `dig-node pair list` /
//! `dig-node pair approve <id>` immediately after installing.
//!
//! All three are placed in the SAME bin dir, which the installer adds to PATH;
//! this module makes that availability EXPLICIT + verified rather than merely
//! incidental. The check spawns each CLI **by bare name** with PATH augmented
//! to include the install bin dir (simulating the fresh shell the user will
//! open), so it proves name-resolution, not just that a file exists on disk. A
//! CLI that fails to resolve makes its component NOT ready (#493 fail-loud).
//!
//! Layering: [`augmented_path`] (the PATH string the fresh shell would carry)
//! is pure + unit-tested; [`cli_resolves`] performs the spawn.

use std::path::Path;
use std::process::Command;

use crate::proc::HideConsole;

/// The result of verifying one CLI resolves on PATH.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CliPathCheck {
    /// The CLI id (e.g. `dig-node`).
    pub cli: String,
    /// `true` iff the CLI ran (`<cli> --version` succeeded) resolved by bare
    /// name against the post-install PATH.
    pub resolved: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// The PATH value a freshly-opened shell would carry after the installer added
/// `bin_dir`: `current` with `bin_dir` guaranteed present (prepended if
/// absent, case-insensitively on Windows). Pure — the OS list separator is
/// supplied so the logic is unit-tested identically on every host.
pub fn augmented_path(current: &str, bin_dir: &str, sep: char) -> String {
    let bin_trimmed = bin_dir.trim_end_matches(['/', '\\']);
    let already = current.split(sep).any(|p| {
        let p = p.trim().trim_end_matches(['/', '\\']);
        #[cfg(windows)]
        {
            p.eq_ignore_ascii_case(bin_trimmed)
        }
        #[cfg(not(windows))]
        {
            p == bin_trimmed
        }
    });
    if already {
        return current.to_string();
    }
    if current.is_empty() {
        bin_dir.to_string()
    } else {
        format!("{bin_dir}{sep}{current}")
    }
}

/// Verify `<exe_name>` resolves by bare name and runs `--version`, using a PATH
/// that includes `bin_dir` (the fresh-shell PATH). `exe_name` is the on-disk
/// file name (`dig-node.exe` on Windows, `dig-node` elsewhere) — passed with no
/// directory component so the OS resolves it via PATH, exactly as a user's
/// shell would. Returns the trimmed `--version` output on success.
pub fn cli_resolves(bin_dir: &Path, exe_name: &str) -> Result<String, String> {
    let sep = if cfg!(windows) { ';' } else { ':' };
    let current = std::env::var("PATH").unwrap_or_default();
    let path = augmented_path(&current, &bin_dir.to_string_lossy(), sep);
    let out = Command::new(exe_name)
        .arg("--version")
        .env("PATH", &path)
        .hide_console()
        .output()
        .map_err(|e| format!("`{exe_name}` did not resolve on PATH ({e})"))?;
    if !out.status.success() {
        return Err(format!(
            "`{exe_name} --version` exited with {}",
            out.status.code().unwrap_or(-1)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn augmented_path_prepends_when_absent() {
        assert_eq!(
            augmented_path("/usr/bin:/bin", "/home/u/.dig/bin", ':'),
            "/home/u/.dig/bin:/usr/bin:/bin"
        );
    }

    #[test]
    fn augmented_path_is_idempotent_when_present() {
        assert_eq!(
            augmented_path("/home/u/.dig/bin:/usr/bin", "/home/u/.dig/bin", ':'),
            "/home/u/.dig/bin:/usr/bin"
        );
    }

    #[test]
    fn augmented_path_handles_empty() {
        assert_eq!(augmented_path("", "/opt/dig/bin", ':'), "/opt/dig/bin");
    }

    #[test]
    fn augmented_path_ignores_trailing_separator_dupes() {
        // A trailing-slash variant already on PATH must not be re-added.
        assert_eq!(
            augmented_path("/opt/dig/bin/:/usr/bin", "/opt/dig/bin", ':'),
            "/opt/dig/bin/:/usr/bin"
        );
    }

    #[cfg(windows)]
    #[test]
    fn augmented_path_is_case_insensitive_on_windows() {
        assert_eq!(
            augmented_path(
                r"C:\apps\DIGSTORE\BIN;C:\Windows",
                r"C:\Apps\DigStore\bin",
                ';'
            ),
            r"C:\apps\DIGSTORE\BIN;C:\Windows"
        );
    }

    #[test]
    fn cli_resolves_errors_for_a_missing_binary() {
        // A name that certainly is not on PATH must be reported as unresolved,
        // never panic (the fail-loud path depends on this).
        let dir = std::env::temp_dir();
        let err = cli_resolves(&dir, "definitely-not-a-real-dig-cli-xyz").unwrap_err();
        assert!(
            err.contains("did not resolve") || err.contains("exited"),
            "got: {err}"
        );
    }
}
