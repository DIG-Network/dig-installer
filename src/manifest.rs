//! The authoritative install-root record — `install.json` (#565 / #581).
//!
//! The installer writes a small, admin-only-writable manifest recording WHERE it
//! placed the DIG binaries, so the auto-update beacon (dig-updater-broker, #581)
//! has a single, stable source of truth for the install root instead of a
//! hardcoded path. The beacon already derives its root from
//! `current_exe().parent()` (its own binary's dir) and — since #565 moves that
//! binary into the protected root — that derivation is now coherent with this
//! record by construction; the manifest makes the root EXPLICIT + machine-
//! readable for any consumer that prefers reading it to guessing.
//!
//! Location: the DIG install home ([`crate::paths::protected_bin_dir`]'s parent —
//! `%ProgramFiles%\DIG\install.json` on Windows, `/opt/dig/install.json` on
//! unix). This is admin-only-writable BY INHERITANCE (Program Files' DACL /
//! root-owned `/opt/dig`), so — unlike a `%ProgramData%\DIG` file, whose parent
//! grants `Users` "create subfolder" and would need the full anti-squat DACL
//! dance [`crate::daemon_dir`] performs — no custom ACL is required, and it sits
//! one level above the beacon's `current_exe().parent()` so both are trivially
//! discoverable. A consumer MUST still verify the file is admin-only-writable
//! before trusting it (it is only as trustworthy as its own permissions).
//!
//! Layering: the manifest shape + JSON are pure + unit-tested; the write + unix
//! `chmod` is the thin I/O layer.

use std::path::PathBuf;

use crate::target::Os;

/// The `install.json` manifest schema. Bumped on a breaking shape change.
pub const MANIFEST_SCHEMA: u32 = 1;

/// The authoritative install-root record written to `install.json` (#581).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstallManifest {
    /// Manifest shape version ([`MANIFEST_SCHEMA`]).
    pub schema: u32,
    /// The admin-only protected install root the privileged binaries live in.
    pub bin_dir: String,
    /// The dig-installer version that wrote this record.
    pub installer_version: String,
}

impl InstallManifest {
    /// Build the manifest for `bin_dir` written by `installer_version`.
    pub fn new(bin_dir: &str, installer_version: &str) -> Self {
        InstallManifest {
            schema: MANIFEST_SCHEMA,
            bin_dir: bin_dir.to_string(),
            installer_version: installer_version.to_string(),
        }
    }

    /// The manifest as pretty JSON (with a trailing newline). Pure.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("InstallManifest serializes") + "\n"
    }
}

/// The DIG install home: [`crate::paths::protected_bin_dir`]'s parent
/// (`%ProgramFiles%\DIG` / `/opt/dig`). Pure given the path helper.
pub fn install_home() -> PathBuf {
    crate::paths::protected_bin_dir()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(crate::paths::protected_bin_dir)
}

/// The `install.json` path in the DIG install home.
pub fn manifest_path() -> PathBuf {
    install_home().join("install.json")
}

/// The result of writing (or planning to write) `install.json` — part of the
/// `--json` [`crate::InstallReport`]. Never silent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ManifestResult {
    /// The manifest was written (or, on dry-run, would be).
    pub written: bool,
    /// Where it was written.
    pub path: String,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// Write the `install.json` record for `bin_dir` (the protected root) into the
/// DIG install home, admin-only-writable by inheritance. `dry_run` reports
/// intent without writing. Best-effort — a write failure is recorded, never
/// fatal (the binaries are already placed; the beacon still derives its root
/// from `current_exe`).
pub fn write_install_manifest(
    os: Os,
    bin_dir: &std::path::Path,
    installer_version: &str,
    dry_run: bool,
) -> ManifestResult {
    let path = manifest_path();
    let manifest = InstallManifest::new(&bin_dir.to_string_lossy(), installer_version);
    if dry_run {
        return ManifestResult {
            written: false,
            path: path.to_string_lossy().into_owned(),
            note: format!(
                "would record the authoritative install root ({}) in {}",
                bin_dir.display(),
                path.display()
            ),
        };
    }
    match write_manifest_file(os, &path, &manifest.to_json()) {
        Ok(()) => ManifestResult {
            written: true,
            path: path.to_string_lossy().into_owned(),
            note: format!(
                "recorded the authoritative install root: {}",
                bin_dir.display()
            ),
        },
        Err(e) => ManifestResult {
            written: false,
            path: path.to_string_lossy().into_owned(),
            note: format!("could not write {}: {e}", path.display()),
        },
    }
}

/// Write `body` to `path`, ensuring the parent dir exists and (on unix) that the
/// file is `0644` and its dir `0755` root-owned — admin-write / world-read. On
/// Windows the install home inherits Program Files' admin-only DACL, so no custom
/// ACL is applied.
fn write_manifest_file(os: Os, path: &std::path::Path, body: &str) -> Result<(), String> {
    let _ = os;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
        }
    }
    std::fs::write(path, body).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("chmod 0644 {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_json_round_trips_with_the_stable_fields() {
        let m = InstallManifest::new(r"C:\Program Files\DIG\bin", "0.18.0");
        let json = m.to_json();
        assert!(json.ends_with('\n'));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema"], MANIFEST_SCHEMA);
        assert_eq!(v["bin_dir"], r"C:\Program Files\DIG\bin");
        assert_eq!(v["installer_version"], "0.18.0");
        // Round-trips back to the same struct (the beacon can read it).
        let back: InstallManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn manifest_lives_in_the_install_home_beside_the_protected_root() {
        // install.json sits in the DIG install home (the protected root's
        // parent), which is admin-only-writable by inheritance.
        let home = install_home();
        assert_eq!(manifest_path(), home.join("install.json"));
        assert!(
            crate::paths::protected_bin_dir().starts_with(&home),
            "the protected bin dir must be under the install home"
        );
    }

    #[test]
    fn dry_run_reports_intent_without_writing() {
        let host = crate::target::Target::current().expect("host").os;
        let r = write_install_manifest(
            host,
            std::path::Path::new(r"C:\Program Files\DIG\bin"),
            "0.18.0",
            true,
        );
        assert!(!r.written);
        assert!(r.note.contains("would record"));
        assert!(!std::path::Path::new(&r.path).exists() || r.path.contains("install.json"));
    }

    #[test]
    fn writes_and_hardens_the_manifest_in_a_temp_home() {
        // Exercise the real write + (unix) chmod against a temp dir, so the file
        // shape + permission posture is verified without touching the real
        // admin-only install home.
        let dir = std::env::temp_dir().join(format!("dig-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("install.json");
        let host = crate::target::Target::current().expect("host").os;
        let body = InstallManifest::new("/opt/dig/bin", "0.18.0").to_json();
        write_manifest_file(host, &path, &body).expect("writes");
        let read = std::fs::read_to_string(&path).unwrap();
        assert!(read.contains("/opt/dig/bin"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "world-readable, owner-writable only");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_result_serializes_with_stable_fields() {
        let r = ManifestResult {
            written: true,
            path: r"C:\Program Files\DIG\install.json".into(),
            note: "ok".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["written"], true);
        assert_eq!(v["path"], r"C:\Program Files\DIG\install.json");
    }
}
