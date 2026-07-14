//! Migration of an EXISTING install off the legacy user-writable root onto the
//! admin-only protected root (#565).
//!
//! Before #565 the installer placed privileged, service/task-executed binaries
//! in a user-writable dir (`%LOCALAPPDATA%\Programs\{DIG,DigStore}\bin` on
//! Windows; `~/.dig/bin` on unix). This module re-points an existing install to
//! the protected root ([`crate::paths::protected_bin_dir`]) on a re-run, and
//! does so SAFELY — the cardinal rule is that it NEVER executes a binary from
//! the legacy (possibly attacker-replaced) dir while elevated:
//!
//! 1. **Deregister the moving self-registering services BY CANONICAL ID** (via
//!    [`crate::svc::deregister_service`] — `sc delete`/`systemctl disable`/
//!    `launchctl bootout`), so the subsequent normal install re-registers them
//!    fresh from the protected path. dig-node/dig-relay on Windows are the case
//!    that needs this: their own `install` verb is not idempotent and TOLERATES
//!    an "already exists" failure, which would otherwise leave the OLD
//!    registration pointing at the writable legacy binPath. (dig-dns re-points
//!    itself via its clean-reinstall; the beacon re-points itself when
//!    `dig-updater schedule install` re-runs from the new location.)
//! 2. **Remove the legacy binaries** — only KNOWN DIG filenames, one by one,
//!    never a recursive walk (which could follow a junction/reparse point a
//!    squatter planted). On Windows every DIG binary moves, so all are removed;
//!    on unix only the PRIVILEGED binaries move out of `~/.dig/bin` (the user
//!    CLIs legitimately stay there), so only those are removed.
//! 3. **Drop the legacy dir from the user PATH** (Windows) so a stale,
//!    user-writable entry can no longer SHADOW the new protected root.
//!
//! Runs BEFORE the normal install so the re-registration/placement lands on the
//! protected root; a re-registration failure afterward is surfaced fail-loud by
//! the readiness verdict (never a service left on the writable legacy path).
//!
//! Layering: the "which services / which binaries" decisions are PURE and
//! unit-tested ([`services_to_deregister`], [`legacy_removable_stems`],
//! [`crate::paths::path_remove`]); the scan/deregister/delete/PATH-rewrite I/O
//! is the thin imperative layer.

use std::path::{Path, PathBuf};

use crate::paths;
use crate::svc;
use crate::target::{Os, Target};
use crate::InstallPlan;

/// The record of a #565 legacy-root migration — part of the `--json`
/// [`crate::InstallReport`]. Never silent.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct MigrationResult {
    /// A legacy user-writable install was detected and migrated this run.
    pub migrated: bool,
    /// Services stopped + deregistered by id (re-registered fresh by the install).
    pub deregistered: Vec<String>,
    /// Legacy binary files removed from the user-writable root(s).
    pub removed_binaries: Vec<String>,
    /// Legacy bin dirs dropped from the user PATH (Windows).
    pub path_entries_removed: Vec<String>,
    /// Human-readable detail — never silent.
    pub notes: Vec<String>,
}

/// Every DIG binary stem the installer places. Used to scan a legacy root for
/// leftover DIG binaries (by [`Target::exe_name`]) without touching anything the
/// installer did not create.
pub const DIG_BINARY_STEMS: &[&str] = &[
    "digstore",
    "digs",
    "dig-node",
    "dign",
    "dig-dns",
    "digd",
    "dig-updater",
    "dig-updater-worker",
    "dig-relay",
    "dig-installer",
];

/// The DIG binary stems the migration REMOVES from a legacy root on `os`.
/// Windows: every stem moves to the single Program Files root, so all are
/// removed. unix: only the PRIVILEGED binaries move to `/opt/dig/bin` — the user
/// CLIs stay in `~/.dig/bin`, so they are left in place. Pure.
pub fn legacy_removable_stems(os: Os) -> Vec<&'static str> {
    match os {
        Os::Windows => DIG_BINARY_STEMS.to_vec(),
        Os::Linux | Os::MacOs => DIG_BINARY_STEMS
            .iter()
            .copied()
            .filter(|s| paths::is_privileged_component(os, s))
            .collect(),
    }
}

/// The self-registering services this `plan` will re-install onto the protected
/// root and therefore must DEREGISTER first so the re-`install` re-points them
/// (rather than tolerating an "already exists" that keeps the writable legacy
/// binPath) — as `(canonical id, human label)`. Pure.
///
/// Only dig-node/dig-relay ON WINDOWS qualify: their own `install` verb is
/// non-idempotent + tolerated-on-failure, and on Windows they move to Program
/// Files. dig-dns re-points itself via [`crate::dns`]'s clean-reinstall, and on
/// unix dig-node/dig-relay stay user-level in `~/.dig/bin` (they do not move),
/// so neither needs a forced deregistration.
pub fn services_to_deregister(os: Os, plan: &InstallPlan) -> Vec<(&'static str, &'static str)> {
    if os != Os::Windows {
        return Vec::new();
    }
    let mut out = Vec::new();
    if plan.with_dig_node {
        out.push((svc::DIG_NODE_SERVICE_ID, "dig-node"));
    }
    if plan.with_relay {
        out.push((svc::DIG_RELAY_SERVICE_ID, "dig-relay"));
    }
    out
}

/// The legacy roots to scan on `os`, EXCLUDING the current protected root (never
/// migrate the protected root off itself). Pure given the two path helpers.
fn legacy_roots_to_scan(os: Os) -> Vec<PathBuf> {
    let protected = paths::protected_bin_dir();
    paths::legacy_privileged_roots(os)
        .into_iter()
        .filter(|r| r != &protected)
        .collect()
}

/// Scan the legacy roots for leftover DIG binaries: for each existing legacy dir
/// (≠ the protected root), the removable DIG binary FILES present in it. Only
/// probes exact known filenames — never a directory walk (a squatter could plant
/// a junction/reparse point in a user-writable dir). I/O.
fn scan_legacy_binaries(target: &Target) -> Vec<PathBuf> {
    let mut present = Vec::new();
    for root in legacy_roots_to_scan(target.os) {
        if !root.is_dir() {
            continue;
        }
        for stem in legacy_removable_stems(target.os) {
            let candidate = root.join(target.exe_name(stem));
            // `symlink_metadata` does NOT traverse a reparse point/symlink — we
            // only ever act on a real file we ourselves would have written.
            if let Ok(md) = std::fs::symlink_metadata(&candidate) {
                if md.file_type().is_file() {
                    present.push(candidate);
                }
            }
        }
    }
    present
}

/// Migrate an existing install off the legacy user-writable root(s) onto the
/// protected root (#565). No-op (returns a `migrated: false` record) when no
/// legacy install is detected. Runs BEFORE the normal install so the
/// re-registration/placement lands on the protected root. Never executes a
/// legacy-dir binary; a failure to remove a stale binary is logged, not fatal.
pub fn migrate_from_legacy_roots(
    target: &Target,
    plan: &InstallPlan,
    log: &mut dyn FnMut(&str),
) -> MigrationResult {
    let mut result = MigrationResult::default();

    let legacy_binaries = scan_legacy_binaries(target);
    if legacy_binaries.is_empty() {
        return result;
    }
    result.migrated = true;
    log("Migrating an existing install off the user-writable legacy location (#565):");

    // 1. Deregister the moving self-registering services BY ID (never by running
    //    the legacy binary), so the install below re-registers them fresh from
    //    the protected path.
    for (id, label) in services_to_deregister(target.os, plan) {
        // Only bother if the service is actually registered.
        if svc::service_run_state(id) == svc::ServiceRunState::NotFound {
            continue;
        }
        match svc::deregister_service(id) {
            Ok(()) => {
                log(&format!(
                    "    ✓ deregistered the {label} service '{id}' (re-registered from the protected root below)"
                ));
                result.deregistered.push(id.to_string());
            }
            Err(e) => {
                let note = format!("could not fully deregister the {label} service '{id}': {e}");
                log(&format!("    ! {note}"));
                result.notes.push(note);
            }
        }
    }

    // 2. Remove the legacy binaries (known filenames only). They are re-placed
    //    at the protected root by the install that follows.
    for bin in &legacy_binaries {
        match std::fs::remove_file(bin) {
            Ok(()) => {
                log(&format!(
                    "    ✓ removed the legacy binary {}",
                    bin.display()
                ));
                result.removed_binaries.push(bin.display().to_string());
            }
            Err(e) => {
                let note = format!(
                    "could not remove the legacy binary {} ({e}); it is superseded by the copy in \
                     the protected root",
                    bin.display()
                );
                log(&format!("    ! {note}"));
                result.notes.push(note);
            }
        }
    }

    // 3. Drop the legacy dir(s) from the user PATH (Windows) so a stale,
    //    user-writable entry can no longer shadow the new protected root.
    if target.os == Os::Windows {
        for root in legacy_roots_to_scan(target.os) {
            match remove_from_user_path(&root) {
                Ok(true) => {
                    log(&format!(
                        "    ✓ removed the legacy dir from the user PATH: {}",
                        root.display()
                    ));
                    result.path_entries_removed.push(root.display().to_string());
                }
                Ok(false) => {}
                Err(e) => {
                    let note =
                        format!("could not update the user PATH for {}: {e}", root.display());
                    log(&format!("    ! {note}"));
                    result.notes.push(note);
                }
            }
        }
    }

    result
}

/// Remove `dir` from the user PATH (Windows HKCU\Environment\Path), via the pure
/// [`paths::path_remove`]. `Ok(true)` when an entry was removed, `Ok(false)`
/// when `dir` was not present. Windows-only I/O.
#[cfg(windows)]
fn remove_from_user_path(dir: &Path) -> Result<bool, String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_EXPAND_SZ};
    use winreg::{RegKey, RegValue};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (env, _) = hkcu
        .create_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
        .map_err(|e| format!("open HKCU\\Environment: {e}"))?;
    let current: String = env.get_value("Path").unwrap_or_default();
    match paths::path_remove(&current, &dir.to_string_lossy(), ';') {
        None => Ok(false),
        Some(new_path) => {
            let bytes = crate::paths::string_to_reg_expand_sz_bytes(&new_path);
            env.set_raw_value(
                "Path",
                &RegValue {
                    vtype: REG_EXPAND_SZ,
                    bytes,
                },
            )
            .map_err(|e| format!("write HKCU\\Environment\\Path: {e}"))?;
            crate::paths::broadcast_environment_change();
            Ok(true)
        }
    }
}

/// Non-Windows: no user-PATH registry to rewrite (the migration leaves unix
/// `~/.dig/bin` on PATH — the user CLIs legitimately stay there). Never called
/// on unix (the caller gates on `os == Windows`), but present so the module
/// compiles on every target.
#[cfg(not(windows))]
fn remove_from_user_path(_dir: &Path) -> Result<bool, String> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_all() -> InstallPlan {
        InstallPlan {
            with_relay: true,
            ..InstallPlan::default()
        }
    }

    #[test]
    fn windows_removes_every_dig_binary_stem() {
        // On Windows the whole stack moves to Program Files, so every DIG binary
        // in the legacy root is removed.
        let stems = legacy_removable_stems(Os::Windows);
        for s in DIG_BINARY_STEMS {
            assert!(
                stems.contains(s),
                "{s} must be removed from the legacy root on Windows"
            );
        }
    }

    #[test]
    fn unix_removes_only_the_privileged_binaries_leaving_the_user_clis() {
        for os in [Os::Linux, Os::MacOs] {
            let stems = legacy_removable_stems(os);
            // Privileged (moving) binaries are removed …
            for s in ["dig-dns", "dig-updater", "dig-updater-worker"] {
                assert!(stems.contains(&s), "{s} must be removed on {os:?}");
            }
            // … the user CLIs are left in ~/.dig/bin (they do not move).
            for s in ["digstore", "digs", "dig-node", "dign", "digd", "dig-relay"] {
                assert!(
                    !stems.contains(&s),
                    "{s} is a user CLI on {os:?} — must NOT be removed from ~/.dig/bin"
                );
            }
        }
    }

    #[test]
    fn deregisters_dig_node_and_relay_only_on_windows() {
        let plan = plan_all();
        let win = services_to_deregister(Os::Windows, &plan);
        let ids: Vec<&str> = win.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&svc::DIG_NODE_SERVICE_ID));
        assert!(ids.contains(&svc::DIG_RELAY_SERVICE_ID));
        // dig-dns is NOT force-deregistered here (it clean-reinstalls itself).
        assert!(!ids.contains(&svc::DIG_DNS_SERVICE_ID));
        // unix: nothing is force-deregistered (node/relay stay user-level; dns
        // self-reinstalls).
        assert!(services_to_deregister(Os::Linux, &plan).is_empty());
        assert!(services_to_deregister(Os::MacOs, &plan).is_empty());
    }

    #[test]
    fn deregister_list_follows_the_selected_components() {
        let node_only = InstallPlan {
            with_relay: false,
            ..InstallPlan::default()
        };
        let win = services_to_deregister(Os::Windows, &node_only);
        assert_eq!(win.len(), 1, "relay opted out → only dig-node");
        assert_eq!(win[0].0, svc::DIG_NODE_SERVICE_ID);

        let neither = InstallPlan {
            with_dig_node: false,
            with_relay: false,
            ..InstallPlan::default()
        };
        assert!(services_to_deregister(Os::Windows, &neither).is_empty());
    }

    #[test]
    fn legacy_roots_to_scan_never_includes_the_protected_root() {
        // The migration must never try to migrate the protected root off itself
        // (which would delete the freshly-installed binaries). It is excluded on
        // every OS.
        for os in [Os::Windows, Os::Linux, Os::MacOs] {
            let protected = paths::protected_bin_dir();
            assert!(
                !legacy_roots_to_scan(os).contains(&protected),
                "the protected root must never be a legacy scan target on {os:?}"
            );
        }
    }

    #[test]
    fn a_default_migration_result_is_a_clean_no_op() {
        // The no-legacy-install path returns this: nothing migrated, nothing
        // deregistered/removed. (The imperative `migrate_from_legacy_roots` is
        // NOT invoked in unit tests — it performs REAL service deregistration +
        // file removal against real dirs; its safety is exercised by the 3-OS
        // installer e2e job, per SPEC.)
        let result = MigrationResult::default();
        assert!(!result.migrated);
        assert!(result.deregistered.is_empty());
        assert!(result.removed_binaries.is_empty());
        assert!(result.path_entries_removed.is_empty());
    }

    #[test]
    fn migration_result_serializes_with_stable_fields() {
        let r = MigrationResult {
            migrated: true,
            deregistered: vec!["net.dignetwork.dig-node".into()],
            removed_binaries: vec![r"C:\old\dig-node.exe".into()],
            path_entries_removed: vec![r"C:\old".into()],
            notes: vec![],
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["migrated"], true);
        assert_eq!(v["deregistered"][0], "net.dignetwork.dig-node");
        assert_eq!(v["removed_binaries"][0], r"C:\old\dig-node.exe");
    }
}
