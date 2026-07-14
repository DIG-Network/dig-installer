//! Registration of the DIG auto-update beacon's daily scheduler artifact
//! (issue #514).
//!
//! `dig-updater` (`DIG-Network/dig-updater`) is a **transient** process: it
//! never runs as a resident daemon, it wakes once a day, verifies + installs
//! any new signed DIG release, and exits (its own SPEC §8.1). Something OUTSIDE
//! the beacon has to invoke it on that schedule — dig-updater ships that
//! machinery itself, behind `dig-updater schedule install|uninstall|status`
//! (a Windows Scheduled Task / systemd timer / macOS LaunchDaemon that runs
//! `dig-updater run` daily, per its own `dig_updater_broker::scheduler`). This
//! installer therefore does **not** hand-roll a second scheduler: after
//! placing the `dig-updater` (+ sibling `dig-updater-worker`) binaries, it
//! simply asks the freshly-installed `dig-updater` binary to register its own
//! schedule against itself (`std::env::current_exe()`), exactly as
//! [`crate::service::install_service`] delegates to dig-node's own
//! `install`/`start` verbs rather than reimplementing OS service control.
//!
//! This is a **first-class, toggleable install option** — `InstallPlan::auto_update`
//! — default ON, in the same "opens a default-on door, always safe to decline"
//! posture as [`crate::firewall`]/[`crate::scheme`]: a user who declines it (or
//! whose registration fails) simply never gets auto-updates and re-runs the
//! installer manually to pick up new versions.
//!
//! Registering a SYSTEM/root-run daily schedule is itself a privileged
//! operation — the same elevation `dig-node`/`dig-dns`/`dig-relay` service
//! registration already requires (`InstallPlan::requires_elevation`).

use std::path::Path;

use crate::service::run_capturing;

/// The outcome of registering (or removing) the beacon's daily scheduler
/// artifact — mirrors [`crate::firewall::FirewallResult`]: never silent,
/// `applied` says whether THIS call changed the OS scheduler state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BeaconResult {
    /// Whether the schedule command actually ran to a zero exit. `dig-updater
    /// schedule install`/`uninstall` are themselves idempotent (a re-install
    /// overwrites the existing artifact; an uninstall of an absent artifact
    /// still exits zero — SPEC §8.2), so unlike the firewall rule this is
    /// `true` on every successful call, not only a genuine state transition.
    /// `false` on dry-run or a real failure — `note` always explains which.
    pub applied: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// Register the beacon's daily scheduler artifact by delegating to
/// `<dig_updater_bin> schedule install`. Never panics/aborts the overall
/// install — a failure is recorded in the result's `note`, mirroring every
/// other best-effort registration step in this crate. `dry_run` reports
/// intent without spawning anything.
pub fn register(dig_updater_bin: &Path, dry_run: bool) -> BeaconResult {
    if dry_run {
        return BeaconResult {
            applied: false,
            note: "would run `dig-updater schedule install` to register the daily \
                   update-check scheduler"
                .to_string(),
        };
    }
    run_schedule(dig_updater_bin, "install", "registered")
}

/// Remove the beacon's daily scheduler artifact by delegating to
/// `<dig_updater_bin> schedule uninstall`. Idempotent — dig-updater's own
/// `uninstall` verb treats an already-absent artifact as success, not an
/// error (SPEC §8.2). `dry_run` reports intent without spawning anything.
pub fn unregister(dig_updater_bin: &Path, dry_run: bool) -> BeaconResult {
    if dry_run {
        return BeaconResult {
            applied: false,
            note: "would run `dig-updater schedule uninstall` to remove the daily \
                   update-check scheduler (if present)"
                .to_string(),
        };
    }
    run_schedule(dig_updater_bin, "uninstall", "removed")
}

/// Spawn `<bin> schedule <action>`, capturing stdio (never inheriting — see
/// [`crate::service::run_dig_node`] for why: a raw child write would corrupt
/// this installer's own `--json` contract). `verb` is the past-tense word used
/// in the success note (`"registered"`/`"removed"`).
fn run_schedule(bin: &Path, action: &str, verb: &str) -> BeaconResult {
    let args = vec!["schedule".to_string(), action.to_string()];
    match run_capturing(bin, &args, &std::collections::BTreeMap::new()) {
        Ok(()) => BeaconResult {
            applied: true,
            note: format!("{verb} the daily update-check scheduler"),
        },
        Err(e) => BeaconResult {
            applied: false,
            note: format!("could not run `dig-updater schedule {action}`: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A harmless stub binary that exits 0 (`success = true`) or non-zero
    /// (`success = false`), ignoring its args — drives `register`/`unregister`'s
    /// spawn + result-assembly logic without registering a real OS schedule.
    /// Mirrors `service::tests::stub_exit` (see its doc comment for the
    /// `ETXTBSY` write-then-exec race this dodges on unix by pointing at a
    /// pre-existing system binary instead of a freshly written script).
    #[cfg(windows)]
    fn stub_exit(dir: &std::path::Path, success: bool) -> std::path::PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(if success { "ok.cmd" } else { "fail.cmd" });
        let code = if success { 0 } else { 1 };
        std::fs::write(&p, format!("@echo off\r\nexit /b {code}\r\n")).unwrap();
        p
    }

    #[cfg(not(windows))]
    fn stub_exit(_dir: &std::path::Path, success: bool) -> std::path::PathBuf {
        let base = if success { "true" } else { "false" };
        for cand in [format!("/bin/{base}"), format!("/usr/bin/{base}")] {
            let p = std::path::PathBuf::from(&cand);
            if p.exists() {
                return p;
            }
        }
        std::path::PathBuf::from(format!("/bin/{base}"))
    }

    fn tmp_subdir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("dig-installer-beacon-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn register_dry_run_reports_intent_without_spawning() {
        let r = register(
            &std::path::PathBuf::from("/definitely/not/a/real/dig-updater"),
            true,
        );
        assert!(!r.applied);
        assert!(r.note.contains("would run"));
        assert!(r.note.contains("schedule install"));
    }

    #[test]
    fn unregister_dry_run_reports_intent_without_spawning() {
        let r = unregister(
            &std::path::PathBuf::from("/definitely/not/a/real/dig-updater"),
            true,
        );
        assert!(!r.applied);
        assert!(r.note.contains("would run"));
        assert!(r.note.contains("schedule uninstall"));
    }

    #[test]
    fn register_succeeds_when_the_binary_exits_zero() {
        let dir = tmp_subdir("register-ok");
        let bin = stub_exit(&dir, true);
        let r = register(&bin, false);
        assert!(r.applied);
        assert!(r.note.contains("registered"), "got: {}", r.note);
    }

    #[test]
    fn register_surfaces_a_nonzero_exit() {
        let dir = tmp_subdir("register-fail");
        let bin = stub_exit(&dir, false);
        let r = register(&bin, false);
        assert!(!r.applied);
        assert!(r.note.contains("could not run"), "got: {}", r.note);
    }

    #[test]
    fn unregister_succeeds_when_the_binary_exits_zero() {
        let dir = tmp_subdir("unregister-ok");
        let bin = stub_exit(&dir, true);
        let r = unregister(&bin, false);
        assert!(r.applied);
        assert!(r.note.contains("removed"), "got: {}", r.note);
    }

    #[test]
    fn unregister_surfaces_a_nonzero_exit() {
        let dir = tmp_subdir("unregister-fail");
        let bin = stub_exit(&dir, false);
        let r = unregister(&bin, false);
        assert!(!r.applied);
        assert!(r.note.contains("could not run"), "got: {}", r.note);
    }

    #[test]
    fn register_errors_when_the_binary_is_missing() {
        let missing = std::env::temp_dir().join("definitely-not-a-real-dig-updater-binary-xyz");
        let r = register(&missing, false);
        assert!(!r.applied);
        assert!(r.note.contains("could not run"), "got: {}", r.note);
    }

    #[test]
    fn beacon_result_serializes_with_stable_fields() {
        let r = BeaconResult {
            applied: true,
            note: "ok".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["applied"], true);
        assert_eq!(v["note"], "ok");
    }
}
