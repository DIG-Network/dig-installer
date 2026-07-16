//! Professional install hardening (#573): a Windows Add/Remove Programs (ARP)
//! entry, service auto-recovery configuration, install rollback on partial
//! failure, and a post-install health verification across components.
//!
//! These make the install behave like a well-behaved native package:
//!   * it shows up in **Add/Remove Programs** with a working Uninstall button
//!     (whose command is the #568 whole-stack `uninstall`),
//!   * its services **auto-recover** if they crash (SCM failure actions),
//!   * a **partial-failure install rolls back** cleanly — never a half-written
//!     install (the #544 half-write lesson),
//!   * a **post-install health verify** fails LOUDLY if any component is down.
//!
//! Every value/argument builder here is pure and unit-tested; the registry/SCM
//! writes are the thin I/O layer.

use serde::Serialize;

// ---------------------------------------------------------------------------
// Add/Remove Programs (ARP) entry
// ---------------------------------------------------------------------------

/// The `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` subkey the
/// installer registers under (a stable, DIG-owned key name). Reading/removing
/// only THIS key never touches another product's ARP entry.
pub const ARP_KEY: &str = "DIG_Network";

/// The product display name shown in Add/Remove Programs.
pub const ARP_DISPLAY_NAME: &str = "DIG Network";

/// The publisher shown in Add/Remove Programs.
pub const ARP_PUBLISHER: &str = "DIG Network";

/// The values written under the ARP subkey. Pure data — the Windows registry
/// write is the I/O layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArpEntry {
    pub display_name: String,
    pub display_version: String,
    pub publisher: String,
    /// The command Add/Remove Programs runs on "Uninstall" — the #568 whole-stack
    /// `uninstall` on this installer's persisted binary. Quoted so a spaced path
    /// (Program Files) is one argument; no shell wrapper.
    pub uninstall_string: String,
    /// The install root shown as `InstallLocation`.
    pub install_location: String,
    /// ARP flags: DIG has no in-place modify/repair UI, so both are 1.
    pub no_modify: u32,
    pub no_repair: u32,
}

/// Build the ARP entry values for a given installed version, installer binary
/// path, and install root. The Uninstall button invokes the #568 whole-stack
/// `uninstall` — the ARP entry and the uninstall command are the same contract.
/// Pure.
pub fn arp_entry(
    version: &str,
    installer_bin: &std::path::Path,
    install_root: &std::path::Path,
) -> ArpEntry {
    ArpEntry {
        display_name: ARP_DISPLAY_NAME.to_string(),
        display_version: version.to_string(),
        publisher: ARP_PUBLISHER.to_string(),
        uninstall_string: format!("\"{}\" --uninstall", installer_bin.display()),
        install_location: install_root.display().to_string(),
        no_modify: 1,
        no_repair: 1,
    }
}

// ---------------------------------------------------------------------------
// Service auto-recovery (SCM failure actions)
// ---------------------------------------------------------------------------

/// The Windows `sc.exe failure <service>` arguments that configure a service to
/// **restart automatically** on crash: restart after 5s for the first two
/// failures, then take no action, with the failure counter resetting daily.
/// Pure — the `sc` invocation is the I/O layer.
///
/// `reset=86400` (1 day) + `actions=restart/5000/restart/5000/""/5000` is the
/// standard "self-heal a crashed service without hammering a hard-down one"
/// policy.
pub fn windows_service_recovery_args(service_name: &str) -> Vec<String> {
    vec![
        "failure".to_string(),
        service_name.to_string(),
        "reset=86400".to_string(),
        "actions=restart/5000/restart/5000//5000".to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Install rollback
// ---------------------------------------------------------------------------

/// One reversible action taken during an install, recorded so it can be undone
/// on failure. The variants name WHAT was created; the rollback reverses each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum InstallAction {
    /// A file was written at this path (undo = delete it).
    FileCreated(String),
    /// A service was registered by this name (undo = deregister it).
    ServiceRegistered(String),
    /// The ARP entry was written (undo = delete the subkey).
    ArpEntryWritten,
    /// The URL-scheme handlers were registered (undo = unregister them).
    SchemeRegistered,
}

/// Records the actions an install performed and, on failure, reverses them in
/// **LIFO order** so the system is returned to a clean pre-install state — never
/// a half-written install (the #544 half-write lesson).
///
/// The guard is filled as each step succeeds. On overall success the caller
/// [`commit`](Self::commit)s it (the actions stand). On failure the caller
/// [`rollback`](Self::rollback)s, which invokes the injected undo for each
/// recorded action, newest first.
#[derive(Debug, Default)]
pub struct RollbackGuard {
    actions: Vec<InstallAction>,
    committed: bool,
}

/// The outcome of a rollback: every action attempted (LIFO), and any undo that
/// itself failed (so a rollback failure is never silent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RollbackReport {
    /// The actions reversed, newest-first.
    pub reversed: Vec<InstallAction>,
    /// Undo failures (empty = a clean rollback to a pristine state).
    pub failures: Vec<String>,
}

impl RollbackReport {
    /// The rollback fully restored a clean state (no undo failed).
    pub fn clean(&self) -> bool {
        self.failures.is_empty()
    }
}

impl RollbackGuard {
    /// Start a fresh guard with no recorded actions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed, reversible install action.
    pub fn record(&mut self, action: InstallAction) {
        self.actions.push(action);
    }

    /// Mark the install successful — the recorded actions stand and a later
    /// drop/rollback is a no-op.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Was the guard committed (install succeeded)?
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// The actions recorded so far, oldest-first (as performed).
    pub fn actions(&self) -> &[InstallAction] {
        &self.actions
    }

    /// Reverse every recorded action in LIFO order via `undo`, returning a
    /// report. A committed guard reverses nothing. `undo(action)` returns
    /// `Ok(())` on a successful reversal or `Err(msg)` to record a failure —
    /// rollback continues reversing the rest regardless, so one stuck undo never
    /// strands the earlier actions.
    pub fn rollback(
        &self,
        undo: &mut dyn FnMut(&InstallAction) -> Result<(), String>,
    ) -> RollbackReport {
        let mut reversed = Vec::new();
        let mut failures = Vec::new();
        if self.committed {
            return RollbackReport { reversed, failures };
        }
        for action in self.actions.iter().rev() {
            match undo(action) {
                Ok(()) => reversed.push(action.clone()),
                Err(e) => failures.push(format!("{action:?}: {e}")),
            }
        }
        RollbackReport { reversed, failures }
    }
}

// ---------------------------------------------------------------------------
// Post-install health verification
// ---------------------------------------------------------------------------

/// One component's post-install health outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentHealth {
    pub component: String,
    pub healthy: bool,
    pub note: String,
}

/// The aggregate post-install health verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthVerifyReport {
    pub components: Vec<ComponentHealth>,
}

impl HealthVerifyReport {
    /// True iff EVERY verified component is healthy. A single down component
    /// fails the verify LOUDLY (the caller surfaces it, never a silent pass).
    pub fn all_healthy(&self) -> bool {
        self.components.iter().all(|c| c.healthy)
    }

    /// The names of any unhealthy components (for a clear failure message).
    pub fn unhealthy(&self) -> Vec<&str> {
        self.components
            .iter()
            .filter(|c| !c.healthy)
            .map(|c| c.component.as_str())
            .collect()
    }
}

/// Aggregate per-component health outcomes into a verify report. Pure — the
/// caller performs the actual probes (e.g. [`crate::health::wait_for_node_health`])
/// and feeds the results here.
pub fn verify_components(components: Vec<ComponentHealth>) -> HealthVerifyReport {
    HealthVerifyReport { components }
}

// ---------------------------------------------------------------------------
// I/O layer (Windows registry + SCM). Thin wrappers over the pure builders
// above; best-effort — a failure is returned, never panics.
// ---------------------------------------------------------------------------

/// The full `HKLM` path to the DIG ARP subkey (relative to `HKEY_LOCAL_MACHINE`).
const ARP_SUBKEY_PATH: &str =
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\DIG_Network";

/// Write the Add/Remove Programs entry (Windows). Requires elevation (HKLM).
/// Best-effort — returns a note; a failure never aborts the install.
#[cfg(windows)]
pub fn write_arp_entry(entry: &ArpEntry) -> Result<String, String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_WRITE};
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey_with_flags(ARP_SUBKEY_PATH, KEY_WRITE)
        .map_err(|e| format!("create ARP subkey: {e} (needs elevation)"))?;
    key.set_value("DisplayName", &entry.display_name)
        .and_then(|_| key.set_value("DisplayVersion", &entry.display_version))
        .and_then(|_| key.set_value("Publisher", &entry.publisher))
        .and_then(|_| key.set_value("UninstallString", &entry.uninstall_string))
        .and_then(|_| key.set_value("InstallLocation", &entry.install_location))
        .and_then(|_| key.set_value("NoModify", &entry.no_modify))
        .and_then(|_| key.set_value("NoRepair", &entry.no_repair))
        .map_err(|e| format!("write ARP values: {e}"))?;
    Ok(format!(
        "registered '{}' in Add/Remove Programs",
        entry.display_name
    ))
}

/// Remove the DIG ARP entry (Windows). Idempotent — absent is a clean no-op.
#[cfg(windows)]
pub fn remove_arp_entry() -> Result<String, String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.delete_subkey_all(ARP_SUBKEY_PATH) {
        Ok(()) => Ok("removed the Add/Remove Programs entry".into()),
        Err(_) => Ok("Add/Remove Programs entry already absent".into()),
    }
}

/// Configure a Windows service to auto-restart on crash via `sc.exe failure`.
/// Best-effort — returns a note; a failure never aborts the install.
#[cfg(windows)]
pub fn configure_service_recovery(service_name: &str) -> Result<String, String> {
    use crate::proc::HideConsole;
    use std::process::Command;
    let args = windows_service_recovery_args(service_name);
    let status = Command::new("sc")
        .args(&args)
        .hide_console()
        .status()
        .map_err(|e| format!("run sc failure: {e}"))?;
    if status.success() {
        Ok(format!("{service_name}: auto-recovery configured"))
    } else {
        Err(format!(
            "sc failure {service_name} exited with {:?}",
            status.code()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn arp_uninstall_string_invokes_the_whole_stack_uninstall() {
        let e = arp_entry(
            "0.26.0",
            &PathBuf::from(r"C:\Program Files\DIG\dig-installer.exe"),
            &PathBuf::from(r"C:\Program Files\DIG"),
        );
        assert_eq!(
            e.uninstall_string,
            r#""C:\Program Files\DIG\dig-installer.exe" --uninstall"#
        );
        assert!(e.uninstall_string.contains("--uninstall"));
        assert_eq!(e.display_version, "0.26.0");
        assert_eq!(e.display_name, "DIG Network");
        assert_eq!(e.no_modify, 1);
        assert_eq!(e.no_repair, 1);
    }

    #[test]
    fn service_recovery_args_configure_auto_restart_with_daily_reset() {
        let args = windows_service_recovery_args("dig-node");
        assert_eq!(args[0], "failure");
        assert_eq!(args[1], "dig-node");
        assert!(args.iter().any(|a| a == "reset=86400"));
        assert!(args.iter().any(|a| a.starts_with("actions=restart")));
    }

    #[test]
    fn rollback_reverses_actions_in_lifo_order() {
        let mut guard = RollbackGuard::new();
        guard.record(InstallAction::FileCreated("a".into()));
        guard.record(InstallAction::ServiceRegistered("dig-node".into()));
        guard.record(InstallAction::SchemeRegistered);

        let mut order = Vec::new();
        let report = guard.rollback(&mut |a| {
            order.push(format!("{a:?}"));
            Ok(())
        });
        assert!(report.clean());
        assert_eq!(report.reversed.len(), 3);
        // LIFO: scheme (last recorded) reversed first, file (first recorded) last.
        assert_eq!(order[0], format!("{:?}", InstallAction::SchemeRegistered));
        assert_eq!(
            order[2],
            format!("{:?}", InstallAction::FileCreated("a".into()))
        );
    }

    #[test]
    fn committed_guard_reverses_nothing() {
        let mut guard = RollbackGuard::new();
        guard.record(InstallAction::FileCreated("a".into()));
        guard.commit();
        assert!(guard.is_committed());
        let report = guard.rollback(&mut |_| panic!("must not undo a committed install"));
        assert!(report.reversed.is_empty());
        assert!(report.clean());
    }

    #[test]
    fn rollback_continues_past_a_failed_undo_and_reports_it() {
        // The #544 lesson: one stuck undo must not strand the earlier actions —
        // rollback keeps going and surfaces the failure, never a half-removed state.
        let mut guard = RollbackGuard::new();
        guard.record(InstallAction::FileCreated("a".into()));
        guard.record(InstallAction::ServiceRegistered("dig-node".into()));
        guard.record(InstallAction::FileCreated("b".into()));

        let report = guard.rollback(&mut |a| match a {
            InstallAction::ServiceRegistered(_) => Err("service busy".into()),
            _ => Ok(()),
        });
        assert!(!report.clean(), "a failed undo must not report clean");
        assert_eq!(report.failures.len(), 1);
        // The two file deletes still happened despite the middle failure.
        assert_eq!(report.reversed.len(), 2);
    }

    #[test]
    fn health_verify_fails_loudly_when_any_component_is_down() {
        let report = verify_components(vec![
            ComponentHealth {
                component: "dig-node".into(),
                healthy: true,
                note: "ok".into(),
            },
            ComponentHealth {
                component: "dig-dns".into(),
                healthy: false,
                note: "no response on :53".into(),
            },
        ]);
        assert!(!report.all_healthy());
        assert_eq!(report.unhealthy(), vec!["dig-dns"]);
    }

    #[test]
    fn health_verify_passes_when_all_components_up() {
        let report = verify_components(vec![ComponentHealth {
            component: "dig-node".into(),
            healthy: true,
            note: "ok".into(),
        }]);
        assert!(report.all_healthy());
        assert!(report.unhealthy().is_empty());
    }

    #[test]
    fn reports_serialize_with_stable_fields() {
        let arp: serde_json::Value = serde_json::to_value(arp_entry(
            "1.0.0",
            &PathBuf::from("/x/dig-installer"),
            &PathBuf::from("/x"),
        ))
        .unwrap();
        assert_eq!(arp["display_name"], "DIG Network");
        assert_eq!(arp["no_modify"], 1);

        let rb: serde_json::Value = serde_json::to_value(RollbackReport {
            reversed: vec![InstallAction::SchemeRegistered],
            failures: vec![],
        })
        .unwrap();
        assert!(rb["reversed"].is_array());
    }
}
