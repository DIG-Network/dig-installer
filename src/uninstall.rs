//! The first-class `uninstall` orchestrator (#568): one command that removes
//! the ENTIRE DIG install and leaves ZERO residue.
//!
//! Before this, teardown was a set of piecemeal flags (`--uninstall-dig-node`,
//! `--uninstall-dig-dns`, `--unregister-scheme`, `--uninstall-dig-updater`) that
//! a user had to run one by one and could easily leave half-removed. `uninstall`
//! composes them into a single ordered, idempotent orchestration that:
//!
//!   1. stops + deregisters ALL services (dig-node, dig-relay, dig-dns),
//!   2. removes the auto-update beacon's scheduler registration,
//!   3. unregisters the dig/chia/urn URL-scheme handlers,
//!   4. removes the dig.local hosts entry + the peer firewall rule,
//!   5. deletes ALL installed binaries (both bin roots),
//!   6. asks the GUI backend to unconfigure the browser extension forcelist
//!      (#612/#648) where a GUI install configured it,
//!
//! then re-scans and reports any residue.
//!
//! ## Hard invariants
//!
//! * **Idempotent.** Every step treats "already absent" as success, so a second
//!   `uninstall` run is a clean no-op — never an error.
//! * **Zero residue.** After a real run [`UninstallReport::complete`] is true iff
//!   the post-run inventory finds nothing left; a residual item is reported, not
//!   hidden.
//! * **Never delete pre-existing org policy.** Machine-wide policy the installer
//!   did NOT create — an admin's DNS configuration, an enterprise browser policy,
//!   a foreign scheme handler — is left untouched (each underlying step only
//!   removes DIG-owned entries; this orchestrator never widens that scope).
//!
//! The ordering + report accounting is a pure core (unit-tested with injected
//! step outcomes); the real teardown wires the existing per-component functions.

use serde::Serialize;

/// Every component stem the installer may place, listed in TEARDOWN order:
/// service/scheduler-backed components first (so a running service is never left
/// pointing at a binary we already deleted), then the user CLIs, then the
/// installer's own persisted copy last. Binary deletion walks this list against
/// both bin roots.
pub const COMPONENT_STEMS: &[&str] = &[
    "dig-node",
    "dign",
    "dig-relay",
    "dig-dns",
    "dig-updater",
    "dig-updater-worker",
    "digstore",
    "digs",
    "digd",
    "dig-installer",
];

/// One teardown step's outcome. Never silent — `note` always explains what
/// happened (removed / already-absent / needs-elevation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UninstallStep {
    /// A stable, machine-readable step id (e.g. `"services"`, `"scheme"`).
    pub id: String,
    /// Did the step reach its desired end-state (removed OR already absent)?
    pub ok: bool,
    /// Human-readable detail.
    pub note: String,
}

/// The structured result of an `uninstall` run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UninstallReport {
    /// The ordered steps performed.
    pub steps: Vec<UninstallStep>,
    /// Anything the post-run inventory still found (empty on a clean uninstall).
    pub residue: Vec<String>,
    /// Whether this was a dry-run (intent only, nothing touched).
    pub dry_run: bool,
}

impl UninstallReport {
    fn new(dry_run: bool) -> Self {
        Self {
            steps: Vec::new(),
            residue: Vec::new(),
            dry_run,
        }
    }

    fn record(&mut self, id: &str, ok: bool, note: impl Into<String>) {
        self.steps.push(UninstallStep {
            id: id.to_string(),
            ok,
            note: note.into(),
        });
    }

    /// A clean uninstall: every step reached its end-state AND the post-run
    /// inventory found no residue. On a dry-run this reflects the PLAN's
    /// success, not an actual removal.
    pub fn complete(&self) -> bool {
        self.residue.is_empty() && self.steps.iter().all(|s| s.ok)
    }
}

/// The set of side-effecting teardown actions, injected so the orchestration
/// order + report accounting can be unit-tested without touching the OS. The
/// production implementation ([`SystemActions`]) wires the existing
/// per-component functions; tests supply a fake that records calls.
///
/// Every method returns `(ok, note)` where `ok` means "reached the desired
/// end-state (removed or already-absent)" — an idempotent second run returns
/// `true` with an "already absent" note, never an error.
pub trait UninstallActions {
    /// Stop + deregister all DIG services (dig-node, dig-relay, dig-dns).
    fn stop_services(&mut self) -> (bool, String);
    /// Remove the auto-update beacon's scheduler registration.
    fn remove_beacon(&mut self) -> (bool, String);
    /// Unregister the dig/chia/urn URL-scheme handlers (DIG-owned only).
    fn unregister_scheme(&mut self) -> (bool, String);
    /// Remove the dig.local hosts entry + the peer firewall rule.
    fn remove_network_config(&mut self) -> (bool, String);
    /// Delete all installed DIG binaries from both bin roots.
    fn delete_binaries(&mut self) -> (bool, String);
    /// Ask the GUI backend to unconfigure the extension forcelist (#612/#648).
    fn unconfigure_forcelist(&mut self) -> (bool, String);
    /// Re-scan for anything still present; the returned strings are the residue.
    fn scan_residue(&mut self) -> Vec<String>;
}

/// Run the full uninstall orchestration against `actions`, in the fixed teardown
/// order, producing a structured [`UninstallReport`]. Pure control flow — all
/// side effects go through `actions`, so this is unit-tested directly.
///
/// `dry_run` is recorded on the report; in a real dry-run the injected
/// `actions` are the no-op/intent variants, so this function's control flow is
/// identical either way.
pub fn orchestrate(actions: &mut dyn UninstallActions, dry_run: bool) -> UninstallReport {
    let mut report = UninstallReport::new(dry_run);

    let (ok, note) = actions.stop_services();
    report.record("services", ok, note);

    let (ok, note) = actions.remove_beacon();
    report.record("beacon", ok, note);

    let (ok, note) = actions.unregister_scheme();
    report.record("scheme", ok, note);

    let (ok, note) = actions.remove_network_config();
    report.record("network", ok, note);

    // Binaries are deleted only AFTER their services/schedulers are gone, so a
    // live service never points at a deleted binary mid-teardown.
    let (ok, note) = actions.delete_binaries();
    report.record("binaries", ok, note);

    let (ok, note) = actions.unconfigure_forcelist();
    report.record("forcelist", ok, note);

    report.residue = actions.scan_residue();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake that records the call order and returns scripted outcomes.
    #[derive(Default)]
    struct FakeActions {
        calls: Vec<String>,
        residue: Vec<String>,
        fail_step: Option<String>,
    }

    impl FakeActions {
        fn outcome(&mut self, id: &str) -> (bool, String) {
            self.calls.push(id.to_string());
            let ok = self.fail_step.as_deref() != Some(id);
            (
                ok,
                format!("{id}: {}", if ok { "removed" } else { "FAILED" }),
            )
        }
    }

    impl UninstallActions for FakeActions {
        fn stop_services(&mut self) -> (bool, String) {
            self.outcome("services")
        }
        fn remove_beacon(&mut self) -> (bool, String) {
            self.outcome("beacon")
        }
        fn unregister_scheme(&mut self) -> (bool, String) {
            self.outcome("scheme")
        }
        fn remove_network_config(&mut self) -> (bool, String) {
            self.outcome("network")
        }
        fn delete_binaries(&mut self) -> (bool, String) {
            self.outcome("binaries")
        }
        fn unconfigure_forcelist(&mut self) -> (bool, String) {
            self.outcome("forcelist")
        }
        fn scan_residue(&mut self) -> Vec<String> {
            self.calls.push("scan".to_string());
            self.residue.clone()
        }
    }

    #[test]
    fn tears_down_services_before_deleting_binaries() {
        let mut a = FakeActions::default();
        orchestrate(&mut a, false);
        let svc = a.calls.iter().position(|c| c == "services").unwrap();
        let bins = a.calls.iter().position(|c| c == "binaries").unwrap();
        assert!(
            svc < bins,
            "services must be stopped before binaries deleted"
        );
    }

    #[test]
    fn scans_for_residue_last() {
        let mut a = FakeActions::default();
        orchestrate(&mut a, false);
        assert_eq!(a.calls.last().unwrap(), "scan");
    }

    #[test]
    fn clean_run_with_no_residue_is_complete() {
        let mut a = FakeActions::default();
        let r = orchestrate(&mut a, false);
        assert!(r.complete());
        assert!(r.residue.is_empty());
        assert_eq!(r.steps.len(), 6);
        assert!(r.steps.iter().all(|s| s.ok));
    }

    #[test]
    fn residual_item_makes_the_run_incomplete() {
        let mut a = FakeActions {
            residue: vec!["C:\\Program Files\\DIG\\dign.exe".into()],
            ..Default::default()
        };
        let r = orchestrate(&mut a, false);
        assert!(!r.complete(), "leftover binary must fail completeness");
        assert_eq!(r.residue.len(), 1);
    }

    #[test]
    fn a_failed_step_makes_the_run_incomplete_even_with_no_residue() {
        let mut a = FakeActions {
            fail_step: Some("scheme".into()),
            ..Default::default()
        };
        let r = orchestrate(&mut a, false);
        assert!(!r.complete());
        let scheme = r.steps.iter().find(|s| s.id == "scheme").unwrap();
        assert!(!scheme.ok);
    }

    #[test]
    fn dry_run_flag_is_recorded() {
        let mut a = FakeActions::default();
        let r = orchestrate(&mut a, true);
        assert!(r.dry_run);
    }

    #[test]
    fn report_serializes_with_stable_fields() {
        let mut a = FakeActions {
            residue: vec!["x".into()],
            ..Default::default()
        };
        let r = orchestrate(&mut a, false);
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["steps"][0]["id"], "services");
        assert_eq!(v["residue"][0], "x");
        assert_eq!(v["dry_run"], false);
    }

    #[test]
    fn component_stems_list_services_before_user_clis() {
        // The teardown list drives binary-deletion order; service-backed
        // components come before the user CLIs and the installer's own copy.
        let node = COMPONENT_STEMS
            .iter()
            .position(|s| *s == "dig-node")
            .unwrap();
        let digstore = COMPONENT_STEMS
            .iter()
            .position(|s| *s == "digstore")
            .unwrap();
        let installer = COMPONENT_STEMS
            .iter()
            .position(|s| *s == "dig-installer")
            .unwrap();
        assert!(node < digstore);
        assert_eq!(
            installer,
            COMPONENT_STEMS.len() - 1,
            "installer removed last"
        );
    }
}
