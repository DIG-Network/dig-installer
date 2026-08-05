//! The first-class `uninstall` orchestrator (#568): one command that removes
//! the ENTIRE DIG install and leaves ZERO residue.
//!
//! Before this, teardown was a set of piecemeal flags (`--uninstall-dig-node`,
//! `--uninstall-dig-dns`, `--unregister-scheme`, `--uninstall-dig-updater`) that
//! a user had to run one by one and could easily leave half-removed. `uninstall`
//! composes them into a single ordered, idempotent orchestration that:
//!
//!   1. stops + deregisters ALL services (dig-node, dig-relay, dig-dns),
//!   2. stops the user-session processes (dig-app, dign) + removes dig-app's
//!      login autostart — before any deletion, because a running image cannot be
//!      deleted on Windows,
//!   3. removes the auto-update beacon's scheduler registration,
//!   4. unregisters the dig/chia/urn URL-scheme handlers,
//!   5. removes the dig.local hosts entry + the peer firewall rule,
//!   6. removes the system-wide login-`PATH` fragment,
//!   7. removes every MSI-installed DIG product with `msiexec /x` — before the
//!      binaries, since that removal needs the product's own files ([`crate::msi`]),
//!   8. deletes ALL installed binaries (both bin roots),
//!   9. asks the GUI backend to unconfigure the browser extension forcelist
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
    // The store CLI under BOTH spellings. `dig-store` is what the installer places today; `digstore`
    // is the pre-rename name (epic #703) that older installs left on disk. Listing only `digstore`
    // meant `dig-store.exe` was neither deleted NOR scanned for — an uninstall left it in
    // `C:\Program Files\DIG\bin` and still reported `residue: []` (#854).
    "dig-store",
    "digstore",
    "digs",
    "digd",
    // The per-user identity agent (#912). Listed after the daemons and before the
    // installer's own copy: it is a user-session process, so nothing machine-wide
    // ever points at it — its per-user autostart artifact is torn down separately
    // (`autostart::deregister`).
    "dig-app",
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
    fn stop_services(&mut self) -> ServiceTeardown;
    /// Stop the running user-session processes (`dig-app`, `dign`) and remove dig-app's per-user
    /// login autostart.
    ///
    /// These have no service registration, so nothing else stops them — and on Windows a running
    /// image cannot be deleted, so leaving `dig-app` up makes the binary deletion fail with
    /// `os error 5` and the whole uninstall exit non-zero (#854).
    fn stop_user_agent(&mut self) -> (bool, String);
    /// Remove every MSI-installed DIG product via `msiexec /x <ProductCode>`.
    ///
    /// Its own step because deleting an MSI product's FILES is not an uninstall: the product stays
    /// registered in the Windows Installer database, leaving a ghost Add/Remove-Programs entry and a
    /// later upgrade that believes an older version is still present (see [`crate::msi`]).
    fn remove_msi_products(&mut self) -> (bool, String);
    /// Remove the auto-update beacon's scheduler registration.
    fn remove_beacon(&mut self) -> (bool, String);
    /// Unregister the dig/chia/urn URL-scheme handlers (DIG-owned only).
    fn unregister_scheme(&mut self) -> (bool, String);
    /// Remove the dig.local hosts entry + the peer firewall rule.
    fn remove_network_config(&mut self) -> (bool, String);
    /// Revert the DIG TLS trust anchor(s) recorded in the trust-manifest ledger, then remove the
    /// privileged TLS root (#623/#858).
    ///
    /// Its own step because a trust anchor is machine-wide state that outlives every binary: an
    /// installed CA left in the OS Root store keeps the machine trusting a private CA after DIG is
    /// gone. Strictly DIG-owned scope — only the anchors this install's ledger recorded — and
    /// idempotent (an already-absent anchor / root is success).
    fn remove_tls_trust(&mut self) -> (bool, String);
    /// Delete all installed DIG binaries from both bin roots, EXCEPT the
    /// binaries of the component stems in `skip` — those had a failed service
    /// teardown, so deleting their binary would orphan a still-registered
    /// service pointing at a missing ImagePath (which #573's SCM auto-recovery
    /// would then thrash on). Leave them for an elevated re-run.
    fn delete_binaries(&mut self, skip: &[String]) -> (bool, String);
    /// Ask the GUI backend to unconfigure the extension forcelist (#612/#648).
    fn unconfigure_forcelist(&mut self) -> (bool, String);
    /// Remove the SYSTEM-WIDE login-`PATH` fragment an elevated install writes
    /// (`/etc/profile.d/dig-path.sh` on Linux, `/etc/paths.d/dig` on macOS).
    ///
    /// Its own step because it is machine-wide state that outlives every binary: left behind, it keeps
    /// a now-empty — or worse, re-created by somebody else — directory on every account's login `PATH`,
    /// root's included (#1748).
    fn remove_login_path_fragment(&mut self) -> (bool, String);
    /// Re-scan for anything still present; the returned strings are the residue.
    fn scan_residue(&mut self) -> Vec<String>;
}

/// The outcome of the service-teardown step. Carries the aggregate `ok` + note
/// AND the component stems whose service could NOT be deregistered, so the
/// orchestrator can refuse to delete THOSE binaries (avoiding an orphaned
/// service → deleted-binary mismatch — blocker #4). A component absent from
/// `failed_components` was torn down cleanly (or was already absent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct ServiceTeardown {
    /// Every service reached its desired end-state (removed or already-absent).
    pub ok: bool,
    /// Human-readable detail across all services.
    pub note: String,
    /// Component stems whose service teardown FAILED — their binaries must be
    /// left in place (never deleted) to avoid orphaning a live registration.
    pub failed_components: Vec<String>,
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

    let services = actions.stop_services();
    report.record("services", services.ok, services.note);

    // Immediately after the services, and long before any deletion: from here on nothing DIG is
    // running, so no image is held open when `delete_binaries` reaches it.
    let (ok, note) = actions.stop_user_agent();
    report.record("user-agent", ok, note);

    let (ok, note) = actions.remove_beacon();
    report.record("beacon", ok, note);

    let (ok, note) = actions.unregister_scheme();
    report.record("scheme", ok, note);

    let (ok, note) = actions.remove_network_config();
    report.record("network", ok, note);

    // Revert the trust anchor while the ledger under the TLS root still exists (this step removes
    // the root last), and before the binaries so teardown of machine-wide trust state never lags a
    // now-empty install.
    let (ok, note) = actions.remove_tls_trust();
    report.record("tls-trust", ok, note);

    // Before the binaries: while they still exist the fragment is at least pointing at something this
    // installer placed, so removing it first never widens the window in which it names a directory
    // somebody else could re-create.
    let (ok, note) = actions.remove_login_path_fragment();
    report.record("login-path", ok, note);

    // BEFORE the binary deletion, because `msiexec /x` needs the product's own files to run its
    // uninstall sequence — deleting them first turns a clean removal into a broken one that leaves
    // the product registered.
    let (ok, note) = actions.remove_msi_products();
    report.record("msi", ok, note);

    // Binaries are deleted only AFTER their services/schedulers are gone, so a
    // live service never points at a deleted binary mid-teardown. Crucially, a
    // component whose service teardown FAILED (`failed_components`) keeps its
    // binary — deleting it would leave a still-registered service pointing at a
    // missing ImagePath (an orphan; blocker #4). Those are left for an elevated
    // re-run, which the residue scan then reports as not-yet-complete.
    let (ok, note) = actions.delete_binaries(&services.failed_components);
    let note = if services.failed_components.is_empty() {
        note
    } else {
        format!(
            "{note}; left in place (service not fully torn down): {}",
            services.failed_components.join(", ")
        )
    };
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
        /// Component stems `stop_services` reports as failed-to-deregister.
        service_failed: Vec<String>,
        /// The `skip` set `delete_binaries` was actually invoked with (records
        /// the orchestrator's gating decision for assertions).
        delete_skip: Option<Vec<String>>,
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
        fn stop_services(&mut self) -> ServiceTeardown {
            self.calls.push("services".to_string());
            ServiceTeardown {
                ok: self.service_failed.is_empty() && self.fail_step.as_deref() != Some("services"),
                note: "services".into(),
                failed_components: self.service_failed.clone(),
            }
        }
        fn stop_user_agent(&mut self) -> (bool, String) {
            self.outcome("user-agent")
        }
        fn remove_msi_products(&mut self) -> (bool, String) {
            self.outcome("msi")
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
        fn remove_tls_trust(&mut self) -> (bool, String) {
            self.outcome("tls-trust")
        }
        fn delete_binaries(&mut self, skip: &[String]) -> (bool, String) {
            self.calls.push("binaries".to_string());
            self.delete_skip = Some(skip.to_vec());
            let ok = self.fail_step.as_deref() != Some("binaries");
            (ok, format!("binaries: skip={skip:?}"))
        }
        fn unconfigure_forcelist(&mut self) -> (bool, String) {
            self.outcome("forcelist")
        }
        fn remove_login_path_fragment(&mut self) -> (bool, String) {
            self.outcome("login-path")
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

    /// The machine-wide login-`PATH` fragment MUST be removed by an uninstall.
    ///
    /// It was not, and nothing else would ever notice: it is a file in `/etc`, not a binary in a bin
    /// root, so the residue scan does not look at it. Left behind it keeps a directory on every
    /// account's login `PATH` — root's included — after the install that justified it is gone (#1748).
    #[test]
    fn the_machine_wide_login_path_fragment_is_removed() {
        let mut a = FakeActions::default();
        let r = orchestrate(&mut a, false);
        assert!(
            a.calls.iter().any(|c| c == "login-path"),
            "uninstall never removed the system-wide PATH fragment: {:?}",
            a.calls
        );
        let step = r
            .steps
            .iter()
            .find(|s| s.id == "login-path")
            .expect("the step must be reported, not silent");
        assert!(step.ok);
        // Before the binaries, so the fragment never outlives them.
        let frag = a.calls.iter().position(|c| c == "login-path").unwrap();
        let bins = a.calls.iter().position(|c| c == "binaries").unwrap();
        assert!(frag < bins);
    }

    /// A failure to remove it fails the whole uninstall rather than being swallowed.
    #[test]
    fn a_failed_login_path_removal_makes_the_run_incomplete() {
        let mut a = FakeActions {
            fail_step: Some("login-path".to_string()),
            ..Default::default()
        };
        let r = orchestrate(&mut a, false);
        assert!(!r.complete());
    }

    /// dig-app is a running user process with no service registration, and Windows will not let a
    /// running image be deleted — so an uninstall that never stops it fails the binary deletion with
    /// `os error 5` and exits non-zero. The ORDER is the property: stopping it after the deletion
    /// would leave the same failure, so the assertion is positional, not merely "the step exists".
    #[test]
    fn the_user_agent_is_stopped_before_any_binary_is_deleted() {
        let mut a = FakeActions::default();
        let r = orchestrate(&mut a, false);
        let stop = a
            .calls
            .iter()
            .position(|c| c == "user-agent")
            .expect("the user-session agent must be stopped");
        let bins = a.calls.iter().position(|c| c == "binaries").unwrap();
        assert!(
            stop < bins,
            "dig-app must be stopped BEFORE its binary is deleted: {:?}",
            a.calls
        );
        assert!(r.steps.iter().any(|s| s.id == "user-agent"));
    }

    /// `msiexec /x` runs the product's OWN uninstall sequence from the product's OWN files, so it has
    /// to happen while those files still exist. Deleting the binaries first would leave the product
    /// registered in the Windows Installer database — the exact ghost this step exists to prevent.
    #[test]
    fn msi_products_are_removed_before_the_binaries_are_deleted() {
        let mut a = FakeActions::default();
        orchestrate(&mut a, false);
        let msi = a
            .calls
            .iter()
            .position(|c| c == "msi")
            .expect("MSI-installed products must be removed");
        let bins = a.calls.iter().position(|c| c == "binaries").unwrap();
        assert!(
            msi < bins,
            "msiexec must run before the files go: {:?}",
            a.calls
        );
    }

    /// A failed `msiexec /x` leaves a registered product behind, which is precisely the incomplete
    /// state the report exists to surface — it must not be swallowed into a green run.
    #[test]
    fn a_failed_msi_removal_makes_the_run_incomplete() {
        let mut a = FakeActions {
            fail_step: Some("msi".to_string()),
            ..Default::default()
        };
        let r = orchestrate(&mut a, false);
        assert!(!r.complete());
        assert!(!r.steps.iter().find(|s| s.id == "msi").unwrap().ok);
    }

    /// Likewise a process we could not stop: its binary cannot be deleted, so reporting the run as
    /// complete would be a false green.
    #[test]
    fn a_failed_user_agent_stop_makes_the_run_incomplete() {
        let mut a = FakeActions {
            fail_step: Some("user-agent".to_string()),
            ..Default::default()
        };
        let r = orchestrate(&mut a, false);
        assert!(!r.complete());
    }

    /// The DIG TLS trust anchor is machine-wide state (a CA in the OS Root store) that outlives
    /// every binary, so an uninstall MUST revert it — and before the binaries, so the ledger under
    /// the TLS root is still present when the revert reads it. The order is the property: reverting
    /// after the root is gone would leave a trusted private CA behind with nothing to revert it by.
    #[test]
    fn the_tls_trust_anchor_is_reverted_before_the_binaries() {
        let mut a = FakeActions::default();
        let r = orchestrate(&mut a, false);
        let tls = a
            .calls
            .iter()
            .position(|c| c == "tls-trust")
            .expect("the TLS trust anchor must be reverted");
        let bins = a.calls.iter().position(|c| c == "binaries").unwrap();
        assert!(
            tls < bins,
            "the trust anchor must be reverted before the binaries: {:?}",
            a.calls
        );
        assert!(r.steps.iter().find(|s| s.id == "tls-trust").unwrap().ok);
    }

    /// A failed trust revert leaves a private CA trusted machine-wide — precisely the residue the
    /// report must surface, never swallow into a green run.
    #[test]
    fn a_failed_tls_trust_revert_makes_the_run_incomplete() {
        let mut a = FakeActions {
            fail_step: Some("tls-trust".to_string()),
            ..Default::default()
        };
        let r = orchestrate(&mut a, false);
        assert!(!r.complete());
        assert!(!r.steps.iter().find(|s| s.id == "tls-trust").unwrap().ok);
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
        assert_eq!(r.steps.len(), 10);
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
    fn a_failed_service_teardown_skips_that_components_binary_delete() {
        // Blocker #4: an unelevated uninstall where dig-node's service could not
        // be deregistered must NOT delete dig-node's binary — otherwise a
        // still-registered service points at a missing ImagePath (orphan). The
        // orchestrator gates delete_binaries on the failed set, and the leftover
        // binary makes the run not-yet-complete (prompting an elevated re-run).
        let mut a = FakeActions {
            service_failed: vec!["dig-node".into()],
            residue: vec!["/opt/dig/bin/dig-node".into()],
            ..Default::default()
        };
        let r = orchestrate(&mut a, false);
        assert_eq!(
            a.delete_skip.as_deref(),
            Some(&["dig-node".to_string()][..]),
            "the failed component must be passed to delete_binaries as skip"
        );
        let services = r.steps.iter().find(|s| s.id == "services").unwrap();
        assert!(!services.ok, "a failed service teardown is not ok");
        assert!(
            !r.complete(),
            "an incomplete service teardown + left-in-place binary is not complete"
        );
    }

    #[test]
    fn a_failed_dig_dns_service_teardown_skips_dig_dns_and_digd_binaries() {
        // Blocker #4 residual (dig-dns): an elevated uninstall where the dig-dns
        // SERVICE deregister failed (its binaries dig-dns + the digd alias are
        // reported in failed_components) must skip deleting BOTH binaries and
        // leave the run not-yet-complete.
        let mut a = FakeActions {
            service_failed: vec!["dig-dns".into(), "digd".into()],
            residue: vec!["/opt/dig/bin/dig-dns".into(), "/opt/dig/bin/digd".into()],
            ..Default::default()
        };
        let r = orchestrate(&mut a, false);
        assert_eq!(
            a.delete_skip.as_deref(),
            Some(&["dig-dns".to_string(), "digd".to_string()][..]),
            "both dig-dns and digd must be skipped when the dig-dns service teardown failed"
        );
        assert!(!r.steps.iter().find(|s| s.id == "services").unwrap().ok);
        assert!(!r.complete());
    }

    #[test]
    fn a_clean_service_teardown_deletes_everything_no_skip() {
        let mut a = FakeActions::default();
        let r = orchestrate(&mut a, false);
        assert_eq!(
            a.delete_skip.as_deref(),
            Some(&[][..]),
            "a clean teardown skips nothing"
        );
        assert!(r.complete());
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

    /// Every binary the installer PLACES must be in the teardown list, under the name it is placed
    /// with. `dig-store.exe` was not: the list carried only the pre-rename `digstore`, so a real
    /// uninstall left `C:\Program Files\DIG\bin\dig-store.exe` on disk AND reported `residue: []` —
    /// the deletion walk and the residue scan read the same list, so the omission hid itself.
    ///
    /// The names come from the installer's own component set rather than a copy of the list, so a
    /// future component cannot be added to the installer and forgotten here.
    #[test]
    fn every_installed_binary_stem_is_in_the_teardown_list() {
        for stem in [
            "dig-node",
            "dign",
            "dig-dns",
            "digd",
            "dig-updater",
            "dig-updater-worker",
            "dig-store",
            "digs",
            "dig-app",
            "dig-relay",
            "dig-installer",
        ] {
            assert!(
                COMPONENT_STEMS.contains(&stem),
                "{stem} is installed but would never be deleted or reported as residue"
            );
        }
        // The pre-rename spelling stays, so an older install is still cleaned up.
        assert!(COMPONENT_STEMS.contains(&"digstore"));
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
