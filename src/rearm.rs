//! Restoring a privileged registration the #565 legacy-root migration removed and nothing later in
//! the run will put back (dig_ecosystem#1854 for the beacon, #1863 for the three services).
//!
//! # The defect, stated once
//!
//! The migration deregisters EVERY privileged registration whose binary resolves under a legacy
//! user-writable root, INDEPENDENT of the current plan — that independence is the #565 invariant and
//! must stay. But each component's install step re-registers only when the plan SELECTS that
//! component. So a re-run that DECLINES a component silently deleted its working registration:
//! declining a component is documented as "installs nothing", never "uninstall what is already
//! there".
//!
//! PR #49 fixed exactly this for the auto-update beacon. This module is that fix with the component
//! lifted out, so the three services (`dig-node`, `dig-relay`, `dig-dns`) cannot each grow their own
//! subtly different copy — the failure mode that produced the defect in the first place.
//!
//! # The guard ORDER is load-bearing
//!
//! plan-selects → was-deregistered → root-is-protected → register → report, in that order and no
//! other:
//!
//! 1. **plan-selects** first, because when the plan installs the component its own step registers it
//!    fresh from the binary it just placed; re-arming here as well is a double registration against
//!    a path that may not hold the new binary yet.
//! 2. **was-deregistered** next, because a registration this migration never touched needs no
//!    restoring — and arming one the host never had is the nearest wrong implementation.
//! 3. **root-is-protected** last before acting, because registering a machine-wide privileged
//!    artifact at a CALLER-SELECTED `--bin-dir` path is the #565 escalation itself. A security guard
//!    whose default is "allow" is one careless call site away from being bypassed, which is why the
//!    root is a required parameter rather than an `Option`.
//!
//! Nothing here is fatal: everything else in the run succeeded, and the state is REPORTED.

use std::path::Path;

/// The result of one re-arm attempt — deliberately component-agnostic, so the beacon's
/// [`crate::beacon::BeaconResult`] and a service registration can both be expressed by it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RearmOutcome {
    /// Did the registration actually get restored? `false` means the host is now WITHOUT it and this
    /// run could not put it back — reported, never silent.
    pub applied: bool,
    /// Human-readable detail behind [`Self::applied`].
    pub note: String,
}

/// The component-specific consequence + remedy for a re-arm that FAILED.
///
/// Carried as data rather than generated from the label, because a generic sentence is not good
/// enough here: the point of reporting a failed re-arm is that the operator learns what the host has
/// LOST ("auto-updates are now DISABLED on this host") and the EXACT command that restores it —
/// SPEC §5 requires the command, not a procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RearmAdvice {
    /// What the host has lost, in the operator's terms.
    pub consequence: String,
    /// The exact command that restores it.
    pub restore: String,
}

/// One re-armed (or failed) registration, as it appears in the `--json` install report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RearmRecord {
    /// The registration's own label — the same string the migration reported deregistering, so the
    /// two halves of the story can be matched up by a reader or a script.
    pub label: String,
    /// Did the re-arm succeed?
    pub applied: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

impl RearmRecord {
    /// Pair an outcome with the label it belongs to.
    pub fn new(label: &str, outcome: &RearmOutcome) -> Self {
        RearmRecord {
            label: label.to_string(),
            applied: outcome.applied,
            note: outcome.note.clone(),
        }
    }
}

/// Everything the re-arm decision needs, as one value.
///
/// Grouped rather than passed as six positional parameters because the guard ORDER is the
/// load-bearing part of this module, and a six-argument call site invites the one transposition that
/// would be silent and fatal: swapping "the root this run used" for "the root that is TRUSTED", which
/// is the entire #565 comparison.
#[derive(Debug, Clone, Copy)]
pub struct RearmRequest<'a> {
    /// The registration's label, as [`crate::regaudit::PrivilegedReg::label`] reports it.
    pub label: &'a str,
    /// Every label the migration deregistered.
    pub deregistered: &'a [String],
    /// Does the current plan select this component, so its own install step registers it fresh?
    pub plan_selects: bool,
    /// The root this run's privileged binaries actually went to.
    pub expected_root: &'a Path,
    /// The admin-only protected root — the ONLY root a machine-wide registration may point into.
    pub protected_root: &'a Path,
    /// What the operator has lost, and the exact command that restores it, if the re-arm fails.
    pub advice: &'a RearmAdvice,
}

/// Restore the privileged registration named by the request if — and only if — the migration removed
/// it and nothing else in this run will.
///
/// `register` is handed the PROTECTED ROOT directory (never the legacy path, whose binary the
/// migration deleted and which must never be executed anyway, #565); the caller's closure joins
/// whatever binary name it needs. `None` means there was nothing to do; otherwise the outcome, whose
/// `applied: false` says the registration is genuinely gone until the next run that selects the
/// component.
///
/// See the module docs for why the guards are in this order.
pub fn rearm_after_migration(
    request: &RearmRequest<'_>,
    register: &mut dyn FnMut(&Path) -> RearmOutcome,
    log: &mut dyn FnMut(&str),
) -> Option<RearmOutcome> {
    let &RearmRequest {
        label,
        deregistered,
        plan_selects,
        expected_root,
        protected_root,
        advice,
    } = request;
    if plan_selects {
        return None; // this run's own install step registers it fresh
    }
    if !deregistered.iter().any(|d| d == label) {
        return None; // this host's registration was never touched — nothing to restore
    }
    if expected_root != protected_root {
        log(&format!(
            "Not re-arming the {label} registration the migration removed (#1854/#1863): this run's \
             privileged install root is {}, not the protected root {}, and a machine-wide \
             privileged registration must never be created at a caller-selected path (#565). \
             {label} stays unregistered on this host; restore it with a default-root \
             `dig-installer` run that selects it.",
            expected_root.display(),
            protected_root.display()
        ));
        return None;
    }

    log(&format!(
        "Re-arming the {label} registration the migration removed (#1854/#1863):"
    ));
    let outcome = register(protected_root);
    if outcome.applied {
        log(&format!("    ✓ {}", outcome.note));
    } else {
        log(&format!(
            "    ! {} ({}). {}",
            advice.consequence, outcome.note, advice.restore
        ));
    }
    Some(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The protected root every row judges against — a literal, so no assertion below can become a
    /// tautology by reading the same helper the implementation does.
    fn protected() -> PathBuf {
        PathBuf::from("/opt/dig/bin")
    }

    /// Drive the re-arm, recording the roots `register` was handed and every log line.
    fn rearm(
        label: &str,
        deregistered: &[&str],
        plan_selects: bool,
        expected_root: &Path,
        succeeds: bool,
    ) -> (Option<RearmOutcome>, Vec<PathBuf>, String) {
        let owned: Vec<String> = deregistered.iter().map(|d| (*d).to_string()).collect();
        let mut armed = Vec::new();
        let mut lines = Vec::new();
        let advice = RearmAdvice {
            consequence: format!("{label} is now UNREGISTERED on this host"),
            restore: format!("Re-run the installer with {label} enabled to restore it"),
        };
        let outcome = rearm_after_migration(
            &RearmRequest {
                label,
                deregistered: &owned,
                plan_selects,
                expected_root,
                protected_root: &protected(),
                advice: &advice,
            },
            &mut |root| {
                armed.push(root.to_path_buf());
                RearmOutcome {
                    applied: succeeds,
                    note: if succeeds {
                        format!("re-registered {label}")
                    } else {
                        "the binary is not in the protected root either".to_string()
                    },
                }
            },
            &mut |line| lines.push(line.to_string()),
        );
        (outcome, armed, lines.join("\n"))
    }

    /// The four labels this generic serves, so a row proves the rule rather than one component's
    /// luck. `"dig-node service"` etc. are the labels [`crate::regaudit::PrivilegedReg::label`]
    /// reports — asserted against that source in `lib.rs`, not duplicated as truth here.
    const LABELS: [&str; 4] = [
        "dig-updater beacon",
        "dig-node service",
        "dig-relay service",
        "dig-dns service",
    ];

    /// The full (plan_selects x was_deregistered x root_is_protected) table, per label: 8 rows each.
    /// Exactly ONE combination may register — declining a component the migration vacated, at the
    /// protected root.
    #[test]
    fn only_a_declined_and_deregistered_component_at_the_protected_root_is_rearmed() {
        let elsewhere = PathBuf::from("/home/alice/.dig/bin");
        for label in LABELS {
            for plan_selects in [true, false] {
                for was_deregistered in [true, false] {
                    for root_is_protected in [true, false] {
                        let deregistered: Vec<&str> = if was_deregistered {
                            vec!["some other thing", label]
                        } else {
                            vec!["some other thing"]
                        };
                        let root = if root_is_protected {
                            protected()
                        } else {
                            elsewhere.clone()
                        };
                        let (outcome, armed, _) =
                            rearm(label, &deregistered, plan_selects, &root, true);
                        let should_register =
                            !plan_selects && was_deregistered && root_is_protected;
                        assert_eq!(
                            armed.len(),
                            usize::from(should_register),
                            "{label}: plan_selects {plan_selects}, deregistered \
                             {was_deregistered}, protected root {root_is_protected}"
                        );
                        assert_eq!(
                            outcome.is_some(),
                            should_register,
                            "{label}: the outcome must be reported exactly when something ran"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_register_closure_is_handed_the_protected_root_never_the_legacy_one() {
        // #565's cardinal rule: the legacy binary is deleted and must never be executed, so the
        // restore points at the protected root.
        let (_, armed, _) = rearm(
            "dig-node service",
            &["dig-node service"],
            false,
            &protected(),
            true,
        );
        assert_eq!(armed, vec![protected()]);
    }

    #[test]
    fn a_caller_selected_root_is_refused_and_named_in_the_log() {
        let custom = PathBuf::from("/tmp/attacker-chosen");
        let (outcome, armed, log) = rearm(
            "dig-relay service",
            &["dig-relay service"],
            false,
            &custom,
            true,
        );
        assert!(armed.is_empty(), "must never arm a caller-selected root");
        assert!(
            outcome.is_none(),
            "nothing ran, so there is nothing to report"
        );
        assert!(
            log.contains("Not re-arming"),
            "the skip must be logged: {log}"
        );
        assert!(
            log.contains("/tmp/attacker-chosen"),
            "the log must name the root it refused: {log}"
        );
    }

    #[test]
    fn a_failed_rearm_is_reported_loudly_with_how_to_restore_it() {
        let (outcome, _, log) = rearm(
            "dig-dns service",
            &["dig-dns service"],
            false,
            &protected(),
            false,
        );
        assert!(
            outcome.is_some_and(|o| !o.applied),
            "a failed re-arm must still be reported, never swallowed"
        );
        assert!(
            log.contains("dig-dns service is now UNREGISTERED"),
            "the component-specific consequence must reach the operator: {log}"
        );
        assert!(log.contains("Re-run the installer"), "got: {log}");
    }

    #[test]
    fn a_label_that_merely_shares_a_prefix_is_not_a_match() {
        // Substring matching would let "dig-node service" be restored because "dig-node service
        // watchdog" was deregistered — a registration this host never had.
        let (outcome, armed, _) = rearm(
            "dig-node service",
            &["dig-node service watchdog"],
            false,
            &protected(),
            true,
        );
        assert!(armed.is_empty());
        assert!(outcome.is_none());
    }

    #[test]
    fn a_record_carries_the_label_alongside_the_outcome() {
        let outcome = RearmOutcome {
            applied: true,
            note: "re-registered".to_string(),
        };
        let record = RearmRecord::new("dig-node service", &outcome);
        assert_eq!(record.label, "dig-node service");
        assert!(record.applied);
        assert_eq!(record.note, "re-registered");
    }
}
