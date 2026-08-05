//! Removal of a SUPERSEDED DIG install root (dig_ecosystem#2205).
//!
//! # What this is, and how it differs from the #565 migration
//!
//! [`crate::migrate`] vacates a LEGACY USER-WRITABLE root. That is a privilege-escalation surface, so
//! the migration is mandatory and aggressive: it DEREGISTERS any service still pointing at such a root
//! and then deletes the binaries, because leaving them is worse than any breakage removing them could
//! cause.
//!
//! A superseded root is the opposite trade. Before the Windows install root was unified on
//! `%ProgramFiles%\DIG\bin`, each component lived in its own directory under `%ProgramFiles%\DIG
//! Network`. Those directories are admin-only-writable, so nothing escalates by being left there — but
//! they stay on the machine `Path`, which a new shell composes BEFORE the user `Path`, so a stale
//! `dig-node.exe` there wins the bare name against a correct current install. Measured on the machine
//! that raised #2205:
//!
//! ```text
//! fresh session PATH entry [50]  C:\Program Files\DIG Network\dig-node\   <- superseded, wins
//! fresh session PATH entry [51]  C:\Program Files\DIG\bin                 <- current install
//! ```
//!
//! The install then correctly failed its own reachability check
//! ([`crate::pathcheck::verify_cli_resolves`]) — the check was right and the layout was wrong.
//!
//! # Removal is conditional, and the REFUSAL is the feature
//!
//! Deleting a directory something still points at breaks DIG on a machine that was working, which is
//! strictly worse than the stale directory. So removal is a verdict reached from gathered evidence
//! ([`decide`], pure) rather than an optimistic delete, and it refuses on any of:
//!
//! 1. a privileged registration (a service `PathName`, the beacon task) whose binary resolves under the
//!    root — deleting it would leave a registration pointing at nothing;
//! 2. a RUNNING process whose image resolves under the root — that binary is in use right now;
//! 3. an entry the current root does not also have — the root would then be the only copy of
//!    something, and this is a cleanup, never a data-losing one.
//!
//! Each component's directory is judged INDEPENDENTLY: a refusal on one must not leave another's stale
//! directory on `PATH`.
//!
//! Layering matches the rest of the crate: the verdict is pure and unit-tested against every refusal
//! reason; the scan/delete/PATH-rewrite is a thin imperative layer.

use std::path::{Path, PathBuf};

use crate::paths;
use crate::regaudit;
use crate::target::{Os, Target};

/// What was observed about one candidate superseded root — the whole input to [`decide`].
///
/// Gathered by [`gather`]; constructed directly by tests, so every verdict is reachable without a real
/// install.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RootEvidence {
    /// The candidate directory.
    pub root: PathBuf,
    /// Immediate entry names in `root` — files AND directories, exactly as read. Not recursive: a
    /// nested directory is compared as one opaque entry, which is what makes rule 3 conservative.
    pub entries: Vec<String>,
    /// Immediate entry names in the CURRENT install root, for the same comparison.
    pub current_entries: Vec<String>,
    /// Labels of privileged registrations whose configured binary resolves under `root`.
    pub referencing_registrations: Vec<String>,
    /// Image paths of running processes that resolve under `root`.
    pub running_images: Vec<String>,
}

/// The verdict [`decide`] reaches for one candidate root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing on the machine depends on this root and it is fully duplicated by the current one.
    Remove,
    /// Something still depends on it. Carries the reason verbatim for the log and the `--json` report.
    Refuse(String),
}

/// Decide whether a superseded root may be removed. Pure.
///
/// The three refusal reasons are checked in order of how badly getting them wrong would hurt: a live
/// registration first (a machine that boots into a broken service), then a running process, then an
/// entry that exists nowhere else (unrecoverable). The first that fires is reported, because one
/// sufficient reason to refuse is the whole answer.
pub fn decide(evidence: &RootEvidence) -> Verdict {
    let root = evidence.root.display();

    if !evidence.referencing_registrations.is_empty() {
        return Verdict::Refuse(format!(
            "{root} is still referenced by {} — removing it would leave a privileged registration \
             pointing at a path that no longer exists",
            evidence.referencing_registrations.join(", ")
        ));
    }
    if !evidence.running_images.is_empty() {
        return Verdict::Refuse(format!(
            "{root} is in use by a running process ({}) — its binaries are live, not superseded",
            evidence.running_images.join(", ")
        ));
    }
    let only_here = entries_absent_from(&evidence.entries, &evidence.current_entries);
    if !only_here.is_empty() {
        return Verdict::Refuse(format!(
            "{root} holds {} which the current install root does not — it is not a superseded copy \
             of anything, so removing it would lose the only copy",
            only_here.join(", ")
        ));
    }
    Verdict::Remove
}

/// The entries present in `root_entries` and absent from `current_entries`.
///
/// Case-INSENSITIVE, because this compares Windows filenames, where `Dig-Node.exe` and `dig-node.exe`
/// are the same file; a case-sensitive comparison would report a duplicated binary as unique and
/// refuse every removal. Pure.
fn entries_absent_from(root_entries: &[String], current_entries: &[String]) -> Vec<String> {
    root_entries
        .iter()
        .filter(|e| {
            !current_entries
                .iter()
                .any(|c| c.eq_ignore_ascii_case(e.as_str()))
        })
        .cloned()
        .collect()
}

/// The record of the superseded-root cleanup — part of the `--json` [`crate::InstallReport`]. Never
/// silent: a refusal is reported just as loudly as a removal, so an install that still fails its
/// reachability check says why in the same output.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SupersedeResult {
    /// A superseded root was found and acted on this run.
    pub acted: bool,
    /// Roots whose binaries and PATH entries were removed.
    pub removed_roots: Vec<String>,
    /// Binary files deleted from those roots.
    pub removed_binaries: Vec<String>,
    /// `"<scope>: <dir>"` for every persisted PATH entry dropped.
    pub path_entries_removed: Vec<String>,
    /// Roots deliberately LEFT in place, with the reason ([`decide`]).
    pub refused: Vec<String>,
    /// Human-readable detail — never silent.
    pub notes: Vec<String>,
}

/// Remove every superseded install root that [`decide`] clears, and drop its persisted PATH entries.
///
/// Runs BEFORE the post-install reachability check so a cleared shadow is gone by the time that check
/// reads the persisted PATH — the check re-reads the registry, so the removal is visible to it.
///
/// Never fatal: a root that cannot be cleaned is recorded and the install continues. The reachability
/// check is what fails an install over a shadow, and it is still free to do so.
pub fn remove_superseded_roots(target: &Target, log: &mut dyn FnMut(&str)) -> SupersedeResult {
    let mut result = SupersedeResult::default();
    let current_root = paths::protected_bin_dir();
    let current_entries = entry_names(&current_root);

    for root in paths::superseded_roots(target.os) {
        if !root.is_dir() {
            // The directory is gone but a PATH entry naming it can outlive it. Dropping that costs
            // nothing and stops it shadowing again if anything ever recreates the directory.
            drop_path_entries(&root, &mut result, log);
            continue;
        }
        if !result.acted {
            result.acted = true;
            log("Cleaning up a superseded DIG install root (#2205):");
        }
        let evidence = gather(target, &root, &current_entries);
        match decide(&evidence) {
            Verdict::Refuse(reason) => {
                log(&format!("    · left in place: {reason}"));
                result.refused.push(reason);
            }
            Verdict::Remove => {
                remove_root(target, &root, &mut result, log);
                drop_path_entries(&root, &mut result, log);
            }
        }
    }
    result
}

/// Gather the evidence for one candidate root. I/O; the classification it feeds is [`decide`].
fn gather(target: &Target, root: &Path, current_entries: &[String]) -> RootEvidence {
    RootEvidence {
        root: root.to_path_buf(),
        entries: entry_names(root),
        current_entries: current_entries.to_vec(),
        referencing_registrations: regaudit::regs_pointing_under(&[root.to_path_buf()], target.os)
            .iter()
            .map(|reg| reg.label().to_string())
            .collect(),
        running_images: running_images_under(root, target.os),
    }
}

/// The immediate entry names of `dir` (empty when it cannot be read).
///
/// `read_dir` is a READ, so unlike the migration's delete path it may enumerate freely; the
/// reparse-point caution applies to what is deleted, not to what is looked at.
fn entry_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect()
}

/// Delete the DIG binaries in `root`, then the directory itself (and its parent, if that leaves the
/// superseded base empty).
///
/// Only KNOWN DIG filenames are deleted, one by one, and `symlink_metadata` is used so a reparse point
/// is never followed — the same rule [`crate::migrate`] follows. [`decide`] has already established
/// that every entry here also exists in the current root, so this cannot be the only copy of anything;
/// the filename restriction is the second, independent guard.
fn remove_root(target: &Target, root: &Path, result: &mut SupersedeResult, log: &mut dyn FnMut(&str)) {
    for stem in crate::migrate::DIG_BINARY_STEMS {
        let candidate = root.join(target.exe_name(stem));
        match std::fs::symlink_metadata(&candidate) {
            Ok(md) if md.file_type().is_file() => match std::fs::remove_file(&candidate) {
                Ok(()) => {
                    log(&format!("    ✓ removed {}", candidate.display()));
                    result.removed_binaries.push(candidate.display().to_string());
                }
                Err(e) => {
                    let note = format!("could not remove {} ({e})", candidate.display());
                    log(&format!("    ! {note}"));
                    result.notes.push(note);
                }
            },
            _ => {}
        }
    }
    // Non-recursive: an unexpected leftover keeps the directory and is reported, never bulldozed.
    if std::fs::remove_dir(root).is_ok() {
        result.removed_roots.push(root.display().to_string());
        if let Some(base) = paths::superseded_root_base(target.os) {
            let _ = std::fs::remove_dir(&base); // only succeeds once every component dir is gone
        }
    } else {
        result
            .notes
            .push(format!("{} still holds entries and was kept", root.display()));
    }
}

/// Drop `root` from every persisted PATH scope that carries it, recording what changed.
fn drop_path_entries(root: &Path, result: &mut SupersedeResult, log: &mut dyn FnMut(&str)) {
    match paths::remove_from_persisted_path(root) {
        Ok(scopes) => {
            for scope in scopes {
                log(&format!(
                    "    ✓ removed from the {}: {}",
                    scope.label(),
                    root.display()
                ));
                result
                    .path_entries_removed
                    .push(format!("{}: {}", scope.label(), root.display()));
            }
        }
        Err(e) => {
            let note = format!("could not drop {} from the persisted PATH: {e}", root.display());
            log(&format!("    ! {note}"));
            result.notes.push(note);
        }
    }
}

/// Image paths of running processes whose executable resolves under `root`.
///
/// Windows only, via PowerShell: `Get-Process` is the one query that yields a full image PATH (a
/// ToolHelp snapshot alone gives only the base name, which cannot tell the superseded root's
/// `dig-node.exe` from the current root's). Spawned through [`crate::proc::powershell`], which resolves
/// the interpreter absolutely and clears the inherited variables that change how it resolves code.
///
/// Fails CLOSED in the sense that matters: if the query cannot run, no process is reported, so the
/// caller may proceed to delete — but on Windows a running image cannot be deleted anyway (the delete
/// returns a sharing violation, which `remove_root` records and the directory survives). The query is
/// the informative guard; the filesystem is the backstop.
#[cfg(windows)]
fn running_images_under(root: &Path, os: Os) -> Vec<String> {
    let script = "Get-Process | ForEach-Object { $_.Path } | Where-Object { $_ }";
    let Ok(out) = crate::proc::powershell(script).output() else {
        return Vec::new();
    };
    images_under(&String::from_utf8_lossy(&out.stdout), root, os)
}

/// Non-Windows: superseded roots are a Windows-only layout ([`paths::superseded_roots`] is empty
/// elsewhere), so this is never reached with a real candidate.
#[cfg(not(windows))]
fn running_images_under(_root: &Path, _os: Os) -> Vec<String> {
    Vec::new()
}

/// The lines of `image_paths` that resolve under `root`. Pure — the parsing and the prefix rule are
/// tested without spawning anything.
fn images_under(image_paths: &str, root: &Path, os: Os) -> Vec<String> {
    image_paths
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter(|l| regaudit::bin_path_under(l, root, os))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = r"C:\Program Files\DIG Network\dig-node";

    /// Evidence for a root that is a pure duplicate: one binary, also present in the current root,
    /// nothing referencing it and nothing running. The baseline every refusal test varies by ONE fact.
    fn duplicate_root() -> RootEvidence {
        RootEvidence {
            root: PathBuf::from(ROOT),
            entries: vec!["dig-node.exe".to_string()],
            current_entries: vec!["dig-node.exe".to_string(), "digstore.exe".to_string()],
            referencing_registrations: Vec::new(),
            running_images: Vec::new(),
        }
    }

    /// The control, and it has to come first: the baseline fixture MUST clear. Without it every
    /// refusal test below is satisfied by an implementation that refuses unconditionally.
    #[test]
    fn a_root_nothing_depends_on_is_removed() {
        assert_eq!(decide(&duplicate_root()), Verdict::Remove);
    }

    /// REFUSAL 1 — a service `PathName` still points under the root. This is the measured shape from
    /// #2205 inverted: on that machine both services had already been re-pointed at the current root,
    /// which is what made removal safe; had they not been, deleting would have left two services
    /// pointing at nothing.
    ///
    /// Varies exactly one field from the cleared baseline, so it cannot pass by the fixture being
    /// unremovable for some other reason.
    #[test]
    fn a_root_a_service_still_points_at_is_refused() {
        let evidence = RootEvidence {
            referencing_registrations: vec!["dig-node service".to_string()],
            ..duplicate_root()
        };
        match decide(&evidence) {
            Verdict::Refuse(reason) => {
                assert!(reason.contains("dig-node service"), "got: {reason}");
                assert!(reason.contains(ROOT), "the reason must name the root: {reason}");
            }
            Verdict::Remove => panic!("a root a privileged registration points at must NOT be removed"),
        }
    }

    /// REFUSAL 2 — a process is running from the root right now.
    #[test]
    fn a_root_with_a_running_process_is_refused() {
        let evidence = RootEvidence {
            running_images: vec![format!(r"{ROOT}\dig-node.exe")],
            ..duplicate_root()
        };
        match decide(&evidence) {
            Verdict::Refuse(reason) => assert!(reason.contains("running process"), "got: {reason}"),
            Verdict::Remove => panic!("a root with a live process must NOT be removed"),
        }
    }

    /// REFUSAL 3 — the root holds something the current install root does not, so it is not a
    /// superseded copy and deleting it would lose the only copy.
    ///
    /// The fixture keeps `dig-node.exe` duplicated and adds ONE unique entry, so the difference
    /// between this and the cleared baseline is exactly the property under test — an implementation
    /// that compared only the entry COUNT, or only the first entry, is distinguishable here.
    #[test]
    fn a_root_holding_something_the_current_root_lacks_is_refused() {
        let evidence = RootEvidence {
            entries: vec!["dig-node.exe".to_string(), "operator-notes.txt".to_string()],
            ..duplicate_root()
        };
        match decide(&evidence) {
            Verdict::Refuse(reason) => {
                assert!(reason.contains("operator-notes.txt"), "got: {reason}");
                assert!(
                    !reason.contains("dig-node.exe"),
                    "the duplicated binary is not a reason to refuse: {reason}"
                );
            }
            Verdict::Remove => panic!("a root holding a unique file must NOT be removed"),
        }
    }

    /// Filenames compare case-insensitively: a Windows current root holding `DIG-NODE.EXE` already
    /// holds `dig-node.exe`. A case-sensitive comparison would call every binary unique and refuse
    /// every removal, which would leave #2205 unfixed while every refusal test above still passed.
    #[test]
    fn a_duplicate_differing_only_in_case_is_not_unique() {
        let evidence = RootEvidence {
            entries: vec!["dig-node.exe".to_string()],
            current_entries: vec!["DIG-NODE.EXE".to_string()],
            ..duplicate_root()
        };
        assert_eq!(decide(&evidence), Verdict::Remove);
    }

    /// An empty superseded directory is removable: there is nothing to lose, and its PATH entry is
    /// exactly the thing that must stop shadowing.
    #[test]
    fn an_empty_root_is_removable() {
        let evidence = RootEvidence {
            entries: Vec::new(),
            ..duplicate_root()
        };
        assert_eq!(decide(&evidence), Verdict::Remove);
    }

    /// A registration is reported ahead of a unique file when BOTH hold: one sufficient reason is the
    /// whole answer, and the live registration is the one an operator must act on first.
    #[test]
    fn the_most_serious_reason_is_the_one_reported() {
        let evidence = RootEvidence {
            entries: vec!["only-here.dll".to_string()],
            referencing_registrations: vec!["dig-dns service".to_string()],
            running_images: vec![format!(r"{ROOT}\dig-dns.exe")],
            ..duplicate_root()
        };
        match decide(&evidence) {
            Verdict::Refuse(reason) => assert!(reason.contains("dig-dns service"), "got: {reason}"),
            Verdict::Remove => panic!("must refuse"),
        }
    }

    // -- the candidate set -----------------------------------------------------

    /// The current install root must never be a removal candidate — that would delete the binaries
    /// this very run placed. Asserted on Windows's map specifically, because that is the only OS with
    /// superseded roots and the check must hold whichever host runs the suite.
    #[test]
    fn the_current_install_root_is_never_a_candidate() {
        let current = paths::protected_bin_dir();
        assert!(
            !paths::superseded_roots(Os::Windows).contains(&current),
            "the current root must never be scheduled for removal"
        );
    }

    /// Every candidate sits under the superseded base and is named for a real DIG component, and the
    /// component measured in #2205 is among them.
    #[test]
    fn candidates_are_the_per_component_dirs_under_the_superseded_base() {
        let base = paths::superseded_root_base(Os::Windows).expect("Windows has a superseded base");
        let candidates = paths::superseded_roots(Os::Windows);
        assert!(
            candidates.contains(&base.join("dig-node")),
            "the root measured in #2205 must be a candidate: {candidates:?}"
        );
        for candidate in &candidates {
            assert_eq!(candidate.parent(), Some(base.as_path()));
            let name = candidate.file_name().unwrap().to_string_lossy().to_string();
            assert!(
                crate::migrate::DIG_BINARY_STEMS.contains(&name.as_str()),
                "{name} is not a DIG component"
            );
        }
    }

    /// unix has always had the single `/opt/dig/bin` root, so there is nothing to vacate and this
    /// cleanup must be inert there — otherwise a unix install would start deleting directories it
    /// never created.
    #[test]
    fn unix_has_no_superseded_roots() {
        for os in [Os::Linux, Os::MacOs] {
            assert!(paths::superseded_root_base(os).is_none());
            assert!(paths::superseded_roots(os).is_empty());
        }
    }

    // -- running-process matching ----------------------------------------------

    /// The running-process filter must match on the ROOT, not on the executable name — the whole
    /// difficulty of #2205 is that the superseded and the current copy share a filename.
    ///
    /// The fixture therefore lists BOTH copies as running. Only the one under the candidate root may
    /// be returned; an implementation matching by base name returns both and is caught.
    #[test]
    fn a_running_process_is_matched_by_root_not_by_executable_name() {
        let listing = format!(
            "{ROOT}\\dig-node.exe\r\nC:\\Program Files\\DIG\\bin\\dig-node.exe\r\n\r\nC:\\Windows\\explorer.exe\n"
        );
        assert_eq!(
            images_under(&listing, Path::new(ROOT), Os::Windows),
            vec![format!(r"{ROOT}\dig-node.exe")]
        );
    }

    #[test]
    fn no_running_process_under_the_root_yields_nothing() {
        let listing = "C:\\Program Files\\DIG\\bin\\dig-node.exe\nC:\\Windows\\explorer.exe\n";
        assert!(images_under(listing, Path::new(ROOT), Os::Windows).is_empty());
    }

    // -- the report ------------------------------------------------------------

    #[test]
    fn a_default_result_is_a_clean_no_op() {
        let r = SupersedeResult::default();
        assert!(!r.acted);
        assert!(r.removed_roots.is_empty());
        assert!(r.refused.is_empty());
    }

    #[test]
    fn the_result_serializes_with_stable_fields() {
        let r = SupersedeResult {
            acted: true,
            removed_roots: vec![ROOT.to_string()],
            removed_binaries: vec![format!(r"{ROOT}\dig-node.exe")],
            path_entries_removed: vec![format!("machine PATH: {ROOT}")],
            refused: vec!["still referenced".to_string()],
            notes: Vec::new(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["acted"], true);
        assert_eq!(v["removed_roots"][0], ROOT);
        assert_eq!(v["path_entries_removed"][0], format!("machine PATH: {ROOT}"));
        assert_eq!(v["refused"][0], "still referenced");
    }
}
