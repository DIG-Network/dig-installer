//! Superseding a SECOND, competing installation of a DIG component (dig_ecosystem#2205).
//!
//! # The situation
//!
//! A Windows machine can end up with two managed copies of one component. dig-installer places
//! `dig-node.exe` in `%ProgramFiles%\DIG\bin`; an OLDER dig-node MSI package placed its own in a
//! SECOND, competing location under `%ProgramFiles%\DIG Network\dig-node\` (`dig-node.wxs` ->
//! `INSTALLFOLDER`), added THAT directory to the MACHINE `Path` through its own `PathEntry` component,
//! and registered the same `net.dignetwork.dig-node` service through `ServiceInstall`.
//!
//! A new shell composes the machine `Path` BEFORE the user `Path`, so that legacy copy wins the bare
//! name against the copy this run places. Measured on the machine that raised #2205:
//!
//! ```text
//! fresh session PATH entry [50]  C:\Program Files\DIG Network\dig-node\   <- the legacy copy, wins
//! fresh session PATH entry [51]  C:\Program Files\DIG\bin                 <- this installer's copy
//! ```
//!
//! The install then correctly failed its own reachability check
//! ([`crate::pathcheck::verify_cli_resolves`]). The check was right; the machine had two installers.
//!
//! Since dig-node 0.99.9/0.99.10 (`874ac4c`) the MSI installs to the SAME canonical
//! `%ProgramFiles%\DIG\bin` root with NO PATH row — so on an up-to-date machine the MSI IS the current
//! install, not a shadow. Supersession is therefore decided from the product's recorded install
//! LOCATION and narrowed to a genuine legacy shadow, so this step can never uninstall the live
//! canonical install (dig_ecosystem#2304).
//!
//! # Two paths, because two different things can own that directory
//!
//! **A registered MSI product** is removed by [`supersede_msi_products`], via `msiexec /x`, and never
//! by deleting files. Its files, Add/Remove-Programs registration, machine-PATH component and service
//! are one transaction in the Windows Installer database; deleting the directory leaves all of them
//! pointing at nothing. That runs EARLY, before this run registers any service, because the package's
//! `ServiceControl` deletes the shared service on uninstall.
//!
//! **An orphaned directory** — no registered product, a failed uninstall, a hand-deleted registration
//! — has no database to respect, so it is removed here, conditionally.
//!
//! # For the orphan path, the REFUSAL is the feature
//!
//! Deleting a directory something still points at breaks DIG on a machine that was working, which is
//! strictly worse than the stale directory. So removal is a verdict reached from gathered evidence
//! ([`decide`], pure) rather than an optimistic delete, and it refuses on any of:
//!
//! 0. a STILL-REGISTERED Windows Installer product owning the directory — absolute, never a fallback;
//! 1. a privileged registration (a service `PathName`, the beacon task) whose binary resolves under the
//!    root — deleting it would leave a registration pointing at nothing;
//! 2. a RUNNING process whose image resolves under the root — that binary is in use right now;
//! 3. an entry the current root does not also have — the root would then be the only copy of
//!    something, and this is a cleanup, never a data-losing one.
//!
//! Each component's directory is judged INDEPENDENTLY: a refusal on one must not leave another's stale
//! directory on `PATH`.
//!
//! # How this differs from the #565 migration
//!
//! [`crate::migrate`] vacates a LEGACY USER-WRITABLE root, which is a privilege-escalation surface, so
//! it is mandatory and aggressive: it DEREGISTERS any service pointing at such a root and deletes the
//! binaries, because leaving them is worse than any breakage removing them could cause. Nothing here is
//! user-writable, so nothing escalates, and the trade runs the other way.
//!
//! Layering matches the rest of the crate: the verdict and the product selection are pure and
//! unit-tested; the scan/delete/PATH-rewrite/msiexec is a thin imperative layer.

use std::path::{Path, PathBuf};

use crate::msi;
use crate::paths;
use crate::regaudit;
use crate::target::{Os, Target};

/// Removing one directory from every persisted PATH scope that carries it, as an injectable boundary.
///
/// Production is [`paths::remove_from_persisted_path`]; a test supplies its own so the orchestration
/// around the write is provable without touching `HKLM`.
pub type PathEntryRemover<'a> = dyn FnMut(&Path) -> Result<Vec<paths::PathScope>, String> + 'a;

/// What was observed about one candidate superseded root — the whole input to [`decide`].
///
/// Gathered from the machine by [`remove_superseded_roots`]; constructed directly by tests, so every
/// verdict is reachable without a real install.
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
    /// The Add/Remove-Programs name of a STILL-REGISTERED Windows Installer product owning this root,
    /// if any. `Some` is an absolute bar on deleting anything here — see refusal 0 in [`decide`].
    pub registered_msi_product: Option<String>,
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
/// The refusal reasons are checked in order of how badly getting them wrong would hurt: a registered
/// MSI product first (an unrecoverable ghost), then a live registration (a machine that boots into a
/// broken service), then a running process, then an entry that exists nowhere else. The first that
/// fires is reported, because one sufficient reason to refuse is the whole answer.
///
/// # Refusal 0 is absolute, and it is the one that was learned the hard way
///
/// A directory owned by a REGISTERED Windows Installer product must never be deleted here, under any
/// circumstance — not as a fallback, and specifically not after an `msiexec` attempt has failed. The
/// files, the Add/Remove-Programs registration, the MSI-owned machine-PATH component and the service
/// are one transaction in the Installer database, and deleting the files alone leaves all three
/// pointing at nothing:
///
/// ```text
/// DisplayName    : DIG NETWORK: NODE
/// DisplayVersion : 0.98.0
/// UninstallString: MsiExec.exe /I{3285965C-DFE5-43E7-9F3D-6F92426AFE00}
/// ```
///
/// That was measured on a real machine after exactly this directory was removed by hand: a product
/// still registered, its repair broken, and its later upgrade convinced an older version is present.
/// `crate::msi`'s module header calls that outcome unacceptable, and it is right.
///
/// The sanctioned removal is `msiexec /x`, run EARLY by [`supersede_msi_products`] — before this run
/// registers its own services, because the package's `ServiceControl` deletes the shared service on
/// uninstall. If that did not happen or did not succeed, refusing here is the correct end state:
/// loud, recoverable, and reported alongside the reachability verdict it explains.
pub fn decide(evidence: &RootEvidence) -> Verdict {
    let root = evidence.root.display();

    if let Some(product) = &evidence.registered_msi_product {
        return Verdict::Refuse(format!(
            "{root} belongs to the registered Windows Installer product \"{product}\" — it can \n             only be removed by `msiexec /x`, which also removes its Add/Remove-Programs entry, \n             its machine-PATH component and its service; deleting the directory would leave a \n             registered product with no files"
        ));
    }
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

/// Uninstall, via `msiexec /x`, every DIG Windows Installer product this run supersedes.
///
/// # Why this is an INSTALL step, and why it must be an EARLY one
///
/// A DIG MSI package installs the same component this run installs, to `%ProgramFiles%\DIG
/// Network\<stem>\`, adds that directory to the MACHINE `Path` through its own `PathEntry` component,
/// and registers the same service through `ServiceInstall`. The machine `Path` is composed before the
/// user `Path`, so the MSI's copy wins the bare name against the copy this run places and the install
/// correctly fails its own reachability check. Two managed copies of one component is not a state
/// either installer can keep coherent, so the install takes over: it removes the product properly.
///
/// The ordering is not a preference. The package's `ServiceControl` STOPS AND DELETES
/// `net.dignetwork.dig-node` on uninstall, so running this after the service step would delete the
/// service this run had just registered — measured, by hand, on the machine that raised #2205. Placed
/// beside the #565 migration, before any component is installed, the normal install then registers the
/// service fresh from the current root. Same vacate-then-reregister shape, same reason.
///
/// Never fatal: a product that will not uninstall is reported, and [`decide`]'s refusal 0 then keeps
/// the file-deletion path away from its directory.
pub fn supersede_msi_products(
    installing: &[&str],
    dry_run: bool,
    log: &mut dyn FnMut(&str),
) -> Vec<msi::MsiRemoval> {
    let installed = msi::installed_dig_products();
    let mut remove = |stem, code| msi::remove_one_product(stem, code, dry_run);
    supersede_msi_products_with(installing, &installed, &mut remove, log)
}

/// Uninstalling ONE superseded MSI product, as an injectable boundary.
///
/// Production removes it with `msiexec /x` ([`msi::remove_one_product`]); a test supplies its own so
/// the ORCHESTRATION — and, critically, that NO destructive `msiexec` is invoked when nothing is a
/// legacy shadow (dig_ecosystem#2304 AC2) — is provable without spawning `msiexec` or touching the
/// Windows Installer database.
pub type MsiRemover<'a> = dyn FnMut(String, msi::ProductCode) -> msi::MsiRemoval + 'a;

/// [`supersede_msi_products`] with the installed-product set and the removal action injected.
///
/// The removal is only ever reached for a product [`msi::products_to_supersede`] selected — which, per
/// dig_ecosystem#2304, is ONLY a genuine legacy shadow under `%ProgramFiles%\DIG Network`, never the
/// current canonical `%ProgramFiles%\DIG\bin` install. On an up-to-date machine the selection is empty
/// and this returns before `remove_product` is ever called, so a later-step install failure cannot have
/// uninstalled the live canonical dig-node.
pub fn supersede_msi_products_with(
    installing: &[&str],
    installed: &[msi::InstalledMsiProduct],
    remove_product: &mut MsiRemover<'_>,
    log: &mut dyn FnMut(&str),
) -> Vec<msi::MsiRemoval> {
    let superseding = msi::products_to_supersede(installed, installing);
    if superseding.is_empty() {
        return Vec::new();
    }
    log("Superseding a legacy-shadow MSI-installed DIG component this run replaces (#2205/#2304):");
    superseding
        .into_iter()
        .map(|(stem, code)| {
            let removal = remove_product(stem, code);
            let mark = if removal.outcome.ok() {
                '\u{2713}'
            } else {
                '!'
            };
            log(&format!("    {mark} {}", removal.note));
            removal
        })
        .collect()
}

/// Remove every superseded install root that [`decide`] clears, and drop its persisted PATH entries.
///
/// Runs BEFORE the post-install reachability check so a cleared shadow is gone by the time that check
/// reads the persisted PATH — the check re-reads the registry, so the removal is visible to it.
///
/// Never fatal: a root that cannot be cleaned is recorded and the install continues. The reachability
/// check is what fails an install over a shadow, and it is still free to do so.
pub fn remove_superseded_roots(target: &Target, log: &mut dyn FnMut(&str)) -> SupersedeResult {
    remove_superseded_roots_with(target, &mut paths::remove_from_persisted_path, log)
}

/// [`remove_superseded_roots`] with the persisted-PATH write injected.
///
/// The injection exists so the ORCHESTRATION is testable (dig_ecosystem#2205 review F3). The real
/// remover writes `HKLM`, which no unit test may do, and the untestable half was the primary unblock:
/// an unconditional early return in the PATH-drop path left the whole suite green, so the fix could
/// have regressed to a no-op and shipped.
pub fn remove_superseded_roots_with(
    target: &Target,
    remove_path_entry: &mut PathEntryRemover<'_>,
    log: &mut dyn FnMut(&str),
) -> SupersedeResult {
    let mut result = SupersedeResult::default();
    let current_root = paths::protected_bin_dir();
    let current_entries = entry_names(&current_root);

    for root in paths::superseded_roots(target.os) {
        if !root.is_dir() {
            // The directory is gone but a PATH entry naming it can outlive it. Dropping that costs
            // nothing and stops it shadowing again if anything ever recreates the directory — and a
            // machine-PATH write is a real change, so it must show up in the report either way.
            if drop_path_entries(&root, remove_path_entry, &mut result, log) {
                result.acted = true;
            }
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
                remove_root(
                    target,
                    &root,
                    paths::superseded_root_base(target.os).as_deref(),
                    &mut result,
                    log,
                );
                drop_path_entries(&root, remove_path_entry, &mut result, log);
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
        registered_msi_product: registered_msi_product_for(root),
    }
}

/// The Add/Remove-Programs name of a registered Windows Installer product owning `root`, if any.
///
/// A candidate root is `<superseded base>/<component stem>` by construction
/// ([`paths::superseded_roots`]), and the MSI package for that stem installs exactly there
/// (`dig-node.wxs` -> `INSTALLFOLDER`), so the directory's own name is the attribution. A directory
/// not named for a known MSI package's stem is not an MSI product's directory.
fn registered_msi_product_for(root: &Path) -> Option<String> {
    let stem = root.file_name()?.to_string_lossy().to_string();
    let installed = msi::installed_dig_products();
    msi::MSI_PACKAGES
        .iter()
        .find(|p| p.stem.eq_ignore_ascii_case(&stem))
        .filter(|p| {
            installed
                .iter()
                .any(|ip| ip.stem.eq_ignore_ascii_case(p.stem))
        })
        .map(|p| p.display_name.to_string())
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

/// Delete the DIG binaries in `root`, then the directory itself — and `base`, if removing `root` left
/// the superseded base empty.
///
/// `base` is INJECTED rather than derived from `target`, so a test can exercise the real deletion
/// against a temporary directory without the tidy-up reaching for a real `%ProgramFiles%` path.
///
/// Only KNOWN DIG filenames are deleted, one by one, and `symlink_metadata` is used so a reparse point
/// is never followed — the same rule [`crate::migrate`] follows. [`decide`] has already established
/// that every entry here also exists in the current root, so this cannot be the only copy of anything;
/// the filename restriction is the second, independent guard.
fn remove_root(
    target: &Target,
    root: &Path,
    base: Option<&Path>,
    result: &mut SupersedeResult,
    log: &mut dyn FnMut(&str),
) {
    for stem in crate::migrate::DIG_BINARY_STEMS {
        let candidate = root.join(target.exe_name(stem));
        match std::fs::symlink_metadata(&candidate) {
            Ok(md) if md.file_type().is_file() => match std::fs::remove_file(&candidate) {
                Ok(()) => {
                    log(&format!("    ✓ removed {}", candidate.display()));
                    result
                        .removed_binaries
                        .push(candidate.display().to_string());
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
        if let Some(base) = base {
            let _ = std::fs::remove_dir(base); // only succeeds once every component dir is gone
        }
    } else {
        result.notes.push(format!(
            "{} still holds entries and was kept",
            root.display()
        ));
    }
}

/// Drop `root` from every persisted PATH scope that carries it, recording what changed.
fn drop_path_entries(
    root: &Path,
    remove_path_entry: &mut PathEntryRemover<'_>,
    result: &mut SupersedeResult,
    log: &mut dyn FnMut(&str),
) -> bool {
    match remove_path_entry(root) {
        Ok(scopes) => {
            let changed = !scopes.is_empty();
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
            changed
        }
        Err(e) => {
            let note = format!(
                "could not drop {} from the persisted PATH: {e}",
                root.display()
            );
            log(&format!("    ! {note}"));
            result.notes.push(note);
            // A failed write is not a change, but it IS something the run must report.
            true
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
// Called in production only from the Windows `running_images_under`, but left un-gated for the same
// reason as `pathcheck::expand_env_refs`: a `cfg(windows)` gate would hide its tests from every unix
// runner, and matching a process by ROOT rather than by executable name is exactly the rule that must
// stay pinned.
#[cfg_attr(not(windows), allow(dead_code))]
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
            registered_msi_product: None,
        }
    }

    /// The control, and it has to come first: the baseline fixture MUST clear. Without it every
    /// refusal test below is satisfied by an implementation that refuses unconditionally.
    #[test]
    fn a_root_nothing_depends_on_is_removed() {
        assert_eq!(decide(&duplicate_root()), Verdict::Remove);
    }

    /// REFUSAL 0 — the root belongs to a REGISTERED Windows Installer product.
    ///
    /// The gating finding on the first round of this PR, and it was reproduced by hand on a real
    /// machine before any test existed: deleting this directory left
    ///
    /// ```text
    /// DisplayName    : DIG NETWORK: NODE
    /// UninstallString: MsiExec.exe /I{3285965C-DFE5-43E7-9F3D-6F92426AFE00}
    /// ```
    ///
    /// — a registered product with no files, no PATH component and no service.
    ///
    /// The fixture varies ONE field from the CLEARED baseline, and that matters more here than
    /// anywhere else in this module: on the real machine none of the other three refusals fired. The
    /// installer registers its own services earlier in the same run, so refusal 1 was defused by the
    /// installer's own work; the services were stopped, so refusal 2 was silent; and the current root
    /// held `dig-node.exe` by then, so refusal 3 was silent too. A baseline that refused for some
    /// other reason would have hidden exactly the hole that shipped.
    #[test]
    fn a_root_owned_by_a_registered_msi_product_is_refused() {
        let evidence = RootEvidence {
            registered_msi_product: Some("DIG NETWORK: NODE".to_string()),
            ..duplicate_root()
        };
        match decide(&evidence) {
            Verdict::Refuse(reason) => {
                assert!(reason.contains("DIG NETWORK: NODE"), "got: {reason}");
                assert!(
                    reason.contains("msiexec"),
                    "the reason must name the only correct removal: {reason}"
                );
            }
            Verdict::Remove => panic!(
                "deleting a registered MSI product's directory leaves a ghost Add/Remove-Programs \
                 entry, a broken repair, and a service pointing at nothing"
            ),
        }
    }

    /// Refusal 0 outranks every other reason, including a still-live service.
    ///
    /// Both are true on an MSI-installed machine before the services are re-pointed, and the operator
    /// action differs: `msiexec /x` removes the service correctly, whereas the refusal-1 wording would
    /// send them to deregister it by hand and then still leave the product registered.
    #[test]
    fn the_msi_refusal_outranks_a_referencing_registration() {
        let evidence = RootEvidence {
            registered_msi_product: Some("DIG NETWORK: NODE".to_string()),
            referencing_registrations: vec!["dig-node service".to_string()],
            running_images: vec![format!(r"{ROOT}\dig-node.exe")],
            entries: vec!["only-here.dll".to_string()],
            ..duplicate_root()
        };
        match decide(&evidence) {
            Verdict::Refuse(reason) => assert!(reason.contains("msiexec"), "got: {reason}"),
            Verdict::Remove => panic!("must refuse"),
        }
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
                assert!(
                    reason.contains(ROOT),
                    "the reason must name the root: {reason}"
                );
            }
            Verdict::Remove => {
                panic!("a root a privileged registration points at must NOT be removed")
            }
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

    // -- the deletion itself ---------------------------------------------------

    /// A `Target` for the host's own OS, so `exe_name` produces the filenames these tests create.
    fn host_target() -> Target {
        Target::current().expect("the host OS is supported")
    }

    /// The cleared path, end to end on a real filesystem: the DIG binaries go, the directory goes,
    /// and the now-empty base goes with it.
    ///
    /// This is the half `decide` cannot speak for. It is asserted on real files rather than a mock
    /// because the property at issue — that the deletion actually happens and is confined to the
    /// candidate — is a filesystem property.
    #[test]
    fn a_cleared_root_and_its_emptied_base_are_really_deleted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("DIG Network");
        let root = base.join("dig-node");
        std::fs::create_dir_all(&root).expect("create");
        let target = host_target();
        let binary = root.join(target.exe_name("dig-node"));
        std::fs::write(&binary, b"superseded").expect("write");

        let mut result = SupersedeResult::default();
        remove_root(&target, &root, Some(&base), &mut result, &mut |_| {});

        assert!(!binary.exists(), "the superseded binary must be deleted");
        assert!(!root.exists(), "the superseded root must be deleted");
        assert!(
            !base.exists(),
            "an emptied superseded base must be deleted too"
        );
        assert_eq!(result.removed_roots, vec![root.display().to_string()]);
        assert_eq!(result.removed_binaries, vec![binary.display().to_string()]);
        assert!(result.notes.is_empty(), "a clean removal reports no note");
    }

    /// The deletion is confined to KNOWN DIG filenames, and an unexpected leftover keeps the whole
    /// directory rather than being bulldozed.
    ///
    /// `decide` should never route such a root here (rule 3 refuses it), so this asserts the SECOND,
    /// independent guard — the one that still holds if the verdict is ever wrong. The fixture pairs a
    /// DIG binary with a foreign file so both halves are observable in one run: the DIG binary must
    /// go, the foreign file must stay, and the directory must survive because the foreign file does.
    #[test]
    fn deletion_is_confined_to_known_dig_filenames_and_keeps_a_directory_that_is_not_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("DIG Network");
        let root = base.join("dig-node");
        std::fs::create_dir_all(&root).expect("create");
        let target = host_target();
        let dig_binary = root.join(target.exe_name("dig-node"));
        let foreign = root.join("operator-notes.txt");
        std::fs::write(&dig_binary, b"superseded").expect("write");
        std::fs::write(&foreign, b"do not delete me").expect("write");

        let mut result = SupersedeResult::default();
        remove_root(&target, &root, Some(&base), &mut result, &mut |_| {});

        assert!(!dig_binary.exists(), "the DIG binary is still removed");
        assert!(
            foreign.exists(),
            "a file the installer did not place must survive"
        );
        assert!(
            root.exists(),
            "a non-empty directory must be kept, never bulldozed"
        );
        assert!(result.removed_roots.is_empty());
        assert!(
            result
                .notes
                .iter()
                .any(|n| n.contains("still holds entries")),
            "keeping the directory must be reported, not silent: {:?}",
            result.notes
        );
    }

    /// `entry_names` reports what is really there, and an unreadable/absent directory yields nothing
    /// rather than panicking — the verdict for a vanished root must still be reachable.
    #[test]
    fn entry_names_lists_a_real_directory_and_tolerates_a_missing_one() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("dig-node.exe"), b"x").expect("write");
        std::fs::create_dir(tmp.path().join("nested")).expect("mkdir");

        let mut found = entry_names(tmp.path());
        found.sort();
        assert_eq!(
            found,
            vec!["dig-node.exe".to_string(), "nested".to_string()]
        );
        assert!(entry_names(&tmp.path().join("no-such-dir")).is_empty());
    }

    // -- the PATH-entry drop, and the orchestration around it (review F3) ------

    /// A remover that records every directory it was asked about and replies from a script.
    fn recording_remover(
        script: Result<Vec<paths::PathScope>, String>,
        seen: &mut Vec<String>,
    ) -> impl FnMut(&Path) -> Result<Vec<paths::PathScope>, String> + '_ {
        move |dir: &Path| {
            seen.push(dir.display().to_string());
            script.clone()
        }
    }

    /// THE F3 property: the PATH entry really is dropped, and the report says which scope changed.
    ///
    /// An unconditional early return at the top of `drop_path_entries` used to leave the whole suite
    /// green — so the primary unblock could have regressed to a no-op and shipped. The remover is
    /// injected because the real one writes `HKLM`, which no unit test may do.
    #[test]
    fn a_dropped_path_entry_is_recorded_for_every_scope_that_carried_it() {
        let mut seen = Vec::new();
        let mut result = SupersedeResult::default();
        let root = Path::new(ROOT);
        let changed = {
            let mut remover = recording_remover(
                Ok(vec![paths::PathScope::Machine, paths::PathScope::User]),
                &mut seen,
            );
            drop_path_entries(root, &mut remover, &mut result, &mut |_| {})
        };

        assert!(
            changed,
            "a scope was changed, so the caller must learn about it"
        );
        assert_eq!(
            seen,
            vec![ROOT.to_string()],
            "the remover is asked about the root itself"
        );
        assert_eq!(
            result.path_entries_removed,
            vec![
                format!("machine PATH: {ROOT}"),
                format!("user PATH: {ROOT}"),
            ],
            "both scopes must be reported, and named"
        );
        assert!(result.notes.is_empty());
    }

    /// A root on NO scope changes nothing and reports nothing — otherwise every clean machine would
    /// claim a PATH edit it never made.
    #[test]
    fn a_root_on_no_path_scope_reports_no_change() {
        let mut seen = Vec::new();
        let mut result = SupersedeResult::default();
        let changed = {
            let mut remover = recording_remover(Ok(Vec::new()), &mut seen);
            drop_path_entries(Path::new(ROOT), &mut remover, &mut result, &mut |_| {})
        };
        assert!(!changed);
        assert!(result.path_entries_removed.is_empty());
        assert!(result.notes.is_empty());
    }

    /// A failed write is REPORTED, never swallowed: the machine PATH still shadows the current root,
    /// which is exactly what the operator needs to be told.
    #[test]
    fn a_failed_path_write_is_reported_as_a_note_not_silently_dropped() {
        let mut seen = Vec::new();
        let mut result = SupersedeResult::default();
        let changed = {
            let mut remover = recording_remover(
                Err("open machine PATH for write: access denied".into()),
                &mut seen,
            );
            drop_path_entries(Path::new(ROOT), &mut remover, &mut result, &mut |_| {})
        };
        assert!(changed, "a failure is still something the run must surface");
        assert!(result.path_entries_removed.is_empty());
        assert_eq!(result.notes.len(), 1);
        assert!(
            result.notes[0].contains("access denied"),
            "got: {:?}",
            result.notes
        );
    }

    /// The orchestration reaches the PATH drop for EVERY candidate, including the ones whose directory
    /// is already gone — a stale machine-PATH entry outlives its directory and still shadows.
    ///
    /// Also pins the non-gating report defect the reviewer found: a run whose only change was a
    /// machine-PATH edit on an already-gone directory must still report `acted`, or that edit is
    /// invisible in `--json`.
    #[test]
    fn every_candidate_reaches_the_path_drop_and_a_path_only_change_is_reported() {
        // Windows STATED, not `host_target()`. The gating `test + coverage` job runs ubuntu-only, and
        // `superseded_roots(Os::Linux)` is empty -- so on the one runner that blocks merge the loop
        // body never executed and the test fell into its own `candidates.is_empty()` arm, which is
        // true for ANY loop body including none. Proven: deleting the PATH-drop leg fails this test
        // on a Windows target and PASSES on a Linux one (dig-installer#62 review, round 2).
        //
        // Host-independent: `superseded_roots(Os::Windows)` is a pure function of the OS, and the
        // not-a-directory branch these candidates take reaches no Windows-only I/O.
        let target = Target {
            os: Os::Windows,
            arch: host_target().arch,
        };
        let mut seen = Vec::new();
        let result = {
            let mut remover = recording_remover(Ok(vec![paths::PathScope::Machine]), &mut seen);
            remove_superseded_roots_with(&target, &mut remover, &mut |_| {})
        };

        let candidates = paths::superseded_roots(target.os);
        assert_eq!(
            seen.len(),
            candidates.len(),
            "every candidate must reach the PATH drop, not only the ones whose directory exists"
        );
        if candidates.is_empty() {
            // unix: nothing to supersede, so nothing may be reported either.
            assert!(!result.acted);
            assert!(result.path_entries_removed.is_empty());
        } else {
            assert!(
                result.acted,
                "a machine-PATH edit is a real change and must not be missing from the report"
            );
            assert_eq!(result.path_entries_removed.len(), candidates.len());
        }
    }

    // -- which MSI products an install supersedes (review F1) ------------------

    /// Only a product for a component THIS RUN installs is superseded. Removing a DIG MSI for a
    /// component the run was not asked to install would leave the machine without it, with no
    /// replacement coming.
    ///
    /// The fixture offers two installed products and selects one, so a filter that passed everything
    /// through and a filter that dropped everything are both distinguishable.
    #[test]
    fn only_a_product_for_a_component_this_run_installs_is_superseded() {
        let code = |g: &str| msi::parse_product_code(g).expect("valid GUID");
        // Both are genuine LEGACY SHADOWS (under `%ProgramFiles%\DIG Network`) — so selection here
        // turns purely on the stem, which is what this test pins.
        let shadow = |stem: &str| {
            Some(
                paths::superseded_root_base(Os::Windows)
                    .expect("Windows has a legacy base")
                    .join(stem),
            )
        };
        let installed = vec![
            msi::InstalledMsiProduct {
                stem: "dig-node".to_string(),
                code: code("{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}"),
                location: shadow("dig-node"),
            },
            msi::InstalledMsiProduct {
                stem: "dig-relay".to_string(),
                code: code("{01234567-89AB-CDEF-0123-456789ABCDEF}"),
                location: shadow("dig-relay"),
            },
        ];

        let selected = msi::products_to_supersede(&installed, &["dig-node", "dign", "digstore"]);
        assert_eq!(selected.len(), 1, "got: {selected:?}");
        assert_eq!(selected[0].0, "dig-node");

        assert!(
            msi::products_to_supersede(&installed, &["digstore"]).is_empty(),
            "a run installing neither product supersedes neither"
        );
        assert_eq!(
            msi::products_to_supersede(&installed, &["DIG-NODE"]).len(),
            1,
            "stems compare case-insensitively"
        );
        assert!(msi::products_to_supersede(&[], &["dig-node"]).is_empty());
    }

    /// AC2 (dig_ecosystem#2304): on an up-to-date machine — where the dig-node MSI installed to the
    /// CURRENT canonical `%ProgramFiles%\DIG\bin` — the supersede step takes NO destructive action, so
    /// no `msiexec /x` can uninstall the live install and a later-step failure leaves it intact.
    ///
    /// The removal boundary is injected and COUNTS its calls: the load-bearing property is not "the
    /// returned list is empty" (which a filter at any layer could satisfy) but "the destructive action
    /// was never reached". The fixture pairs a canonical dig-node with a legacy-shadow dig-relay the run
    /// is NOT installing, so a stem-only OR a location-blind implementation is both distinguishable.
    #[test]
    fn a_canonical_install_is_never_superseded_so_no_msiexec_runs() {
        let canonical = paths::protected_bin_dir();
        let legacy = paths::superseded_root_base(Os::Windows).expect("Windows has a legacy base");
        let code = |g: &str| msi::parse_product_code(g).expect("valid GUID");
        let installed = vec![
            msi::InstalledMsiProduct {
                stem: "dig-node".to_string(),
                code: code("{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}"),
                location: Some(canonical.clone()),
            },
            msi::InstalledMsiProduct {
                stem: "dig-relay".to_string(),
                code: code("{01234567-89AB-CDEF-0123-456789ABCDEF}"),
                location: Some(legacy.join("dig-relay")),
            },
        ];

        let mut removed: Vec<String> = Vec::new();
        let out = {
            let mut remover = |stem: String, code: msi::ProductCode| {
                removed.push(stem.clone());
                msi::MsiRemoval {
                    stem,
                    product_code: code.as_str().to_string(),
                    outcome: msi::MsiOutcome::Removed,
                    note: "should never be reached".to_string(),
                }
            };
            supersede_msi_products_with(&["dig-node"], &installed, &mut remover, &mut |_| {})
        };

        assert!(
            removed.is_empty(),
            "the canonical dig-node install must never be uninstalled: {removed:?}"
        );
        assert!(
            out.is_empty(),
            "nothing was superseded, so nothing is reported"
        );
    }

    /// The regression complement of AC2: a genuine legacy shadow the run installs IS still removed via
    /// the boundary (the #2205 case must keep working).
    #[test]
    fn a_legacy_shadow_this_run_installs_is_still_superseded() {
        let legacy = paths::superseded_root_base(Os::Windows).expect("Windows has a legacy base");
        let installed = vec![msi::InstalledMsiProduct {
            stem: "dig-node".to_string(),
            code: msi::parse_product_code("{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}").unwrap(),
            location: Some(legacy.join("dig-node")),
        }];

        let mut removed: Vec<String> = Vec::new();
        let out = {
            let mut remover = |stem: String, code: msi::ProductCode| {
                removed.push(stem.clone());
                msi::MsiRemoval {
                    stem,
                    product_code: code.as_str().to_string(),
                    outcome: msi::MsiOutcome::Removed,
                    note: "removed".to_string(),
                }
            };
            supersede_msi_products_with(&["dig-node"], &installed, &mut remover, &mut |_| {})
        };

        assert_eq!(removed, vec!["dig-node".to_string()]);
        assert_eq!(out.len(), 1);
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
        assert_eq!(
            v["path_entries_removed"][0],
            format!("machine PATH: {ROOT}")
        );
        assert_eq!(v["refused"][0], "still referenced");
    }
}
