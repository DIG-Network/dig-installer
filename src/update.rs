//! Version-aware update detection (issue #309): per component, DETECT what is
//! already installed, COMPARE it against the latest available release, and
//! DECIDE whether this run should **Install** (nothing there yet), **Update**
//! (an older or unreadable version is present — replace it), or **Skip** (it
//! is already current).
//!
//! The decision core ([`decide`]) is a pure function of two strings — no I/O,
//! no process spawn — so the whole matrix (absent / older / equal / newer /
//! unparseable, per CLAUDE.md §2.1 TDD) is exercised without touching a real
//! binary or service manager. The one I/O boundary, [`detect_installed_version`],
//! mirrors [`crate::pathcheck::cli_resolves`]: it spawns `<bin> --version` and
//! reads the reported version back. Callers combine the two — resolve the
//! latest release the normal way ([`crate::download::latest_release`]), detect
//! what's on disk, then [`decide`] — to gate the existing #232 stop→replace→
//! restart lifecycle ([`crate::service`]) on whether a replace is even needed.
//!
//! ## Extraction note (#504-B)
//!
//! This module is deliberately dependency-light (a hand-rolled 3-part semver
//! comparator, no `semver` crate) and self-contained so it can be lifted
//! verbatim into the future shared `dig-release-resolver` crate alongside
//! [`crate::release`]/[`crate::download`] without pulling the rest of
//! `dig-installer` along. When that extraction happens, re-export the moved
//! types from here rather than duplicating the logic.

use std::path::Path;
use std::process::Command;

use crate::proc::HideConsole;
use crate::release::Repo;

/// What a version probe found at a component's install destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedVersion {
    /// No binary exists at the expected destination — a first install.
    Absent,
    /// A binary exists and reported this raw `--version` output (e.g.
    /// `"dig-node 0.15.0"`). An empty string means the binary exists but its
    /// version could not be read (spawn failure or non-zero exit) — [`decide`]
    /// treats that the same as any other unparseable version: reinstall it.
    Present(String),
}

/// What this run should do with a component, decided by [`decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateAction {
    /// Nothing was installed — download + register fresh.
    Install,
    /// An older (or unreadable) version was installed — replace it, reusing
    /// the #232 stop→replace→restart lifecycle for service components.
    Update,
    /// The installed version is already current (or newer than the latest
    /// published release) — no-op, left exactly as it is.
    Skip,
}

impl UpdateAction {
    /// The stable machine-readable id for this action (matches the `serde`
    /// `snake_case` wire form) — for callers that want the string without
    /// round-tripping through JSON, e.g. the GUI's status-pill mapping.
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateAction::Install => "install",
            UpdateAction::Update => "update",
            UpdateAction::Skip => "skip",
        }
    }
}

/// The outcome of comparing a [`DetectedVersion`] against the latest
/// available release: what to do, plus enough detail to render it (the CLI
/// log line, the `--json` component entry, the GUI status pill).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UpdateDecision {
    pub action: UpdateAction,
    /// The version that was detected before this run (`None` when [`DetectedVersion::Absent`]).
    pub installed_version: Option<String>,
    /// The latest version available (bare semver, e.g. `"0.15.0"`).
    pub latest_version: String,
    /// A single human-readable line covering both the decision and the
    /// version transition, e.g. `"not installed → install v0.15.0"`,
    /// `"v0.14.0 → v0.15.0 (update)"`, `"v0.15.0 (up to date)"`. Used
    /// verbatim in the CLI run summary and the GUI status pill.
    pub summary: String,
}

/// A minimal 3-part semver (`MAJOR.MINOR.PATCH`) — exactly as much as this
/// installer needs to order releases. Deliberately stricter than full SemVer
/// (no pre-release/build-metadata ordering): every DIG-Network release tag
/// this installer resolves is a bare `vX.Y.Z` (git-cliff's Conventional-Commit
/// bump), so a string that doesn't fit this shape is far more likely to be a
/// broken/foreign `--version` output than a real pre-release tag — and
/// [`decide`] already treats "can't parse" as "reinstall to be safe", which is
/// the correct conservative default either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SimpleVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl SimpleVersion {
    /// Parse `"v0.15.0"` or `"0.15.0"` into its three numeric parts. `None`
    /// for anything else — extra dot-segments, non-numeric parts, or a
    /// pre-release/build suffix (`"0.15.0-rc.1"`) all fail to parse, which is
    /// the intended "can't confirm, reinstall" fallback (see the struct doc).
    fn parse(s: &str) -> Option<SimpleVersion> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let mut parts = s.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None; // more than three dot-segments
        }
        Some(SimpleVersion {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for SimpleVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Pull the version token out of a CLI's `--version` output. clap's default
/// formatter prints `"<name> <version>"` (e.g. `"dig-node 0.15.0"`); a bare
/// `"0.15.0"` also works since we just take the last whitespace-separated
/// token of the first line.
fn extract_version_token(raw: &str) -> Option<&str> {
    raw.lines().next()?.split_whitespace().last()
}

/// The core decision matrix (pure — no I/O): given what was detected at a
/// component's destination and the latest available version, decide
/// Install/Update/Skip. Every cell of the matrix maps to one of three
/// actions:
///
/// | detected                          | vs. latest        | action   |
/// |-----------------------------------|--------------------|----------|
/// | [`DetectedVersion::Absent`]       | —                  | Install  |
/// | present, parses, older            | installed < latest | Update   |
/// | present, parses, equal            | installed == latest| Skip     |
/// | present, parses, newer            | installed > latest | Skip     |
/// | present, does not parse           | —                  | Update (treated as a reinstall) |
pub fn decide(detected: &DetectedVersion, latest_version: &str) -> UpdateDecision {
    let latest = latest_version.to_string();
    match detected {
        DetectedVersion::Absent => UpdateDecision {
            action: UpdateAction::Install,
            installed_version: None,
            latest_version: latest.clone(),
            summary: format!("not installed → install v{latest}"),
        },
        DetectedVersion::Present(raw) => {
            let token = extract_version_token(raw).unwrap_or("");
            match (SimpleVersion::parse(token), SimpleVersion::parse(&latest)) {
                (Some(installed), Some(latest_parsed)) if installed < latest_parsed => {
                    UpdateDecision {
                        action: UpdateAction::Update,
                        installed_version: Some(installed.to_string()),
                        latest_version: latest.clone(),
                        summary: format!("v{installed} → v{latest} (update)"),
                    }
                }
                (Some(installed), Some(_)) => UpdateDecision {
                    // installed == latest, or installed > latest (a locally
                    // newer build than the latest published release) — both
                    // are "nothing to do" per the decision matrix above.
                    action: UpdateAction::Skip,
                    installed_version: Some(installed.to_string()),
                    latest_version: latest.clone(),
                    summary: format!("v{installed} (up to date)"),
                },
                _ => {
                    // Either the installed version string didn't parse, or (in
                    // the theoretical case) the latest one didn't — either way
                    // we can't PROVE it's current, so reinstall rather than
                    // silently leave a broken/unknown binary in place.
                    let shown = if token.is_empty() {
                        "unknown version".to_string()
                    } else {
                        token.to_string()
                    };
                    UpdateDecision {
                        action: UpdateAction::Update,
                        installed_version: Some(shown.clone()),
                        latest_version: latest.clone(),
                        summary: format!(
                            "{shown} → v{latest} (update — installed version unreadable, reinstalling)"
                        ),
                    }
                }
            }
        }
    }
}

/// [`decide`], with `--force-reinstall` layered on top: when `force` is set,
/// a decision that would otherwise be [`UpdateAction::Skip`] is upgraded to
/// [`UpdateAction::Update`] (Install/Update decisions are already replacing
/// the artifact, so force changes nothing for them). Kept as a thin wrapper
/// rather than a third branch inside [`decide`] so the core matrix stays
/// force-agnostic and trivially testable on its own.
pub fn decide_with_force(
    detected: &DetectedVersion,
    latest_version: &str,
    force_reinstall: bool,
) -> UpdateDecision {
    let decision = decide(detected, latest_version);
    if force_reinstall && decision.action == UpdateAction::Skip {
        UpdateDecision {
            action: UpdateAction::Update,
            summary: format!("{} — forced reinstall", decision.summary),
            ..decision
        }
    } else {
        decision
    }
}

/// Spawn `<bin_path> --version` and return its trimmed stdout, or `None` if
/// the process could not be spawned or exited non-zero. Internal probe used
/// by [`detect_installed_version`]; split out so tests can inject a fake
/// probe instead of spawning a real process (mirrors
/// `service::stop_running_dig_node_with`'s injectable "is serving" pattern).
fn spawn_version_probe(bin_path: &Path) -> Option<String> {
    let out = Command::new(bin_path)
        .arg("--version")
        .hide_console()
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Detect what's installed at `bin_path`: [`DetectedVersion::Absent`] if
/// nothing exists there yet, otherwise [`DetectedVersion::Present`] with
/// whatever `--version` reported (an empty string if the binary exists but
/// couldn't be queried — [`decide`] treats that as unparseable → reinstall).
/// Read-only: never touches `bin_path`, so it is safe to call under
/// `--dry-run` for an accurate preview.
pub fn detect_installed_version(bin_path: &Path) -> DetectedVersion {
    detect_installed_version_with(bin_path, spawn_version_probe)
}

/// [`detect_installed_version`] with an injectable version probe — production
/// passes [`spawn_version_probe`]; tests pass a fixed answer so detection is
/// exercised without a real spawnable binary.
fn detect_installed_version_with(
    bin_path: &Path,
    probe: impl Fn(&Path) -> Option<String>,
) -> DetectedVersion {
    if !bin_path.exists() {
        return DetectedVersion::Absent;
    }
    DetectedVersion::Present(probe(bin_path).unwrap_or_default())
}

/// Resolve the latest available version (bare semver, e.g. `"0.15.0"`) for a
/// component's [`Repo`]. Production wires this to
/// [`crate::download::latest_release`] + [`crate::release::version_from_tag`]
/// (see [`live_latest_version_resolver`]); tests inject a fixed answer so
/// [`check_updates`] runs deterministically without a network call.
pub type LatestVersionResolver<'a> = dyn Fn(&Repo) -> Result<String, String> + 'a;

/// The production [`LatestVersionResolver`]: the real GitHub API round trip.
pub fn live_latest_version_resolver(repo: &Repo) -> Result<String, String> {
    crate::download::latest_release(repo).map(|r| crate::release::version_from_tag(&r.tag_name))
}

/// The components this module tracks version-aware Install/Update/Skip
/// status for (issue #309's explicit scope, extended by #514: digstore,
/// dig-node, dig-dns, dig-updater — `digs`/`dig-updater-worker`/`dig-relay`/
/// the DIG Browser are not update-tracked). Each entry's id matches
/// [`crate::asset::AssetKind::RawBinary`]'s on-PATH exe name (via
/// `Target::exe_name`), so a caller builds a destination with
/// `bin_dir.join(target.exe_name(id))`.
pub fn tracked_components() -> [(&'static str, Repo); 4] {
    [
        ("dig-store", Repo::dig_store()),
        ("dig-node", Repo::dig_node()),
        ("dig-dns", Repo::dig_dns()),
        ("dig-updater", Repo::dig_updater()),
    ]
}

/// One component's live update status — the GUI/agent-facing shape:
/// `decision` is `None` when the latest release couldn't be resolved (e.g.
/// offline), distinct from a real Install/Update/Skip verdict.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComponentStatus {
    pub component: String,
    pub decision: Option<UpdateDecision>,
    /// Present alongside `decision: None` — why the check couldn't run.
    pub error: Option<String>,
}

/// Check Install/Update/Skip status for every [`tracked_components`] entry,
/// WITHOUT installing anything — the GUI's pre-install Components-screen
/// preview (the CLI instead computes this inline, reusing the version it
/// already resolved during the real install — see `lib.rs::run_report_gated`
/// — rather than paying for a second API round trip per component).
pub fn check_updates(
    bin_dir: &Path,
    target: &crate::target::Target,
    resolve_latest: &LatestVersionResolver<'_>,
) -> Vec<ComponentStatus> {
    tracked_components()
        .into_iter()
        .map(|(id, repo)| {
            let dest = bin_dir.join(target.exe_name(id));
            match resolve_latest(&repo) {
                Ok(latest) => ComponentStatus {
                    component: id.to_string(),
                    decision: Some(decide(&detect_installed_version(&dest), &latest)),
                    error: None,
                },
                Err(e) => ComponentStatus {
                    component: id.to_string(),
                    decision: None,
                    error: Some(e),
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- SimpleVersion::parse -------------------------------------------------

    #[test]
    fn parses_bare_and_v_prefixed_semver() {
        assert_eq!(
            SimpleVersion::parse("0.15.0"),
            Some(SimpleVersion {
                major: 0,
                minor: 15,
                patch: 0
            })
        );
        assert_eq!(
            SimpleVersion::parse("v1.2.3"),
            Some(SimpleVersion {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
    }

    #[test]
    fn rejects_malformed_versions() {
        assert_eq!(SimpleVersion::parse(""), None);
        assert_eq!(SimpleVersion::parse("not-a-version"), None);
        assert_eq!(SimpleVersion::parse("1.2"), None, "needs all three parts");
        assert_eq!(
            SimpleVersion::parse("1.2.3.4"),
            None,
            "rejects a fourth segment"
        );
        assert_eq!(
            SimpleVersion::parse("1.2.3-rc.1"),
            None,
            "a pre-release suffix is unparseable here — falls back to reinstall"
        );
    }

    #[test]
    fn orders_by_major_then_minor_then_patch() {
        assert!(SimpleVersion::parse("0.14.0") < SimpleVersion::parse("0.15.0"));
        assert!(SimpleVersion::parse("0.15.0") < SimpleVersion::parse("1.0.0"));
        assert!(SimpleVersion::parse("1.2.3") < SimpleVersion::parse("1.2.10"));
    }

    // -- extract_version_token ------------------------------------------------

    #[test]
    fn extracts_the_version_from_clap_style_output() {
        assert_eq!(extract_version_token("dig-node 0.15.0"), Some("0.15.0"));
        assert_eq!(extract_version_token("0.15.0"), Some("0.15.0"));
        assert_eq!(extract_version_token(""), None);
    }

    #[test]
    fn action_as_str_matches_the_serde_wire_form() {
        assert_eq!(UpdateAction::Install.as_str(), "install");
        assert_eq!(UpdateAction::Update.as_str(), "update");
        assert_eq!(UpdateAction::Skip.as_str(), "skip");
        assert_eq!(
            serde_json::to_string(&UpdateAction::Update).unwrap(),
            "\"update\""
        );
    }

    // -- decide(): the full Install/Update/Skip/unparseable decision matrix ---

    #[test]
    fn absent_decides_install() {
        let d = decide(&DetectedVersion::Absent, "0.15.0");
        assert_eq!(d.action, UpdateAction::Install);
        assert_eq!(d.installed_version, None);
        assert_eq!(d.latest_version, "0.15.0");
        assert_eq!(d.summary, "not installed → install v0.15.0");
    }

    #[test]
    fn older_installed_decides_update() {
        let d = decide(
            &DetectedVersion::Present("dig-node 0.14.0".to_string()),
            "0.15.0",
        );
        assert_eq!(d.action, UpdateAction::Update);
        assert_eq!(d.installed_version.as_deref(), Some("0.14.0"));
        assert_eq!(d.summary, "v0.14.0 → v0.15.0 (update)");
    }

    #[test]
    fn equal_installed_decides_skip() {
        let d = decide(
            &DetectedVersion::Present("digstore 0.15.0".to_string()),
            "0.15.0",
        );
        assert_eq!(d.action, UpdateAction::Skip);
        assert_eq!(d.summary, "v0.15.0 (up to date)");
    }

    #[test]
    fn newer_installed_than_latest_decides_skip() {
        // A locally newer build than the latest published release is still
        // "nothing to do" — never downgrade.
        let d = decide(
            &DetectedVersion::Present("dig-dns 0.16.0".to_string()),
            "0.15.0",
        );
        assert_eq!(d.action, UpdateAction::Skip);
        assert_eq!(d.summary, "v0.16.0 (up to date)");
    }

    #[test]
    fn unparseable_installed_version_decides_update() {
        let d = decide(
            &DetectedVersion::Present("garbage output".to_string()),
            "0.15.0",
        );
        assert_eq!(d.action, UpdateAction::Update);
        assert!(d.summary.contains("unreadable"), "got: {}", d.summary);
    }

    #[test]
    fn empty_probe_output_decides_update() {
        // The probe ran (binary exists) but produced nothing usable (spawn
        // failure/non-zero exit already collapsed to ""): same "can't prove
        // it's current" fallback as a garbled string.
        let d = decide(&DetectedVersion::Present(String::new()), "0.15.0");
        assert_eq!(d.action, UpdateAction::Update);
        assert!(d.summary.contains("unknown version"), "got: {}", d.summary);
    }

    // -- decide_with_force -----------------------------------------------------

    #[test]
    fn force_reinstall_upgrades_a_skip_to_update() {
        let detected = DetectedVersion::Present("digstore 0.15.0".to_string());
        let forced = decide_with_force(&detected, "0.15.0", true);
        assert_eq!(forced.action, UpdateAction::Update);
        assert!(forced.summary.contains("forced reinstall"));
    }

    #[test]
    fn force_reinstall_does_not_change_an_install_or_update_decision() {
        let install = decide_with_force(&DetectedVersion::Absent, "0.15.0", true);
        assert_eq!(install.action, UpdateAction::Install);
        let update = decide_with_force(
            &DetectedVersion::Present("dig-node 0.14.0".to_string()),
            "0.15.0",
            true,
        );
        assert_eq!(update.action, UpdateAction::Update);
        assert!(
            !update.summary.contains("forced"),
            "an update decision was already replacing the artifact; force adds nothing"
        );
    }

    #[test]
    fn without_force_a_skip_stays_a_skip() {
        let detected = DetectedVersion::Present("digstore 0.15.0".to_string());
        let d = decide_with_force(&detected, "0.15.0", false);
        assert_eq!(d.action, UpdateAction::Skip);
    }

    // -- detect_installed_version_with (injectable probe) ----------------------

    #[test]
    fn detects_absent_when_the_path_does_not_exist() {
        let missing = std::env::temp_dir().join("definitely-not-a-real-dig-cli-update-test");
        let detected = detect_installed_version_with(&missing, |_| panic!("must not spawn"));
        assert_eq!(detected, DetectedVersion::Absent);
    }

    #[test]
    fn detects_present_with_the_probes_output_when_the_path_exists() {
        let dir =
            std::env::temp_dir().join(format!("dig-installer-update-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake_bin = dir.join("fake-dig-node");
        std::fs::write(&fake_bin, b"not a real binary, just needs to exist").unwrap();

        let detected =
            detect_installed_version_with(&fake_bin, |_| Some("dig-node 0.14.0".to_string()));
        assert_eq!(
            detected,
            DetectedVersion::Present("dig-node 0.14.0".to_string())
        );

        let unreadable = detect_installed_version_with(&fake_bin, |_| None);
        assert_eq!(unreadable, DetectedVersion::Present(String::new()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- check_updates (the GUI preview path, network-injected) -----------------

    #[test]
    fn check_updates_covers_exactly_the_four_tracked_components() {
        let target = crate::target::Target {
            os: crate::target::Os::Linux,
            arch: crate::target::Arch::X64,
        };
        let bin_dir = std::env::temp_dir().join("dig-installer-check-updates-test");
        let resolve_latest = |_: &Repo| -> Result<String, String> { Ok("1.0.0".to_string()) };
        let statuses = check_updates(&bin_dir, &target, &resolve_latest);
        let ids: Vec<&str> = statuses.iter().map(|s| s.component.as_str()).collect();
        assert_eq!(
            ids,
            vec!["dig-store", "dig-node", "dig-dns", "dig-updater"],
            "issue #514 extends the tracked set to include the auto-update beacon"
        );
        for s in &statuses {
            let decision = s.decision.as_ref().expect("resolver succeeded");
            assert_eq!(decision.action, UpdateAction::Install, "nothing on disk");
        }
    }

    #[test]
    fn check_updates_reports_an_error_entry_when_resolution_fails() {
        let target = crate::target::Target {
            os: crate::target::Os::Linux,
            arch: crate::target::Arch::X64,
        };
        let bin_dir = std::env::temp_dir().join("dig-installer-check-updates-error-test");
        let resolve_latest = |_: &Repo| -> Result<String, String> { Err("offline".to_string()) };
        let statuses = check_updates(&bin_dir, &target, &resolve_latest);
        for s in &statuses {
            assert!(s.decision.is_none());
            assert_eq!(s.error.as_deref(), Some("offline"));
        }
    }
}
