//! The universal DIG installer (library surface) — a **thin shim**.
//!
//! It bundles nothing. At install time it resolves, per host OS/arch, the LATEST
//! GitHub release asset for each selected component and downloads it:
//!
//! * the **digstore CLI** (`DIG-Network/digstore`) → placed on PATH,
//! * the **dig-node** local node (`DIG-Network/dig-node`) → installed + started
//!   as an OS service (Windows service / systemd / launchd) by delegating to
//!   dig-node's own `install`/`start` subcommands, and (best-effort) a
//!   `127.0.0.2 dig.local` hosts entry so consumers reach it port-free,
//! * the **DIG Browser** (`DIG-Network/DIG_Browser`) → the native installer
//!   (`.exe`/`.dmg`/`.AppImage`) downloaded for the user to run.
//!
//! Each component is selectable (`--with-digstore`/`--with-dig-node`/
//! `--with-browser`/`--service`) with a pinnable per-artifact version override,
//! and every download is integrity-checked. The asset for a release is resolved
//! from the release's *actual* asset list ([`asset::select_asset`]) rather than a
//! single guessed filename, so the installer is resilient to naming differences
//! across the producing repos.
//!
//! See SYSTEM.md → "Canonical terminology & branding" for the $DIG / DIGHUb /
//! dig-node naming this installer's user-facing copy follows, and
//! AGENT_FRIENDLY.md → dig-installer for the `--json`/exit-code/error-code
//! contract.
//!
//! Layering: the pure logic ([`target`], [`release`], [`asset`], [`hosts`],
//! [`paths::path_append`], [`download::release_from_json`], [`service::install_env`])
//! is unit-tested; [`run`] is the imperative orchestration that performs I/O.

pub mod asset;
pub mod download;
pub mod error;
pub mod hosts;
pub mod paths;
pub mod release;
pub mod service;
pub mod target;

use std::path::PathBuf;

use asset::AssetKind;
use error::InstallError;
use release::Repo;
use service::ServiceConfig;
use target::Target;

/// What the user asked the installer to do.
#[derive(Debug, Clone)]
pub struct InstallPlan {
    /// Directory to place the downloaded binaries in.
    pub bin_dir: PathBuf,
    /// Install the digstore CLI (default true).
    pub with_digstore: bool,
    /// digstore version/tag to install: `None` ⇒ latest released.
    pub digstore_version: Option<String>,
    /// Also install + register dig-node as a service.
    pub with_dig_node: bool,
    /// dig-node version/tag to install: `None` ⇒ latest released.
    pub dig_node_version: Option<String>,
    /// Service configuration when `with_dig_node` is set.
    pub service: ServiceConfig,
    /// Also download the DIG Browser native installer.
    pub with_browser: bool,
    /// DIG Browser version/tag to install: `None` ⇒ latest released.
    pub browser_version: Option<String>,
    /// Add the bin dir to PATH (default true).
    pub modify_path: bool,
    /// Print actions without performing them.
    pub dry_run: bool,
}

impl Default for InstallPlan {
    fn default() -> Self {
        InstallPlan {
            bin_dir: paths::default_bin_dir(),
            with_digstore: true,
            digstore_version: None,
            with_dig_node: false,
            dig_node_version: None,
            service: ServiceConfig::default(),
            with_browser: false,
            browser_version: None,
            modify_path: true,
            dry_run: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Structured result (the `--json` payload). All fields are stable, snake_case.
// ---------------------------------------------------------------------------

/// One installed/resolved component in the result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComponentResult {
    /// Component id: `digstore` | `dig-node` | `browser`.
    pub component: String,
    /// Resolved version (bare semver, e.g. `0.6.0`).
    pub version: String,
    /// Resolved git tag (e.g. `v0.6.0`).
    pub tag: String,
    /// The release asset selected for this OS/arch.
    pub asset: String,
    /// The download URL.
    pub url: String,
    /// Where the artifact was written (or would be, on dry-run).
    pub dest: String,
}

/// The PATH change applied (or that would be).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PathResult {
    pub modified: bool,
    pub dir: String,
    pub note: String,
}

/// The dig-node service + dig.local hosts result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceResult {
    pub installed: bool,
    pub started: bool,
    pub port: u16,
    pub note: String,
    /// dig.local hosts registration (best-effort; never fails the install).
    pub dig_local: String,
}

/// The full structured install result emitted under `--json`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InstallReport {
    pub schema_version: u32,
    pub installer_version: String,
    pub target: String,
    pub dry_run: bool,
    pub components: Vec<ComponentResult>,
    pub path: Option<PathResult>,
    pub service: Option<ServiceResult>,
    /// Absolute paths actually written (empty on dry-run).
    pub installed: Vec<String>,
}

/// The `--json` schema version. Bump on a breaking change to the payload shape.
pub const SCHEMA_VERSION: u32 = 1;

/// Resolve a component's release (tag + asset list): an explicit version
/// (specific tag) or the repo's latest release.
fn resolve_release(
    repo: &Repo,
    requested: &Option<String>,
) -> Result<download::Release, InstallError> {
    let result = match requested {
        Some(v) => {
            let tag = release::tag_from_input(v);
            download::release_by_tag(repo, &tag)
        }
        None => download::latest_release(repo),
    };
    result.map_err(|e| classify_release_error(repo, requested, &e))
}

/// Map a release-discovery error to a typed [`InstallError`]. A 404 means the
/// release (or the whole repo's releases) does not exist → `ASSET_NOT_FOUND`,
/// not a transport failure — so an agent can tell "nothing published yet" apart
/// from "the network is down".
fn classify_release_error(repo: &Repo, requested: &Option<String>, e: &str) -> InstallError {
    if e.contains("404") || e.contains("Not Found") {
        let what = match requested {
            Some(v) => format!(
                "release {} of {}/{}",
                release::tag_from_input(v),
                repo.owner,
                repo.name
            ),
            None => format!("any published release of {}/{}", repo.owner, repo.name),
        };
        InstallError::asset_not_found(format!("no {what} found"))
            .with_hint("the component may not be published yet; check the releases page or pin a known version")
    } else {
        InstallError::network(e.to_string())
    }
}

/// Resolve which asset to download for `target`, returning the component result
/// shell (the dest is filled by the caller). Pure resolution against the release
/// asset list; raises `ASSET_NOT_FOUND` if no asset matches this OS/arch.
fn resolve_component(
    repo: &Repo,
    requested: &Option<String>,
    target: &Target,
    kind: AssetKind,
    bin_dir: &std::path::Path,
) -> Result<ComponentResult, InstallError> {
    let rel = resolve_release(repo, requested)?;
    let asset =
        asset::select_asset(&rel.asset_names, target, kind, &repo.stem).ok_or_else(|| {
            InstallError::asset_not_found(format!(
                "no {} asset for {target} in {}/{} release {}",
                repo.stem, repo.owner, repo.name, rel.tag_name
            ))
            .with_hint("pin a known-good version with the matching --*-version flag")
        })?;
    let version = release::version_from_tag(&rel.tag_name);
    let url = repo.asset_download_url(&rel.tag_name, &asset);
    // Raw binaries go to a normalized exe name on PATH; installers keep their
    // published filename (the user runs them directly).
    let dest = match kind {
        AssetKind::RawBinary => bin_dir.join(target.exe_name(&repo.stem)),
        AssetKind::Installer => bin_dir.join(&asset),
    };
    Ok(ComponentResult {
        component: repo.stem.clone(),
        version,
        tag: rel.tag_name,
        asset,
        url,
        dest: dest.to_string_lossy().into_owned(),
    })
}

/// Download a resolved component to its dest (no-op on dry-run).
fn download_component(c: &ComponentResult, dry_run: bool) -> Result<(), InstallError> {
    if dry_run {
        return Ok(());
    }
    download::download_binary(&c.url, std::path::Path::new(&c.dest), None).map_err(|e| {
        // Distinguish a 404 (asset gone) from a transport error from a disk error.
        if e.contains("404") || e.contains("Not Found") {
            InstallError::asset_not_found(e)
        } else if e.contains("write") || e.contains("create") {
            InstallError::io(e)
        } else {
            InstallError::network(e)
        }
    })
}

/// Run the install plan end-to-end, returning a structured [`InstallReport`].
///
/// `log` receives human-readable progress lines (the caller routes them to
/// stdout in pretty mode or stderr under `--json`). On success the report is the
/// machine-readable record of everything resolved + done.
pub fn run_report(
    plan: &InstallPlan,
    log: &mut dyn FnMut(&str),
) -> Result<InstallReport, InstallError> {
    let target = Target::current().map_err(|e| {
        InstallError::unsupported_target(e)
            .with_hint("DIG releases target windows-x64, linux-x64, macos-arm64, macos-x64")
    })?;
    log(&format!("DIG installer — target {target}"));
    if plan.dry_run {
        log("(dry run — no changes will be made)");
    }

    let mut report = InstallReport {
        schema_version: SCHEMA_VERSION,
        installer_version: env!("CARGO_PKG_VERSION").to_string(),
        target: target.to_string(),
        dry_run: plan.dry_run,
        components: Vec::new(),
        path: None,
        service: None,
        installed: Vec::new(),
    };

    // 1. digstore CLI.
    if plan.with_digstore {
        log("Installing the digstore CLI:");
        let c = resolve_component(
            &Repo::digstore(),
            &plan.digstore_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir,
        )?;
        log_component(log, &c);
        download_component(&c, plan.dry_run)?;
        if !plan.dry_run {
            report.installed.push(c.dest.clone());
        }
        report.components.push(c);
    }

    // 2. PATH (only meaningful if we placed a PATH binary).
    if plan.modify_path && (plan.with_digstore || plan.with_dig_node) {
        log(&format!("Adding {} to PATH:", plan.bin_dir.display()));
        let dir = plan.bin_dir.to_string_lossy().into_owned();
        if plan.dry_run {
            log("    (would add to PATH)");
            report.path = Some(PathResult {
                modified: false,
                dir,
                note: "would add to PATH".to_string(),
            });
        } else {
            match paths::add_to_path(&plan.bin_dir) {
                Ok(note) => {
                    log(&format!("    ✓ {note}"));
                    report.path = Some(PathResult {
                        modified: true,
                        dir,
                        note,
                    });
                }
                Err(e) => {
                    // Non-fatal: the binary is placed; only PATH wiring failed.
                    let note = format!("could not update PATH automatically ({e})");
                    log(&format!("    ! {note}"));
                    report.path = Some(PathResult {
                        modified: false,
                        dir,
                        note,
                    });
                }
            }
        }
    }

    // 3. dig-node service (optional) + dig.local hosts entry.
    if plan.with_dig_node {
        log("Installing the dig-node local node:");
        let c = resolve_dig_node(&plan.dig_node_version, &target, &plan.bin_dir, log)?;
        log_component(log, &c);
        download_component(&c, plan.dry_run)?;
        if !plan.dry_run {
            report.installed.push(c.dest.clone());
        }
        let dig_node_path = PathBuf::from(c.dest.clone());
        report.components.push(c);

        report.service = Some(register_dig_node(&dig_node_path, plan, log));
    }

    // 4. DIG Browser native installer (optional).
    if plan.with_browser {
        log("Downloading the DIG Browser installer:");
        let c = resolve_component(
            &Repo::dig_browser(),
            &plan.browser_version,
            &target,
            AssetKind::Installer,
            &plan.bin_dir,
        )?;
        log_component(log, &c);
        download_component(&c, plan.dry_run)?;
        if !plan.dry_run {
            log(&format!("    run the installer to finish: {}", c.dest));
            report.installed.push(c.dest.clone());
        }
        report.components.push(c);
    }

    log("Done.");
    Ok(report)
}

/// Resolve dig-node, falling back to the pre-rename `dig-companion` release if
/// the renamed repo has no matching release yet.
fn resolve_dig_node(
    requested: &Option<String>,
    target: &Target,
    bin_dir: &std::path::Path,
    log: &mut dyn FnMut(&str),
) -> Result<ComponentResult, InstallError> {
    match resolve_component(
        &Repo::dig_node(),
        requested,
        target,
        AssetKind::RawBinary,
        bin_dir,
    ) {
        Ok(c) => Ok(c),
        Err(primary) => {
            log(&format!("    (dig-node release not resolvable: {primary})"));
            log("    trying the pre-rename dig-companion release…");
            // The legacy repo's stem is dig-companion; normalize the on-PATH name
            // back to dig-node so the service command + later use are consistent.
            let mut c = resolve_component(
                &Repo::dig_node_legacy(),
                requested,
                target,
                AssetKind::RawBinary,
                bin_dir,
            )?;
            c.component = "dig-node".to_string();
            c.dest = bin_dir
                .join(target.exe_name("dig-node"))
                .to_string_lossy()
                .into_owned();
            Ok(c)
        }
    }
}

/// Register dig-node as an OS service and best-effort write the dig.local hosts
/// entry. Never returns `Err` — a service/hosts failure is recorded in the
/// result, not propagated (the binary is already placed).
fn register_dig_node(
    dig_node_path: &std::path::Path,
    plan: &InstallPlan,
    log: &mut dyn FnMut(&str),
) -> ServiceResult {
    log(&format!(
        "Registering dig-node as an OS service (port {}):",
        plan.service.port
    ));
    let mut result = ServiceResult {
        installed: false,
        started: false,
        port: plan.service.port,
        note: String::new(),
        dig_local: String::new(),
    };

    if plan.dry_run {
        result.note = format!(
            "would run `dig-node install`{}",
            if plan.service.start {
                " && `dig-node start`"
            } else {
                ""
            }
        );
        log(&format!("    ({})", result.note));
        result.dig_local = format!(
            "would add {} {} to {}",
            hosts::DIG_LOCAL_IP,
            hosts::DIG_LOCAL_HOST,
            hosts::hosts_path().display()
        );
        log(&format!("    ({})", result.dig_local));
        return result;
    }

    match service::install_service(dig_node_path, &plan.service) {
        Ok(note) => {
            log(&format!("    ✓ {note}"));
            result.installed = true;
            result.started = plan.service.start;
            result.note = note;
        }
        Err(e) => {
            // Service install can need elevation (Windows SCM). Best-effort:
            // surface it, do NOT fail the install — the binary is placed.
            log(&format!("    ! {e}"));
            log(&format!(
                "    dig-node is installed at {}; run `dig-node install` from an elevated console to register the service.",
                dig_node_path.display()
            ));
            result.note = e;
        }
    }

    // dig.local hosts entry — best-effort, never aborts (task #91, installer
    // side). Failure (needs elevation) leaves consumers on localhost.
    match hosts::write_dig_local() {
        Ok(Some(note)) => {
            log(&format!("    ✓ dig.local: {note}"));
            result.dig_local = note;
        }
        Ok(None) => {
            log("    ✓ dig.local already registered");
            result.dig_local = "already present".to_string();
        }
        Err(e) => {
            log(&format!(
                "    ! could not write the dig.local hosts entry ({e}); the local node stays reachable at localhost. Re-run elevated to add it."
            ));
            result.dig_local = format!("not written ({e})");
        }
    }

    result
}

/// Log a resolved component's source + dest in the pretty format.
fn log_component(log: &mut dyn FnMut(&str), c: &ComponentResult) {
    log(&format!("  {} {} ({})", c.component, c.version, c.asset));
    log(&format!("    from {}", c.url));
    log(&format!("    to   {}", c.dest));
}

/// Back-compat convenience: run the plan, printing pretty progress to stdout,
/// returning the installed binary paths. Prefer [`run_report`] for the
/// structured result.
pub fn run(plan: &InstallPlan) -> Result<Vec<PathBuf>, String> {
    let report = run_report(plan, &mut |line| println!("{line}")).map_err(|e| e.to_string())?;
    Ok(report.installed.into_iter().map(PathBuf::from).collect())
}
