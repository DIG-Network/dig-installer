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
//!   (`.exe`/`.dmg`/`.AppImage`) downloaded for the user to run, and
//! * **dig-dns** (`DIG-Network/dig-dns`) → installed + registered as an OS
//!   service (Windows Service / macOS LaunchDaemon / Linux systemd unit) for
//!   local `*.dig` name resolution. Unlike dig-node/dig-relay, dig-dns ships
//!   no `install`/`start` subcommands of its own, so this installer owns the
//!   full per-OS service + split-DNS/NRPT + browser-policy wiring directly
//!   (see [`dns`]), self-verifying with `dig-dns doctor` when done.
//!
//! Each component is selectable (`--with-digstore`/`--with-dig-node`/
//! `--with-browser`/`--with-dig-dns`/`--service`) with a pinnable per-artifact version override,
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
pub mod dns;
pub mod download;
pub mod error;
pub mod health;
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
    /// Also install + register dig-relay as a service (run-your-own-relay). OPTIONAL/advanced —
    /// the default node points at the canonical relay.dig.net, so most users never run one.
    pub with_relay: bool,
    /// dig-relay version/tag to install: `None` ⇒ latest released.
    pub relay_version: Option<String>,
    /// Relay service configuration when `with_relay` is set.
    pub relay_service: ServiceConfigRelay,
    /// Also install dig-dns and register it as an OS service (local `*.dig`
    /// name resolution: a DNS responder + HTTP gateway).
    pub with_dig_dns: bool,
    /// dig-dns version/tag to install: `None` ⇒ latest released.
    pub dig_dns_version: Option<String>,
    /// dig-dns service configuration when `with_dig_dns` is set (start +
    /// optional dig-node endpoint override forwarded to `dig-dns serve --node`).
    pub dns_service: dns::DnsInstallConfig,
    /// Add the bin dir to PATH (default true).
    pub modify_path: bool,
    /// Print actions without performing them.
    pub dry_run: bool,
}

/// Re-export alias so `InstallPlan` reads cleanly (`service::RelayServiceConfig`).
pub use service::RelayServiceConfig as ServiceConfigRelay;

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
            with_relay: false,
            relay_version: None,
            relay_service: ServiceConfigRelay::default(),
            with_dig_dns: false,
            dig_dns_version: None,
            dns_service: dns::DnsInstallConfig::default(),
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
    /// The post-install verification (task #140): does the OS resolver
    /// actually map `dig.local` → `127.0.0.2` right now? `false` on dry-run
    /// (nothing was written to check) or if the hosts write/OS resolution
    /// didn't converge — see `dig_local_resolve_note` for why.
    pub dig_local_resolves: bool,
    /// Human-readable detail behind [`Self::dig_local_resolves`] — never
    /// silent (CLAUDE.md task #140: "failures surface a clear message").
    pub dig_local_resolve_note: String,
    /// The post-install RPC health check (task #223): was `rpc.discover`
    /// actually attempted against the service's loopback port? `false` on
    /// dry-run or when the service was never started (nothing to probe).
    pub health_checked: bool,
    /// Did the health check confirm the node is answering RPC? `false`
    /// whenever `health_checked` is `false` — see [`Self::health_note`] for
    /// why (never silent, same convention as `dig_local_resolve_note`).
    pub health_ok: bool,
    /// Human-readable detail behind [`Self::health_ok`].
    pub health_note: String,
}

/// The result of uninstalling the dig-node service + removing the `dig.local`
/// hosts entry (task #140) — the counterpart to [`ServiceResult`]. Standalone
/// action (mirrors `--uninstall-dig-dns`'s [`dns::DnsUninstallResult`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceUninstallResult {
    /// The dig-node OS service was removed (or, on dry-run, would be).
    pub uninstalled: bool,
    /// The `dig.local` hosts entry this installer added was removed (or, on
    /// dry-run, would be). `false` if there was nothing tagged to remove
    /// (idempotent no-op) or the removal needs elevation.
    pub dig_local_removed: bool,
    /// Human-readable detail — never silent.
    pub note: String,
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
    /// The run-your-own-relay service result (only when `--with-relay`).
    pub relay: Option<RelayResult>,
    /// The dig-dns OS-service install result (only when `--with-dig-dns`).
    pub dns: Option<dns::DnsInstallResult>,
    /// Absolute paths actually written (empty on dry-run).
    pub installed: Vec<String>,
}

/// The dig-relay service result (run-your-own-relay).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RelayResult {
    pub installed: bool,
    pub started: bool,
    pub port: u16,
    pub health_port: u16,
    pub note: String,
}

/// The `--json` schema version. Bump on a breaking change to the payload shape.
pub const SCHEMA_VERSION: u32 = 1;

/// A release resolver: given a [`Repo`] and an optional requested version, return
/// that repo's release (tag + asset list) or a typed [`InstallError`].
///
/// This is the **single network boundary** of the orchestration. The production
/// resolver ([`resolve_release`]) hits the GitHub API; tests inject a
/// pure in-memory resolver so the entire [`run_report`] flow — component
/// resolution, asset selection, URL/dest building, the PATH/service/relay report
/// branches, and dry-run — is exercised without any I/O.
type ReleaseResolver<'a> =
    dyn Fn(&Repo, &Option<String>) -> Result<download::Release, InstallError> + 'a;

/// The production [`ReleaseResolver`]: resolve a component's release (tag + asset
/// list) over the network — an explicit version (specific tag) or the repo's
/// latest release.
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
/// shell (the dest is filled by the caller). The release (tag + asset list) is
/// obtained via `resolve` (the network boundary); the asset selection, URL, and
/// dest building below are pure. Raises `ASSET_NOT_FOUND` if no asset matches
/// this OS/arch.
fn resolve_component(
    resolve: &ReleaseResolver<'_>,
    repo: &Repo,
    requested: &Option<String>,
    target: &Target,
    kind: AssetKind,
    bin_dir: &std::path::Path,
) -> Result<ComponentResult, InstallError> {
    let rel = resolve(repo, requested)?;
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
    run_report_with(plan, &resolve_release, log)
}

/// [`run_report`] with an injectable release resolver (the network boundary).
///
/// Production code calls [`run_report`], which passes the real
/// [`resolve_release`]. Tests pass a pure in-memory resolver so the whole
/// orchestration — component resolution, asset selection, dest building, the
/// PATH/service/relay report branches, and dry-run — runs deterministically
/// without any I/O. (Dry-run still never spawns a process or writes a file.)
fn run_report_with(
    plan: &InstallPlan,
    resolve: &ReleaseResolver<'_>,
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
        relay: None,
        dns: None,
        installed: Vec::new(),
    };

    // 1. digstore CLI.
    if plan.with_digstore {
        log("Installing the digstore CLI:");
        let c = resolve_component(
            resolve,
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
    if plan.modify_path && (plan.with_digstore || plan.with_dig_node || plan.with_dig_dns) {
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
        let c = resolve_dig_node(resolve, &plan.dig_node_version, &target, &plan.bin_dir, log)?;
        log_component(log, &c);
        download_component(&c, plan.dry_run)?;
        if !plan.dry_run {
            report.installed.push(c.dest.clone());
        }
        let dig_node_path = PathBuf::from(c.dest.clone());
        report.components.push(c);

        report.service = Some(register_dig_node(&dig_node_path, plan, log));
    }

    // 4. dig-dns (optional): local `*.dig` name resolution, installed as an OS service. Unlike
    //    dig-node/dig-relay, dig-dns has no `install`/`start` subcommands of its own, so this
    //    installer owns the full per-OS service + split-DNS/NRPT + browser-policy wiring (see
    //    the `dns` module) and self-verifies with `dig-dns doctor` once started.
    if plan.with_dig_dns {
        log("Installing dig-dns (local *.dig name resolution):");
        let c = resolve_component(
            resolve,
            &Repo::dig_dns(),
            &plan.dig_dns_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir,
        )?;
        log_component(log, &c);
        download_component(&c, plan.dry_run)?;
        if !plan.dry_run {
            report.installed.push(c.dest.clone());
        }
        let dig_dns_path = PathBuf::from(c.dest.clone());
        report.components.push(c);

        report.dns = Some(register_dig_dns(&dig_dns_path, &target, plan, log));
    }

    // 5. dig-relay service (optional, advanced — run-your-own-relay). The DEFAULT node already
    //    points at relay.dig.net, so this is only for users who want to operate a relay.
    if plan.with_relay {
        log("Installing the dig-relay (run-your-own-relay):");
        let c = resolve_component(
            resolve,
            &Repo::dig_relay(),
            &plan.relay_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir,
        )?;
        log_component(log, &c);
        download_component(&c, plan.dry_run)?;
        if !plan.dry_run {
            report.installed.push(c.dest.clone());
        }
        let relay_path = PathBuf::from(c.dest.clone());
        report.components.push(c);

        report.relay = Some(register_relay(&relay_path, plan, log));
    }

    // 6. DIG Browser native installer (optional).
    if plan.with_browser {
        log("Downloading the DIG Browser installer:");
        let c = resolve_component(
            resolve,
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

/// Register dig-relay as an OS service by delegating to its own `install`/`start` subcommands.
/// Never returns `Err` — a service failure is recorded in the result, not propagated (the binary
/// is already placed). Mirrors [`register_dig_node`].
fn register_relay(
    relay_path: &std::path::Path,
    plan: &InstallPlan,
    log: &mut dyn FnMut(&str),
) -> RelayResult {
    log(&format!(
        "Registering dig-relay as an OS service (relay {}, health {}):",
        plan.relay_service.port, plan.relay_service.health_port
    ));
    let mut result = RelayResult {
        installed: false,
        started: false,
        port: plan.relay_service.port,
        health_port: plan.relay_service.health_port,
        note: String::new(),
    };

    if plan.dry_run {
        result.note = format!(
            "would run `dig-relay install`{}",
            if plan.relay_service.start {
                " && `dig-relay start`"
            } else {
                ""
            }
        );
        log(&format!("    ({})", result.note));
        return result;
    }

    match service::install_relay_service(relay_path, &plan.relay_service) {
        Ok(note) => {
            log(&format!("    ✓ {note}"));
            result.installed = true;
            result.started = plan.relay_service.start;
            result.note = note;
        }
        Err(e) => {
            // Service install can need elevation (Windows SCM). Best-effort: surface it, do NOT
            // fail the install — the binary is placed.
            log(&format!("    ! {e}"));
            log(&format!(
                "    dig-relay is installed at {}; run `dig-relay install` from an elevated console to register the service.",
                relay_path.display()
            ));
            result.note = e;
        }
    }

    result
}

/// Register dig-dns as an OS service (DNS responder + HTTP gateway for local
/// `*.dig` name resolution) by delegating to [`dns::install`] — dig-dns ships
/// no `install`/`start` subcommands of its own, so this installer owns the
/// full per-OS wiring (systemd/LaunchDaemon/Windows Service, split-DNS/NRPT,
/// the Chrome/Edge DoH policy) directly. Never panics/aborts the overall
/// install — a permission or platform issue is recorded in the result, not
/// propagated (the binary is already placed). Prints the `doctor`
/// self-verification report, the live path(s), the bound gateway port, the
/// PAC URL, and the browser-fallback instruction once the service starts
/// (task #177).
fn register_dig_dns(
    dig_dns_path: &std::path::Path,
    target: &Target,
    plan: &InstallPlan,
    log: &mut dyn FnMut(&str),
) -> dns::DnsInstallResult {
    log("Registering dig-dns as an OS service (DNS responder + HTTP gateway):");
    // The Windows Service Control Manager needs a binary that itself speaks the
    // service protocol; dig-dns's `serve` is a plain blocking CLI loop, so the
    // SCM is pointed at THIS installer's own binary (persisted here) running
    // the hidden `run-dig-dns-service` entrypoint, which spawns the real
    // `dig-dns serve` as a supervised child (see `dns::windows`). Unused on
    // macOS/Linux, where the service execs `dig_dns_path` directly.
    let persist_bin = plan.bin_dir.join(target.exe_name("dig-installer"));

    let result = dns::install(dig_dns_path, &persist_bin, &plan.dns_service, plan.dry_run);

    if plan.dry_run {
        log(&format!("    ({})", result.note));
        return result;
    }

    if result.installed {
        log(&format!("    ✓ {}", result.note));
    } else {
        log(&format!("    ! {}", result.note));
        if !result.needs_elevation {
            log(&format!(
                "    dig-dns is downloaded at {}; re-run dig-installer elevated (Administrator/root) to register the service.",
                dig_dns_path.display()
            ));
        }
    }

    if let Some(doctor) = &result.doctor {
        log("    dig-dns doctor:");
        for c in &doctor.checks {
            log(&format!(
                "      [{}] {}: {}",
                c.status.to_uppercase(),
                c.name,
                c.detail
            ));
            if let Some(fix) = &c.fix {
                log(&format!("            fix: {fix}"));
            }
        }
    }
    log(&format!(
        "    live path(s): {}",
        if result.paths_live.is_empty() {
            "NONE".to_string()
        } else {
            result.paths_live.join(", ")
        }
    ));
    if let Some(port) = result.bound_port {
        log(&format!("    gateway bound port: {port}"));
    }
    if let Some(url) = &result.pac_url {
        log(&format!("    PAC URL: {url}"));
    }
    if let Some(fallback) = &result.fallback_instruction {
        log(&format!("    {fallback}"));
    }

    result
}

/// Resolve dig-node, falling back to the pre-rename `dig-companion` release if
/// the renamed repo has no matching release yet.
fn resolve_dig_node(
    resolve: &ReleaseResolver<'_>,
    requested: &Option<String>,
    target: &Target,
    bin_dir: &std::path::Path,
    log: &mut dyn FnMut(&str),
) -> Result<ComponentResult, InstallError> {
    match resolve_component(
        resolve,
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
                resolve,
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
        dig_local_resolves: false,
        dig_local_resolve_note: String::new(),
        health_checked: false,
        health_ok: false,
        health_note: String::new(),
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
        result.dig_local_resolve_note = "skipped (dry run)".to_string();
        result.health_note = "skipped (dry run)".to_string();
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

    // Post-install resolve check (task #140): confirm the OS resolver actually
    // maps dig.local -> 127.0.0.2 now, regardless of whether THIS run wrote
    // the entry or found it already present — proves the write took effect,
    // never silent either way.
    let resolved = hosts::resolve_dig_local();
    if resolved.resolves {
        log(&format!("    ✓ dig.local resolve check: {}", resolved.note));
    } else {
        log(&format!(
            "    ! dig.local resolve check FAILED: {} — consumers fall back to localhost until this resolves.",
            resolved.note
        ));
    }
    result.dig_local_resolves = resolved.resolves;
    result.dig_local_resolve_note = resolved.note;

    // Post-install RPC health check (task #223): confirm the node is
    // actually ANSWERING on its configured port — distinct from the
    // dig.local resolve check above, which only proves DNS resolution.
    // Skipped when the service was never started (nothing to probe): with
    // `--no-service-start` the user explicitly deferred starting it, and if
    // `install_service` itself failed, `result.started` is already `false`.
    if result.started {
        let health = health::wait_for_node_health(
            plan.service.port,
            HEALTH_CHECK_ATTEMPTS,
            HEALTH_CHECK_INTERVAL,
        );
        if health.healthy {
            log(&format!("    ✓ health check: {}", health.note));
        } else {
            log(&format!(
                "    ! health check FAILED: {} — the service may not have started correctly.",
                health.note
            ));
        }
        result.health_checked = health.checked;
        result.health_ok = health.healthy;
        result.health_note = health.note;
    } else {
        result.health_note = "skipped (service not started)".to_string();
    }

    result
}

/// Health-check retry budget for [`register_dig_node`]: up to 10 attempts,
/// 500ms apart (5s worst case) — enough for a freshly-started service to
/// bind its socket. Mirrors `dns::doctor::wait_for_doctor`'s own budget.
const HEALTH_CHECK_ATTEMPTS: u32 = 10;
const HEALTH_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Uninstall the dig-node OS service and remove the `dig.local` hosts entry
/// this installer added (task #140) — the counterpart to [`register_dig_node`].
/// A standalone action (mirrors `--uninstall-dig-dns` / [`dns::uninstall`]):
/// it locates the dig-node binary a prior `--with-dig-node` install placed at
/// `bin_dir` (by the same [`Target::exe_name`] convention `register_dig_node`
/// uses) and runs its own `uninstall` subcommand, then removes the hosts
/// entry. Never touches the digstore/browser/relay/dig-dns installs. Never
/// panics/aborts — a failure (missing binary, needs elevation) is recorded in
/// the result, always with a clear `note` (never silent).
pub fn uninstall_dig_node(
    bin_dir: &std::path::Path,
    dry_run: bool,
    log: &mut dyn FnMut(&str),
) -> ServiceUninstallResult {
    let target = match Target::current() {
        Ok(t) => t,
        Err(e) => {
            let note = format!("could not detect the current OS/arch target: {e}");
            log(&format!("! {note}"));
            return ServiceUninstallResult {
                uninstalled: false,
                dig_local_removed: false,
                note,
            };
        }
    };
    let bin = bin_dir.join(target.exe_name("dig-node"));

    if dry_run {
        let note = format!(
            "would run `{} uninstall` and remove the dig.local hosts entry",
            bin.display()
        );
        log(&format!("({note})"));
        return ServiceUninstallResult {
            uninstalled: false,
            dig_local_removed: false,
            note,
        };
    }

    log("Uninstalling the dig-node OS service:");
    let mut notes: Vec<String> = Vec::new();
    let uninstalled = match service::uninstall_service(&bin) {
        Ok(n) => {
            log(&format!("    ✓ {n}"));
            notes.push(n);
            true
        }
        Err(e) => {
            log(&format!("    ! {e}"));
            notes.push(e);
            false
        }
    };

    log("Removing the dig.local hosts entry:");
    let dig_local_removed = match hosts::remove_dig_local() {
        Ok(Some(n)) => {
            log(&format!("    ✓ {n}"));
            notes.push(n);
            true
        }
        Ok(None) => {
            let n = "dig.local: already absent (nothing to remove)".to_string();
            log(&format!("    ✓ {n}"));
            notes.push(n);
            false
        }
        Err(e) => {
            let n = format!("could not remove the dig.local hosts entry ({e}); re-run elevated");
            log(&format!("    ! {n}"));
            notes.push(n);
            false
        }
    };

    ServiceUninstallResult {
        uninstalled,
        dig_local_removed,
        note: notes.join("; "),
    }
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

// ---------------------------------------------------------------------------
// Agent-facing JSON surfaces (AGENT_FRIENDLY.md → dig-installer). Pure string
// builders, so they live in the library and are unit-tested directly rather than
// only through the binary's e2e contract test.
// ---------------------------------------------------------------------------

/// The structured error envelope emitted to stdout under `--json` on failure:
/// `{"ok":false,"error":{code,exit_code,message,hint}}`.
pub fn error_json(e: &InstallError) -> String {
    let envelope = serde_json::json!({
        "ok": false,
        "error": {
            "code": e.code(),
            "exit_code": e.exit_code(),
            "message": e.message(),
            "hint": e.hint(),
        }
    });
    serde_json::to_string(&envelope).expect("error envelope serializes")
}

/// The structured envelope emitted to stdout under `--json` for
/// `--uninstall-dig-dns`: `{"ok":true,"result":<DnsUninstallResult>}` (never
/// `ok:false` — [`dns::uninstall`] cannot fail, only report `needs_elevation`).
pub fn dns_uninstall_json(result: &dns::DnsUninstallResult) -> String {
    let envelope = serde_json::json!({ "ok": true, "result": result });
    serde_json::to_string(&envelope).expect("dns uninstall envelope serializes")
}

/// The structured envelope emitted to stdout under `--json` for
/// `--uninstall-dig-node`: `{"ok":true,"result":<ServiceUninstallResult>}`
/// (mirrors [`dns_uninstall_json`]; [`uninstall_dig_node`] never returns an
/// `Err` — a failure is recorded in the result's `note`, not raised).
pub fn service_uninstall_json(result: &ServiceUninstallResult) -> String {
    let envelope = serde_json::json!({ "ok": true, "result": result });
    serde_json::to_string(&envelope).expect("service uninstall envelope serializes")
}

/// The full machine-readable invocation contract for `--help-json`: the
/// component catalogue, supported targets, global/per-command flags, and the
/// exit-code table. An agent introspects this instead of scraping `--help`.
pub fn help_json() -> String {
    let exit_codes: Vec<_> = error::EXIT_CODES
        .iter()
        .map(|(code, name, meaning)| {
            serde_json::json!({ "exit_code": code, "code": name, "meaning": meaning })
        })
        .collect();
    let doc = serde_json::json!({
        "name": "dig-installer",
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": SCHEMA_VERSION,
        "description": "Universal DIG installer (thin shim): resolves + downloads the latest \
    per-OS/arch release asset for the digstore CLI, dig-node service, dig-dns service, and DIG Browser.",
        "components": [
            { "id": "digstore", "repo": "DIG-Network/digstore", "default": true, "flag": "--no-digstore disables", "kind": "raw_binary" },
            { "id": "dig-node", "repo": "DIG-Network/dig-node", "default": false, "flag": "--with-dig-node | --service", "kind": "raw_binary+service+dig.local+health-check" },
            { "id": "dig-relay", "repo": "DIG-Network/dig-relay", "default": false, "flag": "--with-relay", "kind": "raw_binary+service" },
            { "id": "dig-dns", "repo": "DIG-Network/dig-dns", "default": false, "flag": "--with-dig-dns", "kind": "raw_binary+service+split-dns+browser-policy" },
            { "id": "browser",  "repo": "DIG-Network/DIG_Browser", "default": false, "flag": "--with-browser", "kind": "installer" }
        ],
        "targets": ["windows-x64", "linux-x64", "macos-arm64", "macos-x64"],
        "global_flags": [
            { "flag": "--json", "description": "single structured JSON result to stdout, prose to stderr" },
            { "flag": "--help-json", "description": "print this contract" },
            { "flag": "--dry-run", "description": "resolve + print the plan, change nothing" },
            { "flag": "--no-path", "description": "do not modify PATH" }
        ],
        "flags": [
            { "flag": "--bin-dir", "value": "DIR", "description": "where to place binaries" },
            { "flag": "--no-digstore", "description": "skip the digstore CLI" },
            { "flag": "--digstore-version", "value": "VERSION", "description": "pin digstore version (default: latest)" },
            { "flag": "--with-dig-node", "alias": "--service", "description": "install + start the dig-node service" },
            { "flag": "--dig-node-version", "value": "VERSION", "description": "pin dig-node version (default: latest)" },
            { "flag": "--dig-node-port", "value": "PORT", "default": 9778, "description": "loopback port for the dig-node service" },
            { "flag": "--no-service-start", "description": "install the service but do not start it" },
            { "flag": "--uninstall-dig-node", "description": "uninstall the dig-node OS service + remove the dig.local hosts entry this installer created (idempotent; does not touch the digstore/browser/relay/dig-dns installs)" },
            { "flag": "--with-browser", "description": "download the DIG Browser native installer" },
            { "flag": "--browser-version", "value": "VERSION", "description": "pin DIG Browser version (default: latest)" },
            { "flag": "--with-relay", "description": "install + start dig-relay as a service (run-your-own-relay; advanced — the default node uses relay.dig.net)" },
            { "flag": "--relay-version", "value": "VERSION", "description": "pin dig-relay version (default: latest)" },
            { "flag": "--relay-port", "value": "PORT", "default": 9450, "description": "relay WebSocket port for the relay service" },
            { "flag": "--relay-health-port", "value": "PORT", "default": 9451, "description": "relay HTTP /health port for the relay service" },
            { "flag": "--with-dig-dns", "description": "install + register dig-dns as an OS service (local *.dig name resolution: DNS responder + HTTP gateway)" },
            { "flag": "--dig-dns-version", "value": "VERSION", "description": "pin dig-dns version (default: latest)" },
            { "flag": "--dig-dns-node", "value": "URL", "description": "dig-node endpoint dig-dns's gateway should use (forwarded as `dig-dns serve --node`); default: dig-dns's own ladder" },
            { "flag": "--uninstall-dig-dns", "description": "uninstall the dig-dns OS service + OS wiring this installer created (idempotent, zero residue; does not touch pre-existing org policy)" }
        ],
        "exit_codes": exit_codes
    });
    serde_json::to_string_pretty(&doc).expect("help doc serializes") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // -- Test scaffolding: a pure, in-memory release resolver ----------------
    //
    // The orchestration's only I/O is release discovery (the GitHub API) and the
    // actual download/service/hosts side effects. We inject a fake resolver and
    // drive every run in `dry_run` mode, so the full plan — component resolution,
    // asset selection, dest building, the PATH/service/relay/dig.local report
    // branches — runs deterministically with NO network and NO side effects.

    /// Build a resolver from a map of `repo.name` → (tag, asset names). A repo
    /// absent from the map resolves to an `ASSET_NOT_FOUND`-classified error
    /// (mirroring a GitHub 404), exercising the legacy-fallback + error paths.
    fn resolver_from(
        releases: HashMap<&'static str, (&'static str, Vec<&'static str>)>,
    ) -> impl Fn(&Repo, &Option<String>) -> Result<download::Release, InstallError> {
        move |repo: &Repo, requested: &Option<String>| match releases.get(repo.name.as_str()) {
            Some((tag, assets)) => Ok(download::Release {
                tag_name: tag.to_string(),
                asset_names: assets.iter().map(|s| s.to_string()).collect(),
            }),
            None => Err(classify_release_error(
                repo,
                requested,
                "HTTP 404 Not Found",
            )),
        }
    }

    /// The full DIG asset set across every component repo, for the current OS
    /// (the test runs against `Target::current()`, so resolve the live slug).
    fn all_releases() -> HashMap<&'static str, (&'static str, Vec<&'static str>)> {
        // Names cover all four OS/arch slugs + the browser installers, so the
        // asset matcher finds a match whatever host the test runs on.
        let digstore: Vec<&'static str> = vec![
            "digstore-0.6.0-windows-x64.exe",
            "digstore-0.6.0-linux-x64",
            "digstore-0.6.0-macos-arm64",
            "digstore-0.6.0-macos-x64",
        ];
        let node: Vec<&'static str> = vec![
            "dig-node-0.2.0-windows-x64.exe",
            "dig-node-0.2.0-linux-x64",
            "dig-node-0.2.0-macos-arm64",
            "dig-node-0.2.0-macos-x64",
        ];
        let relay: Vec<&'static str> = vec![
            "dig-relay-0.1.0-windows-x64.exe",
            "dig-relay-0.1.0-linux-x64",
            "dig-relay-0.1.0-macos-arm64",
            "dig-relay-0.1.0-macos-x64",
        ];
        let browser: Vec<&'static str> = vec![
            "DIG-Browser-1.0.0-windows-x64.exe",
            "DIG-Browser-1.0.0-macos.dmg",
            "DIG-Browser-1.0.0-linux-x86_64.AppImage",
        ];
        let dns: Vec<&'static str> = vec![
            "dig-dns-0.6.0-windows-x64.exe",
            "dig-dns-0.6.0-linux-x64",
            "dig-dns-0.6.0-macos-arm64",
            "dig-dns-0.6.0-macos-x64",
        ];
        let mut m = HashMap::new();
        m.insert("digstore", ("v0.6.0", digstore));
        m.insert("dig-node", ("v0.2.0", node));
        m.insert("dig-relay", ("v0.1.0", relay));
        m.insert("DIG_Browser", ("v1.0.0", browser));
        m.insert("dig-dns", ("v0.6.0", dns));
        m
    }

    /// A plan with every component OFF, dry-run on — the caller flips on what a
    /// given test needs.
    fn base_plan() -> InstallPlan {
        InstallPlan {
            bin_dir: std::env::temp_dir().join("dig-installer-test-bin"),
            with_digstore: false,
            digstore_version: None,
            with_dig_node: false,
            dig_node_version: None,
            service: ServiceConfig::default(),
            with_browser: false,
            browser_version: None,
            with_relay: false,
            relay_version: None,
            relay_service: ServiceConfigRelay::default(),
            with_dig_dns: false,
            dig_dns_version: None,
            dns_service: dns::DnsInstallConfig::default(),
            modify_path: false,
            dry_run: true,
        }
    }

    fn run_dry(
        plan: &InstallPlan,
        releases: HashMap<&'static str, (&'static str, Vec<&'static str>)>,
    ) -> Result<InstallReport, InstallError> {
        let resolve = resolver_from(releases);
        run_report_with(plan, &resolve, &mut |_| {})
    }

    #[test]
    fn empty_plan_resolves_nothing_but_reports_target() {
        // Nothing selected: the report still carries the schema/target/installer
        // metadata and empty component/path/service sections.
        let report = run_dry(&base_plan(), HashMap::new()).expect("empty plan ok");
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.installer_version, env!("CARGO_PKG_VERSION"));
        assert!(!report.target.is_empty());
        assert!(report.dry_run);
        assert!(report.components.is_empty());
        assert!(report.path.is_none());
        assert!(report.service.is_none());
        assert!(report.relay.is_none());
        assert!(report.dns.is_none());
        assert!(report.installed.is_empty());
    }

    #[test]
    fn digstore_only_resolves_the_cli_component() {
        let mut plan = base_plan();
        plan.with_digstore = true;
        let report = run_dry(&plan, all_releases()).expect("digstore resolves");
        assert_eq!(report.components.len(), 1);
        let c = &report.components[0];
        assert_eq!(c.component, "digstore");
        assert_eq!(c.version, "0.6.0");
        assert_eq!(c.tag, "v0.6.0");
        assert!(c.asset.starts_with("digstore-0.6.0-"));
        assert!(c
            .url
            .contains("github.com/DIG-Network/digstore/releases/download/v0.6.0/"));
        // dry-run installs nothing on disk.
        assert!(report.installed.is_empty());
    }

    #[test]
    fn modify_path_records_a_would_add_path_result_on_dry_run() {
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.modify_path = true;
        let report = run_dry(&plan, all_releases()).expect("ok");
        let path = report.path.expect("path result present");
        // dry-run never mutates PATH; it records the intent.
        assert!(!path.modified);
        assert_eq!(path.note, "would add to PATH");
        assert!(path.dir.contains("dig-installer-test-bin"));
    }

    #[test]
    fn path_is_skipped_when_no_path_binary_is_installed() {
        // modify_path is on, but only the browser (an installer, not a PATH
        // binary) is selected → no PATH result.
        let mut plan = base_plan();
        plan.with_browser = true;
        plan.modify_path = true;
        let report = run_dry(&plan, all_releases()).expect("ok");
        assert!(report.path.is_none());
        assert_eq!(report.components.len(), 1);
        assert_eq!(report.components[0].component, "DIG-Browser");
    }

    #[test]
    fn dig_node_dry_run_reports_service_and_dig_local_intent() {
        let mut plan = base_plan();
        plan.with_dig_node = true;
        plan.service = ServiceConfig {
            port: 9099,
            start: true,
        };
        let report = run_dry(&plan, all_releases()).expect("dig-node resolves");
        // The node component is resolved...
        assert!(report.components.iter().any(|c| c.component == "dig-node"));
        // ...and the service section records the would-install + would-start +
        // would-add-dig.local intent (no process spawned, no hosts write).
        let svc = report.service.expect("service result present");
        assert!(!svc.installed);
        assert_eq!(svc.port, 9099);
        assert!(svc.note.contains("would run `dig-node install`"));
        assert!(svc.note.contains("`dig-node start`"));
        assert!(svc.dig_local.contains("dig.local"));
        // Dry-run never probes OS resolution (nothing was written to check).
        assert!(!svc.dig_local_resolves);
        assert_eq!(svc.dig_local_resolve_note, "skipped (dry run)");
        // Dry-run never probes the node's RPC either (task #223).
        assert!(!svc.health_checked);
        assert!(!svc.health_ok);
        assert_eq!(svc.health_note, "skipped (dry run)");
    }

    #[test]
    fn dig_node_dry_run_without_start_omits_start_from_note() {
        let mut plan = base_plan();
        plan.with_dig_node = true;
        plan.service = ServiceConfig {
            port: 8080,
            start: false,
        };
        let report = run_dry(&plan, all_releases()).expect("ok");
        let svc = report.service.expect("service");
        assert!(svc.note.contains("would run `dig-node install`"));
        assert!(!svc.note.contains("start"));
    }

    #[test]
    fn dig_node_falls_back_to_legacy_dig_companion_release() {
        // The renamed dig-node repo has no release; the legacy dig-companion repo
        // does. Resolution must fall back AND normalize the on-PATH name to
        // dig-node (so the service command stays consistent across the rename).
        let mut releases = all_releases();
        releases.remove("dig-node");
        releases.insert(
            "dig-companion",
            (
                "v0.1.5",
                vec![
                    "dig-companion-0.1.5-windows-x64.exe",
                    "dig-companion-0.1.5-linux-x64",
                    "dig-companion-0.1.5-macos-arm64",
                    "dig-companion-0.1.5-macos-x64",
                ],
            ),
        );
        let mut plan = base_plan();
        plan.with_dig_node = true;
        let report = run_dry(&plan, releases).expect("legacy fallback resolves");
        let node = report
            .components
            .iter()
            .find(|c| c.component == "dig-node")
            .expect("normalized to dig-node");
        // Sourced from the legacy repo + asset, but presented as dig-node.
        assert!(node.url.contains("dig-companion"));
        assert!(node.dest.contains("dig-node"));
    }

    #[test]
    fn relay_dry_run_reports_relay_service_intent() {
        let mut plan = base_plan();
        plan.with_relay = true;
        plan.relay_service = ServiceConfigRelay {
            port: 9450,
            health_port: 9451,
            start: true,
        };
        let report = run_dry(&plan, all_releases()).expect("relay resolves");
        assert!(report.components.iter().any(|c| c.component == "dig-relay"));
        let relay = report.relay.expect("relay result present");
        assert!(!relay.installed);
        assert_eq!(relay.port, 9450);
        assert_eq!(relay.health_port, 9451);
        assert!(relay.note.contains("would run `dig-relay install`"));
        assert!(relay.note.contains("`dig-relay start`"));
    }

    #[test]
    fn relay_dry_run_without_start_omits_start_from_note() {
        let mut plan = base_plan();
        plan.with_relay = true;
        plan.relay_service = ServiceConfigRelay {
            port: 9450,
            health_port: 9451,
            start: false,
        };
        let report = run_dry(&plan, all_releases()).expect("ok");
        let relay = report.relay.expect("relay");
        assert!(relay.note.contains("would run `dig-relay install`"));
        assert!(!relay.note.contains("start"));
    }

    #[test]
    fn dig_dns_dry_run_reports_the_would_install_intent_without_touching_the_system() {
        // Dry-run must never spawn a process, write a service, or need elevation —
        // it just records what WOULD happen (mirrors dig-node/relay's dry-run contract).
        let mut plan = base_plan();
        plan.with_dig_dns = true;
        let report = run_dry(&plan, all_releases()).expect("dig-dns resolves");
        assert!(report.components.iter().any(|c| c.component == "dig-dns"));
        let dns_result = report.dns.expect("dns result present");
        assert!(!dns_result.installed);
        assert!(!dns_result.needs_elevation);
        assert!(
            dns_result.note.contains("would"),
            "got: {}",
            dns_result.note
        );
        assert!(dns_result.doctor.is_none(), "dry-run never runs doctor");
        assert!(dns_result.paths_live.is_empty());
    }

    #[test]
    fn dig_dns_dry_run_forwards_a_node_override_and_puts_it_on_path() {
        let mut plan = base_plan();
        plan.with_dig_dns = true;
        plan.dns_service.node = Some("http://localhost:9778".to_string());
        plan.modify_path = true;
        let report = run_dry(&plan, all_releases()).expect("ok");
        assert_eq!(
            plan.dns_service.node.as_deref(),
            Some("http://localhost:9778")
        );
        // dig-dns places a raw PATH binary, same as digstore/dig-node.
        let path = report
            .path
            .expect("path result present with only dig-dns selected");
        assert!(path.dir.contains("dig-installer-test-bin"));
    }

    #[test]
    fn full_plan_resolves_all_components_in_order() {
        // digstore + dig-node + dig-dns + relay + browser, PATH on. All five
        // components resolve, plus path/service/dns/relay sections.
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.with_dig_node = true;
        plan.with_dig_dns = true;
        plan.with_relay = true;
        plan.with_browser = true;
        plan.modify_path = true;
        let report = run_dry(&plan, all_releases()).expect("full plan ok");
        let ids: Vec<&str> = report
            .components
            .iter()
            .map(|c| c.component.as_str())
            .collect();
        assert_eq!(
            ids,
            vec![
                "digstore",
                "dig-node",
                "dig-dns",
                "dig-relay",
                "DIG-Browser"
            ]
        );
        assert!(report.path.is_some());
        assert!(report.service.is_some());
        assert!(report.dns.is_some());
        assert!(report.relay.is_some());
    }

    #[test]
    fn missing_digstore_release_is_asset_not_found() {
        // No release published at all → a typed ASSET_NOT_FOUND (a 404 means
        // "nothing published", distinct from a transport error).
        let mut plan = base_plan();
        plan.with_digstore = true;
        let err = run_dry(&plan, HashMap::new()).unwrap_err();
        assert_eq!(err.code(), "ASSET_NOT_FOUND");
        assert!(err.message().contains("digstore"));
        assert!(err.hint().is_some());
    }

    #[test]
    fn release_present_but_no_matching_asset_is_asset_not_found() {
        // The release exists but ships nothing for any OS/arch (only a tarball).
        let mut releases = HashMap::new();
        releases.insert(
            "digstore",
            ("v0.6.0", vec!["source-code.tar.gz", "notes.txt"]),
        );
        let mut plan = base_plan();
        plan.with_digstore = true;
        let err = run_dry(&plan, releases).unwrap_err();
        assert_eq!(err.code(), "ASSET_NOT_FOUND");
        assert!(err.message().contains("no digstore asset"));
    }

    #[test]
    fn pinned_version_is_threaded_through_resolution() {
        // A pinned digstore version is honoured: the resolver receives the
        // request, and the resolved component reflects the returned tag.
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.digstore_version = Some("0.6.0".to_string());
        let report = run_dry(&plan, all_releases()).expect("pinned resolves");
        assert_eq!(report.components[0].tag, "v0.6.0");
    }

    #[test]
    fn report_serializes_to_the_stable_json_shape() {
        // The --json payload shape is a stable contract; assert the top-level
        // keys + nested field names serialize as documented (snake_case).
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.with_dig_node = true;
        plan.with_dig_dns = true;
        plan.modify_path = true;
        let report = run_dry(&plan, all_releases()).expect("ok");
        let v: serde_json::Value = serde_json::to_value(&report).unwrap();
        for key in [
            "schema_version",
            "installer_version",
            "target",
            "dry_run",
            "components",
            "path",
            "service",
            "relay",
            "dns",
            "installed",
        ] {
            assert!(v.get(key).is_some(), "report JSON missing key {key}");
        }
        let c = &v["components"][0];
        for key in ["component", "version", "tag", "asset", "url", "dest"] {
            assert!(c.get(key).is_some(), "component JSON missing key {key}");
        }
        let svc = &v["service"];
        for key in [
            "installed",
            "started",
            "port",
            "note",
            "dig_local",
            "dig_local_resolves",
            "dig_local_resolve_note",
            "health_checked",
            "health_ok",
            "health_note",
        ] {
            assert!(svc.get(key).is_some(), "service JSON missing key {key}");
        }
        let dns_json = &v["dns"];
        for key in [
            "installed",
            "started",
            "needs_elevation",
            "note",
            "doctor",
            "paths_live",
            "bound_port",
            "pac_url",
            "fallback_instruction",
        ] {
            assert!(dns_json.get(key).is_some(), "dns JSON missing key {key}");
        }
    }

    #[test]
    fn capturing_logger_records_progress_lines() {
        // run_report_with drives the `log` sink for every step; assert it is
        // exercised end-to-end (the pretty/--json front-ends route these).
        let mut lines: Vec<String> = Vec::new();
        let mut plan = base_plan();
        plan.with_digstore = true;
        let resolve = resolver_from(all_releases());
        let report =
            run_report_with(&plan, &resolve, &mut |l| lines.push(l.to_string())).expect("ok");
        assert_eq!(report.components.len(), 1);
        assert!(lines.iter().any(|l| l.contains("DIG installer — target")));
        assert!(lines.iter().any(|l| l.contains("dry run")));
        assert!(lines
            .iter()
            .any(|l| l.contains("Installing the digstore CLI")));
        assert!(lines.iter().any(|l| l == "Done."));
    }

    // -- Agent-facing JSON surfaces -----------------------------------------

    #[test]
    fn help_json_is_valid_and_lists_every_component_and_exit_code() {
        let doc = help_json();
        let v: serde_json::Value = serde_json::from_str(&doc).expect("help-json is valid JSON");
        assert_eq!(v["name"], "dig-installer");
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));

        let ids: Vec<&str> = v["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        for id in ["digstore", "dig-node", "dig-relay", "dig-dns", "browser"] {
            assert!(ids.contains(&id), "help-json missing component {id}");
        }

        // The exit-code table mirrors EXIT_CODES exactly.
        let codes: Vec<&str> = v["exit_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["code"].as_str().unwrap())
            .collect();
        for &(_, name, _) in error::EXIT_CODES.iter() {
            assert!(codes.contains(&name), "help-json missing exit code {name}");
        }
        assert!(v["targets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "linux-x64"));
    }

    #[test]
    fn error_json_carries_code_exit_code_message_and_hint() {
        let e = InstallError::network("github unreachable").with_hint("retry later");
        let v: serde_json::Value = serde_json::from_str(&error_json(&e)).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "NETWORK");
        assert_eq!(v["error"]["exit_code"], 4);
        assert_eq!(v["error"]["message"], "github unreachable");
        assert_eq!(v["error"]["hint"], "retry later");
    }

    #[test]
    fn error_json_emits_null_hint_when_absent() {
        let e = InstallError::io("disk full");
        let v: serde_json::Value = serde_json::from_str(&error_json(&e)).unwrap();
        assert_eq!(v["error"]["code"], "IO");
        assert!(v["error"]["hint"].is_null());
    }

    // -- dig-node uninstall (task #140) --------------------------------------

    #[test]
    fn uninstall_dig_node_dry_run_reports_intent_without_touching_the_system() {
        let bin_dir = std::env::temp_dir().join("dig-installer-test-uninstall-bin");
        let mut lines: Vec<String> = Vec::new();
        let result = uninstall_dig_node(&bin_dir, true, &mut |l| lines.push(l.to_string()));
        assert!(!result.uninstalled);
        assert!(!result.dig_local_removed);
        assert!(result.note.contains("would run"), "got: {}", result.note);
        assert!(result.note.contains("uninstall"), "got: {}", result.note);
        assert!(result.note.contains("dig.local"), "got: {}", result.note);
        assert!(lines.iter().any(|l| l.contains("would run")));
    }

    #[test]
    fn uninstall_dig_node_surfaces_a_missing_binary_without_panicking() {
        // No `--with-dig-node` was ever run against this bin_dir, so the
        // binary is missing — the failure must be recorded, not panic/abort,
        // and the note must be non-empty (never silent, task #140).
        let bin_dir = std::env::temp_dir().join(format!(
            "dig-installer-test-no-node-bin-{}",
            std::process::id()
        ));
        let result = uninstall_dig_node(&bin_dir, false, &mut |_| {});
        assert!(!result.uninstalled);
        assert!(!result.note.is_empty());
    }

    #[test]
    fn service_uninstall_json_wraps_the_result_in_an_ok_envelope() {
        let result = ServiceUninstallResult {
            uninstalled: true,
            dig_local_removed: true,
            note: "dig-node service uninstalled; removed dig.local from /etc/hosts".to_string(),
        };
        let v: serde_json::Value = serde_json::from_str(&service_uninstall_json(&result)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["result"]["uninstalled"], true);
        assert_eq!(v["result"]["dig_local_removed"], true);
    }

    #[test]
    fn dns_uninstall_json_wraps_the_result_in_an_ok_envelope() {
        let result = dns::DnsUninstallResult {
            uninstalled: true,
            needs_elevation: false,
            note: "removed: Windows service \"net.dignetwork.dig-dns\"".to_string(),
            residue_removed: vec!["Windows service \"net.dignetwork.dig-dns\"".to_string()],
        };
        let v: serde_json::Value = serde_json::from_str(&dns_uninstall_json(&result)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["result"]["uninstalled"], true);
        assert_eq!(
            v["result"]["residue_removed"][0],
            "Windows service \"net.dignetwork.dig-dns\""
        );
    }
}
