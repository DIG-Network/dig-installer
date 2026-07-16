//! The universal DIG installer (library surface) — a **thin shim**.
//!
//! It bundles nothing. At install time it resolves, per host OS/arch, the LATEST
//! GitHub release asset for each selected component and downloads it:
//!
//! * the **digstore CLI** (`DIG-Network/digstore`) → placed on PATH, along with
//!   its **`digs` alias binary** (issue #434) — published in the SAME digstore
//!   release under a separate asset stem, installed alongside digstore in the
//!   same bin dir (no separate flag or PATH entry),
//! * the **dig-node** local node (`DIG-Network/dig-node`) → installed + started
//!   as an OS service (Windows service / systemd / launchd) by delegating to
//!   dig-node's own `install`/`start` subcommands, along with its **`dign`
//!   alias binary** (issue #548) — published in the SAME dig-node release
//!   under a separate asset stem, installed alongside dig-node in the same bin
//!   dir — and (best-effort) a `127.0.0.2 dig.local` hosts entry so consumers
//!   reach it port-free,
//! * the **DIG Browser** (`DIG-Network/DIG_Browser`) → the native installer
//!   (`.exe`/`.dmg`/`.AppImage`) downloaded for the user to run, and
//! * **dig-dns** (`DIG-Network/dig-dns`) → installed + registered as an OS
//!   service (Windows Service / macOS LaunchDaemon / Linux systemd unit) for
//!   local `*.dig` name resolution, along with its **`digd` alias binary**
//!   (issue #548) — published in the SAME dig-dns release under a separate
//!   asset stem, installed alongside dig-dns in the same bin dir. Unlike
//!   dig-node/dig-relay, dig-dns ships no `install`/`start` subcommands of its
//!   own, so this installer owns the full per-OS service + split-DNS/NRPT +
//!   browser-policy wiring directly (see [`dns`]), self-verifying with
//!   `dig-dns doctor` when done.
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
pub mod beacon;
pub mod browsers;
pub mod daemon_dir;
pub mod dns;
pub mod download;
pub mod elevation;
pub mod error;
pub mod firewall;
pub mod forcelist;
pub mod health;
pub mod hosts;
pub mod manifest;
pub mod migrate;
pub mod pathcheck;
pub mod paths;
pub mod proc;
pub mod regaudit;
pub mod release;
pub mod scheme;
pub mod secure;
pub mod service;
pub mod svc;
pub mod target;
pub mod update;

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
    /// Install the digstore CLI (default true — part of the universal 3-component
    /// stack, #301). Also gates the `digs` alias binary (issue #434), which has
    /// no flag of its own and installs/uninstalls alongside digstore.
    pub with_digstore: bool,
    /// digstore version/tag to install: `None` ⇒ latest released. Also threads
    /// through to the `digs` alias resolution (published in the same release).
    pub digstore_version: Option<String>,
    /// Install + register dig-node as a boot-start OS service (default true —
    /// part of the universal 3-component stack, #301). Also gates the `dign`
    /// alias binary (issue #548), which has no flag of its own and
    /// installs/uninstalls alongside dig-node.
    pub with_dig_node: bool,
    /// dig-node version/tag to install: `None` ⇒ latest released. Also threads
    /// through to the `dign` alias resolution (published in the same release).
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
    /// Install dig-dns and register it as a boot-start OS service (local `*.dig`
    /// name resolution: a DNS responder + HTTP gateway). Default true — part of
    /// the universal 3-component stack, #301. Also gates the `digd` alias
    /// binary (issue #548), which has no flag of its own and
    /// installs/uninstalls alongside dig-dns.
    pub with_dig_dns: bool,
    /// dig-dns version/tag to install: `None` ⇒ latest released. Also threads
    /// through to the `digd` alias resolution (published in the same release).
    pub dig_dns_version: Option<String>,
    /// dig-dns service configuration when `with_dig_dns` is set (start +
    /// optional dig-node endpoint override forwarded to `dig-dns serve --node`).
    pub dns_service: dns::DnsInstallConfig,
    /// Add the bin dir to PATH (default true).
    pub modify_path: bool,
    /// Register the `chia://` (+ best-effort `urn:`) OS URL-scheme handler that
    /// routes clicked links through the local dig-node into the browser (#389).
    /// Default true — a first-class, toggleable install option
    /// (`--no-register-scheme` opts out). Per-user, no elevation.
    pub register_scheme: bool,
    /// Open an inbound firewall rule scoped to the dig-node executable on its
    /// peer-RPC port (#424), so the freshly-installed node is reachable for
    /// direct peer connections immediately (relay fallback still works if
    /// declined). Default true — a first-class, toggleable install option
    /// (`--no-open-firewall` opts out). Only applied when [`Self::with_dig_node`]
    /// is set; needs the same elevation the dig-node service registration
    /// already requires.
    pub open_firewall: bool,
    /// Install the DIG auto-update beacon (`dig-updater` + its
    /// `dig-updater-worker` sibling, `DIG-Network/dig-updater`) and register
    /// its daily update-check scheduler (issue #514). Default true — a
    /// first-class, toggleable install option (`--no-auto-update` opts out),
    /// mirroring [`Self::register_scheme`]/[`Self::open_firewall`]'s
    /// default-on-but-always-safe-to-decline posture: without it, DIG simply
    /// never auto-updates and the user re-runs the installer manually for new
    /// versions.
    pub auto_update: bool,
    /// dig-updater version/tag to install: `None` ⇒ latest released. Also
    /// pins the `dig-updater-worker` sibling, published in the same release.
    pub dig_updater_version: Option<String>,
    /// Force a fresh reinstall of every selected tracked component (digstore /
    /// dig-node / dig-dns / dig-updater) even when [`update::decide`] would
    /// otherwise call it up to date (issue #309). Default false: a bare
    /// re-run is a version-aware update that skips what's already current.
    /// Has no effect on a component that was already going to Install or
    /// Update — those already replace the artifact.
    pub force_reinstall: bool,
    /// Print actions without performing them.
    pub dry_run: bool,
}

/// Re-export alias so `InstallPlan` reads cleanly (`service::RelayServiceConfig`).
pub use service::RelayServiceConfig as ServiceConfigRelay;

impl InstallPlan {
    /// Whether running this plan requires OS elevation (Administrator/root).
    ///
    /// Registering an OS service (dig-node, dig-dns, dig-relay), a daily
    /// update-scheduler artifact (dig-updater, #514), or writing the
    /// `dig.local` hosts entry needs elevation; a `--dry-run` changes nothing
    /// so never does. Additionally (#565): writing into the admin-only protected
    /// install root itself needs elevation — so even a CLI-only install elevates
    /// on Windows (where the whole stack lives under `%ProgramFiles%\DIG\bin`),
    /// while a CLI-only unix install into the per-user `~/.dig/bin` still does
    /// not. An explicit `--bin-dir` override is treated as the user's own
    /// (possibly-writable) choice and does not, by itself, force elevation.
    /// This gates the pre-install elevation check (#492).
    pub fn requires_elevation(&self, os: target::Os) -> bool {
        if self.dry_run {
            return false;
        }
        if self.with_dig_node || self.with_dig_dns || self.with_relay || self.auto_update {
            return true;
        }
        // #565: a CLI-only install still writes binaries into the protected root
        // on a platform where that root is admin-only (Windows Program Files).
        let places_a_binary = self.with_digstore || self.with_browser;
        places_a_binary
            && !self.has_custom_bin_dir()
            && self.bin_dir_for("digstore", os) == paths::protected_bin_dir()
    }

    /// The directory a given `component` is installed into on `os` (#565).
    ///
    /// A PRIVILEGED component (one a service/scheduled-task executes — see
    /// [`paths::is_privileged_component`]) goes into the admin-only
    /// [`paths::protected_bin_dir`]; every other (user-run) component goes into
    /// [`Self::bin_dir`]. An explicit `--bin-dir` override wins for the WHOLE
    /// stack ([`Self::has_custom_bin_dir`]) — the user chose one dir and takes
    /// responsibility for it. On Windows the two roots coincide (Program Files),
    /// so the whole stack lands there either way.
    pub fn bin_dir_for(&self, component: &str, os: target::Os) -> PathBuf {
        if paths::is_privileged_component(os, component) && !self.has_custom_bin_dir() {
            paths::protected_bin_dir()
        } else {
            self.bin_dir.clone()
        }
    }

    /// Did the user pick a bin dir explicitly (rather than the built-in default)?
    /// When they did, that one dir is used for every component (the override
    /// wins over the per-component protected-root routing, #565).
    pub fn has_custom_bin_dir(&self) -> bool {
        self.bin_dir != paths::default_bin_dir()
    }

    /// Will this plan place at least one binary into the DEFAULT admin-only
    /// [`paths::protected_bin_dir`] (#565)? True when a selected component is
    /// [`paths::is_privileged_component`] AND no `--bin-dir` override redirected
    /// it — so it is `false` under any `--bin-dir` override.
    ///
    /// This answers "does a privileged binary land in the built-in protected
    /// root?" — NOT "does this plan install a privileged binary at all?" The
    /// #565 gates (migration + audit + ACL verify) must fire on a `--bin-dir`
    /// privileged install too, so they gate on [`Self::installs_a_privileged_binary`]
    /// / [`Self::privileged_install_root`] instead; this predicate is retained to
    /// express the narrower default-root question.
    pub fn installs_a_protected_component(&self, os: target::Os) -> bool {
        if self.has_custom_bin_dir() {
            return false;
        }
        self.selected_components()
            .iter()
            .any(|c| paths::is_privileged_component(os, c))
    }

    /// The directory a PRIVILEGED/service-executed component will actually land
    /// in — the admin-only [`paths::protected_bin_dir`] by default, OR the
    /// user's `--bin-dir` when an override redirected the whole stack (#565 H3).
    /// `None` when no privileged component is selected (nothing to gate).
    ///
    /// This is the dir the fail-loud ACL verify (`secure::verify_install_root`)
    /// must run on — DECOUPLED from [`Self::installs_a_protected_component`] so a
    /// privileged install into a NON-admin-only custom dir (the CLI `--bin-dir`
    /// case, and the shipped GUI's user-writable `bin_dir`) STILL gets verified
    /// and REFUSES ready if the dir grants unprivileged write, instead of
    /// silently shipping the escalation.
    pub fn privileged_install_root(&self, os: target::Os) -> Option<PathBuf> {
        let component = self
            .selected_components()
            .into_iter()
            .find(|c| paths::is_privileged_component(os, c))?;
        Some(self.bin_dir_for(component, os))
    }

    /// Whether this plan installs a privileged/service-executed binary ANYWHERE —
    /// the admin-only protected root by default OR a custom `--bin-dir`/GUI dir
    /// (`true` exactly when [`Self::privileged_install_root`] is `Some`). This is
    /// the ONE gate for the #565 privileged-registration maintenance both the
    /// legacy-root migration (§ [`migrate::migrate_from_legacy_roots`]) and the
    /// post-install binPath audit (§ [`regaudit::audit`]) run under.
    ///
    /// Deliberately DECOUPLED from [`Self::installs_a_protected_component`] — the
    /// same decoupling H3 applied to the ACL verify. That predicate is `false`
    /// under a `--bin-dir` override (the path the GUI passes + the e2e uses), so
    /// gating on it SKIPPED the migration + audit there: a pre-#565 legacy-bound
    /// service/beacon registration was never vacated or flagged, readiness
    /// reported ready, and a non-admin could overwrite the legacy binary to run
    /// code as SYSTEM. Gating on this predicate closes that residual — the
    /// maintenance runs whenever a privileged binary is placed, on every path.
    /// (Both the migration and the audit only ever ACT on legacy roots, never the
    /// custom dir, so running them on a `--bin-dir` install is safe.)
    pub fn installs_a_privileged_binary(&self, os: target::Os) -> bool {
        self.privileged_install_root(os).is_some()
    }

    /// The component ids this plan will install (before per-OS availability
    /// gating), so placement/elevation/verification decisions share one list.
    fn selected_components(&self) -> Vec<&'static str> {
        let mut c = Vec::new();
        if self.with_digstore {
            c.extend(["digstore", "digs"]);
        }
        if self.with_dig_node {
            c.extend(["dig-node", "dign"]);
        }
        if self.with_dig_dns {
            c.extend(["dig-dns", "digd"]);
        }
        if self.auto_update {
            c.extend(["dig-updater", "dig-updater-worker"]);
        }
        if self.with_relay {
            c.push("dig-relay");
        }
        c
    }
}

impl Default for InstallPlan {
    /// The universal-installer default (#301): install the full DIG stack —
    /// digstore + dig-node + dig-dns — in one run, adding the bin dir to PATH.
    /// dig-relay (advanced) and the DIG Browser are NOT in the default plan; they
    /// are explicit opt-ins.
    fn default() -> Self {
        InstallPlan {
            bin_dir: paths::default_bin_dir(),
            with_digstore: true,
            digstore_version: None,
            with_dig_node: true,
            dig_node_version: None,
            service: ServiceConfig::default(),
            with_browser: false,
            browser_version: None,
            with_relay: false,
            relay_version: None,
            relay_service: ServiceConfigRelay::default(),
            with_dig_dns: true,
            dig_dns_version: None,
            dns_service: dns::DnsInstallConfig::default(),
            modify_path: true,
            register_scheme: true,
            open_firewall: true,
            auto_update: true,
            dig_updater_version: None,
            force_reinstall: false,
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
    /// Component id: `digstore` | `digs` | `dig-node` | `dign` | `dig-dns` |
    /// `digd` | `dig-relay` | `DIG-Browser`.
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
    /// Version-aware update decision for this component (issue #309): whether
    /// this run installed it fresh, replaced an outdated/unreadable install,
    /// or skipped one that was already current. Only `digstore`/`dig-node`/
    /// `dig-dns` (see `update::tracked_components`) are actually detected;
    /// every other component (`digs`, `dign`, `digd`, `dig-relay`, the DIG
    /// Browser) defaults to `Install`, matching their existing
    /// always-fresh-download behavior.
    pub update_action: update::UpdateAction,
    /// The version detected at this component's destination before this run
    /// (`None` when it was absent). Mirrors
    /// [`update::UpdateDecision::installed_version`]; `None` for the
    /// untracked components above.
    pub previous_version: Option<String>,
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
    /// The app-scoped firewall rule this installer opened (#424) was removed
    /// (or, on dry-run, would be). `false` if there was nothing to remove
    /// (idempotent no-op — e.g. it was declined at install time, or this is
    /// Linux, where a rule is never auto-applied).
    pub firewall_rule_removed: bool,
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
    /// The `chia://`/`urn:` URL-scheme registration result (only when
    /// `register_scheme`) — #389.
    pub scheme: Option<scheme::SchemeResult>,
    /// The app-scoped firewall rule result (only when `with_dig_node &&
    /// open_firewall`) — #424.
    pub firewall: Option<firewall::FirewallResult>,
    /// The DIG auto-update beacon's daily scheduler registration result (only
    /// when `auto_update`) — #514.
    pub beacon: Option<beacon::BeaconResult>,
    /// Absolute paths actually written (empty on dry-run).
    pub installed: Vec<String>,
    /// Per-CLI PATH-resolution checks (#496): confirms each required DIG CLI
    /// (digstore / dig-node / dig-dns) resolves by bare name from a fresh shell
    /// so the user can run it immediately. Empty on dry-run. A `resolved: false`
    /// entry makes the install NOT ready.
    pub cli_path_checks: Vec<pathcheck::CliPathCheck>,
    /// Machine-wide daemon state directories created + ACL'd (#501/#499): the
    /// identity-independent control/auth dirs the dig-node/dig-dns daemons +
    /// the operator CLI share. Empty on dry-run / when no daemon is installed.
    pub daemon_dirs: Vec<daemon_dir::DaemonDirResult>,
    /// The post-install verification that the PROTECTED install root denies
    /// unprivileged write (#565): the machine-checkable form of "no service
    /// binary lives where a non-admin could replace it". `None` on dry-run or
    /// when no privileged component was placed (nothing to verify). A definitive
    /// `checked && !secure` makes the install NOT ready ([`evaluate_readiness`]).
    pub install_root_security: Option<secure::InstallRootSecurity>,
    /// The record of migrating an existing install off the legacy user-writable
    /// root onto the protected root (#565): services deregistered/re-pointed,
    /// legacy binaries removed, legacy PATH entries dropped. `None` on dry-run or
    /// when no legacy install was detected.
    pub migration: Option<migrate::MigrationResult>,
    /// The post-registration binPath audit of every privileged DIG registration
    /// (#565 review — H1 backstop + H2b): each service / the SYSTEM beacon task's
    /// ACTUAL configured binary, read back from the OS, and whether it still
    /// resolves under a legacy/user-writable root. An entry with
    /// `under_legacy_root == true` makes the install NOT ready
    /// ([`evaluate_readiness`]). Empty on dry-run / when no privileged component
    /// was placed.
    pub registration_audit: Vec<regaudit::RegistrationAudit>,
    /// The authoritative install-root record written to `install.json` (#581):
    /// the single source of truth the auto-update beacon reads for the install
    /// root. `None` on dry-run or when no privileged component was placed.
    pub install_manifest: Option<manifest::ManifestResult>,
    /// The AGGREGATE verdict (#493): `true` iff EVERY selected component
    /// installed AND its service is verified RUNNING. Only when this is `true`
    /// may a caller print "✓ DIG is ready". Always `true` on a dry-run (nothing
    /// was installed, so nothing failed).
    pub ready: bool,
    /// The per-component failure reasons behind `ready == false` (empty when
    /// ready). Each entry names the component + why it is not ready + the
    /// remedy — never silent (#493).
    pub failures: Vec<String>,
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
        // The tracked call sites (digstore/dig-node/dig-dns in `run_report_gated`)
        // overwrite these with a real `update::decide` verdict; every other
        // caller (digs, dig-relay, the DIG Browser) keeps this default, which
        // matches their existing always-fresh-download behavior.
        update_action: update::UpdateAction::Install,
        previous_version: None,
    })
}

/// Detect what's already at a resolved component's destination, decide
/// Install/Update/Skip against the version just resolved (issue #309), log
/// the decision, and record it onto the [`ComponentResult`] (`update_action`/
/// `previous_version`) so the caller — the digstore/dig-node/dig-dns sections
/// of [`run_report_gated`] — can gate the rest of its lifecycle (the
/// download, the #232 stop/replace/restart) on one source of truth. Detection
/// is read-only (`update::detect_installed_version`), so this is safe to call
/// under `--dry-run` for an accurate preview.
fn apply_update_decision(
    c: &mut ComponentResult,
    force_reinstall: bool,
    log: &mut dyn FnMut(&str),
) -> update::UpdateDecision {
    let detected = update::detect_installed_version(std::path::Path::new(&c.dest));
    let decision = update::decide_with_force(&detected, &c.version, force_reinstall);
    log(&format!("    {}", decision.summary));
    c.update_action = decision.action;
    c.previous_version = decision.installed_version.clone();
    decision
}

/// Download a resolved component to its dest (no-op on dry-run). Returns how
/// the binary was written ([`download::WriteOutcome`]) so a service component's
/// caller can LOUDLY flag the rare locked-destination reboot-replace fallback
/// (#544); most callers simply propagate errors with `?` and ignore the Ok.
fn download_component(
    c: &ComponentResult,
    dry_run: bool,
) -> Result<download::WriteOutcome, InstallError> {
    if dry_run {
        return Ok(download::WriteOutcome::Replaced);
    }
    download::download_binary(&c.url, std::path::Path::new(&c.dest), None).map_err(|e| {
        // Distinguish a 404 (asset gone) from a transport error from a disk error.
        if e.contains("404") || e.contains("Not Found") {
            InstallError::asset_not_found(e)
        } else if e.contains("write") || e.contains("create") || e.contains("stage") {
            InstallError::io(e)
        } else {
            InstallError::network(e)
        }
    })
}

/// LOUDLY flag the locked-destination reboot-replace fallback (#544): when a
/// running binary was still held open at write time, its update was staged and
/// will apply on the next reboot — the user must restart to finish it. A plain
/// in-place [`download::WriteOutcome::Replaced`] logs nothing extra.
fn log_write_outcome(log: &mut dyn FnMut(&str), component: &str, outcome: download::WriteOutcome) {
    if outcome == download::WriteOutcome::ScheduledForReboot {
        log(&format!(
            "    ! {component} was still running and locked its binary, so the update was staged \
             and will apply on the next REBOOT — restart your computer to finish updating {component}."
        ));
    }
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
    run_report_gated(plan, resolve, &elevation::is_elevated, log)
}

/// [`run_report_with`] with an injectable elevation probe (the second I/O
/// boundary, after the release resolver). Production passes
/// [`elevation::is_elevated`]; tests pass a fixed answer so the pre-install
/// elevation gate (#492) — and that it fails FAST, before any download/write —
/// is exercised deterministically.
fn run_report_gated(
    plan: &InstallPlan,
    resolve: &ReleaseResolver<'_>,
    is_elevated: &dyn Fn() -> bool,
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

    // Pre-install privilege guard (#492 + #499): FIRST, before resolving/
    // downloading/writing anything, so a bad-privilege run fails fast and clean
    // with NO partial state. Rejects running as LocalSystem/SYSTEM (#499 — a
    // SYSTEM token breaks the GUI + lands state in the wrong profile) AND an
    // un-elevated run (#492). Only enforced when the plan actually needs
    // elevation (registers a service / writes hosts); a dry-run or digstore-only
    // run does not trip it.
    if plan.requires_elevation(target.os) {
        elevation::guard(is_elevated(), elevation::is_system(), &target)?;
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
        scheme: None,
        firewall: None,
        beacon: None,
        installed: Vec::new(),
        cli_path_checks: Vec::new(),
        daemon_dirs: Vec::new(),
        install_root_security: None,
        migration: None,
        registration_audit: Vec::new(),
        install_manifest: None,
        ready: true,
        failures: Vec::new(),
    };

    // #565: MIGRATE any existing user-writable install off the legacy root, then
    //    ensure the admin-only protected root exists + is hardened (unix `chmod
    //    0755`; Windows inherits Program Files' admin-only DACL) — BEFORE placing
    //    any privileged binary in it. The migration stops + re-points services by
    //    canonical id via the OS service manager; it NEVER executes a binary from
    //    the (possibly attacker-replaced) legacy user-writable dir. Gated on
    //    `installs_a_privileged_binary` — DECOUPLED from
    //    `installs_a_protected_component` so it runs on a `--bin-dir`/GUI
    //    privileged install too (the migration only acts on legacy roots, never
    //    the custom dir): otherwise a legacy-bound registration would survive.
    if !plan.dry_run && plan.installs_a_privileged_binary(target.os) {
        let migration = migrate::migrate_from_legacy_roots(&target, log);
        if migration.migrated {
            report.migration = Some(migration);
        }
        let protected = paths::protected_bin_dir();
        if let Err(e) = secure::ensure_protected_dir(target.os, &protected) {
            log(&format!(
                "    ! could not pre-create the protected install root {} ({e}); the per-binary \
                 write will create it",
                protected.display()
            ));
        }
    }

    // 0. Machine-wide daemon state directories (#501/#499). Created BEFORE any
    //    daemon starts so dig-node/dig-dns write their control-token into a
    //    stable, identity-independent, tightly-ACL'd dir the operator CLI can
    //    read WITHOUT being SYSTEM (enables `dig-node pair approve …` from a
    //    normal shell). Only when a daemon is being installed.
    if plan.with_dig_node || plan.with_dig_dns {
        log("Preparing the machine-wide daemon state directories:");
        report.daemon_dirs = daemon_dir::ensure(target.os, plan.dry_run, log);
    }

    // 1. digstore CLI + its `digs` alias binary (issue #434). `digs` is
    //    published in the SAME digstore release under its own asset stem
    //    (`digs-<ver>-<os_arch>[.exe]`) and behaves identically to `digstore`;
    //    it is resolved/downloaded exactly like digstore — same version pin,
    //    same bin dir (so no separate PATH entry is needed) — and follows the
    //    same `with_digstore`/`digstore_version` flags (it has none of its own).
    if plan.with_digstore {
        log("Installing the digstore CLI:");
        let mut c = resolve_component(
            resolve,
            &Repo::digstore(),
            &plan.digstore_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir_for("digstore", target.os),
        )?;
        log_component(log, &c);
        // #309 version-aware updater: detect what's already at this
        // destination — a read-only check, safe under `--dry-run` — and
        // decide Install/Update/Skip against the version just resolved above.
        let decision = apply_update_decision(&mut c, plan.force_reinstall, log);
        if decision.action != update::UpdateAction::Skip {
            download_component(&c, plan.dry_run)?;
        } else {
            log("    · already up to date — skipping the download");
        }
        if !plan.dry_run {
            report.installed.push(c.dest.clone());
        }
        report.components.push(c);

        log("Installing the digs alias (same digstore CLI, published as a separate binary):");
        let digs = resolve_component(
            resolve,
            &Repo::digs(),
            &plan.digstore_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir_for("digs", target.os),
        )?;
        log_component(log, &digs);
        download_component(&digs, plan.dry_run)?;
        if !plan.dry_run {
            report.installed.push(digs.dest.clone());
        }
        report.components.push(digs);
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

    // 3. dig-node service (optional) + its `dign` alias binary (issue #548) +
    //    dig.local hosts entry.
    if plan.with_dig_node {
        log("Installing the dig-node local node:");
        let mut c = resolve_dig_node(
            resolve,
            &plan.dig_node_version,
            &target,
            &plan.bin_dir_for("dig-node", target.os),
            log,
        )?;
        log_component(log, &c);
        // #309 version-aware updater: decide Install/Update/Skip BEFORE
        // touching anything. Only Install/Update proceed to the #232
        // stop-before-write lifecycle below; Skip leaves the running service
        // and its binary untouched (`register_dig_node` re-verifies it below
        // rather than reinstalling it).
        let decision = apply_update_decision(&mut c, plan.force_reinstall, log);
        if decision.action != update::UpdateAction::Skip {
            // Task #232: stop a currently-running dig-node BEFORE overwriting
            // its binary (Windows locks a running exe's file — overwriting it
            // in place would fail with a sharing violation, or worse, corrupt
            // a partial write). Skip-when-absent/not-serving is not an error;
            // a stop FAILURE aborts this artifact's write entirely rather
            // than risk a half-written binary underneath a still-running
            // service.
            if !plan.dry_run {
                let dest = std::path::Path::new(&c.dest);
                let stop = service::stop_running_dig_node(dest)
                    .map_err(InstallError::service_stop_failed)?;
                log(&format!(
                    "    {} {}",
                    if stop.attempted { "✓" } else { "·" },
                    stop.note
                ));
            }
            let outcome = download_component(&c, plan.dry_run)?;
            log_write_outcome(log, "dig-node", outcome);
        }
        if !plan.dry_run {
            report.installed.push(c.dest.clone());
        }
        let dig_node_path = PathBuf::from(c.dest.clone());
        report.components.push(c);

        // dign (issue #548): a first-class alias of dig-node, published in the
        // SAME dig-node release under its own asset stem, installed alongside
        // it — same version pin, same bin dir, no separate PATH entry needed —
        // mirroring the digs-alongside-digstore pattern above (§1 in this
        // file's header). Not update-tracked (mirrors digs, #309 §7.3): it
        // always re-downloads fresh when present, sharing dig-node's version
        // pin. Resolution failure is gated gracefully (logged, not fatal): the
        // pre-rename `dig-companion` fallback above resolves dig-node from a
        // DIFFERENT repo than `Repo::dign()` targets, so a dig-node install
        // that fell back to the legacy repo has no dign asset to find —
        // exercised by `dig_node_falls_back_to_legacy_dig_companion_release`
        // below — and that must never sink the otherwise-successful install.
        log(
            "Installing the dign alias (same dig-node local node, published as a separate binary):",
        );
        match resolve_component(
            resolve,
            &Repo::dign(),
            &plan.dig_node_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir_for("dign", target.os),
        ) {
            Ok(dign) => {
                log_component(log, &dign);
                download_component(&dign, plan.dry_run)?;
                if !plan.dry_run {
                    report.installed.push(dign.dest.clone());
                }
                report.components.push(dign);
            }
            Err(e) if e.code() == "ASSET_NOT_FOUND" => {
                log(&format!(
                    "    · dign alias not available for this release ({e}) — skipping; dig-node itself is unaffected"
                ));
            }
            Err(e) => return Err(e),
        }

        report.service = Some(register_dig_node(&dig_node_path, plan, &decision, log));

        // 3b. App-scoped firewall rule for dig-node's peer-RPC listener
        //     (#424) — default-on, toggleable, best-effort (never aborts the
        //     install; a decline/failure just means peers reach this node
        //     via the relay fallback instead of directly).
        if plan.open_firewall {
            log("Opening the firewall for dig-node's peer-RPC port:");
            let f = firewall::open(&dig_node_path, plan.dry_run);
            log(&format!(
                "    {} {}",
                if f.applied { "✓" } else { "·" },
                f.note
            ));
            report.firewall = Some(f);
        }
    }

    // 4. dig-dns (optional): local `*.dig` name resolution, installed as an OS service, along
    //    with its `digd` alias binary (issue #548). Unlike dig-node/dig-relay, dig-dns has no
    //    `install`/`start` subcommands of its own, so this installer owns the full per-OS
    //    service + split-DNS/NRPT + browser-policy wiring (see the `dns` module) and
    //    self-verifies with `dig-dns doctor` once started.
    if plan.with_dig_dns {
        log("Installing dig-dns (local *.dig name resolution):");
        match resolve_component(
            resolve,
            &Repo::dig_dns(),
            &plan.dig_dns_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir_for("dig-dns", target.os),
        ) {
            Ok(mut c) => {
                log_component(log, &c);
                // #309 version-aware updater — same decide-before-touch
                // convention as digstore/dig-node above. `register_dig_dns`
                // reuses `dns::verify_existing` (a read-only re-check) rather
                // than the full clean-reinstall path when Skip.
                let decision = apply_update_decision(&mut c, plan.force_reinstall, log);
                if decision.action != update::UpdateAction::Skip {
                    // #544: stop a running dig-dns service BEFORE overwriting its
                    // binary — parity with dig-node/dig-relay's #232 stop-before-
                    // write. dig-dns has no `stop` verb of its own, so the
                    // installer stops the OS service it registered. A stop
                    // failure is non-fatal: the resilient write below falls back
                    // to a reboot-time replace if the binary is still locked.
                    if !plan.dry_run {
                        let dest = std::path::Path::new(&c.dest);
                        let stop = dns::stop_before_replace(dest);
                        log(&format!(
                            "    {} {}",
                            if stop.attempted { "✓" } else { "·" },
                            stop.note
                        ));
                    }
                    let outcome = download_component(&c, plan.dry_run)?;
                    log_write_outcome(log, "dig-dns", outcome);
                }
                if !plan.dry_run {
                    report.installed.push(c.dest.clone());
                }
                let dig_dns_path = PathBuf::from(c.dest.clone());
                report.components.push(c);

                // digd (issue #548): a first-class alias of dig-dns, published
                // in the SAME dig-dns release under its own asset stem,
                // installed alongside it — same version pin, same bin dir, no
                // separate PATH entry needed — exactly mirroring
                // digs-alongside-digstore above. Unlike dign (which has a
                // pre-rename legacy-repo fallback dig-node itself can take),
                // digd resolves against the IDENTICAL repo + version pin as
                // dig-dns itself with no such divergence, so it always
                // succeeds whenever dig-dns just did — no separate gate is
                // needed here (only reached inside this `Ok(mut c)` arm, i.e.
                // once dig-dns itself resolved; the ASSET_NOT_FOUND gate below
                // handles dig-dns being entirely unpublished). Not
                // update-tracked (mirrors digs, #309 §7.3): it always
                // re-downloads fresh, sharing dig-dns's version pin.
                log("Installing the digd alias (same dig-dns resolver, published as a separate binary):");
                let digd = resolve_component(
                    resolve,
                    &Repo::digd(),
                    &plan.dig_dns_version,
                    &target,
                    AssetKind::RawBinary,
                    &plan.bin_dir_for("digd", target.os),
                )?;
                log_component(log, &digd);
                download_component(&digd, plan.dry_run)?;
                if !plan.dry_run {
                    report.installed.push(digd.dest.clone());
                }
                report.components.push(digd);

                report.dns = Some(register_dig_dns(&dig_dns_path, plan, &decision, log));
            }
            // dig-dns is EPIC #174 and may ship no published release yet. Gate
            // this ONE component gracefully instead of failing the whole plan
            // (task #234): record a clear "not yet available" state and let
            // every other selected component (dig-relay, browser, …) still
            // install. A genuine transport failure (not "nothing published")
            // still propagates like every other component.
            Err(e) if e.code() == "ASSET_NOT_FOUND" => {
                let note = format!(
                    "dig-dns is not yet available ({e}) — it is EPIC #174 and has no matching \
                     release yet; skipped, the rest of the install continues. Re-run once a \
                     release is published."
                );
                log(&format!("    ! {note}"));
                report.dns = Some(dns::DnsInstallResult {
                    installed: false,
                    started: false,
                    service_running: false,
                    needs_elevation: false,
                    note,
                    doctor: None,
                    paths_live: Vec::new(),
                    bound_port: None,
                    pac_url: None,
                    fallback_instruction: None,
                });
            }
            Err(e) => return Err(e),
        }
    }

    // 5. The DIG auto-update beacon (dig-updater + its dig-updater-worker sibling, #514) —
    //    default-on, toggleable. Resolves + downloads BOTH binaries (the broker spawns the
    //    worker as a sibling process, so they must be co-located), then asks the freshly-
    //    installed `dig-updater` to register its own daily scheduler against itself
    //    (`beacon::register`) — the same "delegate to the component's own subcommands" pattern
    //    dig-node/dig-relay's service registration already uses.
    if plan.auto_update {
        log("Installing the DIG auto-update beacon:");
        let mut c = resolve_component(
            resolve,
            &Repo::dig_updater(),
            &plan.dig_updater_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir_for("dig-updater", target.os),
        )?;
        log_component(log, &c);
        // #309 version-aware updater, extended to the beacon (#514): same
        // decide-before-touch convention as digstore/dig-node/dig-dns above.
        let decision = apply_update_decision(&mut c, plan.force_reinstall, log);
        if decision.action != update::UpdateAction::Skip {
            download_component(&c, plan.dry_run)?;
        } else {
            log("    · already up to date — skipping the download");
        }
        if !plan.dry_run {
            report.installed.push(c.dest.clone());
        }
        let dig_updater_path = PathBuf::from(c.dest.clone());
        report.components.push(c);

        log("Installing the dig-updater-worker sibling (same release, published as a separate binary):");
        let worker = resolve_component(
            resolve,
            &Repo::dig_updater_worker(),
            &plan.dig_updater_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir_for("dig-updater-worker", target.os),
        )?;
        log_component(log, &worker);
        download_component(&worker, plan.dry_run)?;
        if !plan.dry_run {
            report.installed.push(worker.dest.clone());
        }
        report.components.push(worker);

        log("Registering the beacon's daily update-check scheduler:");
        let b = beacon::register(&dig_updater_path, plan.dry_run);
        log(&format!(
            "    {} {}",
            if b.applied { "✓" } else { "!" },
            b.note
        ));
        report.beacon = Some(b);
    }

    // 6. dig-relay service (optional, advanced — run-your-own-relay). The DEFAULT node already
    //    points at relay.dig.net, so this is only for users who want to operate a relay.
    if plan.with_relay {
        log("Installing the dig-relay (run-your-own-relay):");
        let c = resolve_component(
            resolve,
            &Repo::dig_relay(),
            &plan.relay_version,
            &target,
            AssetKind::RawBinary,
            &plan.bin_dir_for("dig-relay", target.os),
        )?;
        log_component(log, &c);
        // Task #232: stop a currently-running dig-relay before overwriting
        // its binary — same skip-when-absent/not-serving, abort-on-stop-
        // failure contract as dig-node above.
        if !plan.dry_run {
            let dest = std::path::Path::new(&c.dest);
            let stop =
                service::stop_running_dig_relay(dest).map_err(InstallError::service_stop_failed)?;
            log(&format!(
                "    {} {}",
                if stop.attempted { "✓" } else { "·" },
                stop.note
            ));
        }
        let outcome = download_component(&c, plan.dry_run)?;
        log_write_outcome(log, "dig-relay", outcome);
        if !plan.dry_run {
            report.installed.push(c.dest.clone());
        }
        let relay_path = PathBuf::from(c.dest.clone());
        report.components.push(c);

        report.relay = Some(register_relay(&relay_path, plan, log));
    }

    // 7. DIG Browser native installer (optional).
    if plan.with_browser {
        log("Downloading the DIG Browser installer:");
        let c = resolve_component(
            resolve,
            &Repo::dig_browser(),
            &plan.browser_version,
            &target,
            AssetKind::Installer,
            &plan.bin_dir_for("browser", target.os),
        )?;
        log_component(log, &c);
        download_component(&c, plan.dry_run)?;
        if !plan.dry_run {
            log(&format!("    run the installer to finish: {}", c.dest));
            report.installed.push(c.dest.clone());
        }
        report.components.push(c);
    }

    // 8. chia:// (+ urn:) OS URL-scheme handler (#389) — default-on, toggleable.
    //    Registers THIS installer's persisted binary as the handler; a clicked
    //    chia:// link resolves through the local dig-node (§5.3) into the
    //    browser. Per-user (no elevation). Best-effort: a registration failure
    //    is recorded, never aborts the install (the rest already succeeded).
    if plan.register_scheme {
        log("Registering the chia:// URL-scheme handler (opens links via the local dig-node):");
        report.scheme = Some(register_scheme_handler(plan, &target, log));
    }

    // PATH verification (#496): confirm each required DIG CLI resolves by bare
    // name from a fresh shell, so the user can run `dig-node …` / `dig-dns …`
    // immediately. Non-dry-run only (dry-run installs nothing to resolve).
    if !plan.dry_run {
        verify_clis_on_path(&target, &mut report, log);
    }

    // #565: VERIFY the dir every privileged/service-executed binary landed in
    //    denies unprivileged write, now that all are in place. This is the
    //    machine-checkable "no service binary sits where a non-admin could
    //    replace it" gate; a DEFINITIVE breach (an unprivileged Allow-write ACE /
    //    group-writable mode) makes the install NOT ready. The dir is the
    //    admin-only protected root by default OR the `--bin-dir` / GUI-chosen dir
    //    when an override redirected the stack (#565 H3): the verify follows the
    //    binaries so a privileged install into a user-writable custom dir can
    //    NEVER silently succeed.
    if !plan.dry_run {
        if let Some(root) = plan.privileged_install_root(target.os) {
            log("Verifying the install root denies unprivileged write:");
            let verdict = secure::verify_install_root(target.os, &root);
            log(&format!(
                "    {} {}",
                if verdict.checked && !verdict.secure {
                    "!"
                } else {
                    "✓"
                },
                verdict.note
            ));
            report.install_root_security = Some(verdict);

            // #581: record the authoritative install root in install.json so the
            // auto-update beacon has a single source of truth for where DIG lives
            // (coherent with the beacon's own current_exe-derived root). Only for
            // the DEFAULT protected root — a custom override is the user's own dir.
            if root == paths::protected_bin_dir() {
                let m = manifest::write_install_manifest(
                    target.os,
                    &paths::protected_bin_dir(),
                    env!("CARGO_PKG_VERSION"),
                    plan.dry_run,
                );
                log(&format!(
                    "    {} {}",
                    if m.written { "✓" } else { "·" },
                    m.note
                ));
                report.install_manifest = Some(m);
            }
        }

        // #565 (review — H1 backstop + H2b): AUDIT every privileged registration's
        //    ACTUAL configured binPath, read back from the OS (never by executing
        //    the binary). A registration still resolving under a legacy/
        //    user-writable root — a service the tolerated re-install left there, or
        //    an orphaned SYSTEM beacon task a component opt-out stranded — makes the
        //    install NOT ready ([`evaluate_readiness`]). Gated on
        //    `installs_a_privileged_binary` (the SAME gate as the migration above),
        //    so it fires whenever a privileged binary is placed — including on a
        //    `--bin-dir`/GUI install, not only the default protected root.
        if plan.installs_a_privileged_binary(target.os) {
            log("Auditing that every privileged registration runs from the protected root:");
            report.registration_audit = regaudit::audit(target.os);
            for a in &report.registration_audit {
                log(&format!(
                    "    {} {}",
                    if a.under_legacy_root { "!" } else { "✓" },
                    a.note
                ));
            }
        }
    }

    // Aggregate readiness verdict (#493 + @mt-dev firm directive): "if
    // installation of ANY component failed, DIG is NOT ready." Never print a
    // green success line when a selected component didn't install or its
    // service isn't running.
    report.failures = evaluate_readiness(plan, &report);
    report.ready = report.failures.is_empty();
    log_readiness_verdict(&report, log);
    Ok(report)
}

/// Register the `chia://`/`urn:` OS URL-scheme handler (#389). Persists this
/// installer's own binary to `bin_dir` (a stable handler target that survives a
/// transient `irm|iex` download) and points the OS handler at it. Never
/// aborts — a failure is recorded in the result. Reports intent on dry-run.
fn register_scheme_handler(
    plan: &InstallPlan,
    target: &Target,
    log: &mut dyn FnMut(&str),
) -> scheme::SchemeResult {
    if plan.dry_run {
        let r = scheme::register(
            &plan.bin_dir.join(target.exe_name("dig-installer")),
            true,
            true,
        );
        log(&format!("    ({})", r.note));
        return r;
    }
    // Persist the running installer to a stable path so the registered handler
    // keeps working after a transient download copy is gone.
    let handler_bin = plan.bin_dir.join(target.exe_name("dig-installer"));
    if let Ok(current) = std::env::current_exe() {
        if current != handler_bin {
            if let Some(parent) = handler_bin.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::copy(&current, &handler_bin);
        }
    }
    let r = scheme::register(&handler_bin, true, false);
    if r.registered {
        log(&format!("    ✓ {}", r.note));
    } else {
        log(&format!("    ! {}", r.note));
    }
    r
}

/// The user-facing DIG CLIs that MUST be runnable by bare name after install
/// (#496): the digstore CLI + the two node/dns CLIs a user drives directly
/// (e.g. `dig-node pair approve <id>`). dig-relay is a background service (no
/// user CLI surface required); the DIG Browser is a GUI installer.
const REQUIRED_CLIS: &[&str] = &["digstore", "dig-node", "dig-dns"];

/// Verify each installed required CLI resolves by bare name on the post-install
/// PATH (#496) and record the result into `report.cli_path_checks`. Only checks
/// CLIs actually placed this run (present in `report.components`). Logs each
/// check; a failure is folded into the readiness verdict by
/// [`evaluate_readiness`].
fn verify_clis_on_path(target: &Target, report: &mut InstallReport, log: &mut dyn FnMut(&str)) {
    let installed_clis: Vec<String> = report
        .components
        .iter()
        .map(|c| c.component.clone())
        .filter(|id| REQUIRED_CLIS.contains(&id.as_str()))
        .collect();
    if installed_clis.is_empty() {
        return;
    }
    log("Verifying the DIG CLIs resolve on PATH:");
    for cli in installed_clis {
        let exe = target.exe_name(&cli);
        let bin_dir = report
            .components
            .iter()
            .find(|c| c.component == cli)
            .and_then(|c| {
                std::path::Path::new(&c.dest)
                    .parent()
                    .map(|p| p.to_path_buf())
            })
            .unwrap_or_else(paths::default_bin_dir);
        let check = match pathcheck::cli_resolves(&bin_dir, &exe) {
            Ok(version) => {
                let note = format!("`{cli} --version` resolved on PATH ({version})");
                log(&format!("    ✓ {note}"));
                pathcheck::CliPathCheck {
                    cli: cli.clone(),
                    resolved: true,
                    note,
                }
            }
            Err(e) => {
                log(&format!(
                    "    ! {cli} is NOT resolvable on PATH: {e} — open a NEW terminal, or re-run elevated so the PATH change takes effect."
                ));
                pathcheck::CliPathCheck {
                    cli: cli.clone(),
                    resolved: false,
                    note: e,
                }
            }
        };
        report.cli_path_checks.push(check);
    }
}

/// Compute the per-component failure reasons for the aggregate readiness
/// verdict (#493). Pure — reads the assembled [`InstallReport`] so it is
/// unit-tested directly. A dry-run installs nothing, so it never "fails".
///
/// A selected service component is READY only when it installed AND (if a start
/// was requested) its service is verified RUNNING — a bare port listener or a
/// clean-looking log line is NOT sufficient (the false-success bug). dig-node
/// readiness hinges on the real service-manager `RUNNING` check
/// ([`ServiceResult::health_ok`], set from [`svc::is_service_running`]); dig-dns
/// on a live resolution path; dig-relay on a successful registration.
fn evaluate_readiness(plan: &InstallPlan, report: &InstallReport) -> Vec<String> {
    let mut failures = Vec::new();
    if plan.dry_run {
        return failures;
    }

    if plan.with_dig_node {
        match &report.service {
            None => failures.push("dig-node: the node service was not installed".to_string()),
            Some(s) if !s.installed => failures.push(format!(
                "dig-node: the OS service did not register ({}); re-run elevated",
                s.note
            )),
            Some(s) if plan.service.start && !s.health_ok => failures.push(format!(
                "dig-node: the '{}' service is not running ({}); re-run elevated",
                svc::DIG_NODE_SERVICE_ID,
                s.health_note
            )),
            Some(_) => {}
        }
    }

    if plan.with_dig_dns {
        match &report.dns {
            None => failures.push("dig-dns: the resolver service was not installed".to_string()),
            Some(d) if !d.installed => failures.push(format!(
                "dig-dns: the OS service did not register ({}); re-run elevated",
                d.note
            )),
            // F7: gate on the fail-loud service-manager RUNNING poll (mirror the
            // dig-node `health_ok` gate) — a live `paths_live` probe alone is NOT
            // sufficient (another process could satisfy it; #493 false-success).
            Some(d) if plan.dns_service.start && !d.service_running => failures.push(format!(
                "dig-dns: installed but the '{}' service did not reach RUNNING ({}); re-run elevated",
                svc::DIG_DNS_SERVICE_ID, d.note
            )),
            Some(d) if plan.dns_service.start && d.paths_live.is_empty() => failures.push(format!(
                "dig-dns: installed but no live resolution path — the service is not serving ({})",
                d.note
            )),
            Some(_) => {}
        }
    }

    if plan.with_relay {
        match &report.relay {
            None => failures.push("dig-relay: the relay service was not installed".to_string()),
            Some(r) if !r.installed => failures.push(format!(
                "dig-relay: the OS service did not register ({}); re-run elevated",
                r.note
            )),
            Some(_) => {}
        }
    }

    // #514: the beacon's daily scheduler registration gates readiness the same
    // way dig-relay's service registration does above — it is a selected,
    // privileged OS-registration step, not a best-effort convenience like the
    // firewall rule/scheme handler.
    if plan.auto_update {
        match &report.beacon {
            None => failures.push(
                "dig-updater: the auto-update beacon was not installed".to_string(),
            ),
            Some(b) if !b.applied => failures.push(format!(
                "dig-updater: the daily update-check scheduler did not register ({}); re-run elevated",
                b.note
            )),
            Some(_) => {}
        }
    }

    // Machine-wide daemon state-dir hardening (#501 fail-closed, F2/F5): a
    // control-token directory whose tight ACL could NOT be established AND verified
    // by read-back is a hard failure. On failure the dir is deleted (fail closed),
    // so the daemon has no dir to write its control-token into — the install must
    // report NOT ready rather than let a daemon persist a control-token into a
    // world/Users-readable directory (a local privilege escalation). Gate each dir
    // on whether its daemon was selected for install.
    for dir in &report.daemon_dirs {
        let selected = match dir.daemon.as_str() {
            "dig-node" => plan.with_dig_node,
            "dig-dns" => plan.with_dig_dns,
            _ => true,
        };
        if selected && !dir.acl_applied {
            failures.push(format!(
                "{}: the machine-wide state directory could not be hardened + verified ({}); re-run elevated",
                dir.daemon, dir.note
            ));
        }
    }

    // #565: the install root MUST deny unprivileged write. A DEFINITIVE breach
    // (the ACL/mode read back and an unprivileged principal CAN write) is a hard
    // failure — a service binary a non-admin can replace is the exact local
    // privilege escalation this family closes. This now covers a privileged
    // install into a user-writable `--bin-dir`/GUI dir too (#565 H3), since the
    // verify runs on whichever dir the privileged binaries landed in. An
    // inconclusive read (`checked == false`) is only a warning (logged above),
    // never a false failure: the admin-only LOCATION remains the primary guarantee.
    if let Some(sec) = &report.install_root_security {
        if sec.checked && !sec.secure {
            failures.push(format!(
                "install root {}: {} — a non-admin could replace a privileged service binary; \
                 re-run elevated / repair the directory permissions",
                sec.root, sec.note
            ));
        }
    }

    // #565 (review — H2a): a privileged registration that could NOT be
    // deregistered off the legacy root during migration is FATAL — continuing
    // into a tolerated re-install could leave the service/task pointing at the
    // writable legacy binPath.
    if let Some(m) = &report.migration {
        for f in &m.deregister_failures {
            failures.push(format!(
                "migration: {f}; re-run elevated so the privileged registration is re-pointed \
                 into the protected root"
            ));
        }
    }

    // #565 (review — H1 backstop + H2b): any privileged registration whose ACTUAL
    // binPath still resolves under a legacy/user-writable root is a hard failure —
    // an orphaned auto-start service / SYSTEM beacon task a non-admin could replant
    // and run as SYSTEM. This catches both a component opt-out that stranded a
    // registration and a tolerated re-install that never re-pointed it.
    failures.extend(regaudit::audit_failures(&report.registration_audit));

    // PATH resolution (#496): any required CLI that does not resolve by bare
    // name from a fresh shell makes the install NOT ready — the user could not
    // run `dig-node …` / `dig-dns …` otherwise.
    for check in &report.cli_path_checks {
        if !check.resolved {
            failures.push(format!(
                "{}: the CLI is not runnable from a fresh shell ({}); open a new terminal or re-run elevated",
                check.cli, check.note
            ));
        }
    }

    failures
}

/// Log the final, explicit readiness verdict (#493) — a green "✓ DIG is ready"
/// ONLY when every selected component is ready; otherwise an unmistakable
/// "✗ DIG is NOT ready" with each failure + the remedy. This is the last line
/// the CLI prints; `main` maps `report.ready` onto the process exit code.
fn log_readiness_verdict(report: &InstallReport, log: &mut dyn FnMut(&str)) {
    if report.dry_run {
        log("Done (dry run — nothing was installed).");
        return;
    }
    if report.ready {
        log("✓ DIG is ready.");
    } else {
        log("✗ DIG is NOT ready — the following component(s) failed:");
        for f in &report.failures {
            log(&format!("    - {f}"));
        }
        log("Fix the above (re-run as Administrator/root if elevation is the cause) and run the installer again.");
    }
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
///
/// `decision` is the #309 update verdict for this run: when it is
/// [`update::UpdateAction::Skip`] this calls [`dns::verify_existing`] instead
/// of [`dns::install`] — a read-only re-check via the SAME `doctor`/`pac`
/// probes an install ends with, rather than the full per-OS clean-reinstall
/// (task #494) an unconditional re-`install` would otherwise perform on
/// every up-to-date run.
fn register_dig_dns(
    dig_dns_path: &std::path::Path,
    plan: &InstallPlan,
    decision: &update::UpdateDecision,
    log: &mut dyn FnMut(&str),
) -> dns::DnsInstallResult {
    log("Registering dig-dns as an OS service (DNS responder + HTTP gateway):");
    // The OS service runs the dig-dns binary directly (`dig-dns run-service` on
    // Windows — dig-dns's own SCM entrypoint — `dig-dns serve` on macOS/Linux):
    // no installer host-shim to persist (the #499 `1053` fix, see `dns::windows`).
    let mut result = if !plan.dry_run && decision.action == update::UpdateAction::Skip {
        log("    · already up to date — re-verifying the existing service instead of reinstalling it");
        dns::verify_existing(dig_dns_path)
    } else {
        dns::install(dig_dns_path, &plan.dns_service, plan.dry_run)
    };

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

    // Post-install SERVICE health check (#493/#499/#502): when a start was
    // requested, confirm the dig-dns service THIS run registered — identified by
    // its canonical id (`net.dignetwork.dig-dns`) — actually reached RUNNING per
    // the OS service manager (Windows `sc query` / Linux `systemctl is-active` /
    // macOS `launchctl print`, all via `svc`). A Windows 1053 start-timeout, a
    // failed systemd unit, or an unloaded launchd label surfaces here fail-loud
    // instead of a false success. The authoritative readiness gate stays the
    // live doctor path(s) below (a served `.dig` is the strongest signal); this
    // adds the explicit cross-OS "reached RUNNING" confirmation to the note.
    if result.installed && plan.dns_service.start {
        let state = svc::wait_for_service_running(
            svc::DIG_DNS_SERVICE_ID,
            HEALTH_CHECK_ATTEMPTS,
            HEALTH_CHECK_INTERVAL,
        );
        // F7: record the RUNNING verdict as a machine-checkable field so readiness
        // gates on the fail-loud service-manager poll — NOT on `paths_live` alone
        // (another process could satisfy the DNS/gateway probe; the #493 false-success).
        result.service_running = state == svc::ServiceRunState::Running;
        if state == svc::ServiceRunState::Running {
            log(&format!(
                "    ✓ service health: {}",
                state.describe(svc::DIG_DNS_SERVICE_ID)
            ));
            result.note.push_str("; service reached RUNNING");
        } else {
            log(&format!(
                "    ! service health: {} — the resolver may not be serving; re-run elevated if it did not start.",
                state.describe(svc::DIG_DNS_SERVICE_ID)
            ));
            result.note.push_str(&format!(
                "; NOT running ({})",
                state.describe(svc::DIG_DNS_SERVICE_ID)
            ));
        }
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
///
/// `decision` is the #309 update verdict computed for this run: when it is
/// [`update::UpdateAction::Skip`] the binary was NOT replaced, so this skips
/// re-running `dig-node install`/`start` (which would needlessly bounce an
/// already-current, already-running service) and instead treats the service
/// as already registered — the health check below still independently
/// verifies it is genuinely RUNNING, so a skip can never silently paper over
/// a service that died on its own.
fn register_dig_node(
    dig_node_path: &std::path::Path,
    plan: &InstallPlan,
    decision: &update::UpdateDecision,
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

    if decision.action == update::UpdateAction::Skip {
        // Already up to date: leave the registered service exactly as it is
        // rather than bouncing it via a needless `install`/`start`. The
        // health check below still independently confirms it is genuinely
        // RUNNING before this is trusted.
        result.installed = true;
        result.started = plan.service.start;
        result.note = format!(
            "already up to date ({}) — left the running service as-is",
            decision.latest_version
        );
        log(&format!("    · {}", result.note));
    } else {
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

    // Post-install SERVICE health check (#493/#223): confirm the ACTUAL OS
    // service THIS run registered — identified by its canonical id
    // (`net.dignetwork.dig-node`, #494) — is RUNNING per the service manager.
    // This REPLACES the old bare-port probe as the authoritative signal: a
    // dig-node started by SOMETHING ELSE answering on port 9778 must NOT
    // green-light a non-install (the false-success bug). The RPC probe is kept
    // only as secondary confirmation detail in the note. Skipped when the
    // service was never started (`--no-service-start`, or install failed).
    if result.started {
        let state = svc::wait_for_service_running(
            svc::DIG_NODE_SERVICE_ID,
            HEALTH_CHECK_ATTEMPTS,
            HEALTH_CHECK_INTERVAL,
        );
        let running = state == svc::ServiceRunState::Running;
        let mut note = state.describe(svc::DIG_NODE_SERVICE_ID);
        // Secondary confirmation only — never gates readiness (a slow socket
        // bind must not fail a genuinely-running service).
        if running {
            let rpc = health::wait_for_node_health(
                plan.service.port,
                HEALTH_CHECK_ATTEMPTS,
                HEALTH_CHECK_INTERVAL,
            );
            if rpc.healthy {
                note.push_str(&format!("; RPC answered on port {}", plan.service.port));
            } else {
                note.push_str(&format!(
                    "; note: RPC on port {} not yet answering ({})",
                    plan.service.port, rpc.note
                ));
            }
        }
        // Verify the Services-panel DISPLAY name persisted (#494/#499): read it
        // back via `sc qc` DISPLAY_NAME and confirm it is the canonical ALL-CAPS
        // "DIG NETWORK: NODE", not the raw reverse-DNS service id (the #499
        // symptom). Windows-only + non-gating: a cosmetic label mismatch is
        // surfaced in the note but never fails a genuinely-running service.
        #[cfg(windows)]
        if running {
            let dn =
                svc::verify_display_name(svc::DIG_NODE_SERVICE_ID, svc::DIG_NODE_SERVICE_DISPLAY);
            if dn.matches {
                note.push_str(&format!("; {}", dn.note));
            } else {
                note.push_str(&format!("; display name NOT verified — {}", dn.note));
            }
        }

        if running {
            log(&format!("    ✓ health check: {note}"));
        } else {
            log(&format!(
                "    ! health check FAILED: {note} — re-run elevated so the service registers and starts."
            ));
        }
        result.health_checked = true;
        result.health_ok = running;
        result.health_note = note;
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

/// Uninstall the dig-node OS service, remove the `dig.local` hosts entry, and
/// remove the app-scoped firewall rule (#424) this installer added (task
/// #140) — the counterpart to [`register_dig_node`]. A standalone action
/// (mirrors `--uninstall-dig-dns` / [`dns::uninstall`]): it locates the
/// dig-node binary a prior `--with-dig-node` install placed at `bin_dir` (by
/// the same [`Target::exe_name`] convention `register_dig_node` uses) and runs
/// its own `uninstall` subcommand, then removes the hosts entry, then removes
/// the firewall rule (idempotent — a declined/absent rule is a clean no-op).
/// Never touches the digstore/browser/relay/dig-dns installs. Never
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
                firewall_rule_removed: false,
                note,
            };
        }
    };
    let bin = bin_dir.join(target.exe_name("dig-node"));

    if dry_run {
        let note = format!(
            "would run `{} uninstall`, remove the dig.local hosts entry, and remove the firewall rule (if present)",
            bin.display()
        );
        log(&format!("({note})"));
        return ServiceUninstallResult {
            uninstalled: false,
            dig_local_removed: false,
            firewall_rule_removed: false,
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

    log("Removing the dig-node firewall rule (#424):");
    let firewall_result = firewall::close(&bin, false);
    log(&format!(
        "    {} {}",
        if firewall_result.applied { "✓" } else { "·" },
        firewall_result.note
    ));
    notes.push(firewall_result.note.clone());

    ServiceUninstallResult {
        uninstalled,
        dig_local_removed,
        firewall_rule_removed: firewall_result.applied,
        note: notes.join("; "),
    }
}

/// Remove the DIG auto-update beacon's daily scheduler registration (issue
/// #514) — the counterpart to the beacon-install step in [`run_report_gated`].
/// A standalone action (mirrors [`uninstall_dig_node`] / [`dns::uninstall`]):
/// locates the `dig-updater` binary a prior `--auto-update` run placed at
/// `bin_dir` (the same [`Target::exe_name`] convention every tracked component
/// uses) and delegates to its own `schedule uninstall` verb. Never touches the
/// digstore/dig-node/dig-dns/relay/browser installs, and never deletes the
/// downloaded binaries themselves — only the scheduler registration. Never
/// returns an error — a missing binary or elevation issue is recorded in the
/// result's `note`, mirroring every other uninstall action in this crate.
pub fn uninstall_beacon(
    bin_dir: &std::path::Path,
    dry_run: bool,
    log: &mut dyn FnMut(&str),
) -> beacon::BeaconResult {
    let target = match Target::current() {
        Ok(t) => t,
        Err(e) => {
            let note = format!("could not detect the current OS/arch target: {e}");
            log(&format!("! {note}"));
            return beacon::BeaconResult {
                applied: false,
                note,
            };
        }
    };
    let bin = bin_dir.join(target.exe_name("dig-updater"));

    log("Removing the DIG auto-update beacon's daily scheduler:");
    let result = beacon::unregister(&bin, dry_run);
    log(&format!(
        "    {} {}",
        if result.applied { "✓" } else { "·" },
        result.note
    ));
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

/// The structured envelope emitted to stdout under `--json` for
/// `--uninstall-dig-updater`: `{"ok":true,"result":<beacon::BeaconResult>}`
/// (mirrors [`service_uninstall_json`]; [`uninstall_beacon`] never returns an
/// `Err` — a failure is recorded in the result's `note`, not raised).
pub fn beacon_uninstall_json(result: &beacon::BeaconResult) -> String {
    let envelope = serde_json::json!({ "ok": true, "result": result });
    serde_json::to_string(&envelope).expect("beacon uninstall envelope serializes")
}

/// Force-install the DIG extension into the given `selected` browsers (by slug
/// id) for the tracked `channel` — the standalone entry point the GUI install
/// pipeline and the `--set-ext-forcelist-channel` CLI verb call, and the write
/// half of #612.
///
/// Resolves each selected browser to its per-OS managed-policy location for THIS
/// host ([`browsers::policy_targets_for`]), then MERGES our single
/// `ExtensionInstallForcelist` entry beside any pre-existing org forcelist
/// ([`forcelist::apply`]). Marker-owned + idempotent. This writes to admin-only
/// policy locations, so callers MUST run it only in the already-elevated
/// context (#565) — it neither elevates nor reads any user-writable input.
pub fn configure_extension_forcelist(
    selected: &[String],
    channel: forcelist::Channel,
) -> Vec<forcelist::ForcelistOutcome> {
    let os = Target::current().map(|t| t.os).unwrap_or(target::Os::Linux);
    forcelist::apply(&browsers::policy_targets_for(os, selected), channel)
}

/// Remove ONLY the DIG extension's `ExtensionInstallForcelist` entry from the
/// given `selected` browsers — the `--uninstall-ext-forcelist` verb + the
/// force-install part of the full uninstall (#568). Leaves any pre-existing org
/// forcelist untouched; idempotent + zero-residue.
pub fn unconfigure_extension_forcelist(selected: &[String]) -> Vec<forcelist::ForcelistOutcome> {
    let os = Target::current().map(|t| t.os).unwrap_or(target::Os::Linux);
    forcelist::remove(&browsers::policy_targets_for(os, selected))
}

/// Switch the given `selected` browsers to `channel` as a clean per-browser
/// reinstall ([`forcelist::reinstall`]) — remove then re-add, because a
/// nightly build numerically outranks the matching stable and Chromium will not
/// auto-downgrade across the channel boundary. The transition primitive the
/// beacon-follow job (#613) drives; same elevated-context requirement as
/// [`configure_extension_forcelist`].
pub fn switch_extension_forcelist_channel(
    selected: &[String],
    channel: forcelist::Channel,
) -> Vec<forcelist::ForcelistOutcome> {
    let os = Target::current().map(|t| t.os).unwrap_or(target::Os::Linux);
    forcelist::reinstall(&browsers::policy_targets_for(os, selected), channel)
}

/// The `--json` envelope for the forcelist verbs (`--set-ext-forcelist-channel`
/// / `--uninstall-ext-forcelist`): `{"ok":true,"result":[<ForcelistOutcome>…]}`.
/// `ok:false` only when a per-browser write reported [`forcelist::ForcelistAction::Failed`].
pub fn forcelist_json(outcomes: &[forcelist::ForcelistOutcome]) -> String {
    let ok = !outcomes
        .iter()
        .any(|o| o.action == forcelist::ForcelistAction::Failed);
    let envelope = serde_json::json!({ "ok": ok, "result": outcomes });
    serde_json::to_string(&envelope).expect("forcelist envelope serializes")
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
        "description": "Universal DIG installer: by default installs the full DIG stack (the \
    digstore CLI + the dig-node boot-start service + the dig-dns boot-start service) in one run, \
    resolving + downloading the latest per-OS/arch release asset for each. dig-relay and the DIG \
    Browser are opt-in.",
        "components": [
            { "id": "digstore", "repo": "DIG-Network/digstore", "default": true, "flag": "--no-digstore disables", "kind": "raw_binary" },
            { "id": "digs", "repo": "DIG-Network/digstore", "default": true, "flag": "alias of digstore — no separate flag; follows --no-digstore/--with-digstore/--digstore-version", "kind": "raw_binary_alias" },
            { "id": "dig-node", "repo": "DIG-Network/dig-node", "default": true, "flag": "--no-dig-node disables; --with-dig-node/--service redundant", "kind": "raw_binary+boot-start-service+dig.local+health-check" },
            { "id": "dign", "repo": "DIG-Network/dig-node", "default": true, "flag": "alias of dig-node — no separate flag; follows --no-dig-node/--with-dig-node/--dig-node-version", "kind": "raw_binary_alias" },
            { "id": "dig-relay", "repo": "DIG-Network/dig-relay", "default": false, "flag": "--with-relay", "kind": "raw_binary+service" },
            { "id": "dig-dns", "repo": "DIG-Network/dig-dns", "default": true, "flag": "--no-dig-dns disables; --with-dig-dns redundant", "kind": "raw_binary+boot-start-service+split-dns+browser-policy" },
            { "id": "digd", "repo": "DIG-Network/dig-dns", "default": true, "flag": "alias of dig-dns — no separate flag; follows --no-dig-dns/--with-dig-dns/--dig-dns-version", "kind": "raw_binary_alias" },
            { "id": "dig-updater", "repo": "DIG-Network/dig-updater", "default": true, "flag": "--no-auto-update disables; --auto-update redundant", "kind": "raw_binary+daily-scheduler" },
            { "id": "dig-updater-worker", "repo": "DIG-Network/dig-updater", "default": true, "flag": "alias of dig-updater — no separate flag; follows --auto-update/--no-auto-update/--dig-updater-version", "kind": "raw_binary_alias" },
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
            { "flag": "--no-digstore", "description": "opt out of the digstore CLI (installed by default)" },
            { "flag": "--with-digstore", "description": "explicit (redundant) opt-in — digstore installs by default" },
            { "flag": "--digstore-version", "value": "VERSION", "description": "pin digstore version (default: latest)" },
            { "flag": "--no-dig-node", "description": "opt out of the dig-node local node + service (installed by default)" },
            { "flag": "--with-dig-node", "alias": "--service", "description": "explicit (redundant) opt-in — dig-node installs + starts as a boot-start service by default" },
            { "flag": "--dig-node-version", "value": "VERSION", "description": "pin dig-node version (default: latest)" },
            { "flag": "--dig-node-port", "value": "PORT", "default": dig_constants::DIG_NODE_PORT, "description": "loopback port for the dig-node service" },
            { "flag": "--no-service-start", "description": "install the service(s) but do not start them (still registered boot-start)" },
            { "flag": "--uninstall-dig-node", "description": "uninstall the dig-node OS service + remove the dig.local hosts entry + remove the firewall rule this installer created (idempotent; does not touch the digstore/browser/relay/dig-dns installs)" },
            { "flag": "--with-browser", "description": "download the DIG Browser native installer (opt-in)" },
            { "flag": "--browser-version", "value": "VERSION", "description": "pin DIG Browser version (default: latest)" },
            { "flag": "--with-relay", "description": "install + start dig-relay as a service (run-your-own-relay; advanced, opt-in — the default node uses relay.dig.net)" },
            { "flag": "--relay-version", "value": "VERSION", "description": "pin dig-relay version (default: latest)" },
            { "flag": "--relay-port", "value": "PORT", "default": 9450, "description": "relay WebSocket port for the relay service" },
            { "flag": "--relay-health-port", "value": "PORT", "default": 9451, "description": "relay HTTP /health port for the relay service" },
            { "flag": "--no-dig-dns", "description": "opt out of dig-dns + its service (installed by default)" },
            { "flag": "--with-dig-dns", "description": "explicit (redundant) opt-in — dig-dns installs + registers as a boot-start OS service by default (local *.dig name resolution: DNS responder + HTTP gateway)" },
            { "flag": "--dig-dns-version", "value": "VERSION", "description": "pin dig-dns version (default: latest)" },
            { "flag": "--dig-dns-node", "value": "URL", "description": "dig-node endpoint dig-dns's gateway should use (forwarded as `dig-dns serve --node`); default: dig-dns's own ladder" },
            { "flag": "--uninstall-dig-dns", "description": "uninstall the dig-dns OS service + OS wiring this installer created (idempotent, zero residue; does not touch pre-existing org policy)" },
            { "flag": "--no-register-scheme", "description": "opt out of registering the chia:// (+ best-effort urn:) OS URL-scheme handler (registered by default; #389)" },
            { "flag": "--register-scheme", "description": "explicit (redundant) opt-in — the chia:// URL-scheme handler is registered by default" },
            { "flag": "--unregister-scheme", "description": "unregister the chia:// / urn: URL-scheme handler this installer created (idempotent); runs standalone, ignores every other flag" },
            { "flag": "--detect-browsers", "description": "list the installed Chromium-family browsers + their per-OS managed-extension-policy locations (read-only, #609); runs standalone, ignores every other flag; pair with --json for a machine result" },
            { "flag": "--set-ext-forcelist-channel", "description": "force-install the DIG extension into every detected Chromium browser via its ExtensionInstallForcelist managed policy for CHANNEL (stable|nightly, default stable); a channel change writes the per-browser remove->re-add primitive in one pass (staging the uninstall across a policy-refresh cycle to actually cross a nightly->stable downgrade is #613's job); merges beside any org forcelist; requires elevation; runs standalone; pair with --json (#612)" },
            { "flag": "--uninstall-ext-forcelist", "description": "remove ONLY the DIG extension's ExtensionInstallForcelist entry from every detected Chromium browser (idempotent, zero residue; never touches a pre-existing org forcelist); requires elevation; runs standalone (#612)" },
            { "flag": "--no-open-firewall", "description": "opt out of opening the app-scoped inbound firewall rule for dig-node's peer-RPC port (opened by default when dig-node is installed; #424)" },
            { "flag": "--open-firewall", "description": "explicit (redundant) opt-in — the firewall rule is opened by default" },
            { "flag": "--no-auto-update", "description": "opt out of installing + registering the DIG auto-update beacon (installed by default; #514)" },
            { "flag": "--auto-update", "description": "explicit (redundant) opt-in — the auto-update beacon is installed by default" },
            { "flag": "--dig-updater-version", "value": "VERSION", "description": "pin the auto-update beacon's version (default: latest)" },
            { "flag": "--uninstall-dig-updater", "description": "remove the auto-update beacon's daily scheduler registration this installer created (idempotent; does not remove the downloaded binaries or touch the digstore/browser/relay/dig-node/dig-dns installs)" },
            { "flag": "--force-reinstall", "description": "reinstall digstore/dig-node/dig-dns/dig-updater even if `update_policy` would otherwise skip them as already up to date (#309)" }
        ],
        "update_policy": {
            "description": "Every run detects what's already installed for digstore/dig-node/dig-dns/dig-updater (`<bin> --version`), compares it to the release just resolved, and decides per component: absent -> install, an older or unreadable installed version -> update (replace it, reusing the §2 stop/replace/restart lifecycle for the service components), already current (or newer than the latest release) -> skip. A bare re-run is therefore idempotent: it updates only what's outdated and leaves the rest untouched. `--force-reinstall` overrides a skip decision back to update.",
            "components": ["digstore", "dig-node", "dig-dns", "dig-updater"],
            "actions": ["install", "update", "skip"],
            "force_flag": "--force-reinstall"
        },
        "url_scheme_handler": {
            "schemes": ["chia", "urn"],
            "default": true,
            "opt_out": "--no-register-scheme",
            "per_user": true,
            "description": "By default the installer registers itself as the OS handler for chia:// (and best-effort urn:) links: a clicked link is resolved through the local dig-node (the dig.local → localhost → rpc.dig.net ladder) and opened in the browser. Per-user, no elevation. The OS invokes `dig-installer handle-url <uri>` (a hidden subcommand, not part of the public flag surface)."
        },
        "firewall": {
            "port": firewall::DEFAULT_PEER_PORT,
            "port_override_env": firewall::ENV_PEER_PORT,
            "default": true,
            "opt_out": "--no-open-firewall",
            "scope": "the installed dig-node executable only (program-scoped, never a blanket port-open)",
            "families": ["ipv4", "ipv6"],
            "linux": "never auto-applied; prints the manual `ufw allow <port>/tcp` remedy instead",
            "description": "By default the installer opens an inbound firewall rule scoped to the dig-node executable on its mTLS peer-RPC port (dig-node's only non-loopback listener), covering both IPv4 and IPv6. Removed automatically on `--uninstall-dig-node`. Declining it is always safe — dig-relay fallback still reaches the node."
        },
        "auto_update_beacon": {
            "default": true,
            "opt_out": "--no-auto-update",
            "uninstall_flag": "--uninstall-dig-updater",
            "repo": "DIG-Network/dig-updater",
            "description": "By default the installer installs the dig-updater beacon (+ its dig-updater-worker sibling, published in the same release) and asks it to register its own daily OS-scheduled task/systemd-timer/LaunchDaemon (dig-updater's own `schedule install` verb), which checks for new signed DIG releases and installs them automatically. Declining is always safe — nothing auto-updates; re-run the installer manually to get new versions. `--uninstall-dig-updater` removes the scheduler registration (idempotent; leaves the downloaded binaries in place)."
        },
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
            // `digs` (issue #434) is published in the SAME digstore release,
            // under its own stem — see digstore's release.yml.
            "digs-0.6.0-windows-x64.exe",
            "digs-0.6.0-linux-x64",
            "digs-0.6.0-macos-arm64",
            "digs-0.6.0-macos-x64",
        ];
        let node: Vec<&'static str> = vec![
            "dig-node-0.2.0-windows-x64.exe",
            "dig-node-0.2.0-linux-x64",
            "dig-node-0.2.0-macos-arm64",
            "dig-node-0.2.0-macos-x64",
            // `dign` (issue #548) is published in the SAME dig-node release,
            // under its own stem — see dig-node's release.yml.
            "dign-0.2.0-windows-x64.exe",
            "dign-0.2.0-linux-x64",
            "dign-0.2.0-macos-arm64",
            "dign-0.2.0-macos-x64",
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
            // `digd` (issue #548) is published in the SAME dig-dns release,
            // under its own stem — see dig-dns's release.yml.
            "digd-0.6.0-windows-x64.exe",
            "digd-0.6.0-linux-x64",
            "digd-0.6.0-macos-arm64",
            "digd-0.6.0-macos-x64",
        ];
        // The beacon (#514) and its dig-updater-worker sibling publish from the
        // SAME repo (`dig-updater`), so — exactly like digstore/digs above —
        // both asset stems live under ONE map entry keyed by the repo name.
        let updater: Vec<&'static str> = vec![
            "dig-updater-0.6.0-windows-x64.exe",
            "dig-updater-0.6.0-linux-x64",
            "dig-updater-0.6.0-macos-arm64",
            "dig-updater-0.6.0-macos-x64",
            "dig-updater-worker-0.6.0-windows-x64.exe",
            "dig-updater-worker-0.6.0-linux-x64",
            "dig-updater-worker-0.6.0-macos-arm64",
            "dig-updater-worker-0.6.0-macos-x64",
        ];
        let mut m = HashMap::new();
        m.insert("digstore", ("v0.6.0", digstore));
        m.insert("dig-node", ("v0.2.0", node));
        m.insert("dig-relay", ("v0.1.0", relay));
        m.insert("DIG_Browser", ("v1.0.0", browser));
        m.insert("dig-dns", ("v0.6.0", dns));
        m.insert("dig-updater", ("v0.6.0", updater));
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
            register_scheme: false,
            open_firewall: false,
            auto_update: false,
            dig_updater_version: None,
            force_reinstall: false,
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

    /// #301 (universal installer): a bare install with no opt-out flags installs
    /// the FULL DIG stack — the digstore CLI, the dig-node service, the
    /// dig-dns service, AND the auto-update beacon (#514) — in one run.
    /// `InstallPlan::default()` is the single source of truth for that
    /// default; `main.rs` maps the `--no-<component>` opt-outs onto it.
    /// dig-relay (advanced) and the DIG Browser stay opt-in.
    #[test]
    fn default_plan_installs_the_full_dig_stack() {
        let plan = InstallPlan::default();
        assert!(plan.with_digstore, "digstore is installed by default");
        assert!(
            plan.with_dig_node,
            "dig-node is installed by default (#301 universal installer)"
        );
        assert!(
            plan.with_dig_dns,
            "dig-dns is installed by default (#301 universal installer)"
        );
        assert!(
            plan.auto_update,
            "the auto-update beacon is installed by default (#514)"
        );
        assert!(!plan.with_relay, "dig-relay stays opt-in (advanced)");
        assert!(!plan.with_browser, "DIG Browser stays a separate opt-in");
        assert!(plan.modify_path, "the bin dir is added to PATH by default");
    }

    /// #301/#514: driving the DEFAULT plan through the orchestration resolves
    /// the core stack (digstore + dig-node + dig-dns) AND the auto-update
    /// beacon (+ its dig-updater-worker sibling), and neither of the opt-in
    /// components (dig-relay / browser) — proving the default is a genuine
    /// one-shot install end to end, not just struct flags.
    #[test]
    fn default_plan_resolves_all_three_core_components() {
        let plan = InstallPlan {
            bin_dir: std::env::temp_dir().join("dig-installer-test-default"),
            modify_path: false,
            dry_run: true,
            ..InstallPlan::default()
        };
        let report = run_dry(&plan, all_releases()).expect("default plan resolves");
        let names: Vec<&str> = report
            .components
            .iter()
            .map(|c| c.component.as_str())
            .collect();
        assert!(names.contains(&"digstore"), "digstore in default plan");
        assert!(names.contains(&"dig-node"), "dig-node in default plan");
        assert!(names.contains(&"dig-dns"), "dig-dns in default plan");
        assert!(
            names.contains(&"dig-updater"),
            "the auto-update beacon is in the default plan (#514)"
        );
        assert!(
            names.contains(&"dig-updater-worker"),
            "the beacon's worker sibling is in the default plan (#514)"
        );
        assert!(
            !names.contains(&"dig-relay"),
            "dig-relay is opt-in, not in the default plan"
        );
        assert!(
            !names.contains(&"DIG-Browser"),
            "DIG Browser is opt-in, not in the default plan"
        );
    }

    /// #301: `--help-json` must advertise dig-node AND dig-dns as `default: true`
    /// (alongside digstore) so an agent reads the universal-installer default off
    /// the machine contract. dig-relay + browser remain `default: false`.
    #[test]
    fn help_json_advertises_the_full_stack_as_default() {
        let doc: serde_json::Value =
            serde_json::from_str(&help_json()).expect("help_json is valid JSON");
        let by_id = |id: &str| -> bool {
            doc["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["id"] == id)
                .unwrap_or_else(|| panic!("component {id} present"))["default"]
                .as_bool()
                .unwrap()
        };
        assert!(by_id("digstore"), "digstore default: true");
        assert!(by_id("dig-node"), "dig-node default: true (#301)");
        assert!(by_id("dig-dns"), "dig-dns default: true (#301)");
        assert!(by_id("dig-updater"), "dig-updater default: true (#514)");
        assert!(
            by_id("dig-updater-worker"),
            "dig-updater-worker default: true (#514)"
        );
        assert!(!by_id("dig-relay"), "dig-relay stays opt-in");
        assert!(!by_id("browser"), "browser stays opt-in");
    }

    #[test]
    fn help_json_advertises_the_auto_update_beacon_and_opt_out() {
        // #514: mirrors help_json_advertises_the_scheme_handler_and_opt_out /
        // ..._the_firewall_rule_and_opt_out below — the machine contract MUST
        // advertise the beacon's default-on toggle + the CLI opt-out/uninstall
        // flags so an agent discovers them without scraping `--help`.
        let doc: serde_json::Value =
            serde_json::from_str(&help_json()).expect("help_json is valid JSON");
        let flag_present = |f: &str| -> bool {
            doc["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x["flag"] == f)
        };
        assert!(flag_present("--no-auto-update"), "opt-out advertised");
        assert!(flag_present("--auto-update"), "explicit opt-in advertised");
        assert!(
            flag_present("--dig-updater-version"),
            "version pin advertised"
        );
        assert!(
            flag_present("--uninstall-dig-updater"),
            "uninstall advertised"
        );
        let b = &doc["auto_update_beacon"];
        assert_eq!(b["default"], true, "the beacon is installed by default");
        assert_eq!(b["opt_out"], "--no-auto-update");
        assert_eq!(b["uninstall_flag"], "--uninstall-dig-updater");
        assert_eq!(b["repo"], "DIG-Network/dig-updater");
    }

    #[test]
    fn help_json_advertises_the_scheme_handler_and_opt_out() {
        // #389: the chia:// URL-scheme handler is a default-on, toggleable
        // option — the machine contract MUST advertise it + the CLI opt-out so
        // an agent can discover both without scraping `--help`.
        let doc: serde_json::Value =
            serde_json::from_str(&help_json()).expect("help_json is valid JSON");
        let flag_present = |f: &str| -> bool {
            doc["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x["flag"] == f)
        };
        assert!(flag_present("--no-register-scheme"), "opt-out advertised");
        assert!(
            flag_present("--register-scheme"),
            "explicit opt-in advertised"
        );
        assert!(flag_present("--unregister-scheme"), "unregister advertised");
        let h = &doc["url_scheme_handler"];
        assert_eq!(h["default"], true, "the handler is registered by default");
        assert_eq!(h["opt_out"], "--no-register-scheme");
        let schemes = h["schemes"].as_array().unwrap();
        assert!(
            schemes.iter().any(|s| s == "chia"),
            "chia scheme documented"
        );
    }

    #[test]
    fn help_json_advertises_the_firewall_rule_and_opt_out() {
        // #424: the app-scoped firewall rule is a default-on, toggleable
        // option — the machine contract MUST advertise it + the CLI opt-out,
        // same convention as the scheme handler above.
        let doc: serde_json::Value =
            serde_json::from_str(&help_json()).expect("help_json is valid JSON");
        let flag_present = |f: &str| -> bool {
            doc["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x["flag"] == f)
        };
        assert!(flag_present("--no-open-firewall"), "opt-out advertised");
        assert!(
            flag_present("--open-firewall"),
            "explicit opt-in advertised"
        );
        let f = &doc["firewall"];
        assert_eq!(f["default"], true, "the rule is opened by default");
        assert_eq!(f["opt_out"], "--no-open-firewall");
        assert_eq!(f["port"], firewall::DEFAULT_PEER_PORT);
        let families = f["families"].as_array().unwrap();
        assert!(families.iter().any(|x| x == "ipv4"));
        assert!(families.iter().any(|x| x == "ipv6"));
    }

    #[test]
    fn help_json_dig_node_port_default_matches_dig_constants() {
        // Both the CLI flag doc + the actual runtime default (`ServiceConfig`)
        // must be sourced from the SAME constant so they can never drift.
        let doc: serde_json::Value =
            serde_json::from_str(&help_json()).expect("help_json is valid JSON");
        let port_flag = doc["flags"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["flag"] == "--dig-node-port")
            .expect("--dig-node-port documented");
        assert_eq!(port_flag["default"], dig_constants::DIG_NODE_PORT);
        assert_eq!(ServiceConfig::default().port, dig_constants::DIG_NODE_PORT);
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
        assert!(report.firewall.is_none());
        assert!(report.installed.is_empty());
    }

    #[test]
    fn digstore_only_resolves_the_cli_component() {
        // With no other component selected, digstore resolves alongside its
        // `digs` alias (issue #434 — see digs_alias_installs_alongside_digstore_
        // from_the_same_release for the digs-specific assertions).
        let mut plan = base_plan();
        plan.with_digstore = true;
        let report = run_dry(&plan, all_releases()).expect("digstore resolves");
        assert_eq!(report.components.len(), 2);
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
    fn digs_alias_installs_alongside_digstore_from_the_same_release() {
        // Issue #434: `digs` is a first-class alias binary published in the SAME
        // digstore release (digstore#16), under its own asset stem. Selecting
        // digstore must resolve + place BOTH binaries, sharing the bin dir (so
        // no separate PATH entry is needed) and the digstore version pin.
        let mut plan = base_plan();
        plan.with_digstore = true;
        let report = run_dry(&plan, all_releases()).expect("digstore + digs resolve");
        let ids: Vec<&str> = report
            .components
            .iter()
            .map(|c| c.component.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["digstore", "digs"],
            "digs installs right after digstore"
        );

        let digstore = &report.components[0];
        let digs = report
            .components
            .iter()
            .find(|c| c.component == "digs")
            .expect("digs component present");
        assert_eq!(digs.version, "0.6.0");
        assert_eq!(digs.tag, "v0.6.0");
        assert!(digs.asset.starts_with("digs-0.6.0-"));
        assert!(digs
            .url
            .contains("github.com/DIG-Network/digstore/releases/download/v0.6.0/"));

        // Same bin dir as digstore — no separate PATH entry is needed.
        let digstore_dir = std::path::Path::new(&digstore.dest).parent().unwrap();
        let digs_dir = std::path::Path::new(&digs.dest).parent().unwrap();
        assert_eq!(digstore_dir, digs_dir);
        assert_ne!(
            digstore.dest, digs.dest,
            "digstore and digs are distinct files"
        );
        // dry-run installs nothing on disk.
        assert!(report.installed.is_empty());
    }

    #[test]
    fn digs_alias_honors_the_pinned_digstore_version() {
        // A pinned --digstore-version threads through to the digs resolution
        // too, since digs is published in the same digstore release.
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.digstore_version = Some("0.6.0".to_string());
        let report = run_dry(&plan, all_releases()).expect("pinned resolves");
        let digs = report
            .components
            .iter()
            .find(|c| c.component == "digs")
            .expect("digs component present");
        assert_eq!(digs.tag, "v0.6.0");
    }

    #[test]
    fn digs_is_not_installed_when_digstore_is_opted_out() {
        // digs has no separate flag: opting out of digstore opts out of digs too.
        let plan = base_plan(); // with_digstore defaults false in base_plan()
        let report = run_dry(&plan, all_releases()).expect("empty plan ok");
        assert!(!report.components.iter().any(|c| c.component == "digs"));
    }

    #[test]
    fn dign_alias_installs_alongside_dig_node_from_the_same_release() {
        // Issue #548: `dign` is a first-class alias binary published in the SAME
        // dig-node release, under its own asset stem. Selecting dig-node must
        // resolve + place BOTH binaries, sharing the bin dir (so no separate
        // PATH entry is needed) and the dig-node version pin.
        let mut plan = base_plan();
        plan.with_dig_node = true;
        let report = run_dry(&plan, all_releases()).expect("dig-node + dign resolve");
        let ids: Vec<&str> = report
            .components
            .iter()
            .map(|c| c.component.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["dig-node", "dign"],
            "dign installs right after dig-node"
        );

        let dig_node = &report.components[0];
        let dign = report
            .components
            .iter()
            .find(|c| c.component == "dign")
            .expect("dign component present");
        assert_eq!(dign.version, "0.2.0");
        assert_eq!(dign.tag, "v0.2.0");
        assert!(dign.asset.starts_with("dign-0.2.0-"));
        assert!(dign
            .url
            .contains("github.com/DIG-Network/dig-node/releases/download/v0.2.0/"));

        // Same bin dir as dig-node — no separate PATH entry is needed.
        let dig_node_dir = std::path::Path::new(&dig_node.dest).parent().unwrap();
        let dign_dir = std::path::Path::new(&dign.dest).parent().unwrap();
        assert_eq!(dig_node_dir, dign_dir);
        assert_ne!(
            dig_node.dest, dign.dest,
            "dig-node and dign are distinct files"
        );
        // dry-run installs nothing on disk.
        assert!(report.installed.is_empty());
    }

    #[test]
    fn dign_alias_honors_the_pinned_dig_node_version() {
        // A pinned --dig-node-version threads through to the dign resolution
        // too, since dign is published in the same dig-node release.
        let mut plan = base_plan();
        plan.with_dig_node = true;
        plan.dig_node_version = Some("0.2.0".to_string());
        let report = run_dry(&plan, all_releases()).expect("pinned resolves");
        let dign = report
            .components
            .iter()
            .find(|c| c.component == "dign")
            .expect("dign component present");
        assert_eq!(dign.tag, "v0.2.0");
    }

    #[test]
    fn dign_is_not_installed_when_dig_node_is_opted_out() {
        // dign has no separate flag: opting out of dig-node opts out of dign too.
        let plan = base_plan(); // with_dig_node defaults false in base_plan()
        let report = run_dry(&plan, all_releases()).expect("empty plan ok");
        assert!(!report.components.iter().any(|c| c.component == "dign"));
    }

    #[test]
    fn digd_alias_installs_alongside_dig_dns_from_the_same_release() {
        // Issue #548: `digd` is a first-class alias binary published in the SAME
        // dig-dns release, under its own asset stem. Selecting dig-dns must
        // resolve + place BOTH binaries, sharing the bin dir (so no separate
        // PATH entry is needed) and the dig-dns version pin.
        let mut plan = base_plan();
        plan.with_dig_dns = true;
        let report = run_dry(&plan, all_releases()).expect("dig-dns + digd resolve");
        let ids: Vec<&str> = report
            .components
            .iter()
            .map(|c| c.component.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["dig-dns", "digd"],
            "digd installs right after dig-dns"
        );

        let dig_dns = &report.components[0];
        let digd = report
            .components
            .iter()
            .find(|c| c.component == "digd")
            .expect("digd component present");
        assert_eq!(digd.version, "0.6.0");
        assert_eq!(digd.tag, "v0.6.0");
        assert!(digd.asset.starts_with("digd-0.6.0-"));
        assert!(digd
            .url
            .contains("github.com/DIG-Network/dig-dns/releases/download/v0.6.0/"));

        // Same bin dir as dig-dns — no separate PATH entry is needed.
        let dig_dns_dir = std::path::Path::new(&dig_dns.dest).parent().unwrap();
        let digd_dir = std::path::Path::new(&digd.dest).parent().unwrap();
        assert_eq!(dig_dns_dir, digd_dir);
        assert_ne!(
            dig_dns.dest, digd.dest,
            "dig-dns and digd are distinct files"
        );
        // dry-run installs nothing on disk.
        assert!(report.installed.is_empty());
    }

    #[test]
    fn digd_alias_honors_the_pinned_dig_dns_version() {
        // A pinned --dig-dns-version threads through to the digd resolution
        // too, since digd is published in the same dig-dns release.
        let mut plan = base_plan();
        plan.with_dig_dns = true;
        plan.dig_dns_version = Some("0.6.0".to_string());
        let report = run_dry(&plan, all_releases()).expect("pinned resolves");
        let digd = report
            .components
            .iter()
            .find(|c| c.component == "digd")
            .expect("digd component present");
        assert_eq!(digd.tag, "v0.6.0");
    }

    #[test]
    fn digd_is_not_installed_when_dig_dns_is_opted_out() {
        // digd has no separate flag: opting out of dig-dns opts out of digd too.
        let plan = base_plan(); // with_dig_dns defaults false in base_plan()
        let report = run_dry(&plan, all_releases()).expect("empty plan ok");
        assert!(!report.components.iter().any(|c| c.component == "digd"));
    }

    #[test]
    fn digd_is_gated_alongside_dig_dns_availability() {
        // #234's graceful-skip when dig-dns has no published release must also
        // skip digd — it is only reached inside the Ok(mut c) arm after dig-dns
        // itself resolves.
        let mut plan = base_plan();
        plan.with_dig_dns = true;
        let report = run_dry(&plan, HashMap::new()).expect("gated, not an error");
        assert!(!report.components.iter().any(|c| c.component == "dig-dns"));
        assert!(!report.components.iter().any(|c| c.component == "digd"));
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
    fn dig_node_dry_run_reports_the_firewall_rule_intent_when_enabled() {
        // #424: the firewall rule is opened alongside the dig-node service by
        // default; a dry-run must record the intent without touching the OS.
        let mut plan = base_plan();
        plan.with_dig_node = true;
        plan.open_firewall = true;
        let report = run_dry(&plan, all_releases()).expect("dig-node resolves");
        let firewall = report.firewall.expect("firewall result present");
        assert!(!firewall.applied, "dry-run never touches the OS");
        assert!(
            firewall.note.contains("would open"),
            "got: {}",
            firewall.note
        );
    }

    #[test]
    fn dig_node_dry_run_skips_the_firewall_rule_when_declined() {
        // `--no-open-firewall` must leave `report.firewall` entirely absent —
        // not merely a `applied: false` result — so a caller can tell
        // "declined" apart from "attempted and failed".
        let mut plan = base_plan();
        plan.with_dig_node = true;
        plan.open_firewall = false;
        let report = run_dry(&plan, all_releases()).expect("dig-node resolves");
        assert!(report.firewall.is_none());
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
        // dign (issue #548) postdates the pre-rename dig-companion era, so the
        // modern `dig-node` repo having no release at all (forcing this legacy
        // fallback) also means dign is unresolvable — gated gracefully rather
        // than sinking this otherwise-successful install (see
        // `dign_is_gated_gracefully_when_the_release_has_no_dign_asset`).
        assert!(!report.components.iter().any(|c| c.component == "dign"));
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
    fn dig_dns_missing_release_gates_gracefully_and_the_rest_of_the_plan_continues() {
        // dig-dns is EPIC #174 and may ship no release yet (task #234). Selecting
        // it must NOT abort the whole install: components resolved before AND
        // after dig-dns in plan order must still install, and the dns section
        // must record a clear "not yet available" state instead of an Err.
        let mut releases = all_releases();
        releases.remove("dig-dns");
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.with_dig_dns = true;
        plan.with_relay = true; // ordered AFTER dig-dns — proves the plan continues
        let report = run_dry(&plan, releases).expect("dig-dns gate must not fail the plan");

        // digstore (before) and dig-relay (after) both still resolved.
        let ids: Vec<&str> = report
            .components
            .iter()
            .map(|c| c.component.as_str())
            .collect();
        assert!(ids.contains(&"digstore"));
        assert!(ids.contains(&"dig-relay"));
        assert!(
            !ids.contains(&"dig-dns"),
            "dig-dns never resolved, so it must not appear as a component"
        );
        assert!(
            report.relay.is_some(),
            "the plan must continue past the dig-dns gate"
        );

        // The dns section records a clear, non-fatal "not yet available" state.
        let dns = report
            .dns
            .expect("dns section present even though unresolvable");
        assert!(!dns.installed);
        assert!(!dns.started);
        assert!(!dns.needs_elevation);
        assert!(dns.note.contains("not yet available"), "got: {}", dns.note);
        assert!(dns.doctor.is_none());
        assert!(dns.paths_live.is_empty());
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
        // digstore + digs + dig-node + dign + dig-dns + digd + relay + browser,
        // PATH on. All eight components resolve, plus path/service/dns/relay
        // sections.
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
                "digs",
                "dig-node",
                "dign",
                "dig-dns",
                "digd",
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
            "ready",
            "failures",
        ] {
            assert!(v.get(key).is_some(), "report JSON missing key {key}");
        }
        // A dry-run installs nothing, so it is trivially "ready" with no failures.
        assert_eq!(v["ready"], true);
        assert!(v["failures"].as_array().unwrap().is_empty());
        let c = &v["components"][0];
        for key in [
            "component",
            "version",
            "tag",
            "asset",
            "url",
            "dest",
            "update_action",
            "previous_version",
        ] {
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
        assert_eq!(report.components.len(), 2);
        assert!(lines.iter().any(|l| l.contains("DIG installer — target")));
        assert!(lines.iter().any(|l| l.contains("dry run")));
        assert!(lines
            .iter()
            .any(|l| l.contains("Installing the digstore CLI")));
        assert!(lines
            .iter()
            .any(|l| l.contains("Installing the digs alias")));
        // The final line is the readiness verdict (dry-run variant).
        assert!(lines.iter().any(|l| l.contains("Done (dry run")));
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
        for id in [
            "digstore",
            "digs",
            "dig-node",
            "dign",
            "dig-relay",
            "dig-dns",
            "digd",
            "browser",
        ] {
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
        assert!(!result.firewall_rule_removed);
        assert!(result.note.contains("would run"), "got: {}", result.note);
        assert!(result.note.contains("uninstall"), "got: {}", result.note);
        assert!(result.note.contains("dig.local"), "got: {}", result.note);
        assert!(
            result.note.contains("firewall"),
            "the dry-run note documents removing the firewall rule too: {}",
            result.note
        );
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
            firewall_rule_removed: true,
            note: "dig-node service uninstalled; removed dig.local from /etc/hosts; removed the firewall rule".to_string(),
        };
        let v: serde_json::Value = serde_json::from_str(&service_uninstall_json(&result)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["result"]["uninstalled"], true);
        assert_eq!(v["result"]["dig_local_removed"], true);
        assert_eq!(v["result"]["firewall_rule_removed"], true);
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

    #[test]
    fn forcelist_json_is_ok_when_no_write_failed() {
        let outcomes = vec![forcelist::ForcelistOutcome {
            location: r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist".to_string(),
            action: forcelist::ForcelistAction::Wrote,
            note: "added".to_string(),
        }];
        let v: serde_json::Value = serde_json::from_str(&forcelist_json(&outcomes)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["result"][0]["action"], "wrote");
    }

    #[test]
    fn forcelist_json_is_not_ok_when_any_write_failed() {
        let outcomes = vec![
            forcelist::ForcelistOutcome {
                location: "a".to_string(),
                action: forcelist::ForcelistAction::Wrote,
                note: String::new(),
            },
            forcelist::ForcelistOutcome {
                location: "b".to_string(),
                action: forcelist::ForcelistAction::Failed,
                note: "denied".to_string(),
            },
        ];
        let v: serde_json::Value = serde_json::from_str(&forcelist_json(&outcomes)).unwrap();
        assert_eq!(v["ok"], false);
    }

    // -- #492 elevation gate + #493 fail-loud readiness ----------------------

    /// A non-dry-run plan whose ONLY selected component is the dig-node service.
    /// `auto_update` is explicitly off so these dig-node-focused readiness
    /// cases stay isolated to the ONE failure they assert on — the beacon has
    /// its own dedicated readiness tests below.
    fn dig_node_service_plan() -> InstallPlan {
        InstallPlan {
            bin_dir: std::env::temp_dir().join("dig-installer-readiness-test"),
            with_digstore: false,
            with_dig_node: true,
            with_dig_dns: false,
            modify_path: false,
            auto_update: false,
            dry_run: false,
            ..InstallPlan::default()
        }
    }

    /// A report shell (non-dry-run) the readiness tests populate per case.
    fn report_shell() -> InstallReport {
        InstallReport {
            schema_version: SCHEMA_VERSION,
            installer_version: "test".to_string(),
            target: "windows-x64".to_string(),
            dry_run: false,
            components: Vec::new(),
            path: None,
            service: None,
            relay: None,
            dns: None,
            scheme: None,
            firewall: None,
            beacon: None,
            installed: Vec::new(),
            cli_path_checks: Vec::new(),
            daemon_dirs: Vec::new(),
            install_root_security: None,
            migration: None,
            registration_audit: Vec::new(),
            install_manifest: None,
            ready: true,
            failures: Vec::new(),
        }
    }

    fn running_service() -> ServiceResult {
        ServiceResult {
            installed: true,
            started: true,
            port: 9778,
            note: "installed and started".to_string(),
            dig_local: "ok".to_string(),
            dig_local_resolves: true,
            dig_local_resolve_note: "ok".to_string(),
            health_checked: true,
            health_ok: true,
            health_note: "service 'net.dignetwork.dig-node' is RUNNING".to_string(),
        }
    }

    #[test]
    fn requires_elevation_tracks_privileged_actions() {
        use target::Os;
        // A service/hosts install needs elevation; a dry-run or a digstore-only
        // run into a CUSTOM (user-chosen) bin dir does not — an explicit
        // --bin-dir is the user's own choice (base_plan uses a custom temp dir).
        assert!(dig_node_service_plan().requires_elevation(Os::Linux));
        let mut digstore_only = base_plan();
        digstore_only.with_digstore = true;
        digstore_only.dry_run = false;
        assert!(
            !digstore_only.requires_elevation(Os::Windows),
            "digstore-only into a custom --bin-dir does not force elevation"
        );
        assert!(
            !base_plan().requires_elevation(Os::Windows),
            "a dry-run never requires elevation"
        );
    }

    /// #565: a DEFAULT (no `--bin-dir` override) CLI-only install needs
    /// elevation exactly when the CLI lands in the admin-only protected root.
    /// The path helpers are HOST-based (the `os` arg drives only the
    /// privileged-component classification; in production it is always the host
    /// os), so this asserts the real host posture: on Windows the whole stack —
    /// even the CLI — installs into `%ProgramFiles%\DIG\bin` (→ elevation); on
    /// unix the CLI stays in the elevation-free per-user `~/.dig/bin` (→ none).
    #[test]
    fn cli_only_install_elevation_matches_the_protected_root_posture() {
        let host = Target::current().expect("supported host").os;
        let cli_only = InstallPlan {
            with_digstore: true,
            with_dig_node: false,
            with_dig_dns: false,
            auto_update: false,
            with_relay: false,
            dry_run: false,
            ..InstallPlan::default() // default bin_dir → NOT a custom override
        };
        assert!(
            !cli_only.has_custom_bin_dir(),
            "the default plan must not look like a --bin-dir override"
        );
        match host {
            target::Os::Windows => assert!(
                cli_only.requires_elevation(host),
                "a Windows CLI-only install writes into admin-only Program Files"
            ),
            target::Os::Linux | target::Os::MacOs => assert!(
                !cli_only.requires_elevation(host),
                "a unix CLI-only install stays in ~/.dig/bin (no elevation)"
            ),
        }
    }

    /// #565: the per-component protected-root routing. On unix the privileged
    /// service binaries route to `/opt/dig/bin`; the user CLIs stay in the user
    /// root. On Windows the whole stack shares the one Program Files root. An
    /// explicit `--bin-dir` override wins for every component.
    #[test]
    fn bin_dir_for_routes_privileged_components_to_the_protected_root() {
        use target::Os;
        let plan = InstallPlan::default(); // no override
                                           // unix: dig-dns/dig-updater/worker → protected; user CLIs → user root.
        assert_eq!(
            plan.bin_dir_for("dig-dns", Os::Linux),
            paths::protected_bin_dir()
        );
        assert_eq!(
            plan.bin_dir_for("dig-updater", Os::Linux),
            paths::protected_bin_dir()
        );
        assert_eq!(
            plan.bin_dir_for("digstore", Os::Linux),
            paths::default_bin_dir()
        );
        assert_eq!(
            plan.bin_dir_for("dign", Os::Linux),
            paths::default_bin_dir()
        );
        // Windows: every component lands in the single protected root.
        for c in ["digstore", "dig-node", "dig-dns", "dig-updater"] {
            assert_eq!(plan.bin_dir_for(c, Os::Windows), paths::protected_bin_dir());
        }
        // An explicit override wins for the WHOLE stack, on every OS.
        let overridden = InstallPlan {
            bin_dir: std::path::PathBuf::from("/custom/dig"),
            ..InstallPlan::default()
        };
        assert!(overridden.has_custom_bin_dir());
        assert_eq!(
            overridden.bin_dir_for("dig-dns", Os::Linux),
            std::path::PathBuf::from("/custom/dig")
        );
        assert_eq!(
            overridden.bin_dir_for("dig-updater", Os::Windows),
            std::path::PathBuf::from("/custom/dig")
        );
    }

    /// #565: a definitive install-root ACL breach (an unprivileged principal
    /// CAN write where a privileged service binary lives) makes the install NOT
    /// ready; an inconclusive read is only a warning, never a false failure.
    #[test]
    fn readiness_fails_on_a_definitive_install_root_write_breach() {
        let plan = InstallPlan {
            with_digstore: true,
            with_dig_node: false,
            with_dig_dns: false,
            auto_update: false,
            with_relay: false,
            dry_run: false,
            ..InstallPlan::default()
        };
        // Definitive breach → NOT ready, with a clear reason.
        let mut report = report_shell();
        report.install_root_security = Some(secure::InstallRootSecurity {
            root: r"C:\Program Files\DIG\bin".to_string(),
            checked: true,
            secure: false,
            note: "grants WRITE to an unprivileged principal (S-1-5-32-545)".to_string(),
        });
        let failures = evaluate_readiness(&plan, &report);
        assert!(
            failures.iter().any(|f| f.contains("install root")),
            "a definitive write breach must fail readiness: {failures:?}"
        );
        // Inconclusive read → NOT a failure (the admin-only location still holds).
        let mut report = report_shell();
        report.install_root_security = Some(secure::InstallRootSecurity {
            root: r"C:\Program Files\DIG\bin".to_string(),
            checked: false,
            secure: false,
            note: "could not read the ACL back".to_string(),
        });
        let failures = evaluate_readiness(&plan, &report);
        assert!(
            !failures.iter().any(|f| f.contains("install root")),
            "an inconclusive ACL read must not fail readiness: {failures:?}"
        );
    }

    /// #565 review — H1: a re-run that leaves the SYSTEM auto-update beacon task
    /// (or any privileged registration) pointing at a binary inside the
    /// user-writable legacy root is a residual local privilege escalation — a
    /// non-admin replants that path and runs as SYSTEM on the next daily fire.
    /// The post-registration audit MUST make such an install NOT ready.
    #[test]
    fn readiness_fails_when_a_privileged_registration_is_orphaned_under_the_legacy_root() {
        let plan = InstallPlan {
            with_digstore: true,
            with_dig_node: false,
            with_dig_dns: false,
            auto_update: false,
            with_relay: false,
            dry_run: false,
            ..InstallPlan::default()
        };
        let mut report = report_shell();
        report.registration_audit = vec![
            regaudit::RegistrationAudit {
                registration: "dig-updater beacon task".to_string(),
                bin_path: Some(
                    r"C:\Users\me\AppData\Local\Programs\DIG\bin\dig-updater.exe".to_string(),
                ),
                under_legacy_root: true,
                note: "beacon runs a binary under a user-writable legacy root".to_string(),
            },
            regaudit::RegistrationAudit {
                registration: "dig-node".to_string(),
                bin_path: Some(r"C:\Program Files\DIG\bin\dig-node.exe".to_string()),
                under_legacy_root: false,
                note: "dig-node runs from a protected location".to_string(),
            },
        ];
        let failures = evaluate_readiness(&plan, &report);
        assert!(
            failures.iter().any(|f| f.contains("beacon")),
            "an orphaned SYSTEM beacon task under the legacy root must fail readiness: {failures:?}"
        );
        // The already-protected dig-node registration must NOT be flagged.
        assert!(
            !failures.iter().any(|f| f.contains("dig-node")),
            "a protected registration must not fail readiness: {failures:?}"
        );
    }

    /// #565 review — H2a: a privileged registration that could NOT be
    /// deregistered off the legacy root during migration is FATAL — the installer
    /// must not silently continue into a tolerated re-install that leaves the
    /// service at the writable legacy binPath.
    #[test]
    fn readiness_fails_when_a_migration_deregister_failed() {
        let plan = InstallPlan {
            with_digstore: true,
            with_dig_node: false,
            with_dig_dns: false,
            auto_update: false,
            with_relay: false,
            dry_run: false,
            ..InstallPlan::default()
        };
        let mut report = report_shell();
        report.migration = Some(migrate::MigrationResult {
            migrated: true,
            deregister_failures: vec![
                "could not deregister dig-node off the legacy root (access denied)".to_string(),
            ],
            ..Default::default()
        });
        let failures = evaluate_readiness(&plan, &report);
        assert!(
            failures
                .iter()
                .any(|f| f.contains("migration") && f.contains("dig-node")),
            "a failed migration deregister must fail readiness: {failures:?}"
        );
    }

    /// #565 review — H2b: a service whose ACTUAL binPath resolves under the legacy
    /// root — the tolerated-re-install case that left it un-re-pointed — must fail
    /// readiness even though the protected DIR's ACL looks fine.
    #[test]
    fn readiness_fails_when_a_service_binpath_still_points_at_the_legacy_root() {
        let plan = dig_node_service_plan();
        let mut report = report_shell();
        report.service = Some(running_service()); // installed + RUNNING
        report.registration_audit = vec![regaudit::RegistrationAudit {
            registration: "dig-node".to_string(),
            bin_path: Some(
                r"C:\Users\me\AppData\Local\Programs\DIG\bin\dig-node.exe run".to_string(),
            ),
            under_legacy_root: true,
            note: "dig-node runs a binary under a user-writable legacy root".to_string(),
        }];
        let failures = evaluate_readiness(&plan, &report);
        assert!(
            failures.iter().any(|f| f.contains("dig-node")),
            "a service still pointing at the legacy binPath must fail readiness: {failures:?}"
        );
    }

    /// #565 review — H3: a PRIVILEGED component routed into a user-writable custom
    /// `--bin-dir` (the CLI override and the shipped GUI both do this) must STILL
    /// be ACL-verified. `installs_a_protected_component` is false for a custom dir,
    /// but `privileged_install_root` returns that custom dir so the verify runs —
    /// and a definitive write breach on it refuses ready.
    #[test]
    fn custom_bin_dir_privileged_install_is_still_acl_verified_and_can_refuse_ready() {
        use target::Os;
        let host = Target::current().expect("supported host").os;
        let custom = std::path::PathBuf::from(if host == Os::Windows {
            r"C:\Users\me\AppData\Local\Programs\DIG\bin"
        } else {
            "/home/me/.local/dig/bin"
        });
        let plan = InstallPlan {
            bin_dir: custom.clone(),
            with_dig_node: true, // a privileged (service-executed) component
            dry_run: false,
            ..InstallPlan::default()
        };
        assert!(plan.has_custom_bin_dir());
        // The OLD gate is OFF for a custom dir …
        assert!(
            !plan.installs_a_protected_component(host),
            "installs_a_protected_component stays false for a --bin-dir override"
        );
        // … but the verify gate is DECOUPLED: the custom dir is what gets checked.
        assert_eq!(
            plan.privileged_install_root(host),
            Some(custom.clone()),
            "a privileged component into a custom dir must still be routed through the verify"
        );
        // A definitive write breach on that custom dir refuses ready.
        let mut report = report_shell();
        report.service = Some(running_service());
        report.install_root_security = Some(secure::InstallRootSecurity {
            root: custom.to_string_lossy().into_owned(),
            checked: true,
            secure: false,
            note: "grants WRITE to an unprivileged principal (S-1-5-32-545)".to_string(),
        });
        let failures = evaluate_readiness(&plan, &report);
        assert!(
            failures.iter().any(|f| f.contains("install root")),
            "a privileged install into a user-writable custom dir must refuse ready: {failures:?}"
        );
    }

    /// #565 residual — H3 was HALF-applied. The prior fix decoupled the ACL VERIFY
    /// (above) from `installs_a_protected_component`, but left the legacy-root
    /// MIGRATION and the post-install binPath AUDIT gated on it — so on a
    /// `--bin-dir` privileged install (the path the GUI passes + the e2e uses) both
    /// were SKIPPED: a pre-#565 legacy-bound service/beacon registration was never
    /// vacated or flagged, readiness reported ready, and a non-admin could overwrite
    /// the legacy binary to run code as SYSTEM. Both gates now fire whenever a
    /// privileged binary is installed anywhere (`installs_a_privileged_binary`), so
    /// the audit populates the report and `evaluate_readiness` REFUSES ready.
    /// A privileged install into a custom `--bin-dir`, host-INDEPENDENT: dig-dns is
    /// a privileged (service-executed) component on EVERY OS (unlike dig-node, which
    /// is user-level on unix), so `installs_a_privileged_binary` is true on any CI
    /// host. `base_plan` already uses a custom temp bin dir (`has_custom_bin_dir`).
    fn custom_bin_dir_privileged_plan() -> InstallPlan {
        let mut plan = base_plan();
        plan.with_dig_dns = true;
        plan.dry_run = false;
        plan
    }

    #[test]
    fn custom_bin_dir_install_still_migrates_and_audits_legacy_registrations() {
        let host = Target::current().expect("supported host").os;
        let plan = custom_bin_dir_privileged_plan();
        assert!(
            plan.has_custom_bin_dir(),
            "test premise: a --bin-dir override"
        );

        // RED DRIVER: the migration + binPath-audit gate MUST fire on this path …
        assert!(
            plan.installs_a_privileged_binary(host),
            "a --bin-dir privileged install must run the #565 migration + binPath audit"
        );
        // … even though the default-root-only predicate stays off for a custom dir
        // (documenting the exact half-applied H3 hole this closes).
        assert!(
            !plan.installs_a_protected_component(host),
            "installs_a_protected_component is false under --bin-dir — why the old gate wrongly skipped"
        );

        // Consequence, now that the audit runs on this path: a legacy-bound
        // registration it surfaces refuses ready. (Pre-fix the gate was OFF, so the
        // audit never ran, `registration_audit` stayed empty, and readiness wrongly
        // reported ready — the SYSTEM-code-exec the residual left open.) The dig-dns
        // service itself is healthy, so the legacy audit is the SOLE failure.
        let mut report = report_shell();
        report.dns = Some(dns::DnsInstallResult {
            installed: true,
            started: true,
            service_running: true,
            needs_elevation: false,
            note: "registered".to_string(),
            doctor: None,
            paths_live: vec!["dns".to_string()],
            bound_port: None,
            pac_url: None,
            fallback_instruction: None,
        });
        report.registration_audit = vec![regaudit::RegistrationAudit {
            registration: "dig-dns".to_string(),
            bin_path: Some("/home/me/.dig/bin/dig-dns".to_string()),
            under_legacy_root: true,
            note: "dig-dns runs a binary under a user-writable legacy root".to_string(),
        }];
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1, "got: {failures:?}");
        assert!(failures[0].contains("dig-dns") && failures[0].contains("legacy"));
    }

    /// #565 residual — the migration must NOT be skipped on a `--bin-dir` privileged
    /// install. The migration gate is `!dry_run && installs_a_privileged_binary(os)`:
    /// assert it fires for the custom-dir privileged non-dry-run case (it did not
    /// before this fix) and is still (correctly) skipped on a dry-run.
    #[test]
    fn custom_bin_dir_privileged_install_does_not_skip_migration() {
        let host = Target::current().expect("supported host").os;
        let mut plan = custom_bin_dir_privileged_plan();
        let migration_runs = |p: &InstallPlan| !p.dry_run && p.installs_a_privileged_binary(host);
        assert!(
            migration_runs(&plan),
            "the #565 migration must run on a --bin-dir privileged install"
        );
        plan.dry_run = true;
        assert!(
            !migration_runs(&plan),
            "a dry-run installs nothing, so it must never run the migration"
        );
    }

    /// #565 review — H3 (negative): with NO privileged component selected there is
    /// nothing to gate, so `privileged_install_root` is `None` (the verify is
    /// skipped rather than run against an irrelevant dir).
    #[test]
    fn privileged_install_root_is_none_without_a_privileged_component() {
        use target::Os;
        // digstore-only into a custom dir on unix: digstore is NOT privileged
        // there, so there is no service-executed binary to protect.
        let plan = InstallPlan {
            bin_dir: std::path::PathBuf::from("/home/me/.local/dig/bin"),
            with_digstore: true,
            with_dig_node: false,
            with_dig_dns: false,
            auto_update: false,
            with_relay: false,
            ..InstallPlan::default()
        };
        assert_eq!(plan.privileged_install_root(Os::Linux), None);
    }

    #[test]
    fn elevation_gate_fails_fast_before_any_resolution_when_unprivileged() {
        // #492 core: an un-elevated service install returns NOT_ELEVATED WITHOUT
        // ever calling the resolver (the resolver panics if reached) — proving
        // fail-fast, before any download/write, leaving no partial state.
        let resolve = |_: &Repo, _: &Option<String>| -> Result<download::Release, InstallError> {
            panic!("resolver must not run when the elevation gate rejects the run")
        };
        let err = run_report_gated(&dig_node_service_plan(), &resolve, &|| false, &mut |_| {})
            .unwrap_err();
        assert_eq!(err.code(), "NOT_ELEVATED");
        assert_eq!(err.exit_code(), 11);
    }

    #[test]
    fn elevation_gate_lets_an_elevated_run_proceed_to_resolution() {
        // Elevated → the gate passes; resolution proceeds (a bad resolver error
        // here would be a resolution failure, NOT a NOT_ELEVATED gate rejection).
        let resolve = resolver_from(all_releases());
        // Use a dry-run-equivalent by asserting the gate did not short-circuit:
        // an elevated non-dry-run would attempt real I/O, so we assert only that
        // the error (if any) is not the elevation gate.
        let err = run_report_gated(&dig_node_service_plan(), &resolve, &|| true, &mut |_| {});
        if let Err(e) = err {
            assert_ne!(
                e.code(),
                "NOT_ELEVATED",
                "an elevated run must pass the gate"
            );
        }
    }

    #[test]
    fn dry_run_report_is_ready_with_no_failures() {
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.with_dig_node = true;
        plan.with_dig_dns = true;
        let report = run_dry(&plan, all_releases()).expect("ok");
        assert!(
            report.ready,
            "a dry-run installs nothing, so it is trivially ready"
        );
        assert!(report.failures.is_empty());
    }

    #[test]
    fn readiness_fails_when_the_dig_node_service_is_not_running() {
        // #493 core: the service installed but is NOT running per the service
        // manager → NOT ready (a bare port listener can no longer mask this).
        let plan = dig_node_service_plan();
        let mut report = report_shell();
        let mut svc = running_service();
        svc.health_ok = false;
        svc.health_note = "service 'net.dignetwork.dig-node' is not registered".to_string();
        report.service = Some(svc);
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1, "got: {failures:?}");
        assert!(failures[0].contains("dig-node"));
        assert!(failures[0].contains("not running"));
    }

    #[test]
    fn readiness_fails_when_the_dig_node_service_did_not_install() {
        let plan = dig_node_service_plan();
        let report = report_shell(); // service: None
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("dig-node"));
    }

    #[test]
    fn readiness_passes_when_the_service_is_running_and_the_cli_resolves() {
        let plan = dig_node_service_plan();
        let mut report = report_shell();
        report.service = Some(running_service());
        report.cli_path_checks.push(pathcheck::CliPathCheck {
            cli: "dig-node".to_string(),
            resolved: true,
            note: "resolved".to_string(),
        });
        assert!(evaluate_readiness(&plan, &report).is_empty());
    }

    #[test]
    fn readiness_fails_when_dig_dns_has_no_live_resolution_path() {
        // The user's exact symptom: dig-dns "installed" but `live path(s): NONE`.
        let mut plan = base_plan();
        plan.dry_run = false;
        plan.with_dig_dns = true;
        let mut report = report_shell();
        report.dns = Some(dns::DnsInstallResult {
            installed: true,
            started: true,
            service_running: true, // reached RUNNING, but serves no path
            needs_elevation: false,
            note: "registered".to_string(),
            doctor: None,
            paths_live: Vec::new(), // NONE live
            bound_port: None,
            pac_url: None,
            fallback_instruction: None,
        });
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1, "got: {failures:?}");
        assert!(failures[0].contains("dig-dns"));
        assert!(failures[0].contains("no live resolution path"));
    }

    #[test]
    fn readiness_fails_when_the_dig_dns_service_did_not_reach_running() {
        // F7: even with a live resolution path, dig-dns is NOT ready unless OUR
        // service reached RUNNING per the service manager — a path probe another
        // process could satisfy must not mark it ready (#493 false-success).
        let mut plan = base_plan();
        plan.dry_run = false;
        plan.with_dig_dns = true;
        let mut report = report_shell();
        report.dns = Some(dns::DnsInstallResult {
            installed: true,
            started: true,
            service_running: false, // did NOT reach RUNNING
            needs_elevation: false,
            note: "registered".to_string(),
            doctor: None,
            paths_live: vec!["dns".to_string()], // a path probe passed anyway
            bound_port: None,
            pac_url: None,
            fallback_instruction: None,
        });
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1, "got: {failures:?}");
        assert!(failures[0].contains("dig-dns"));
        assert!(failures[0].contains("did not reach RUNNING"));
    }

    #[test]
    fn readiness_fails_when_a_daemon_state_dir_is_not_hardened() {
        // #501 F2/F5: a control-token dir whose tight ACL could not be verified is
        // a hard failure — the install must report NOT ready (fail closed).
        let plan = dig_node_service_plan();
        let mut report = report_shell();
        report.service = Some(running_service());
        report.daemon_dirs = vec![daemon_dir::DaemonDirResult {
            daemon: "dig-node".to_string(),
            path: r"C:\ProgramData\DigNode".to_string(),
            created: false,
            acl_applied: false,
            note: "ACL read-back verification FAILED".to_string(),
        }];
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1, "got: {failures:?}");
        assert!(failures[0].contains("dig-node"));
        assert!(failures[0].contains("state directory could not be hardened"));
    }

    #[test]
    fn readiness_ignores_an_unhardened_dir_for_an_unselected_daemon() {
        // Only the SELECTED daemon's dir gates readiness: a dig-dns dir failure
        // must not fail a dig-node-only install (dig-dns was not requested).
        let plan = dig_node_service_plan(); // with_dig_dns = false
        let mut report = report_shell();
        report.service = Some(running_service());
        report.daemon_dirs = vec![daemon_dir::DaemonDirResult {
            daemon: "dig-dns".to_string(),
            path: r"C:\ProgramData\DigDns".to_string(),
            created: false,
            acl_applied: false,
            note: "not hardened".to_string(),
        }];
        assert!(evaluate_readiness(&plan, &report).is_empty());
    }

    #[test]
    fn readiness_fails_when_a_required_cli_is_not_on_path() {
        // #496: a CLI that does not resolve from a fresh shell makes the install
        // NOT ready even if its service is otherwise up.
        let plan = dig_node_service_plan();
        let mut report = report_shell();
        report.service = Some(running_service());
        report.cli_path_checks.push(pathcheck::CliPathCheck {
            cli: "dig-node".to_string(),
            resolved: false,
            note: "`dig-node` did not resolve on PATH".to_string(),
        });
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1, "got: {failures:?}");
        assert!(failures[0].contains("dig-node"));
        assert!(failures[0].contains("fresh shell"));
    }

    /// #514: an `auto_update`-only plan (the beacon is a privileged OS-scheduler
    /// registration, so it gates readiness like dig-node/dig-relay's own service
    /// registration — never best-effort like the firewall rule/scheme handler).
    fn beacon_only_plan() -> InstallPlan {
        InstallPlan {
            bin_dir: std::env::temp_dir().join("dig-installer-readiness-beacon-test"),
            with_digstore: false,
            with_dig_node: false,
            with_dig_dns: false,
            modify_path: false,
            auto_update: true,
            dry_run: false,
            ..InstallPlan::default()
        }
    }

    #[test]
    fn readiness_fails_when_the_beacon_did_not_install() {
        let plan = beacon_only_plan();
        let report = report_shell(); // beacon: None
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1, "got: {failures:?}");
        assert!(failures[0].contains("dig-updater"));
        assert!(failures[0].contains("not installed"));
    }

    #[test]
    fn readiness_fails_when_the_beacon_scheduler_did_not_register() {
        let plan = beacon_only_plan();
        let mut report = report_shell();
        report.beacon = Some(beacon::BeaconResult {
            applied: false,
            note: "could not run `dig-updater schedule install`: exit code 5".to_string(),
        });
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1, "got: {failures:?}");
        assert!(failures[0].contains("dig-updater"));
        assert!(failures[0].contains("did not register"));
    }

    #[test]
    fn readiness_passes_when_the_beacon_scheduler_registered() {
        let plan = beacon_only_plan();
        let mut report = report_shell();
        report.beacon = Some(beacon::BeaconResult {
            applied: true,
            note: "registered the daily update-check scheduler".to_string(),
        });
        assert!(evaluate_readiness(&plan, &report).is_empty());
    }

    #[test]
    fn readiness_ignores_an_absent_beacon_when_auto_update_is_off() {
        // The beacon is opt-out (`--no-auto-update`) — a plan that declined it
        // must never fail readiness over its absence.
        let plan = dig_node_service_plan(); // auto_update: false
        let mut report = report_shell();
        report.service = Some(running_service());
        assert!(evaluate_readiness(&plan, &report).is_empty());
    }

    #[test]
    fn readiness_verdict_logs_ready_only_when_ready() {
        let mut lines = Vec::new();
        let mut report = report_shell();
        report.ready = true;
        log_readiness_verdict(&report, &mut |l| lines.push(l.to_string()));
        assert!(lines.iter().any(|l| l.contains("✓ DIG is ready")));

        let mut lines = Vec::new();
        let mut report = report_shell();
        report.ready = false;
        report.failures = vec!["dig-node: not running".to_string()];
        log_readiness_verdict(&report, &mut |l| lines.push(l.to_string()));
        assert!(lines.iter().any(|l| l.contains("✗ DIG is NOT ready")));
        assert!(lines.iter().any(|l| l.contains("dig-node: not running")));
        assert!(!lines.iter().any(|l| l.contains("✓ DIG is ready")));
    }

    // -- #309 version-aware updater: end-to-end wiring through run_report ----
    //
    // `update::decide`'s full matrix is unit-tested directly in `update.rs`
    // (pure, no I/O). These tests instead prove the WIRING: that
    // `run_report_gated` actually detects the real file at each tracked
    // component's real computed destination and records the right
    // `update_action`/`previous_version` on its `ComponentResult`. A "Skip"
    // end-to-end run needs a binary that both EXISTS at the exact OS-specific
    // dest name (`digstore.exe` on Windows) AND runs successfully reporting a
    // matching version — not reproducible portably without a compiled stub,
    // so the full matrix's Skip/Update-by-version-compare cells stay covered
    // by `update.rs`'s pure tests; what's tested here is real, cross-platform,
    // and still meaningful: absent → Install, and present-but-unreadable (a
    // plain file that can't be executed, on every OS) → Update.

    /// A plain, non-executable file at `path` — exists on disk but fails to
    /// run as `<path> --version` on every OS (not a valid executable format),
    /// landing in `update::decide`'s "installed version unreadable" cell.
    fn write_unrunnable_file(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"not a real binary").unwrap();
    }

    fn wiring_test_bin_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dig-installer-update-wiring-{tag}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn digstore_wiring_installs_when_absent_and_updates_when_present_but_unreadable() {
        let bin_dir = wiring_test_bin_dir("digstore");
        let _ = std::fs::remove_dir_all(&bin_dir);
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.bin_dir = bin_dir.clone();

        let report = run_dry(&plan, all_releases()).expect("resolves");
        let digstore = report
            .components
            .iter()
            .find(|c| c.component == "digstore")
            .expect("digstore present");
        assert_eq!(digstore.update_action, update::UpdateAction::Install);
        assert_eq!(digstore.previous_version, None);

        let target = Target::current().unwrap();
        write_unrunnable_file(&bin_dir.join(target.exe_name("digstore")));
        let report = run_dry(&plan, all_releases()).expect("resolves");
        let digstore = report
            .components
            .iter()
            .find(|c| c.component == "digstore")
            .expect("digstore present");
        assert_eq!(digstore.update_action, update::UpdateAction::Update);
        assert!(digstore.previous_version.is_some());

        let _ = std::fs::remove_dir_all(&bin_dir);
    }

    #[test]
    fn dig_node_wiring_installs_when_absent_and_updates_when_present_but_unreadable() {
        let bin_dir = wiring_test_bin_dir("dig-node");
        let _ = std::fs::remove_dir_all(&bin_dir);
        let mut plan = base_plan();
        plan.with_dig_node = true;
        plan.bin_dir = bin_dir.clone();

        let report = run_dry(&plan, all_releases()).expect("resolves");
        let node = report
            .components
            .iter()
            .find(|c| c.component == "dig-node")
            .expect("dig-node present");
        assert_eq!(node.update_action, update::UpdateAction::Install);

        let target = Target::current().unwrap();
        write_unrunnable_file(&bin_dir.join(target.exe_name("dig-node")));
        let report = run_dry(&plan, all_releases()).expect("resolves");
        let node = report
            .components
            .iter()
            .find(|c| c.component == "dig-node")
            .expect("dig-node present");
        assert_eq!(node.update_action, update::UpdateAction::Update);
        assert!(node.previous_version.is_some());

        let _ = std::fs::remove_dir_all(&bin_dir);
    }

    #[test]
    fn dig_dns_wiring_installs_when_absent_and_updates_when_present_but_unreadable() {
        let bin_dir = wiring_test_bin_dir("dig-dns");
        let _ = std::fs::remove_dir_all(&bin_dir);
        let mut plan = base_plan();
        plan.with_dig_dns = true;
        plan.bin_dir = bin_dir.clone();

        let report = run_dry(&plan, all_releases()).expect("resolves");
        let dns_component = report
            .components
            .iter()
            .find(|c| c.component == "dig-dns")
            .expect("dig-dns present");
        assert_eq!(dns_component.update_action, update::UpdateAction::Install);

        let target = Target::current().unwrap();
        write_unrunnable_file(&bin_dir.join(target.exe_name("dig-dns")));
        let report = run_dry(&plan, all_releases()).expect("resolves");
        let dns_component = report
            .components
            .iter()
            .find(|c| c.component == "dig-dns")
            .expect("dig-dns present");
        assert_eq!(dns_component.update_action, update::UpdateAction::Update);
        assert!(dns_component.previous_version.is_some());

        let _ = std::fs::remove_dir_all(&bin_dir);
    }

    #[test]
    fn untracked_components_always_default_to_install() {
        // digs/dign/digd/dig-relay/the DIG Browser never run through
        // `apply_update_decision` — they keep the existing always-fresh-download
        // behavior regardless of what's on disk at their destination.
        let bin_dir = wiring_test_bin_dir("untracked");
        let _ = std::fs::remove_dir_all(&bin_dir);
        let mut plan = base_plan();
        plan.with_digstore = true; // brings in `digs` alongside it
        plan.with_dig_node = true; // brings in `dign` alongside it
        plan.with_dig_dns = true; // brings in `digd` alongside it
        plan.with_relay = true;
        plan.bin_dir = bin_dir.clone();

        let target = Target::current().unwrap();
        write_unrunnable_file(&bin_dir.join(target.exe_name("digs")));
        write_unrunnable_file(&bin_dir.join(target.exe_name("dign")));
        write_unrunnable_file(&bin_dir.join(target.exe_name("digd")));
        write_unrunnable_file(&bin_dir.join(target.exe_name("dig-relay")));

        let report = run_dry(&plan, all_releases()).expect("resolves");
        for id in ["digs", "dign", "digd", "dig-relay"] {
            let c = report
                .components
                .iter()
                .find(|c| c.component == id)
                .unwrap_or_else(|| panic!("{id} present"));
            assert_eq!(
                c.update_action,
                update::UpdateAction::Install,
                "{id} is not update-tracked (#309 scope: digstore/dig-node/dig-dns only)"
            );
            assert_eq!(c.previous_version, None);
        }

        let _ = std::fs::remove_dir_all(&bin_dir);
    }

    #[test]
    fn force_reinstall_defaults_off_and_threads_through_the_plan() {
        assert!(
            !InstallPlan::default().force_reinstall,
            "force_reinstall defaults off — a bare run is version-aware, not a blanket reinstall"
        );
    }

    #[test]
    fn update_decision_summary_appears_in_the_cli_run_summary() {
        // The CLI/`--json` "run summary" requirement (#309): the decision's
        // human-readable line must actually reach the log stream a caller
        // sees, not just live on the struct.
        let bin_dir = wiring_test_bin_dir("summary-log");
        let _ = std::fs::remove_dir_all(&bin_dir);
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.bin_dir = bin_dir.clone();
        let resolve = resolver_from(all_releases());

        let mut lines = Vec::new();
        run_report_with(&plan, &resolve, &mut |l| lines.push(l.to_string())).expect("resolves");
        assert!(
            lines.iter().any(|l| l.contains("install v")),
            "first run (nothing on disk) logs an install decision: {lines:?}"
        );

        let target = Target::current().unwrap();
        write_unrunnable_file(&bin_dir.join(target.exe_name("digstore")));
        let mut lines = Vec::new();
        run_report_with(&plan, &resolve, &mut |l| lines.push(l.to_string())).expect("resolves");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("update") && l.contains("unreadable")),
            "second run (unreadable file present) logs a reinstall-as-update decision: {lines:?}"
        );

        let _ = std::fs::remove_dir_all(&bin_dir);
    }
}
