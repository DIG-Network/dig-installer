//! The universal DIG installer (library surface) — a **thin shim**.
//!
//! It bundles nothing. At install time it resolves, per host OS/arch, the LATEST
//! GitHub release asset for each selected component and downloads it:
//!
//! * the **dig-store CLI** (`DIG-Network/digs`) → placed on PATH, along with
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
//! * **dig-app** (`DIG-Network/dig-app`) → the per-user identity agent + tray
//!   (issue #912), the user-facing half of the #908 engine/app split. Placed on
//!   PATH like a user CLI and registered for PER-USER autostart at login (see
//!   [`autostart`]) — Windows HKCU `Run` value / macOS LaunchAgent / Linux
//!   systemd **user** unit — never a machine-wide service, never elevated,
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
//! Each component is selectable (`--with-dig-store`/`--with-dig-node`/
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
pub mod autostart;
pub mod beacon;
pub mod browsers;
pub mod daemon_dir;
pub mod dirfd;
pub mod dns;
pub mod download;
pub mod elevation;
pub mod error;
pub mod firewall;
pub mod forcelist;
pub mod guardedcmd;
pub mod hardening;
pub mod health;
pub mod hosts;
pub mod invoker;
pub mod manifest;
pub mod migrate;
pub mod pathcheck;
pub mod paths;
pub mod proc;
pub mod regaudit;
pub mod release;
pub mod rootchain;
pub mod scheme;
pub mod secure;
pub mod service;
pub mod sources;
pub mod svc;
pub mod target;
pub mod uninstall;
pub mod update;
pub mod userwrite;

use std::path::PathBuf;

use asset::AssetKind;
use error::InstallError;
use hardening::{InstallAction, RollbackGuard, RollbackReport};
use release::Repo;
use service::ServiceConfig;
use target::Target;

/// What the user asked the installer to do.
#[derive(Debug, Clone)]
pub struct InstallPlan {
    /// Directory to place the downloaded binaries in.
    pub bin_dir: PathBuf,
    /// Install the dig-store CLI (default true — part of the universal 3-component
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
    /// Install the **dig-app** per-user identity agent + tray (issue #912). Default
    /// true — dig-app is the user-facing half of the #908 engine/app split, so a
    /// default install ships it alongside the dig-node engine. Unlike the daemons it
    /// is a per-user, unelevated component: on PATH plus a login autostart
    /// ([`Self::dig_app_autostart`]), never a machine-wide service.
    pub with_dig_app: bool,
    /// dig-app version/tag to install: `None` ⇒ latest released (falling back to the
    /// newest pre-release while dig-app publishes nightlies only).
    pub dig_app_version: Option<String>,
    /// Register dig-app to start at login (default true — a first-class, toggleable
    /// install option, `--no-dig-app-autostart` opts out). Per-user, no elevation:
    /// Windows HKCU `Run` value · macOS LaunchAgent · Linux systemd **user** unit.
    /// Declining leaves dig-app installed and on PATH, just not auto-started.
    pub dig_app_autostart: bool,
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
        // dig-app counts here (#912): it registers no service — so it never trips the
        // branch above — yet it IS a binary written into that root, and without this
        // the pre-install guard would be skipped and the write would fail late with a
        // raw permission error instead of the clean elevation verdict.
        let places_a_binary = self.with_digstore || self.with_dig_app || self.with_browser;
        places_a_binary
            && !self.has_custom_bin_dir()
            && self.bin_dir_for("dig-store", os) == paths::protected_bin_dir()
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
            c.extend(["dig-store", "digs"]);
        }
        if self.with_dig_node {
            c.extend(["dig-node", "dign"]);
        }
        if self.with_dig_app {
            c.push("dig-app");
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
            with_dig_app: true,
            dig_app_version: None,
            dig_app_autostart: true,
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
    /// dig-app's per-user login-autostart registration (only when `with_dig_app &&
    /// dig_app_autostart` and dig-app actually resolved) — #912.
    pub autostart: Option<autostart::AutostartResult>,
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
    /// The permission posture of the directory this run's binaries were placed in, when that differs
    /// from [`Self::install_root_security`]'s privileged root — the `--bin-dir` override, or the
    /// per-user root of an unelevated install (#1748).
    ///
    /// REPORTED, never fatal. It is not the no-LPE invariant: a user-writable directory holding
    /// binaries only that same user runs is their own authority. But it is exactly the posture that
    /// made `/usr/local/bin` the wrong install root, so an install must not be silent about it — before
    /// this, the directory root wrote to and executed from was neither checked nor mentioned on any
    /// elevated unix install.
    pub bin_dir_security: Option<secure::InstallRootSecurity>,
    /// The permission posture of the `/usr/local/bin` PATH VENEER, when this run planted links there.
    ///
    /// FATAL under elevation, for the same reason as [`Self::bin_dir_security`] and found the same way —
    /// by an executed escalation rather than by review. The veneer is the directory root's own login `PATH`
    /// resolves DIG commands from, so an account that can write there replaces a link this installer
    /// planted and root runs whatever it points at on the next `sudo dign …`. Refusing the PATH-WIRING step
    /// was not enough: that step is non-fatal by design (a binary is placed; only wiring failed), so an
    /// install onto an attacker-owned veneer still reported `ok: true`.
    ///
    /// `None` when no links were planted — an unelevated or `--bin-dir` install, or Windows.
    pub veneer_security: Option<secure::InstallRootSecurity>,
    /// HOW this run made its CLIs reachable by bare name — symlinks in the `/usr/local/bin` veneer, or the
    /// install directory placed on `PATH` directly ([`paths::Reachability`]).
    ///
    /// Reported because it is a real fork with a security meaning, not an implementation detail: the second
    /// value on an ELEVATED unix install means the veneer was measured UNSAFE and this run deliberately
    /// declined to plant a link there. Read it together with [`Self::veneer_security`], which carries the
    /// verdict that caused the fork. `None` on a dry run.
    pub reachability: Option<paths::Reachability>,
    /// Any DIG symlink this run REMOVED from an unsafe veneer.
    ///
    /// A link an earlier, safe-at-the-time run planted is a live escalation vector once that directory
    /// becomes writable — an unprivileged process replaces it and root runs whatever it points at. So the
    /// fallback removes them, and says which, rather than leaving them for somebody to find.
    pub veneer_links_removed: Vec<String>,
    /// Any directory that PRECEDES the wired install dir on root's login `PATH` and is not established safe.
    ///
    /// Reported because position decides which binary a bare name reaches, and the existing shadow check can
    /// only see a file that is already there (#1748 F2). A `PATH` where a writable directory merely comes
    /// first is a loaded gun: the attacker creates the name whenever she likes and root runs it, having
    /// touched nothing this installer placed. Prepending is the fix; this is the backstop for the cases
    /// prepending cannot win — a user's own `.bashrc`, or `/etc/paths` ordering on macOS, where
    /// `path_helper` reads `/etc/paths` before `/etc/paths.d/*`.
    pub preceding_unsafe_path_dirs: Vec<String>,
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
    /// `true` when ANY component's update was staged for a reboot-time replace
    /// (its running binary was locked, #544/#562) — the install is otherwise
    /// complete but the user MUST restart to finish applying it. Every surface
    /// (the CLI verdict, the `--json` record, the GUI Finish step) reads this so
    /// a reboot-deferred step never reads as fully done.
    pub restart_required: bool,
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
        // The tracked call sites (dig-store/dig-node/dig-dns in `run_report_gated`)
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
/// `previous_version`) so the caller — the dig-store/dig-node/dig-dns sections
/// of [`run_report_gated`] — can gate the rest of its lifecycle (the
/// download, the #232 stop/replace/restart) on one source of truth. Detection
/// is read-only (`update::detect_installed_version`), so this is safe to call
/// under `--dry-run` for an accurate preview.
fn apply_update_decision(
    c: &mut ComponentResult,
    force_reinstall: bool,
    log: &mut dyn FnMut(&str),
) -> update::UpdateDecision {
    let dest = std::path::Path::new(&c.dest);
    // The probe RUNS the installed binary, as root, before anything has been downloaded or written. If
    // it sits where an unprivileged account could have replaced it, that is arbitrary root code
    // execution, so the probe is SKIPPED rather than the install failed: an unknown version is
    // unparseable, which `decide` already treats as "reinstall" — the safe answer, and a strictly better
    // outcome than trusting a version string an attacker chose (#1748 F1).
    let detected = match secure::root_exec_guard(dest) {
        Ok(()) => update::detect_installed_version(dest),
        Err(why) => {
            log(&format!("    ! not probing the installed version — {why}"));
            update::detect_installed_version_with(dest, |_| None)
        }
    };
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

/// LOUDLY flag the locked-destination reboot-replace fallback (#544/#562): when
/// a running binary was still held open at write time, its update was staged and
/// will apply on the next reboot — the user must restart to finish it. Returns
/// `true` when the write was reboot-deferred, so the caller records it on
/// [`InstallReport::restart_required`] (surfaced at EVERY component site — the
/// CLI verdict, the `--json` record, the GUI Finish step). A plain in-place
/// [`download::WriteOutcome::Replaced`] logs nothing and returns `false`.
#[must_use]
fn log_write_outcome(
    log: &mut dyn FnMut(&str),
    component: &str,
    outcome: download::WriteOutcome,
) -> bool {
    if outcome == download::WriteOutcome::ScheduledForReboot {
        log(&format!(
            "    ! {component} was still running and locked its binary, so the update was staged \
             and will apply on the next REBOOT — restart your computer to finish updating {component}."
        ));
        true
    } else {
        false
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
    // elevation (registers a service / writes hosts); a dry-run or dig-store-only
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
        autostart: None,
        installed: Vec::new(),
        cli_path_checks: Vec::new(),
        daemon_dirs: Vec::new(),
        install_root_security: None,
        bin_dir_security: None,
        veneer_security: None,
        reachability: None,
        veneer_links_removed: Vec::new(),
        preceding_unsafe_path_dirs: Vec::new(),
        migration: None,
        registration_audit: Vec::new(),
        install_manifest: None,
        ready: true,
        failures: Vec::new(),
        restart_required: false,
    };

    // A partial-failure install must never leave a half-written stack (the #544
    // half-write lesson, #573): every privileged step below records itself into
    // this guard the instant it succeeds. If ANY step fails before the install
    // completes, `rollback_partial_install` reverses the recorded steps in LIFO
    // order; only a fully-successful run `commit`s the guard so the steps stand.
    let mut guard = RollbackGuard::new();
    let run_steps = |report: &mut InstallReport,
                     guard: &mut RollbackGuard,
                     log: &mut dyn FnMut(&str)|
     -> Result<(), InstallError> {
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

        // 1. dig-store CLI + its `digs` alias binary (issue #434). `digs` is
        //    published in the SAME dig-store release under its own asset stem
        //    (`digs-<ver>-<os_arch>[.exe]`) and behaves identically to `dig-store`;
        //    it is resolved/downloaded exactly like dig-store — same version pin,
        //    same bin dir (so no separate PATH entry is needed) — and follows the
        //    same `with_digstore`/`digstore_version` flags (it has none of its own).
        if plan.with_digstore {
            log("Installing the dig-store CLI:");
            let mut c = resolve_dig_store(
                resolve,
                &plan.digstore_version,
                &target,
                &plan.bin_dir_for("dig-store", target.os),
                log,
            )?;
            log_component(log, &c);
            // #309 version-aware updater: detect what's already at this
            // destination — a read-only check, safe under `--dry-run` — and
            // decide Install/Update/Skip against the version just resolved above.
            let decision = apply_update_decision(&mut c, plan.force_reinstall, log);
            if decision.action != update::UpdateAction::Skip {
                let outcome = download_component(&c, plan.dry_run)?;
                report.restart_required |= log_write_outcome(log, "dig-store", outcome);
            } else {
                log("    · already up to date — skipping the download");
            }
            if !plan.dry_run {
                note_binary_written(report, guard, &c.dest);
            }
            report.components.push(c);

            log("Installing the digs alias (same dig-store CLI, published as a separate binary):");
            let digs = resolve_component(
                resolve,
                &Repo::digs(),
                &plan.digstore_version,
                &target,
                AssetKind::RawBinary,
                &plan.bin_dir_for("digs", target.os),
            )?;
            log_component(log, &digs);
            let outcome = download_component(&digs, plan.dry_run)?;
            report.restart_required |= log_write_outcome(log, "digs", outcome);
            if !plan.dry_run {
                note_binary_written(report, guard, &digs.dest);
            }
            report.components.push(digs);
        }

        // The veneer's posture is measured ONCE, here, before anything is wired or linked, and the same
        // answer drives both steps (#1748). Measuring twice would let them disagree, and a run that links
        // into one directory while wiring another leaves the CLIs unreachable — which is this whole issue.
        //
        // The verdict is recorded either way. It is FATAL only when the veneer is actually the mechanism in
        // play (`evaluate_readiness`): when we fall back it is a recorded DOWNGRADE, not a failure, because
        // the install is then reachable through a chain root owns end to end.
        let veneer_verdict = if cfg!(unix) && !plan.dry_run {
            Some(secure::verify_install_root(
                target.os,
                std::path::Path::new(paths::UNIX_MACHINE_BIN_DIR),
            ))
        } else {
            None
        };
        let veneer_is_safe = veneer_verdict
            .as_ref()
            // Absent measurement (Windows, or a dry run) must not silently mean "unsafe" and re-route the
            // whole install: on Windows there is no veneer, and a dry run wires nothing.
            .map(|v| v.is_established_safe())
            .unwrap_or(true);
        let reachability = paths::reachability_for(target.os, &plan.bin_dir, veneer_is_safe);
        if let Some(v) = &veneer_verdict {
            if !v.is_established_safe() {
                log(&format!(
                    "    ! {} is not safe to resolve DIG commands from: {}",
                    paths::UNIX_MACHINE_BIN_DIR,
                    v.note
                ));
                log("    · falling back: the protected root goes on PATH directly, and no link is planted");
            }
        }
        report.veneer_security = veneer_verdict;
        report.reachability = Some(reachability);

        // 2. PATH (only meaningful if we placed a PATH binary).
        if plan.modify_path
            && (plan.with_digstore || plan.with_dig_node || plan.with_dig_app || plan.with_dig_dns)
        {
            // The dir REPORTED is the one that actually has to be searchable, which since the veneer
            // is not the dir binaries are placed in (#1748): an elevated install wires (or finds
            // already present) `/usr/local/bin` and links into it, never `/opt/dig/bin`. Reporting the
            // install dir here said "Adding /opt/dig/bin to PATH" for a run that did no such thing, and
            // put a directory that is deliberately never on PATH into `report.path.dir`, which is a
            // machine-consumed field.
            let wired = paths::reachable_dir(target.os, &plan.bin_dir, veneer_is_safe);
            // "Checking", not "Adding": on the default elevated install the veneer is already on PATH and
            // this step writes nothing, so announcing an addition described a run that did not happen
            // (#1748, C3).
            log(&format!("Ensuring {} is on PATH:", wired.display()));
            let dir = wired.to_string_lossy().into_owned();
            if plan.dry_run {
                log("    (would add to PATH)");
                report.path = Some(PathResult {
                    modified: false,
                    dir,
                    note: "would add to PATH".to_string(),
                });
            } else {
                match paths::add_to_path(&plan.bin_dir, veneer_is_safe) {
                    Ok(wiring) => {
                        log(&format!("    ✓ {}", wiring.note));
                        report.path = Some(PathResult {
                            // OBSERVED, never assumed: the wiring itself reports whether it changed
                            // anything, like every other field in this struct.
                            modified: wiring.changed,
                            dir,
                            note: wiring.note,
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
                report.restart_required |= log_write_outcome(log, "dig-node", outcome);
            }
            if !plan.dry_run {
                note_binary_written(report, guard, &c.dest);
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
                    let outcome = download_component(&dign, plan.dry_run)?;
                    report.restart_required |= log_write_outcome(log, "dign", outcome);
                    if !plan.dry_run {
                        note_binary_written(report, guard, &dign.dest);
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
            // Record ONLY a genuinely fresh registration (`Install`) for rollback —
            // never an `Update`/`Skip` of a service the user already had, so a
            // rollback restores the pre-install state without removing what predated
            // this run.
            if decision.action == update::UpdateAction::Install
                && report.service.as_ref().is_some_and(|s| s.installed)
            {
                guard.record(InstallAction::ServiceRegistered(
                    svc::DIG_NODE_SERVICE_ID.to_string(),
                ));
            }

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

        // 3c. dig-app (issue #912): the per-user identity agent + tray, the USER-FACING half of the
        //     stack that pairs with the dig-node engine installed above (the #908 node↔app split —
        //     the engine is identity-agnostic, the app IS the identity). Unlike every daemon here it
        //     is NOT a machine-wide service: it runs in the user's own session, so it is placed on
        //     PATH like a user CLI and registered for PER-USER autostart at login (`autostart`) —
        //     Windows HKCU Run value, macOS LaunchAgent, Linux systemd user unit — with no
        //     elevation. Both binary + autostart, because a binary a stranger cannot start is not a
        //     distribution.
        //
        //     Resolution failure is gated gracefully, exactly as the `dign` alias above is: dig-app
        //     publishes nightlies ahead of its first stable release, and a release that has no
        //     asset for this OS/arch must never sink the otherwise-successful stack install.
        if plan.with_dig_app {
            log("Installing dig-app (the DIG identity agent + tray):");
            match resolve_component(
                resolve,
                &Repo::dig_app(),
                &plan.dig_app_version,
                &target,
                AssetKind::RawBinary,
                &plan.bin_dir_for("dig-app", target.os),
            ) {
                Ok(mut c) => {
                    log_component(log, &c);
                    // #309 version-aware updater: dig-app is a tracked component (it is a
                    // first-class installed binary, not an alias sharing another component's
                    // version pin), so a re-run skips a download that would change nothing.
                    let decision = apply_update_decision(&mut c, plan.force_reinstall, log);
                    if decision.action != update::UpdateAction::Skip {
                        let outcome = download_component(&c, plan.dry_run)?;
                        report.restart_required |= log_write_outcome(log, "dig-app", outcome);
                    } else {
                        log("    · already up to date — skipping the download");
                    }
                    if !plan.dry_run {
                        note_binary_written(report, guard, &c.dest);
                    }
                    let dig_app_path = PathBuf::from(c.dest.clone());
                    report.components.push(c);

                    if plan.dig_app_autostart {
                        log("Registering dig-app to start at login (per-user, no elevation):");
                        let a = autostart::register(&dig_app_path, target.os, plan.dry_run);
                        log(&format!(
                            "    {} {}",
                            // `!`, never `·`: an install that silently produces no autostart is a
                            // dig-app that never starts at login, which is the false-tick class this
                            // verification exists to remove. The note carries the actionable reason.
                            if a.registered { "✓" } else { "!" },
                            a.note
                        ));
                        if a.registered {
                            guard.record(InstallAction::AutostartRegistered);
                        }
                        report.autostart = Some(a);
                    }
                }
                Err(e) if e.code() == "ASSET_NOT_FOUND" => {
                    log(&format!(
                        "    · dig-app is not available for this target yet ({e}) — skipping; the \
                         rest of the stack is unaffected"
                    ));
                }
                Err(e) => return Err(e),
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
                    // convention as dig-store/dig-node above. `register_dig_dns`
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
                        report.restart_required |= log_write_outcome(log, "dig-dns", outcome);
                    }
                    if !plan.dry_run {
                        note_binary_written(report, guard, &c.dest);
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
                    let outcome = download_component(&digd, plan.dry_run)?;
                    report.restart_required |= log_write_outcome(log, "digd", outcome);
                    if !plan.dry_run {
                        note_binary_written(report, guard, &digd.dest);
                    }
                    report.components.push(digd);

                    let dns_result = register_dig_dns(&dig_dns_path, plan, &decision, log);
                    // #627 WU2: `dig-dns configure-os` wires + flushes + VERIFIES
                    // the OS resolver. In the rare case it wired the split-DNS
                    // but the OS did not go live before a restart, OR that into
                    // the #562 restart verdict (reusing the existing surface — no
                    // new field). The expected case is activated ⇒ no prompt.
                    if dns_result.reboot_required {
                        report.restart_required = true;
                        if let Some(reason) = &dns_result.reboot_reason {
                            log(&format!(
                                "    ! restart required to activate .dig resolution: {reason}"
                            ));
                        }
                    }
                    report.dns = Some(dns_result);
                    // Fresh (`Install`) registrations only — see the dig-node note.
                    if decision.action == update::UpdateAction::Install
                        && report.dns.as_ref().is_some_and(|d| d.installed)
                    {
                        guard.record(InstallAction::ServiceRegistered(
                            svc::DIG_DNS_SERVICE_ID.to_string(),
                        ));
                    }
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
                        reboot_required: false,
                        reboot_reason: None,
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
            // decide-before-touch convention as dig-store/dig-node/dig-dns above.
            let decision = apply_update_decision(&mut c, plan.force_reinstall, log);
            if decision.action != update::UpdateAction::Skip {
                let outcome = download_component(&c, plan.dry_run)?;
                report.restart_required |= log_write_outcome(log, "dig-updater", outcome);
            } else {
                log("    · already up to date — skipping the download");
            }
            if !plan.dry_run {
                note_binary_written(report, guard, &c.dest);
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
            let outcome = download_component(&worker, plan.dry_run)?;
            report.restart_required |= log_write_outcome(log, "dig-updater-worker", outcome);
            if !plan.dry_run {
                note_binary_written(report, guard, &worker.dest);
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
                let stop = service::stop_running_dig_relay(dest)
                    .map_err(InstallError::service_stop_failed)?;
                log(&format!(
                    "    {} {}",
                    if stop.attempted { "✓" } else { "·" },
                    stop.note
                ));
            }
            let outcome = download_component(&c, plan.dry_run)?;
            report.restart_required |= log_write_outcome(log, "dig-relay", outcome);
            if !plan.dry_run {
                note_binary_written(report, guard, &c.dest);
            }
            let relay_path = PathBuf::from(c.dest.clone());
            report.components.push(c);

            report.relay = Some(register_relay(&relay_path, plan, log));
            // The relay is opt-in + not update-tracked here, so any successful
            // registration this run is fresh and rollback-reversible.
            if report.relay.as_ref().is_some_and(|r| r.installed) {
                guard.record(InstallAction::ServiceRegistered(
                    svc::DIG_RELAY_SERVICE_ID.to_string(),
                ));
            }
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
                note_binary_written(report, guard, &c.dest);
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
            if report.scheme.as_ref().is_some_and(|s| s.registered) {
                guard.record(InstallAction::SchemeRegistered);
            }
        }

        // PATH verification (#496): confirm each required DIG CLI resolves by bare
        // name from a fresh shell, so the user can run `dig-node …` / `dig-dns …`
        // immediately. Non-dry-run only (dry-run installs nothing to resolve).
        if !plan.dry_run {
            link_protected_clis(&target, report, veneer_is_safe, log);
            verify_clis_on_path(&target, invoker::target_user(), report, log);
            #[cfg(unix)]
            {
                let wired = paths::reachable_dir(target.os, &plan.bin_dir, veneer_is_safe);
                report_preceding_unsafe_path_dirs(&target, &wired, report, log);
            }
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
                    if verdict.is_blocking() { "!" } else { "✓" },
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
                // #619: audit against the ACTUAL install root this run used (the
                // allowlist) — the default protected root, or the `--bin-dir`/GUI
                // dir the whole stack was redirected to. A registration whose
                // binary resolves anywhere else fails readiness.
                let expected_root = plan
                    .privileged_install_root(target.os)
                    .unwrap_or_else(paths::protected_bin_dir);
                report.registration_audit = regaudit::audit(target.os, &expected_root);
                for a in &report.registration_audit {
                    log(&format!(
                        "    {} {}",
                        if a.under_legacy_root { "!" } else { "✓" },
                        a.note
                    ));
                }
            }

            // #1748 (F9): AFTER the privileged verify above, because the dedupe inside asks whether that
            // verify actually produced a verdict. Called before it the guard could never fire, and the
            // same directory was reported twice on the default install.
            report_bin_dir_posture(plan, &target, report, log);
        }

        // Professional hardening (#573): register the Add/Remove Programs entry (its
        // Uninstall button runs the #568 whole-stack `uninstall`) and configure
        // service auto-recovery. Best-effort on a real Windows install — a failure is
        // logged, never fatal (the install itself already succeeded).
        #[cfg(windows)]
        if !plan.dry_run {
            apply_windows_hardening(plan, &target, guard, log);
        }

        Ok(())
    };

    // Run every install step; a mid-install failure rolls the completed
    // privileged steps back (LIFO, best-effort) BEFORE the error propagates, so
    // the guarantee SPEC §3.11 makes — "never a half-written install" — holds.
    match run_steps(&mut report, &mut guard, log) {
        Ok(()) => guard.commit(),
        Err(e) => {
            rollback_partial_install(&guard, &target, log);
            return Err(e);
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

/// Note a freshly written binary: append it to the install report AND record it
/// for rollback, so a later mid-install failure deletes it rather than leaving a
/// half-written stack (#573/#544). Called only on a real (non-dry-run) write.
fn note_binary_written(report: &mut InstallReport, guard: &mut RollbackGuard, dest: &str) {
    report.installed.push(dest.to_string());
    guard.record(InstallAction::FileCreated(dest.to_string()));
}

/// Reverse ONE recorded privileged install action (#573/#544). Best-effort and
/// idempotent: an already-absent target is a clean success, and a genuine
/// reversal failure is returned as `Err(msg)` so the LIFO rollback records it
/// and carries on rather than stranding the earlier steps. Never panics.
///
/// Each variant maps to the exact inverse of the step that recorded it:
///   * [`InstallAction::FileCreated`] → delete the written binary,
///   * [`InstallAction::ServiceRegistered`] → deregister the service by its
///     canonical id via the OS service manager,
///   * [`InstallAction::SchemeRegistered`] → unregister the `dig://`/`chia://`/
///     `urn:` handlers we created,
///   * [`InstallAction::ArpEntryWritten`] → remove the Add/Remove Programs entry,
///   * [`InstallAction::AutostartRegistered`] → remove dig-app's per-user login
///     autostart artifact (#912).
fn undo_install_action(action: &InstallAction) -> Result<(), String> {
    match action {
        InstallAction::FileCreated(path) => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove {path}: {e}")),
        },
        InstallAction::ServiceRegistered(id) => svc::deregister_service(id),
        InstallAction::SchemeRegistered => {
            // `unregister` is itself idempotent + best-effort (only ever removes
            // handlers that point at our `dign open`), so a reversal always
            // leaves the scheme registry no worse than pristine.
            scheme::unregister(false);
            Ok(())
        }
        InstallAction::AutostartRegistered => {
            // `deregister` treats an already-absent artifact as success, so the
            // reversal is idempotent like every other undo here.
            autostart::deregister(Target::current().map(|t| t.os).unwrap_or(target::Os::Linux))
        }
        InstallAction::ArpEntryWritten => {
            #[cfg(windows)]
            {
                hardening::remove_arp_entry().map(|_| ())
            }
            #[cfg(not(windows))]
            {
                Ok(())
            }
        }
    }
}

/// Reverse the privileged steps a partial-failure install recorded — LIFO,
/// best-effort (#573/#544) — so a mid-install failure never leaves a half-written
/// stack (SPEC §3.11). Every reversal (and any reversal that itself failed) is
/// logged; a stuck undo is surfaced, never fatal. A no-op when nothing privileged
/// was recorded yet (e.g. a failure during resolution, before the first write).
fn rollback_partial_install(
    guard: &RollbackGuard,
    _target: &Target,
    log: &mut dyn FnMut(&str),
) -> RollbackReport {
    if guard.actions().is_empty() {
        return RollbackReport {
            reversed: Vec::new(),
            failures: Vec::new(),
        };
    }
    log("Install failed partway — rolling back the completed steps (#573):");
    let report = guard.rollback(&mut |a| undo_install_action(a));
    for a in &report.reversed {
        log(&format!("    ↩ reversed {a:?}"));
    }
    for f in &report.failures {
        log(&format!("    ! rollback could not fully reverse {f}"));
    }
    report
}

/// Apply Windows install hardening (#573): register the Add/Remove Programs
/// entry (its Uninstall button runs the #568 whole-stack `uninstall`) and
/// configure SCM auto-recovery for every service this plan installed. Persists
/// the running installer to a stable path so the ARP Uninstall command keeps
/// working after a transient `irm|iex` download is gone. Best-effort — every
/// failure is logged, never fatal (the install already succeeded by this point).
///
/// The persisted installer + the machine-wide ARP `UninstallString` are pinned to
/// the admin-only [`paths::protected_bin_dir`] and only written when the verified
/// install root is owner-secure (#565): an elevated-exec pointer must NEVER be
/// planted in a user-writable custom `--bin-dir`.
#[cfg(windows)]
fn apply_windows_hardening(
    plan: &InstallPlan,
    target: &Target,
    guard: &mut RollbackGuard,
    log: &mut dyn FnMut(&str),
) {
    log("Registering the Add/Remove Programs entry + service auto-recovery (#573):");

    // #565: the persisted installer + the machine-wide ARP `UninstallString` are
    // an ELEVATED-EXEC pointer, so they are pinned to the admin-only protected
    // root — NEVER a user-chosen `--bin-dir`, which could be user-writable and let
    // an unprivileged user later repoint the pointer at an attacker binary. And we
    // write it ONLY when that protected root is genuinely owner-secure; otherwise
    // the machine-wide entry is skipped entirely (service auto-recovery, which
    // plants no such pointer, still proceeds below).
    let protected = paths::protected_bin_dir();
    let verdict = secure::verify_install_root(target.os, &protected);
    if verdict.is_blocking() {
        log(&format!(
            "    ! skipping the Add/Remove Programs entry — the protected install root is not \
             owner-secure ({})",
            verdict.note
        ));
    } else {
        // Persist the installer to the protected root for the ARP Uninstall command.
        let installer_bin = protected.join(target.exe_name("dig-installer"));
        if let Ok(current) = std::env::current_exe() {
            if current != installer_bin {
                if let Some(parent) = installer_bin.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::copy(&current, &installer_bin);
            }
        }

        let entry = hardening::arp_entry(env!("CARGO_PKG_VERSION"), &installer_bin, &protected);
        match hardening::write_arp_entry(&entry) {
            Ok(n) => {
                log(&format!("    ✓ {n}"));
                guard.record(InstallAction::ArpEntryWritten);
            }
            Err(e) => log(&format!("    ! {e}")),
        }
    }

    // Auto-recovery for each installed Windows service.
    let mut services = Vec::new();
    if plan.with_dig_node {
        services.push("net.dignetwork.dig-node");
    }
    if plan.with_dig_dns {
        services.push("net.dignetwork.dig-dns");
    }
    if plan.with_relay {
        services.push("net.dignetwork.dig-relay");
    }
    for svc in services {
        match hardening::configure_service_recovery(svc) {
            Ok(n) => log(&format!("    ✓ {n}")),
            Err(e) => log(&format!("    · {svc}: {e}")),
        }
    }
}

/// Register the `dig://`/`chia://`/`urn:` OS URL-scheme handlers (#567/#563),
/// each pointing at the installed `dign` binary run as `dign open "%1"`
/// (dig-node = the single URI-resolve-and-open authority). Never aborts — a
/// failure is recorded in the result. Reports intent on dry-run.
fn register_scheme_handler(
    plan: &InstallPlan,
    target: &Target,
    log: &mut dyn FnMut(&str),
) -> scheme::SchemeResult {
    // The `dign` alias (issue #548) is the local dig-node CLI the handlers
    // delegate to; it is installed alongside dig-node in the same run.
    let dign_bin = plan
        .bin_dir_for("dign", target.os)
        .join(target.exe_name("dign"));
    if plan.dry_run {
        let r = scheme::register(&dign_bin, true, true);
        log(&format!("    ({})", r.note));
        return r;
    }
    let r = scheme::register(&dign_bin, true, false);
    if r.registered {
        log(&format!("    ✓ {}", r.note));
    } else {
        log(&format!("    ! {}", r.note));
    }
    r
}

/// The user-facing DIG binaries that MUST be runnable by bare name after install.
///
/// The original set (#496) was the dig-store CLI plus the two node/dns CLIs a user drives directly
/// (e.g. `dig-node pair approve <id>`). #1748 adds the ALIAS binaries and `dig-app`, because a
/// component that was downloaded but never EXECUTED was earning a `✓` for existing on disk: a
/// `dig-app` that cannot load its shared libraries was reported as installed successfully. Anything
/// this installer places and a user is expected to run belongs here.
///
/// dig-relay is a background service (no user CLI surface required); the DIG Browser is a GUI
/// installer, not a CLI; the privileged `dig-updater`/`dig-updater-worker` binaries are invoked by
/// the beacon, never by the user, and live outside PATH by design (#565).
const REQUIRED_CLIS: &[&str] = &[
    "dig-store",
    "digs",
    "dig-node",
    "dign",
    "dig-dns",
    "digd",
    "dig-app",
];

/// The subset of [`REQUIRED_CLIS`] that is a GUI application rather than a command-line tool.
///
/// `dig-app` is the per-user tray agent, so it has no `--version` subcommand to answer. This is NOT a
/// blanket exemption from executability, and must not become one: see [`answers_version`].
const GUI_APPS: &[&str] = &["dig-app"];

/// Does `component` answer `--version`, so its install can be proven by RUNNING it?
///
/// Every real CLI does. A GUI app does not, on any platform: `dig-app --version` never returns,
/// because the binary enters its event loop instead of printing and exiting. The probe is then answered
/// by the [`pathcheck::VERSION_PROBE_TIMEOUT`] kill rather than by the app, which costs a guaranteed
/// 20-second stall and then FAILS the whole install (`✗ DIG is NOT ready`, exit 12) for a tray agent
/// that is behaving normally.
///
/// # This exemption is a known GAP, not a clean bill of health
///
/// Narrowing it to macOS was tried and REVERTED, on evidence. The claim was that Linux and Windows
/// `dig-app` does exit, so the probe would be meaningful there and would catch the real defect — on
/// stock Ubuntu `dig-app` dies with `libxdo.so.3: cannot open shared object file`. On a headless
/// ubuntu-latest runner it does NOT exit: the e2e install failed with
/// `dig-app --version did not finish within 20s and was killed` (run 30400688672). So the probe cannot
/// distinguish "cannot load" from "started fine" for this binary, and demanding it turns every headless
/// Linux install red.
///
/// What remains for `dig-app` is therefore RESOLUTION only ([`pathcheck::verify_cli_resolves`]) — the
/// #1748 property that the invoking user's login shell finds the copy this run placed — and the note it
/// emits says so explicitly rather than printing a bare `✓`. Nothing else makes up the difference:
/// [`autostart::register`] WRITES a unit file and never enables or starts it
/// ([`autostart::enable_command`] only prints advice a human must run), so a written unit is fully
/// consistent with a binary that cannot load.
///
/// Closing the gap needs a probe that does not require the process to EXIT — spawn it, observe briefly,
/// and treat "still running" as loaded while treating a loader failure (exit 126/127, or
/// `error while loading shared libraries` on stderr) as a hard failure. That is tracked separately
/// because it must be verified against a real headless box before it can gate an install.
fn answers_version(component: &str) -> bool {
    !GUI_APPS.contains(&component)
}

/// Link every installed user-facing CLI that lives in the protected root into the machine bin dir, so
/// it is reachable by bare name (#1748).
///
/// `dig-dns` must live in `/opt/dig/bin` because a machine-wide service executes it (#565), and that
/// directory is on no shell's default `PATH` — so `dig-dns doctor`, a command the docs tell users to
/// run, resolved for nobody. Both ends of the link are root-owned `0755`, so reachability is gained
/// without making a service-executed binary replaceable by an unprivileged user.
///
/// Best-effort: a link failure is logged and folded into readiness by the PATH verification that
/// follows (which will find the CLI unreachable), rather than aborting an otherwise-complete install.
fn link_protected_clis(
    target: &Target,
    report: &mut InstallReport,
    veneer_is_safe: bool,
    log: &mut dyn FnMut(&str),
) {
    #[cfg(unix)]
    {
        let to_link: Vec<(String, String)> = report
            .components
            .iter()
            .filter(|c| {
                // Keyed on where the binary actually landed, so a per-user or `--bin-dir` install
                // plants no links (#1748).
                let dir = std::path::Path::new(&c.dest)
                    .parent()
                    .unwrap_or(std::path::Path::new(""));
                paths::needs_machine_bin_link(target.os, &c.component, dir, veneer_is_safe)
            })
            .map(|c| (c.component.clone(), c.dest.clone()))
            .collect();
        // REMOVAL FIRST, and outside the `to_link` guard (#1748 F1).
        //
        // This block used to sit BELOW an `if to_link.is_empty() { return; }` early return, which made it
        // unreachable: `to_link` is built from `needs_machine_bin_link`, which is `reachability_for(..) ==
        // VeneerLinks`, so it is empty by construction exactly when `!veneer_is_safe` — the only condition
        // the removal runs under. A contradiction, and deleting the whole block left 685 tests passing,
        // because the only test that covered it called the helper directly and never traversed this seam.
        //
        // Shipped, that meant: a safe install plants the link, Homebrew arrives, `/usr/local/bin` becomes
        // `<user>:admin 0775`, root re-runs the installer and it reports ready with the stale link still
        // there for an unprivileged account to re-point.
        if !veneer_is_safe {
            // A link an earlier, safe-at-the-time run planted is a live vector once the directory is
            // writable, and only this installer can take it away. `/usr/local/bin` really does change
            // posture under us, and this is where that gets noticed.
            let names: Vec<String> = report
                .components
                .iter()
                .map(|c| target.exe_name(&c.component))
                .collect();
            let removed = paths::remove_veneer_links(&names, target.os);
            if removed.is_empty() {
                log(&format!(
                    "    · no link planted in {} — it is not safe to resolve DIG commands from, so the                      protected root is on PATH directly instead",
                    paths::UNIX_MACHINE_BIN_DIR
                ));
            } else {
                for link in &removed {
                    log(&format!(
                        "    ✓ removed {link} — a link in a directory a non-root account can write is one                          they can re-point, and root runs whatever it points at"
                    ));
                }
            }
            report.veneer_links_removed = removed;
        }

        if to_link.is_empty() {
            return;
        }
        log(&format!(
            "Linking the protected-root CLIs into {}:",
            paths::UNIX_MACHINE_BIN_DIR
        ));
        for (component, dest) in to_link {
            let exe = target.exe_name(&component);
            match paths::link_into_machine_bin(std::path::Path::new(&dest), &exe) {
                Ok(link) => log(&format!("    ✓ {} → {dest}", link.display())),
                Err(e) => log(&format!("    ! could not link {component}: {e}")),
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Windows installs the whole stack into one root, so there is nothing to link.
        let _ = (target, report, log);
    }
}

/// Record every directory that precedes the wired install directory on the target user's login `PATH` and
/// is NOT established safe (#1748 F2).
///
/// Prepending the protected root is the primary fix, but it cannot always win: a user's own `.bashrc` runs
/// after `/etc/profile.d`, and on macOS `path_helper` composes `/etc/paths` — which ships `/usr/local/bin` —
/// before `/etc/paths.d/*`. So position is VERIFIED rather than assumed, and a losing `PATH` fails readiness
/// instead of reporting a green install whose commands an attacker can claim at any time.
///
/// Only meaningful under elevation, and only for directories a non-root account can actually write: the
/// ordinary `/usr/bin`/`/bin` entries precede us on every box and are root-owned, which is fine.
#[cfg(unix)]
fn report_preceding_unsafe_path_dirs(
    target: &Target,
    wired: &std::path::Path,
    report: &mut InstallReport,
    log: &mut dyn FnMut(&str),
) {
    if !invoker::is_root() {
        return;
    }
    let user = invoker::target_user();
    let Ok(path) = pathcheck::login_shell_path(user) else {
        // The PATH itself could not be read; `verify_clis_on_path` already reports that failure, and
        // guessing here would only duplicate it.
        return;
    };
    let wired_str = wired.to_string_lossy().to_string();
    let unsafe_before: Vec<String> = pathcheck::entries_before(&path, &wired_str, ':')
        .into_iter()
        .filter(|dir| {
            secure::verify_install_root(target.os, std::path::Path::new(dir)).is_blocking()
        })
        .collect();
    if unsafe_before.is_empty() {
        return;
    }
    log(&format!(
        "    ! these directories come BEFORE {wired_str} on {}'s PATH and are not safe: {}",
        user.name,
        unsafe_before.join(", ")
    ));
    log("    · a non-root account can create a DIG command name there and win the resolution");
    report.preceding_unsafe_path_dirs = unsafe_before;
}

/// Report the permission posture of the directory this run's binaries were PLACED in, when that is not
/// already covered by the privileged-root verify (#1748).
///
/// The #565 check is applied to [`InstallPlan::privileged_install_root`], which is the protected root —
/// so on every elevated unix install before this, the directory root actually wrote to and executed from
/// was neither checked nor mentioned. That is precisely how `/usr/local/bin`, user-writable under
/// Homebrew, became the install root without anything noticing.
///
/// Always REPORTED; fatal only under ELEVATION ([`evaluate_readiness`]). Root wrote those binaries and
/// root-side execs and services resolve them, so a writable directory is an escalation there — whereas
/// unelevated it is the user's own authority, and refusing would turn away every ordinary per-user install
/// and every Homebrew Mac. What must never happen either way is SILENCE: the posture is logged and lands
/// in `install.json` as [`InstallReport::bin_dir_security`], so a reviewer or a script can see it.
fn report_bin_dir_posture(
    plan: &InstallPlan,
    target: &Target,
    report: &mut InstallReport,
    log: &mut dyn FnMut(&str),
) {
    let bin_dir = &plan.bin_dir;
    // Skip only when the privileged verify ACTUALLY RAN on this exact directory — one verdict per dir,
    // no duplicated log line on the common default install.
    //
    // `report.install_root_security` rather than `privileged_install_root()`, because those two came
    // apart (#1748). The #565 verify is gated on the plan selecting a PRIVILEGED component, while since
    // the veneer every ELEVATED install places its binaries in the protected root. So a CLI-only sudo
    // install wrote into `/opt/dig/bin`, linked `/usr/local/bin` at it, and nothing checked the
    // directory's mode at all — which is how a world-writable protected root reached a green install.
    if report.install_root_security.is_some()
        && plan.privileged_install_root(target.os).as_ref() == Some(bin_dir)
    {
        return;
    }
    let verdict = secure::verify_install_root(target.os, bin_dir);
    log(&format!(
        "Install directory posture ({}):",
        bin_dir.display()
    ));
    log(&format!(
        "    {} {}",
        if verdict.is_blocking() {
            // `!` because it is worth a human's attention, but readiness is unaffected: see the doc above.
            "!"
        } else {
            "✓"
        },
        verdict.note
    ));
    report.bin_dir_security = Some(verdict);
}

/// Verify each installed user-facing binary resolves by bare name **on the target user's own PATH**
/// and actually RUNS (#496, corrected by #1748), recording the result into `report.cli_path_checks`.
///
/// Only binaries actually placed this run (present in `report.components`) are checked. A failure is
/// folded into the readiness verdict by [`evaluate_readiness`].
///
/// # Why this no longer takes the install's bin dir
///
/// It used to: it read each component's install directory, prepended that directory to our own
/// `PATH`, and checked the CLI resolved against the result — which is always true once the download
/// succeeded, in every environment. The check therefore passed against a `sudo` install that had put
/// the whole stack in `/root/.dig/bin`, where no user could reach it. The PATH is now READ from the
/// target user's login shell and never modified, so the only way to pass is for the install to
/// genuinely be reachable by the person who ran it. See [`pathcheck`].
fn verify_clis_on_path(
    target: &Target,
    user: &invoker::TargetUser,
    report: &mut InstallReport,
    log: &mut dyn FnMut(&str),
) {
    // Each CLI is carried with the destination THIS run wrote it to, so the check can confirm the
    // bare name resolves to that copy rather than to a stale one left on PATH by an earlier install.
    let installed_clis: Vec<(String, String)> = report
        .components
        .iter()
        .filter(|c| REQUIRED_CLIS.contains(&c.component.as_str()))
        .map(|c| (c.component.clone(), c.dest.clone()))
        .collect();
    if installed_clis.is_empty() {
        return;
    }
    log(&format!(
        "Verifying the DIG CLIs resolve + run in {}'s login shell:",
        user.name
    ));
    for (cli, dest) in installed_clis {
        let exe = target.exe_name(&cli);
        let dest_path = std::path::Path::new(&dest);
        let outcome = if answers_version(&cli) {
            pathcheck::verify_cli(user, &exe, dest_path).map(|version| {
                format!(
                    "`{cli} --version` resolved + ran as {} ({version})",
                    user.name
                )
            })
        } else {
            pathcheck::verify_cli_resolves(user, &exe, dest_path).map(|resolved| {
                format!(
                    "`{cli}` resolves to {} on {}'s PATH — NOT verified to run (a GUI app with \
                     no `--version`; on macOS the probe never returns)",
                    resolved.display(),
                    user.name
                )
            })
        };
        let check = match outcome {
            Ok(note) => {
                log(&format!("    ✓ {note}"));
                pathcheck::CliPathCheck {
                    cli: cli.clone(),
                    resolved: true,
                    note,
                }
            }
            Err(e) => {
                log(&format!("    ! {cli} is NOT usable by {}: {e}", user.name));
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
    evaluate_readiness_when(plan, report, invoker::is_root())
}

/// [`evaluate_readiness`] with the elevated-ness supplied instead of read from the ambient uid.
///
/// The last gate in the crate to get this seam, and it needed it for the same reason as the others: the
/// `is_root()` branch below is only reachable when the test process really is root, so on an unprivileged
/// runner replacing it with `false` changed nothing observable and the suite stayed green — including the
/// test named `an_elevated_install_into_a_writable_directory_is_fatal`, whose own doc claimed both arms
/// were covered (#1748 C3).
fn evaluate_readiness_when(
    plan: &InstallPlan,
    report: &InstallReport,
    elevated: bool,
) -> Vec<String> {
    let mut failures = Vec::new();
    if plan.dry_run {
        return failures;
    }

    if plan.with_dig_node {
        match &report.service {
            None => failures.push("dig-node: the node service was not installed".to_string()),
            Some(s) if !s.installed => failures.push(format!(
                "dig-node: the OS service did not register ({})",
                s.note
            )),
            Some(s) if plan.service.start && !s.health_ok => failures.push(format!(
                "dig-node: the '{}' service is not running ({})",
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
                "dig-dns: the OS service did not register ({})",
                d.note
            )),
            // F7: gate on the fail-loud service-manager RUNNING poll (mirror the
            // dig-node `health_ok` gate) — a live `paths_live` probe alone is NOT
            // sufficient (another process could satisfy it; #493 false-success).
            Some(d) if plan.dns_service.start && !d.service_running => failures.push(format!(
                "dig-dns: installed but the '{}' service did not reach RUNNING ({})",
                svc::DIG_DNS_SERVICE_ID,
                d.note
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
                "dig-relay: the OS service did not register ({})",
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
            None => {
                failures.push("dig-updater: the auto-update beacon was not installed".to_string())
            }
            Some(b) if !b.applied => failures.push(format!(
                "dig-updater: the daily update-check scheduler did not register ({})",
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
                "{}: the machine-wide state directory could not be hardened + verified ({})",
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
        if sec.is_blocking() {
            failures.push(format!(
                "install root {}: {} — a non-admin could replace a privileged service binary; \
                 repair the directory permissions",
                sec.root, sec.note
            ));
        }
    }

    // #1748: the same rule for the directory this run's binaries were PLACED in, when the check above
    // did not cover it — but FATAL only under elevation.
    //
    // Elevation is what makes a writable directory an escalation rather than a preference: root wrote
    // the binaries, `/usr/local/bin` links point into them, and services and root-side execs resolve
    // them. A CLI-only `sudo` install selects no privileged component, so the gate above never fired,
    // and a world-writable protected root shipped as a fully green install.
    //
    // Unelevated it stays a REPORT: a directory holding binaries only that same user runs is their own
    // authority, and failing on it would refuse every ordinary per-user install and every Homebrew Mac.
    // #1748 F2: a directory that PRECEDES our install dir on root's PATH and is not established safe means
    // an attacker can create a DIG command name there and win the resolution — without touching anything
    // this installer placed. The existing shadow check only sees a file that is already there, so position
    // is its own failure.
    if elevated && !report.preceding_unsafe_path_dirs.is_empty() {
        failures.push(format!(
            "PATH order: {} precede{} the DIG install directory on root's PATH and are not root-owned              without group/other write — a non-root account can create `dign`/`digs` there and root will              run it; repair those directories or remove them from root's PATH",
            report.preceding_unsafe_path_dirs.join(", "),
            if report.preceding_unsafe_path_dirs.len() == 1 { "s" } else { "" }
        ));
    }

    // #1748: the veneer is fatal ONLY when it is the mechanism in play.
    //
    // When links are planted there, an account that can write the directory re-points one and root runs
    // whatever it points at — a live escalation, so the install must not report ready. When the run FELL
    // BACK (`Reachability::DirectPathEntry`), the same unsafe verdict is a recorded downgrade rather than a
    // failure: no link was planted, any earlier one was removed, and reachability comes from a chain root
    // owns end to end. Failing then would be a refusal — and a refusal is not a fix.
    if elevated && report.reachability == Some(paths::Reachability::VeneerLinks) {
        if let Some(sec) = &report.veneer_security {
            if sec.is_blocking() {
                failures.push(format!(
                    "PATH directory {}: {} — this is where root's own shell resolves DIG commands, so an                      account that can write there replaces a link this installer planted and root runs it;                      repair the directory permissions",
                    sec.root, sec.note
                ));
            }
        }
    }

    if elevated {
        if let Some(sec) = &report.bin_dir_security {
            if sec.is_blocking() {
                failures.push(format!(
                    "install directory {}: {} — an elevated install wrote binaries there, so a \
                     non-root account could replace one root or a service later executes; repair the \
                     directory permissions",
                    sec.root, sec.note
                ));
            }
        }
    }

    // #565 (review — H2a): a privileged registration that could NOT be
    // deregistered off the legacy root during migration is FATAL — continuing
    // into a tolerated re-install could leave the service/task pointing at the
    // writable legacy binPath.
    if let Some(m) = &report.migration {
        for f in &m.deregister_failures {
            failures.push(format!(
                "migration: {f}; the privileged registration must be re-pointed \
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

    // PATH resolution (#496): any required CLI the TARGET USER cannot resolve by bare name in a
    // fresh login shell, or that resolves but does not run, makes the install NOT ready — the user
    // could not run `dig-node …` / `dig-dns …` otherwise.
    //
    // The remediation is the check's own note and nothing more (#1748). It used to append "open a new
    // terminal or re-run elevated", which was advice the reader could not act on: the check now runs
    // in a *fresh* login shell, so opening another terminal changes nothing, and the failing install
    // that prompted this was already elevated — being told to elevate it again sent people looking for
    // a privilege problem that was never there.
    for check in &report.cli_path_checks {
        if !check.resolved {
            failures.push(format!("{}: {}", check.cli, check.note));
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
        if report.restart_required {
            // A reboot-deferred replace must NOT read as fully done (#562): the
            // install succeeded but a locked binary's update applies only after
            // a restart. Say so unmistakably at the final verdict.
            log("✓ DIG is installed — RESTART REQUIRED to finish applying an update to a component that was running (its new version is staged for the next reboot).");
        } else {
            log("✓ DIG is ready.");
        }
    } else {
        log("✗ DIG is NOT ready — the following component(s) failed:");
        for f in &report.failures {
            log(&format!("    - {f}"));
        }
        log("Fix the above and run the installer again.");
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
                "    ! service health: {} — the resolver may not be serving.",
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

/// Resolve the dig-store CLI, falling back to the pre-rename `dig-store-*` asset
/// stem if the release only carries the old-named assets (epic #703). The repo
/// redirect covers the URL, but the asset STEM changed (`dig-store-*` →
/// `dig-store-*`), so this tries the new stem first and the legacy stem second —
/// mirroring [`resolve_dig_node`]. Either way the on-PATH binary is normalized to
/// `dig-store` so the component id + install path stay consistent.
fn resolve_dig_store(
    resolve: &ReleaseResolver<'_>,
    requested: &Option<String>,
    target: &Target,
    bin_dir: &std::path::Path,
    log: &mut dyn FnMut(&str),
) -> Result<ComponentResult, InstallError> {
    // The asset matcher only *prefers* the queried stem — it does not require it
    // — so against a pre-rename release (which carries `digstore-*`/`digs-*` but
    // no `dig-store-*`) a query for stem `dig-store` would soft-match the wrong
    // binary. Accept the primary result only when it truly resolved a
    // `dig-store-*` asset; otherwise fall through to the legacy stem.
    let primary = resolve_component(
        resolve,
        &Repo::dig_store(),
        requested,
        target,
        AssetKind::RawBinary,
        bin_dir,
    );
    match primary {
        Ok(c) if c.asset.starts_with("dig-store") => Ok(c),
        primary => {
            log("    (no dig-store-* asset; trying the pre-rename digstore asset stem…)");
            // The legacy stem is `digstore`; normalize the on-PATH name back to
            // dig-store so the component id + later use stay consistent.
            match resolve_component(
                resolve,
                &Repo::dig_store_legacy(),
                requested,
                target,
                AssetKind::RawBinary,
                bin_dir,
            ) {
                Ok(mut c) => {
                    c.component = "dig-store".to_string();
                    c.dest = bin_dir
                        .join(target.exe_name("dig-store"))
                        .to_string_lossy()
                        .into_owned();
                    Ok(c)
                }
                // The legacy stem also failed. Prefer the primary dig-store error
                // (the current name) when there was one; a soft-matched-but-wrong
                // primary means the release has neither CLI asset, so surface the
                // legacy miss.
                Err(legacy) => match primary {
                    Ok(_) => Err(legacy),
                    Err(primary_err) => Err(primary_err),
                },
            }
        }
    }
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
            log(&format!("    ! health check FAILED: {note}"));
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
/// Never touches the dig-store/browser/relay/dig-dns installs. Never
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
/// dig-store/dig-node/dig-dns/relay/browser installs, and never deletes the
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

/// The production [`uninstall::UninstallActions`] — wires the real per-component
/// teardown functions behind the injectable action interface so the whole-stack
/// `uninstall` orchestration ([`uninstall::orchestrate`]) can drive them while
/// its ordering + residue accounting stay purely unit-tested.
struct SystemActions<'a> {
    bin_dir: std::path::PathBuf,
    dry_run: bool,
    browser_ids: Vec<String>,
    log: &'a mut dyn FnMut(&str),
}

impl<'a> SystemActions<'a> {
    /// Resolve an installed component binary path (either bin root) for the
    /// current target, preferring the protected root when the component lives
    /// there. Returns the first existing candidate, else the default-root path.
    fn component_bin(&self, target: &Target, stem: &str) -> std::path::PathBuf {
        let name = target.exe_name(stem);
        let candidates = [
            paths::protected_bin_dir().join(&name),
            self.bin_dir.join(&name),
        ];
        candidates
            .iter()
            .find(|p| p.exists())
            .cloned()
            .unwrap_or_else(|| self.bin_dir.join(&name))
    }
}

/// Resolve the absolute path of the INSTALLED `dig-dns` binary under `bin_dir`
/// (or the protected bin dir), returning `Some` only when it actually exists.
/// The standalone `--uninstall-dig-dns` action (#627 WU2) passes this to
/// [`dns::uninstall`] so its resolver teardown shells out to `dig-dns
/// unconfigure-os` by ABSOLUTE path — never a bare `dig-dns` resolved through
/// `PATH` on an elevated process (#565/#657). `None` when no binary is present
/// (nothing to un-wire).
pub fn installed_dig_dns_bin(bin_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let target = Target::current().ok()?;
    let name = target.exe_name("dig-dns");
    [paths::protected_bin_dir().join(&name), bin_dir.join(&name)]
        .into_iter()
        .find(|p| p.exists())
}

/// Did the dig-dns service teardown FAIL to remove the service registration —
/// so its binaries (dig-dns + the digd alias) must be left in place (never
/// deleted) to avoid orphaning a still-registered service (blocker #4)? Gates on
/// the explicit [`dns::DnsUninstallResult::service_removed`] signal — NOT on
/// `uninstalled`, which is `true` when merely a non-service artifact (NRPT rule
/// / browser policy) was removed even though the service deregister itself
/// failed on an elevated run. Pure.
fn dns_service_teardown_failed(dns: &dns::DnsUninstallResult) -> bool {
    !dns.service_removed
}

/// Does a service-teardown `Err` indicate the LAUNCHER BINARY could not be run
/// (missing/unspawnable), rather than the service manager replying? A spawn
/// failure surfaces through [`service::run_capturing`]'s stable `"could not run
/// …"` marker (and the raw OS "no such file"/"cannot find the file"/`os error 2`
/// text). When the launcher is gone we CANNOT confirm the service registration
/// was removed, so this must never be treated as "already absent". Pure.
fn is_launcher_spawn_failure(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("could not run")
        || e.contains("no such file")
        || e.contains("cannot find the file")
        || e.contains("os error 2")
}

/// Is a service-teardown `Err` the idempotent "the service registration is
/// already gone" case (a clean no-op), rather than a real failure? This is
/// TRUE only for a genuine service-MANAGER reply that no such service exists —
/// NOT for a launcher spawn failure ([`is_launcher_spawn_failure`], which leaves
/// the registration state unknown and so is never "absent"). Pure.
fn service_absent_is_ok(err: &str) -> bool {
    if is_launcher_spawn_failure(err) {
        return false;
    }
    let e = err.to_ascii_lowercase();
    e.contains("does not exist")
        || e.contains("not exist")
        || e.contains("not installed")
        || e.contains("not registered")
        || e.contains("no such service")
        || e.contains("service absent")
}

impl uninstall::UninstallActions for SystemActions<'_> {
    fn stop_services(&mut self) -> uninstall::ServiceTeardown {
        let target = match Target::current() {
            Ok(t) => t,
            Err(e) => {
                return uninstall::ServiceTeardown {
                    ok: false,
                    note: format!("could not detect target: {e}"),
                    // Target unknown → we cannot safely delete ANY service
                    // binary; mark them all as not-torn-down.
                    failed_components: vec![
                        "dig-node".into(),
                        "dig-relay".into(),
                        "dig-dns".into(),
                        "digd".into(),
                    ],
                };
            }
        };
        if self.dry_run {
            return uninstall::ServiceTeardown {
                ok: true,
                note: "would stop + deregister the dig-node, dig-relay, and dig-dns services"
                    .into(),
                failed_components: Vec::new(),
            };
        }
        let mut ok = true;
        let mut notes = Vec::new();
        let mut failed: Vec<String> = Vec::new();
        for stem in ["dig-node", "dig-relay"] {
            let bin = self.component_bin(&target, stem);
            // Structured launcher-gone signal: if the deregister binary is
            // missing we cannot run it, so the service state is UNKNOWN — never
            // "already absent". Its binary is gone anyway; mark it failed so the
            // run is not falsely reported complete.
            if !bin.exists() {
                ok = false;
                failed.push(stem.to_string());
                notes.push(format!(
                    "{stem}: launcher binary missing — cannot deregister its service (re-run after reinstall, or remove the service manually)"
                ));
                continue;
            }
            match service::uninstall_service(&bin) {
                Ok(n) => notes.push(format!("{stem}: {n}")),
                Err(e) if service_absent_is_ok(&e) => notes.push(format!("{stem}: already absent")),
                Err(e) => {
                    ok = false;
                    failed.push(stem.to_string());
                    notes.push(format!("{stem}: {e}"));
                }
            }
        }
        // dig-dns has its own teardown (service + DNS wiring). Gate on the
        // explicit `service_removed` signal — NOT `uninstalled` (which is true
        // when ANY artifact, e.g. an NRPT rule or browser policy, was removed
        // even if the SERVICE deregister itself failed). When the service is not
        // confirmed gone (a failed deregister, or an unelevated run), its
        // binaries (dig-dns + the digd alias) must be left in place — deleting
        // them would orphan a still-registered service pointing at a missing
        // ImagePath (the blocker-#4 orphan).
        // #627 WU2: the resolver/browser-policy teardown is delegated to
        // `dig-dns unconfigure-os`, so pass the installed binary's absolute path
        // (this teardown runs BEFORE `delete_binaries`, so the binary is still
        // present). An absent binary ⇒ `None` ⇒ the resolver teardown is skipped
        // best-effort; the service-registration teardown still runs.
        let dig_dns_bin = self.component_bin(&target, "dig-dns");
        let dns = dns::uninstall(dig_dns_bin.exists().then_some(dig_dns_bin.as_path()), false);
        notes.push(format!("dig-dns: {}", dns.note));
        if dns_service_teardown_failed(&dns) {
            ok = false;
            failed.push("dig-dns".to_string());
            failed.push("digd".to_string());
        }
        uninstall::ServiceTeardown {
            ok,
            note: notes.join("; "),
            failed_components: failed,
        }
    }

    fn remove_beacon(&mut self) -> (bool, String) {
        // Idempotent: an absent scheduler registration is a clean no-op.
        let r = uninstall_beacon(&self.bin_dir, self.dry_run, &mut *self.log);
        (true, r.note)
    }

    fn unregister_scheme(&mut self) -> (bool, String) {
        // Only DIG-owned handlers are removed; absent is a clean no-op.
        let r = scheme::unregister(self.dry_run);
        (true, r.note)
    }

    fn remove_network_config(&mut self) -> (bool, String) {
        if self.dry_run {
            return (
                true,
                "would remove the dig.local hosts entry + the peer firewall rule".into(),
            );
        }
        let mut ok = true;
        let mut notes = Vec::new();
        match hosts::remove_dig_local() {
            Ok(Some(n)) => notes.push(n),
            Ok(None) => notes.push("dig.local: already absent".into()),
            Err(e) => {
                ok = false;
                notes.push(format!("dig.local: {e} (re-run elevated)"));
            }
        }
        if let Ok(target) = Target::current() {
            let node_bin = self.component_bin(&target, "dig-node");
            let fw = firewall::close(&node_bin, false);
            notes.push(fw.note);
        }
        (ok, notes.join("; "))
    }

    fn delete_binaries(&mut self, skip: &[String]) -> (bool, String) {
        let target = match Target::current() {
            Ok(t) => t,
            Err(e) => return (false, format!("could not detect target: {e}")),
        };
        let current = std::env::current_exe().ok();
        let roots = [self.bin_dir.clone(), paths::protected_bin_dir()];
        if self.dry_run {
            return (true, "would delete all installed DIG binaries".into());
        }
        let mut ok = true;
        let mut removed = 0usize;
        let mut errs = Vec::new();
        for stem in uninstall::COMPONENT_STEMS {
            // Blocker #4: never delete a binary whose service could not be
            // deregistered — that would orphan a still-registered service
            // pointing at a missing ImagePath. Leave it for an elevated re-run.
            if skip.iter().any(|s| s == stem) {
                continue;
            }
            for root in &roots {
                let path = root.join(target.exe_name(stem));
                if !path.exists() {
                    continue;
                }
                // The running installer cannot delete its own image on Windows;
                // leave it for OS cleanup rather than fail the whole uninstall.
                if current.as_deref() == Some(path.as_path()) {
                    continue;
                }
                match std::fs::remove_file(&path) {
                    Ok(()) => removed += 1,
                    Err(e) => {
                        ok = false;
                        errs.push(format!("{}: {e}", path.display()));
                    }
                }
            }
        }
        // The VENEER links go too (#1748 F4). They live in neither bin root, so the residue scan below never
        // looked at them and an uninstall reported `residue: []` while `/usr/local/bin/digs` still pointed at
        // a binary that no longer exists. That is a false machine-consumed claim on its own — `--uninstall`
        // promises zero residue — and it hands the stale-link escalation its starting state: the next time
        // `/usr/local/bin` becomes writable, there is a DIG-named link sitting there for the taking.
        //
        // Unconditional, and it does not care about the veneer's posture: on uninstall we are removing our
        // own links either way. `remove_links_in`'s discrimination still applies, so a foreign entry of the
        // same name is left alone.
        #[cfg(unix)]
        {
            let names: Vec<String> = uninstall::COMPONENT_STEMS
                .iter()
                .filter(|stem| !skip.iter().any(|s| s == *stem))
                .map(|stem| target.exe_name(stem))
                .collect();
            removed += paths::remove_veneer_links(&names, target.os).len();
        }

        // Remove the Add/Remove Programs entry alongside the binaries (Windows).
        #[cfg(windows)]
        let note_extra = match hardening::remove_arp_entry() {
            Ok(n) => format!("; {n}"),
            Err(e) => {
                ok = false;
                format!("; ARP: {e}")
            }
        };
        #[cfg(not(windows))]
        let note_extra = String::new();
        let note = if errs.is_empty() {
            format!("deleted {removed} binary(ies){note_extra}")
        } else {
            format!("deleted {removed}; failed: {}{note_extra}", errs.join(", "))
        };
        (ok, note)
    }

    fn unconfigure_forcelist(&mut self) -> (bool, String) {
        if self.dry_run {
            return (true, "would unconfigure the extension forcelist".into());
        }
        let outcomes = unconfigure_extension_forcelist(&self.browser_ids);
        let failed: Vec<_> = outcomes
            .iter()
            .filter(|o| o.action == forcelist::ForcelistAction::Failed)
            .map(|o| o.note.clone())
            .collect();
        if failed.is_empty() {
            (
                true,
                "extension forcelist unconfigured (DIG entry only)".into(),
            )
        } else {
            (false, format!("forcelist: {}", failed.join(", ")))
        }
    }

    fn remove_login_path_fragment(&mut self) -> (bool, String) {
        let fragments = paths::login_path_fragment_files();
        if fragments.is_empty() {
            return (true, "no system-wide PATH fragment on this platform".into());
        }
        if self.dry_run {
            return (true, format!("would remove {}", fragments.join(", ")));
        }
        let mut removed = Vec::new();
        let mut failed = Vec::new();
        for f in fragments {
            match std::fs::remove_file(f) {
                Ok(()) => removed.push(f),
                // Absent is the desired end-state, so an unelevated or repeat run is not a failure.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => failed.push(format!("{f}: {e}")),
            }
        }
        if failed.is_empty() {
            let note = if removed.is_empty() {
                "no system-wide PATH fragment to remove".to_string()
            } else {
                format!("removed {}", removed.join(", "))
            };
            (true, note)
        } else {
            (false, format!("PATH fragment: {}", failed.join(", ")))
        }
    }

    fn scan_residue(&mut self) -> Vec<String> {
        if self.dry_run {
            return Vec::new();
        }
        let target = match Target::current() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        let current = std::env::current_exe().ok();
        // The VENEER is scanned as a root of its own (#1748 F4): its links live in neither bin dir, so an
        // uninstall used to report `residue: []` with `/usr/local/bin/digs` still present and dangling.
        // `--uninstall` promises zero residue, and a stale DIG-named entry is also the starting state the
        // stale-link escalation needs.
        let mut roots = vec![self.bin_dir.clone(), paths::protected_bin_dir()];
        #[cfg(unix)]
        roots.push(std::path::PathBuf::from(paths::UNIX_MACHINE_BIN_DIR));
        let mut residue = Vec::new();
        for stem in uninstall::COMPONENT_STEMS {
            for root in &roots {
                let path = root.join(target.exe_name(stem));
                // The running installer image is exempt (self-delete is impossible
                // while running; OS cleanup handles it).
                if current.as_deref() == Some(path.as_path()) {
                    continue;
                }
                // `symlink_metadata`, not `exists()`: a DANGLING symlink left in the veneer is exactly the
                // residue this scan exists to find, and `exists()` follows the link and reports nothing.
                if std::fs::symlink_metadata(&path).is_ok() {
                    residue.push(path.display().to_string());
                }
            }
        }
        residue
    }
}

/// Run the first-class whole-stack `uninstall` (#568): stop + deregister ALL
/// services, remove ALL config, delete ALL binaries, unconfigure the extension
/// forcelist — idempotent, and leaving zero residue. Never deletes pre-existing
/// org policy the installer did not create (each step is DIG-scoped). Reports a
/// structured [`uninstall::UninstallReport`]; on a real run
/// [`uninstall::UninstallReport::complete`] proves the zero-residue outcome.
pub fn uninstall_all(
    bin_dir: &std::path::Path,
    browser_ids: &[String],
    dry_run: bool,
    log: &mut dyn FnMut(&str),
) -> uninstall::UninstallReport {
    log(if dry_run {
        "Planning a full DIG uninstall (dry-run — nothing will be removed):"
    } else {
        "Uninstalling the entire DIG install (services, config, binaries):"
    });
    let mut actions = SystemActions {
        bin_dir: bin_dir.to_path_buf(),
        dry_run,
        browser_ids: browser_ids.to_vec(),
        log,
    };
    let report = uninstall::orchestrate(&mut actions, dry_run);
    for step in &report.steps {
        (actions.log)(&format!(
            "    {} {}: {}",
            if step.ok { "✓" } else { "!" },
            step.id,
            step.note
        ));
    }
    if !dry_run {
        if report.complete() {
            (actions.log)("    ✓ uninstall complete — zero residue");
        } else if !report.residue.is_empty() {
            (actions.log)(&format!(
                "    ! residual items remain: {}",
                report.residue.join(", ")
            ));
        }
    }
    report
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
    dig-store CLI + the dig-node boot-start service + the dig-app per-user identity agent + the     dig-dns boot-start service) in one run, \
    resolving + downloading the latest per-OS/arch release asset for each. dig-relay and the DIG \
    Browser are opt-in.",
        "components": [
            { "id": "dig-store", "repo": "DIG-Network/digs", "default": true, "flag": "--no-dig-store disables", "kind": "raw_binary" },
            { "id": "digs", "repo": "DIG-Network/digs", "default": true, "flag": "alias of dig-store — no separate flag; follows --no-dig-store/--with-dig-store/--dig-store-version", "kind": "raw_binary_alias" },
            { "id": "dig-node", "repo": "DIG-Network/dig-node", "default": true, "flag": "--no-dig-node disables; --with-dig-node/--service redundant", "kind": "raw_binary+boot-start-service+dig.local+health-check" },
            { "id": "dign", "repo": "DIG-Network/dig-node", "default": true, "flag": "alias of dig-node — no separate flag; follows --no-dig-node/--with-dig-node/--dig-node-version", "kind": "raw_binary_alias" },
            { "id": "dig-app", "repo": "DIG-Network/dig-app", "default": true, "flag": "--no-dig-app disables; --with-dig-app redundant; --no-dig-app-autostart keeps the binary but skips the login registration", "kind": "raw_binary+per-user-login-autostart" },
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
            { "flag": "--no-dig-store", "description": "opt out of the dig-store CLI (installed by default)" },
            { "flag": "--with-dig-store", "description": "explicit (redundant) opt-in — dig-store installs by default" },
            { "flag": "--dig-store-version", "value": "VERSION", "description": "pin dig-store version (default: latest)" },
            { "flag": "--no-dig-node", "description": "opt out of the dig-node local node + service (installed by default)" },
            { "flag": "--with-dig-node", "alias": "--service", "description": "explicit (redundant) opt-in — dig-node installs + starts as a boot-start service by default" },
            { "flag": "--dig-node-version", "value": "VERSION", "description": "pin dig-node version (default: latest)" },
            { "flag": "--dig-node-port", "value": "PORT", "default": dig_constants::DIG_NODE_PORT, "description": "loopback port for the dig-node service" },
            { "flag": "--no-service-start", "description": "install the service(s) but do not start them (still registered boot-start)" },
            { "flag": "--uninstall-dig-node", "description": "uninstall the dig-node OS service + remove the dig.local hosts entry + remove the firewall rule this installer created (idempotent; does not touch the dig-store/browser/relay/dig-dns installs)" },
            { "flag": "--with-browser", "description": "download the DIG Browser native installer (opt-in)" },
            { "flag": "--browser-version", "value": "VERSION", "description": "pin DIG Browser version (default: latest)" },
            { "flag": "--with-relay", "description": "install + start dig-relay as a service (run-your-own-relay; advanced, opt-in — the default node uses relay.dig.net)" },
            { "flag": "--relay-version", "value": "VERSION", "description": "pin dig-relay version (default: latest)" },
            { "flag": "--relay-port", "value": "PORT", "default": 9450, "description": "relay WebSocket port for the relay service" },
            { "flag": "--relay-health-port", "value": "PORT", "default": 9451, "description": "relay HTTP /health port for the relay service" },
            { "flag": "--no-dig-app", "description": "opt out of the dig-app identity agent (installed by default)" },
            { "flag": "--with-dig-app", "description": "explicit (redundant) opt-in — dig-app installs + registers a per-user login autostart by default" },
            { "flag": "--dig-app-version", "value": "VERSION", "description": "pin dig-app version (default: latest)" },
            { "flag": "--no-dig-app-autostart", "description": "install dig-app without registering it to start at login (it stays on PATH)" },
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
            { "flag": "--uninstall-dig-updater", "description": "remove the auto-update beacon's daily scheduler registration this installer created (idempotent; does not remove the downloaded binaries or touch the dig-store/browser/relay/dig-node/dig-dns installs)" },
            { "flag": "--force-reinstall", "description": "reinstall dig-store/dig-node/dig-dns/dig-updater even if `update_policy` would otherwise skip them as already up to date (#309)" }
        ],
        "update_policy": {
            "description": "Every run detects what's already installed for dig-store/dig-node/dig-dns/dig-updater (`<bin> --version`), compares it to the release just resolved, and decides per component: absent -> install, an older or unreadable installed version -> update (replace it, reusing the §2 stop/replace/restart lifecycle for the service components), already current (or newer than the latest release) -> skip. A bare re-run is therefore idempotent: it updates only what's outdated and leaves the rest untouched. `--force-reinstall` overrides a skip decision back to update.",
            "components": ["dig-store", "dig-node", "dig-dns", "dig-updater"],
            "actions": ["install", "update", "skip"],
            "force_flag": "--force-reinstall"
        },
        "url_scheme_handler": {
            "schemes": ["dig", "chia", "urn"],
            "default": true,
            "opt_out": "--no-register-scheme",
            "per_user": true,
            "description": "By default the installer registers the OS handlers for dig://, chia:// (and best-effort urn:) links, all delegating to `dign open <uri>` — the local dig-node resolves and opens the clicked link (the dig.local → localhost → rpc.dig.net ladder lives in dig-node, not the installer). Per-user, no elevation."
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
            "dig-store-0.6.0-windows-x64.exe",
            "dig-store-0.6.0-linux-x64",
            "dig-store-0.6.0-macos-arm64",
            "dig-store-0.6.0-macos-x64",
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
        // SAME repo (`dig-updater`), so — exactly like dig-store/digs above —
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
        // dig-app publishes BOTH first-class binaries of the #908 form-factor split from ONE
        // release — the tray agent `dig-app` AND its own `dign` CLI (the U7 migration). The `dign`
        // assets are deliberately present in this fixture: they are the reason asking this repo for
        // `dig-app` must be stem-anchored. `dign` is the SHORTER name, and the selector's length
        // tiebreak would hand it back for `dig-app` if the canonical-stem preference were dropped.
        let app: Vec<&'static str> = vec![
            "dig-app-3.0.0-windows-x64.exe",
            "dig-app-3.0.0-linux-x64",
            "dig-app-3.0.0-macos-arm64",
            "dig-app-3.0.0-macos-x64",
            "dign-3.0.0-windows-x64.exe",
            "dign-3.0.0-linux-x64",
            "dign-3.0.0-macos-arm64",
            "dign-3.0.0-macos-x64",
        ];
        let mut m = HashMap::new();
        m.insert("dig-app", ("v3.0.0", app));
        m.insert("digs", ("v0.6.0", digstore));
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
            bin_dir: crate::sources::fixture_root().join("dig-installer-test-bin"),
            with_digstore: false,
            digstore_version: None,
            with_dig_node: false,
            dig_node_version: None,
            service: ServiceConfig::default(),
            with_dig_app: false,
            dig_app_version: None,
            dig_app_autostart: false,
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

    /// Regression for #573/#544 (partial-failure rollback): a mid-install failure
    /// must never leave a half-written stack. `rollback_partial_install` runs the
    /// PRODUCTION undo (`undo_install_action`) for every privileged action a
    /// partial install recorded; here two real binaries are recorded (as
    /// `note_binary_written` does on each successful write) and a failure is then
    /// forced. The rollback must DELETE both written binaries (no residual file)
    /// and report a clean LIFO reversal — the concrete guarantee SPEC §3.11 makes.
    #[test]
    fn rollback_after_midinstall_failure_removes_written_binaries_573_544() {
        let dir =
            crate::sources::fixture_root().join(format!("dig-rollback-573-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let first = dir.join("digstore.bin");
        let second = dir.join("dig-node.bin");
        std::fs::write(&first, b"first written binary").expect("write first");
        std::fs::write(&second, b"second written binary").expect("write second");

        // Two privileged writes succeeded, recorded newest-last, exactly as the
        // install flow records them; then a later step "fails" (we call rollback).
        let mut guard = RollbackGuard::new();
        guard.record(InstallAction::FileCreated(
            first.to_string_lossy().into_owned(),
        ));
        guard.record(InstallAction::FileCreated(
            second.to_string_lossy().into_owned(),
        ));
        assert!(
            first.exists() && second.exists(),
            "precondition: both written"
        );

        let target = Target::current().expect("host target");
        let report = rollback_partial_install(&guard, &target, &mut |_| {});

        assert!(
            !second.exists(),
            "rollback must delete the newest write first"
        );
        assert!(!first.exists(), "rollback must delete every written binary");
        assert!(report.clean(), "the file reversals must succeed cleanly");
        assert_eq!(report.reversed.len(), 2, "both writes reversed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A committed (fully-successful) install reverses nothing, and an already-
    /// absent file is a clean, idempotent no-op reversal — the rollback is
    /// best-effort and never fails an install that had nothing to undo (#573).
    #[test]
    fn rollback_is_a_clean_noop_when_nothing_privileged_recorded() {
        let target = Target::current().expect("host target");
        let empty = RollbackGuard::new();
        let report = rollback_partial_install(&empty, &target, &mut |_| {});
        assert!(report.reversed.is_empty() && report.clean());

        // An already-absent binary reverses cleanly (idempotent undo).
        let mut guard = RollbackGuard::new();
        guard.record(InstallAction::FileCreated(
            crate::sources::fixture_root()
                .join("dig-573-absent.bin")
                .to_string_lossy()
                .into_owned(),
        ));
        let report = rollback_partial_install(&guard, &target, &mut |_| {});
        assert!(report.clean(), "an absent target is a clean reversal");
        assert_eq!(report.reversed.len(), 1);
    }

    /// #301 (universal installer): a bare install with no opt-out flags installs
    /// the FULL DIG stack — the dig-store CLI, the dig-node service, the
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
            bin_dir: crate::sources::fixture_root().join("dig-installer-test-default"),
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
        assert!(names.contains(&"dig-store"), "digstore in default plan");
        assert!(names.contains(&"dig-node"), "dig-node in default plan");
        assert!(names.contains(&"dig-dns"), "dig-dns in default plan");
        assert!(names.contains(&"dig-app"), "dig-app in default plan (#912)");
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
        assert!(by_id("dig-store"), "digstore default: true");
        assert!(by_id("dig-node"), "dig-node default: true (#301)");
        assert!(by_id("dig-dns"), "dig-dns default: true (#301)");
        assert!(by_id("dig-updater"), "dig-updater default: true (#514)");
        assert!(by_id("dig-app"), "dig-app default: true (#912)");
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
        assert_eq!(c.component, "dig-store");
        assert_eq!(c.version, "0.6.0");
        assert_eq!(c.tag, "v0.6.0");
        assert!(c.asset.starts_with("dig-store-0.6.0-"));
        assert!(c
            .url
            .contains("github.com/DIG-Network/digs/releases/download/v0.6.0/"));
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
            vec!["dig-store", "digs"],
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
            .contains("github.com/DIG-Network/digs/releases/download/v0.6.0/"));

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
        // A pinned --dig-store-version threads through to the digs resolution
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
        assert!(ids.contains(&"dig-store"));
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
        // dig-dns places a raw PATH binary, same as dig-store/dig-node.
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
                "dig-store",
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
        assert!(err.message().contains("digs"));
        assert!(err.hint().is_some());
    }

    #[test]
    fn release_present_but_no_matching_asset_is_asset_not_found() {
        // The release exists but ships nothing for any OS/arch (only a tarball).
        let mut releases = HashMap::new();
        releases.insert("digs", ("v0.6.0", vec!["source-code.tar.gz", "notes.txt"]));
        let mut plan = base_plan();
        plan.with_digstore = true;
        let err = run_dry(&plan, releases).unwrap_err();
        assert_eq!(err.code(), "ASSET_NOT_FOUND");
        assert!(err.message().contains("no dig-store asset"));
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
    fn dig_store_falls_back_to_the_pre_rename_asset_stem() {
        // Epic #703: a transitional release that still carries ONLY the old
        // `digstore-*` assets (no `dig-store-*` yet) must still install, via the
        // legacy-stem fallback — and the resolved component/binary is normalized
        // back to `dig-store` so the id + on-PATH name stay consistent.
        let mut releases = HashMap::new();
        releases.insert(
            "digs",
            (
                "v0.13.0",
                vec![
                    "digstore-0.13.0-windows-x64.exe",
                    "digstore-0.13.0-linux-x64",
                    "digstore-0.13.0-macos-arm64",
                    "digstore-0.13.0-macos-x64",
                    // The `digs` alias is published alongside in the same release
                    // and its stem is unchanged by the rename.
                    "digs-0.13.0-windows-x64.exe",
                    "digs-0.13.0-linux-x64",
                    "digs-0.13.0-macos-arm64",
                    "digs-0.13.0-macos-x64",
                ],
            ),
        );
        let mut plan = base_plan();
        plan.with_digstore = true;
        let report = run_dry(&plan, releases).expect("legacy stem resolves");
        let cli = report
            .components
            .iter()
            .find(|c| c.component == "dig-store")
            .expect("component normalized to dig-store");
        assert!(
            cli.asset.starts_with("digstore-0.13.0-"),
            "resolved the legacy digstore-* asset, got {}",
            cli.asset
        );
        assert!(
            std::path::Path::new(&cli.dest)
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .starts_with("dig-store"),
            "on-PATH binary normalized to dig-store, got {}",
            cli.dest
        );
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
            .any(|l| l.contains("Installing the dig-store CLI")));
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
            "dig-store",
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
        let bin_dir = crate::sources::fixture_root().join("dig-installer-test-uninstall-bin");
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
        let bin_dir = crate::sources::fixture_root().join(format!(
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
            service_removed: true,
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
    fn dns_teardown_failed_when_service_survives_even_if_other_artifacts_removed() {
        // Blocker #4 residual: an ELEVATED dig-dns uninstall where the SERVICE
        // deregister FAILED but the NRPT rule / browser policy WAS removed —
        // `uninstalled == true`, `needs_elevation == false`, but the service is
        // still registered. This MUST be treated as a failed teardown so the
        // dig-dns binary is NOT deleted (which would orphan the live service).
        let service_survived = dns::DnsUninstallResult {
            uninstalled: true, // an artifact WAS removed …
            needs_elevation: false,
            service_removed: false, // … but the service registration survived.
            note: "removed: .dig NRPT rule".to_string(),
            residue_removed: vec![".dig NRPT rule".to_string()],
        };
        assert!(
            dns_service_teardown_failed(&service_survived),
            "a surviving service registration is a failed teardown even when uninstalled==true"
        );

        // A clean teardown (service confirmed gone) is NOT a failure.
        let clean = dns::DnsUninstallResult {
            uninstalled: true,
            needs_elevation: false,
            service_removed: true,
            note: "removed: Windows service".to_string(),
            residue_removed: vec!["Windows service".to_string()],
        };
        assert!(!dns_service_teardown_failed(&clean));

        // An already-absent service (nothing to remove, but confirmed gone) is
        // also NOT a failure — a second uninstall stays a clean no-op.
        let absent = dns::DnsUninstallResult {
            uninstalled: false,
            needs_elevation: false,
            service_removed: true,
            note: "nothing to remove".to_string(),
            residue_removed: Vec::new(),
        };
        assert!(!dns_service_teardown_failed(&absent));
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
            bin_dir: crate::sources::fixture_root().join("dig-installer-readiness-test"),
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
    /// The Windows protected root, as a literal, so the backslashes live in exactly one place.
    const PROGRAM_FILES_BIN: &str = r"C:\Program Files\DIGin";

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
            autostart: None,
            installed: Vec::new(),
            cli_path_checks: Vec::new(),
            daemon_dirs: Vec::new(),
            install_root_security: None,
            bin_dir_security: None,
            veneer_security: None,
            reachability: None,
            veneer_links_removed: Vec::new(),
            preceding_unsafe_path_dirs: Vec::new(),
            migration: None,
            registration_audit: Vec::new(),
            install_manifest: None,
            ready: true,
            failures: Vec::new(),
            restart_required: false,
        }
    }

    #[test]
    fn verdict_flags_restart_required_when_a_component_was_reboot_deferred() {
        // #562: a ready install with a reboot-deferred replace must NOT read as
        // fully done — the final verdict says RESTART REQUIRED, not "ready".
        let mut report = report_shell();
        report.ready = true;
        report.restart_required = true;
        let mut lines = Vec::new();
        log_readiness_verdict(&report, &mut |l| lines.push(l.to_string()));
        let out = lines.join("\n");
        assert!(out.contains("RESTART REQUIRED"), "got: {out}");
        assert!(!out.contains("DIG is ready."));
    }

    #[test]
    fn verdict_says_ready_when_no_restart_needed() {
        let mut report = report_shell();
        report.ready = true;
        report.restart_required = false;
        let mut lines = Vec::new();
        log_readiness_verdict(&report, &mut |l| lines.push(l.to_string()));
        assert!(lines.join("\n").contains("✓ DIG is ready."));
    }

    #[test]
    fn log_write_outcome_returns_true_only_for_reboot_deferred() {
        let mut sink = |_: &str| {};
        assert!(log_write_outcome(
            &mut sink,
            "dig-node",
            download::WriteOutcome::ScheduledForReboot
        ));
        assert!(!log_write_outcome(
            &mut sink,
            "dig-node",
            download::WriteOutcome::Replaced
        ));
    }

    #[test]
    fn service_absent_is_ok_distinguishes_launcher_gone_from_registration_gone() {
        // Blocker #4: a missing-EXECUTABLE spawn error must NOT be swallowed as
        // "service already absent" — the registration state is unknown.
        for spawn_err in [
            "dig-node uninstall failed: could not run C:\\x\\dig-node.exe: The system cannot find the file specified. (os error 2)",
            "dig-node uninstall failed: could not run /opt/dig/bin/dig-node: No such file or directory (os error 2)",
        ] {
            assert!(
                is_launcher_spawn_failure(spawn_err),
                "spawn failure must be recognised: {spawn_err}"
            );
            assert!(
                !service_absent_is_ok(spawn_err),
                "a launcher spawn failure is NOT 'service absent': {spawn_err}"
            );
        }
        // A genuine service-MANAGER reply that no such service exists IS the
        // idempotent already-absent case.
        for absent in [
            "dig-node uninstall failed: sc delete exited with 1060: The specified service does not exist as an installed service.",
            "the service is not registered",
            "no such service",
        ] {
            assert!(
                service_absent_is_ok(absent),
                "a manager 'does not exist' reply is absent: {absent}"
            );
            assert!(!is_launcher_spawn_failure(absent));
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
        // A service/hosts install needs elevation; a dry-run or a dig-store-only
        // run into a CUSTOM (user-chosen) bin dir does not — an explicit
        // --bin-dir is the user's own choice (base_plan uses a custom temp dir).
        assert!(dig_node_service_plan().requires_elevation(Os::Linux));
        let mut digstore_only = base_plan();
        digstore_only.with_digstore = true;
        digstore_only.dry_run = false;
        assert!(
            !digstore_only.requires_elevation(Os::Windows),
            "dig-store-only into a custom --bin-dir does not force elevation"
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
            // On unix the CLI-only install needs elevation exactly when it is ALREADY elevated, because
            // that is when `default_bin_dir()` is the root-owned protected root (#1748). Asserted against
            // the real uid rather than assumed, so this holds in the container root gate too.
            target::Os::Linux | target::Os::MacOs => {
                if invoker::is_root() {
                    assert!(
                        cli_only.requires_elevation(host),
                        "an elevated unix install places even the CLI in the protected root"
                    );
                } else {
                    assert!(
                        !cli_only.requires_elevation(host),
                        "an unelevated unix CLI-only install stays in ~/.dig/bin"
                    );
                }
            }
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
            plan.bin_dir_for("dig-store", Os::Linux),
            paths::default_bin_dir()
        );
        assert_eq!(
            plan.bin_dir_for("dign", Os::Linux),
            paths::default_bin_dir()
        );
        // Windows: every component lands in the single protected root.
        for c in ["dig-store", "dig-node", "dig-dns", "dig-updater"] {
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

    /// #1748 + #565 together: an elevated unix install may put USER CLIs in `/usr/local/bin`, and MUST
    /// NOT put a privileged/service-executed binary there.
    ///
    /// This is the invariant that reconciles the two things `SPEC.md` §1.5/§1.6 assert — that
    /// `/usr/local/bin` is the right elevated user root, and that a Homebrew-style group-writable
    /// prefix is the wrong home for a service binary. Both hold only because the two placements are
    /// separate, so the separation is pinned here rather than left to prose.
    ///
    /// The fixture is the DEFAULT (un-overridden) plan, which is the only way to express "an elevated
    /// install" without depending on the runner's uid. `has_custom_bin_dir()` compares `bin_dir`
    /// against `default_bin_dir()`, and `default_bin_dir()` itself branches on the CURRENT process's
    /// uid — so hardcoding `bin_dir = "/usr/local/bin"` would look like an OVERRIDE on a non-root test
    /// runner and route the privileged set there, inverting the assertion. `InstallPlan::default()`
    /// carries whatever the default is for the uid in play, so the routing under test is the real one
    /// on a root and a non-root runner alike.
    ///
    /// Both classes of component are asked of the SAME plan, so a routing that collapsed them into one
    /// dir — in either direction — is caught; a test that only asked about `dig-dns` would pass against
    /// a build that also sent `dign` to the protected root, and vice versa.
    #[cfg(unix)]
    #[test]
    fn an_elevated_unix_install_keeps_privileged_binaries_out_of_the_machine_bin_dir() {
        use target::Os;
        let machine = std::path::PathBuf::from(paths::UNIX_MACHINE_BIN_DIR);
        let elevated_default = InstallPlan::default();
        assert!(
            !elevated_default.has_custom_bin_dir(),
            "the default plan must not read as an override, or the routing under test is not \
             exercised"
        );
        // The separation the SPEC's two claims both rest on, asserted directly: the machine-wide user
        // root and the privileged root are different directories, so "user CLIs may sit in a
        // possibly-group-writable /usr/local/bin" and "no service binary may" are both satisfiable.
        assert_ne!(paths::protected_bin_dir(), machine);

        // The privileged set stays in the root-owned protected root, which is the dir
        // `secure::verify_install_root` then holds to the no-LPE bar.
        // dig-node and dig-relay joined this set in #1748 F1: the installer EXECUTES them as root
        // (their own `install` verb), so where they SIT is a root-exec surface regardless of the
        // identity their service later runs under.
        for privileged in [
            "dig-dns",
            "dig-updater",
            "dig-updater-worker",
            "dig-node",
            "dig-relay",
        ] {
            assert!(
                paths::is_privileged_component(Os::Linux, privileged),
                "{privileged} must be classified privileged for this test to mean anything"
            );
            assert_eq!(
                elevated_default.bin_dir_for(privileged, Os::Linux),
                paths::protected_bin_dir(),
                "{privileged} is service-executed and must never land in {}, which Homebrew leaves \
                 group-writable on an Intel Mac",
                paths::UNIX_MACHINE_BIN_DIR
            );
        }

        // The user CLIs go to the user root instead — `/usr/local/bin` when this process is root, which
        // is the #1748 fix. Without this half the test would also pass against a build that routed
        // EVERYTHING to the protected root.
        for user_cli in ["dig-store", "digs", "dign", "digd", "dig-app"] {
            assert!(
                !paths::is_privileged_component(Os::Linux, user_cli),
                "{user_cli} is a user-run CLI"
            );
            assert_eq!(
                elevated_default.bin_dir_for(user_cli, Os::Linux),
                paths::default_bin_dir(),
                "a user-run CLI belongs in the §1.6 user root, not the privileged root"
            );
        }
        // THE VENEER (#1748): an ELEVATED install's own bin dir is the ROOT-OWNED protected root, never
        // the machine-wide `/usr/local/bin`. That directory is user-writable under Homebrew on an Intel
        // Mac, and making it the dir root writes to and execs from produced three separate root paths
        // into it. Asserted against the real uid rather than assumed, both ways.
        if invoker::is_root() {
            assert_eq!(
                paths::default_bin_dir(),
                paths::protected_bin_dir(),
                "an elevated install must place binaries where only root can write"
            );
            assert_ne!(
                paths::default_bin_dir(),
                machine,
                "/usr/local/bin is a PATH veneer for symlinks, never an install root"
            );
        } else {
            assert_eq!(
                paths::default_bin_dir(),
                invoker::target_user().dig_bin_dir(),
                "unelevated, nothing runs as root, so the per-user root is correct"
            );
        }

        // And the verify follows the privileged binaries, not the user CLIs: `/usr/local/bin` is never
        // the dir handed to the ACL check on this plan, so a group-writable one cannot fail the
        // install — while an override that genuinely routed a service binary there would be checked.
        assert_eq!(
            elevated_default.privileged_install_root(Os::Linux),
            Some(paths::protected_bin_dir())
        );
        let overridden = InstallPlan {
            bin_dir: std::path::PathBuf::from("/opt/somewhere-else"),
            ..InstallPlan::default()
        };
        assert_eq!(
            overridden.privileged_install_root(Os::Linux),
            Some(std::path::PathBuf::from("/opt/somewhere-else")),
            "an override redirects the privileged root, so the ACL verify must follow it there"
        );
    }

    // -- #1748: the directory binaries LANDED in is verified and reported --------

    /// The #565 verify only ever looked at the PRIVILEGED root, so the directory this run actually wrote
    /// to and executed from went unchecked and unmentioned on every elevated unix install — which is how
    /// a user-writable `/usr/local/bin` became the install root with nothing noticing.
    ///
    /// The verdict must appear in `install.json`, and UNELEVATED it must not sink the install. Asserted on
    /// a world-writable directory, the posture that matters, with the untouched-readiness half asserted too
    /// so this cannot be "fixed" into a blanket refusal. The elevated arm, where the same posture IS fatal,
    /// is `an_elevated_install_into_a_writable_directory_is_fatal`.
    ///
    /// unix-only because on Windows EVERY component is privileged (`is_privileged_component`), so the
    /// privileged root always equals the bin dir and the verdict would be a duplicate — the case the
    /// companion test below pins.
    #[cfg(unix)]
    #[test]
    fn the_directory_binaries_landed_in_is_verified_and_reported() {
        let target = Target::current().expect("host target");
        let dir = crate::sources::fixture_root()
            .join(format!("dig-bindir-posture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        // A CLI-only plan, so there is no privileged root to shadow this directory's verdict.
        let plan = InstallPlan {
            bin_dir: dir.clone(),
            with_digstore: true,
            with_dig_node: false,
            with_dig_dns: false,
            with_dig_app: false,
            auto_update: false,
            with_relay: false,
            ..InstallPlan::default()
        };
        assert_eq!(
            plan.privileged_install_root(target.os),
            None,
            "the fixture must have no privileged root, or the posture report is skipped as duplicate"
        );

        let mut report = report_shell();
        report_bin_dir_posture(&plan, &target, &mut report, &mut |_| {});
        let verdict = report
            .bin_dir_security
            .as_ref()
            .expect("the directory this run wrote to must be reported, never silently skipped");
        assert_eq!(verdict.root, dir.to_string_lossy());
        #[cfg(unix)]
        {
            assert!(verdict.is_blocking(), "got: {}", verdict.note);
        }
        // UNELEVATED it does not sink the install: a user-writable dir holding binaries only that user
        // runs is their own authority, so refusing would break every ordinary per-user install. Injected
        // rather than read from the runner's uid, so both arms hold in the container root gate as well.
        assert!(
            evaluate_readiness_when(&plan, &report, false).is_empty(),
            "unelevated, the bin-dir posture is reported and never fatal"
        );
        // ELEVATED the same posture IS fatal — the arm asserted in full by
        // `an_elevated_install_into_a_writable_directory_is_fatal`.
        assert!(
            !evaluate_readiness_when(&plan, &report, true).is_empty(),
            "an elevated install must not proceed over a writable install directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One verdict per directory — but ONLY when the privileged verify actually PRODUCED one.
    ///
    /// The dedupe used to key on `privileged_install_root()`, i.e. on where privileged binaries WOULD
    /// go, and those came apart from where the verify actually ran (#1748): the #565 check is gated on
    /// the plan selecting a privileged component, while since the veneer every ELEVATED install places
    /// its binaries in the protected root. So a CLI-only `sudo` install wrote into `/opt/dig/bin`,
    /// nothing verified it, and the dedupe suppressed the one check that would have. A world-writable
    /// protected root reached a fully green install that way, measured at mode 0777 on a real run.
    #[test]
    fn the_bin_dir_posture_is_deduped_only_against_a_verify_that_really_ran() {
        let target = Target::current().expect("host target");
        let plan = InstallPlan {
            bin_dir: paths::protected_bin_dir(),
            with_dig_dns: true,
            ..InstallPlan::default()
        };
        assert_eq!(
            plan.privileged_install_root(target.os).as_ref(),
            Some(&plan.bin_dir),
            "the fixture must be the same-directory case"
        );

        // The genuine duplicate: a verdict for this directory already exists, so no second one.
        let mut covered = report_shell();
        covered.install_root_security = Some(secure::InstallRootSecurity::established_safe(
            plan.bin_dir.to_string_lossy().to_string(),
            "already verified".to_string(),
        ));
        report_bin_dir_posture(&plan, &target, &mut covered, &mut |_| {});
        assert!(
            covered.bin_dir_security.is_none(),
            "the privileged-root verify already covers this directory"
        );

        // The case the old dedupe got wrong: NO verify ran, so the directory root wrote into must still
        // be checked rather than silently skipped as a "duplicate" of a verdict that does not exist.
        let mut unchecked = report_shell();
        assert!(unchecked.install_root_security.is_none());
        report_bin_dir_posture(&plan, &target, &mut unchecked, &mut |_| {});
        assert!(
            unchecked.bin_dir_security.is_some(),
            "nothing verified the directory this run wrote binaries into (#1748)"
        );
    }

    /// The removal must be REACHED, not merely implemented — this test goes through `link_protected_clis`.
    ///
    /// # Why this test exists (#1748 F1)
    ///
    /// The removal block sat below an `if to_link.is_empty() { return; }` early return, and `to_link` is
    /// empty by construction exactly when the veneer is unsafe — the only condition the removal runs under.
    /// So it was provably dead code, and **deleting it left 685 tests passing**: the one test covering the
    /// behaviour called `paths::remove_links_in` directly and never traversed this call site. The container
    /// gate missed it too, because its fixture deleted the link before the run.
    ///
    /// The lesson is the fixture, not the assertion: a helper that works proves nothing about a caller that
    /// never calls it. This drives the real seam, with the veneer redirected to a temp directory so it can
    /// run unprivileged.
    #[cfg(unix)]
    #[test]
    fn an_unsafe_veneer_reaches_the_removal_through_link_protected_clis() {
        let target = Target::current().expect("host target");
        if matches!(target.os, target::Os::Windows) {
            return; // The veneer is a unix concept; Windows keeps one root and links nothing.
        }

        let mut report = report_shell();
        report.components.push(ComponentResult {
            component: "digs".to_string(),
            version: "0.19.3".to_string(),
            tag: "v0.19.3".to_string(),
            asset: "digs".to_string(),
            url: String::new(),
            dest: paths::protected_bin_dir()
                .join("digs")
                .to_string_lossy()
                .into_owned(),
            previous_version: None,
            update_action: update::UpdateAction::Install,
        });

        // UNSAFE veneer: nothing may be linked, and the removal must be REACHED. `to_link` is empty here,
        // which is precisely the state in which the early return used to skip the removal entirely.
        let mut lines = Vec::new();
        link_protected_clis(&target, &mut report, false, &mut |l| {
            lines.push(l.to_string())
        });
        let log = lines.join("\n");
        assert!(
            log.contains(paths::UNIX_MACHINE_BIN_DIR),
            "an unsafe veneer must SAY what it did about the veneer, and it said nothing: {log:?}"
        );
        assert!(
            !log.contains("Linking the protected-root CLIs"),
            "no link may be planted into an unsafe veneer: {log:?}"
        );

        // The control that makes the assertion above about the POSTURE rather than about this function
        // being quiet in general: a SAFE veneer takes the linking path and announces it.
        let mut linked = Vec::new();
        link_protected_clis(&target, &mut report, true, &mut |l| {
            linked.push(l.to_string())
        });
        let linked = linked.join("\n");
        assert!(
            linked.contains("Linking the protected-root CLIs"),
            "a safe veneer must still plant links — otherwise the fallback is just an abandonment: {linked:?}"
        );
    }

    /// An unsafe veneer FAILS the install when links are planted there, and does NOT when the run fell back.
    ///
    /// This is the round-7 decision in one assertion, and both arms are load-bearing in opposite directions:
    ///
    /// * fatal when `VeneerLinks` — an account that can write the veneer re-points a link this run planted
    ///   and root executes whatever it points at. Unprivileged CODE running as that user cannot type their
    ///   password but can write that directory, so "they could `sudo` anyway" does not make it benign.
    /// * NOT fatal when `DirectPathEntry` — the run declined to plant a link, removed any earlier one, and
    ///   put the root-owned protected root on `PATH` instead. Failing then would refuse every
    ///   Homebrew-on-Intel Mac, and a refusal is not a fix.
    ///
    /// Without the second arm, making the verdict fatal unconditionally passes every other test in the
    /// suite — which is exactly what it did before this test existed.
    #[test]
    fn an_unsafe_veneer_is_fatal_only_when_it_is_the_mechanism_in_play() {
        let plan = InstallPlan {
            with_digstore: true,
            ..InstallPlan::default()
        };
        let unsafe_veneer = || {
            Some(secure::InstallRootSecurity::detected_unsafe(
                paths::UNIX_MACHINE_BIN_DIR,
                "mode 775 allows group or other to write",
            ))
        };

        // Links planted into a directory a non-root account can write: fatal.
        let mut linking = report_shell();
        linking.veneer_security = unsafe_veneer();
        linking.reachability = Some(paths::Reachability::VeneerLinks);
        let failures = evaluate_readiness_when(&plan, &linking, true);
        assert!(
            failures.iter().any(|f| f.contains(paths::UNIX_MACHINE_BIN_DIR)),
            "a link planted in a writable veneer is a live escalation and must fail readiness: {failures:?}"
        );

        // Fell back: same verdict, no link planted, protected root on PATH instead. A recorded downgrade.
        let mut fell_back = report_shell();
        fell_back.veneer_security = unsafe_veneer();
        fell_back.reachability = Some(paths::Reachability::DirectPathEntry);
        let failures = evaluate_readiness_when(&plan, &fell_back, true);
        assert!(
            !failures.iter().any(|f| f.contains(paths::UNIX_MACHINE_BIN_DIR)),
            "the fallback must INSTALL, not refuse - a refusal on every Homebrew Mac is the failure mode \
             this design exists to avoid: {failures:?}"
        );

        // And unelevated it is never fatal either way, because nothing runs as root.
        for mechanism in [
            paths::Reachability::VeneerLinks,
            paths::Reachability::DirectPathEntry,
        ] {
            let mut unelevated = report_shell();
            unelevated.veneer_security = unsafe_veneer();
            unelevated.reachability = Some(mechanism);
            assert!(
                !evaluate_readiness_when(&plan, &unelevated, false)
                    .iter()
                    .any(|f| f.contains(paths::UNIX_MACHINE_BIN_DIR)),
                "unelevated, the veneer's posture is the user's own authority"
            );
        }
    }

    /// An ELEVATED install into a group/world-writable directory is FATAL, not a note.
    ///
    /// Elevation is what makes the posture an escalation rather than a preference: root wrote the
    /// binaries, `/usr/local/bin` links resolve into them, and root-side execs and services run them.
    /// The unelevated half — the same posture reported and NOT fatal — is asserted by
    /// `the_directory_binaries_landed_in_is_verified_and_reported`, so both arms are covered.
    #[test]
    fn an_elevated_install_into_a_writable_directory_is_fatal() {
        let plan = InstallPlan {
            with_digstore: true,
            ..InstallPlan::default()
        };
        let mut report = report_shell();
        report.bin_dir_security = Some(secure::InstallRootSecurity::detected_unsafe(
            "/opt/dig/bin".to_string(),
            "mode 0777: group and other can write".to_string(),
        ));

        // BOTH arms, stated explicitly rather than branched on the runner's own uid. Branching on
        // `is_root()` meant CI only ever ran the unelevated arm, so replacing the production
        // `if invoker::is_root()` with `if false` changed nothing observable and this test stayed green
        // while claiming to cover both (#1748 C3).
        let elevated = evaluate_readiness_when(&plan, &report, true);
        assert!(
            elevated.iter().any(|f| f.contains("/opt/dig/bin")),
            "an elevated install must NOT report ready over a writable install directory: {elevated:?}"
        );

        let unelevated = evaluate_readiness_when(&plan, &report, false);
        assert!(
            !unelevated.iter().any(|f| f.contains("/opt/dig/bin")),
            "unelevated it is the user's own authority, never a failure: {unelevated:?}"
        );

        // And the ambient entry point agrees with the injected one on this runner, so the two cannot
        // drift apart.
        assert_eq!(
            evaluate_readiness(&plan, &report),
            evaluate_readiness_when(&plan, &report, invoker::is_root())
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
        report.install_root_security = Some(secure::InstallRootSecurity::detected_unsafe(
            r"C:\Program Files\DIG\bin".to_string(),
            "grants WRITE to an unprivileged principal (S-1-5-32-545)".to_string(),
        ));
        let failures = evaluate_readiness(&plan, &report);
        assert!(
            failures.iter().any(|f| f.contains("install root")),
            "a definitive write breach must fail readiness: {failures:?}"
        );
        // An INDETERMINATE read also fails readiness (#1748 WU1). This assertion is inverted from what
        // it used to be, deliberately: "indeterminate -> proceed" was the fail-open policy that seven
        // call sites re-derived independently, and every round of this release found another site where
        // it turned a REFUSAL into a tick. A posture nobody could establish is not evidence of safety,
        // and the note always names the level that could not be verified.
        let mut report = report_shell();
        report.install_root_security = Some(secure::InstallRootSecurity::indeterminate(
            PROGRAM_FILES_BIN.to_string(),
            "could not read the ACL back".to_string(),
        ));
        let failures = evaluate_readiness(&plan, &report);
        assert!(
            failures.iter().any(|f| f.contains("install root")),
            "an unverifiable install root must not report ready: {failures:?}"
        );

        // The control that keeps the policy from collapsing into "always block": an ESTABLISHED-safe root
        // passes. Without it, an `is_blocking()` that returned `true` unconditionally would satisfy both
        // assertions above.
        let mut report = report_shell();
        report.install_root_security = Some(secure::InstallRootSecurity::established_safe(
            PROGRAM_FILES_BIN.to_string(),
            "admin-only, no unprivileged write ACE".to_string(),
        ));
        let failures = evaluate_readiness(&plan, &report);
        assert!(
            !failures.iter().any(|f| f.contains("install root")),
            "a verified-safe install root must not fail readiness: {failures:?}"
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
        report.install_root_security = Some(secure::InstallRootSecurity::detected_unsafe(
            custom.to_string_lossy().into_owned(),
            "grants WRITE to an unprivileged principal (S-1-5-32-545)".to_string(),
        ));
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
            reboot_required: false,
            reboot_reason: None,
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
        // dig-store-only into a custom dir on unix: digstore is NOT privileged
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
            reboot_required: false,
            reboot_reason: None,
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
            reboot_required: false,
            reboot_reason: None,
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
            note:
                "`dig-node` is not on ubuntu's PATH (a fresh login shell searches: /usr/bin:/bin)"
                    .to_string(),
        });
        let failures = evaluate_readiness(&plan, &report);
        assert_eq!(failures.len(), 1, "got: {failures:?}");
        assert!(failures[0].contains("dig-node"));
        // The check's own note IS the remediation — it names the user and the PATH actually searched.
        assert!(failures[0].contains("ubuntu"));
        assert!(failures[0].contains("/usr/bin:/bin"));
    }

    /// #1748: the readiness failure must NOT tell the reader to re-run elevated.
    ///
    /// The install that prompted this WAS elevated — that was the cause, not the cure — and "open a
    /// new terminal" is equally useless now the check already uses a fresh login shell. Both phrases
    /// sent a real reader hunting a privilege problem that did not exist, so their absence is asserted
    /// rather than left to review.
    ///
    /// The `libxdo.so.3` loader failure used as the fixture is a real state — it is what `dig-app`
    /// does on stock Ubuntu — but note that `dig-app` itself is exempt from the version probe
    /// ([`answers_version`]), so production does not currently SURFACE it for that component. The
    /// fixture drives `evaluate_readiness`'s formatting directly, which is the code under test here,
    /// and the message shape is what any real CLI's loader failure produces.
    #[test]
    fn a_path_failure_does_not_advise_re_running_elevated() {
        let plan = dig_node_service_plan();
        let mut report = report_shell();
        report.service = Some(running_service());
        report.cli_path_checks.push(pathcheck::CliPathCheck {
            cli: "dig-app".to_string(),
            resolved: false,
            note: "`/usr/local/bin/dig-app --version` resolved on PATH but did NOT run: \
                   libxdo.so.3: cannot open shared object file"
                .to_string(),
        });
        let failures = evaluate_readiness(&plan, &report);
        let joined = failures.join(" ");
        assert!(
            !joined.contains("re-run elevated"),
            "must not advise elevating an already-elevated install: {joined}"
        );
        assert!(
            !joined.contains("open a new terminal"),
            "the check already used a fresh login shell: {joined}"
        );
        // The actionable detail — the loader error — must survive into the verdict.
        assert!(joined.contains("libxdo.so.3"), "got: {joined}");
    }

    /// #1748: the SERVICE readiness branch must not advise elevating either.
    ///
    /// This is a separate code path from the PATH branch above, and it is the one a real run hit:
    /// `dig-node start` failed with `Failed to connect to bus: No medium found` — root having no
    /// session bus — and the verdict said "re-run elevated" for an install that was already root.
    /// The missing thing was a user SESSION, not privilege, so the advice sent the reader after the
    /// wrong cause. A second actor (the failing service) is required to exercise this branch, which is
    /// why the PATH-branch test above cannot stand in for it.
    #[test]
    fn a_service_failure_does_not_advise_re_running_elevated_either() {
        let plan = dig_node_service_plan();
        let mut report = report_shell();
        let mut svc = running_service();
        svc.health_ok = false;
        svc.health_note = "dig-node start exited with 6: error: Failed to connect to bus: \
                           No medium found"
            .to_string();
        report.service = Some(svc);
        let joined = evaluate_readiness(&plan, &report).join(" ");
        assert!(
            !joined.contains("re-run elevated"),
            "the failing install was already root: {joined}"
        );
        // The real cause must still reach the reader verbatim.
        assert!(joined.contains("Failed to connect to bus"), "got: {joined}");
    }

    /// #514: an `auto_update`-only plan (the beacon is a privileged OS-scheduler
    /// registration, so it gates readiness like dig-node/dig-relay's own service
    /// registration — never best-effort like the firewall rule/scheme handler).
    fn beacon_only_plan() -> InstallPlan {
        InstallPlan {
            bin_dir: crate::sources::fixture_root().join("dig-installer-readiness-beacon-test"),
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
        crate::sources::fixture_root().join(format!(
            "dig-installer-update-wiring-{tag}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn digstore_wiring_installs_when_absent_and_updates_when_present_but_unreadable() {
        let bin_dir = wiring_test_bin_dir("dig-store");
        let _ = std::fs::remove_dir_all(&bin_dir);
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.bin_dir = bin_dir.clone();

        let report = run_dry(&plan, all_releases()).expect("resolves");
        let digstore = report
            .components
            .iter()
            .find(|c| c.component == "dig-store")
            .expect("digstore present");
        assert_eq!(digstore.update_action, update::UpdateAction::Install);
        assert_eq!(digstore.previous_version, None);

        let target = Target::current().unwrap();
        write_unrunnable_file(&bin_dir.join(target.exe_name("dig-store")));
        let report = run_dry(&plan, all_releases()).expect("resolves");
        let digstore = report
            .components
            .iter()
            .find(|c| c.component == "dig-store")
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
                "{id} is not update-tracked (#309 scope: dig-store/dig-node/dig-dns only)"
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
        write_unrunnable_file(&bin_dir.join(target.exe_name("dig-store")));
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

    // -----------------------------------------------------------------------
    // dig-app distribution (#912): the user-facing half of the #908 split must
    // reach a stranger through the ordinary install, not a manual download.
    // -----------------------------------------------------------------------

    /// The default (universal) install SELECTS dig-app. This list drives placement, elevation, and
    /// PATH decisions, so an implementation that downloaded dig-app without declaring it here would
    /// route it wrongly — hence exact list equality.
    #[test]
    fn the_default_plan_selects_dig_app_912() {
        let plan = InstallPlan::default();
        assert!(plan.with_dig_app, "dig-app ships in the default stack");
        assert!(plan.dig_app_autostart, "and starts at login by default");
        assert_eq!(
            plan.selected_components(),
            vec![
                "dig-store",
                "digs",
                "dig-node",
                "dign",
                "dig-app",
                "dig-dns",
                "digd",
                "dig-updater",
                "dig-updater-worker",
            ]
        );
    }

    /// A dig-app-only install registers no service, so it reaches the elevation gate only through
    /// the "places a binary in the protected root" arm. On Windows the whole stack shares the
    /// admin-only Program Files root, so it MUST still elevate — otherwise the guard is skipped and
    /// the write fails late with a raw permission error instead of the clean verdict (#565).
    #[test]
    fn a_dig_app_only_windows_install_still_elevates_912() {
        let mut plan = base_plan();
        plan.bin_dir = paths::default_bin_dir();
        plan.with_dig_app = true;
        plan.dry_run = false;
        assert_eq!(
            plan.bin_dir_for("dig-app", target::Os::Windows),
            paths::protected_bin_dir(),
            "dig-app lands in the protected root on Windows"
        );
        assert!(plan.requires_elevation(target::Os::Windows));
        // A dry-run never elevates, and an explicit --bin-dir is the user's own choice.
        plan.dry_run = true;
        assert!(!plan.requires_elevation(target::Os::Windows));
    }

    /// dig-app is a PER-USER agent, never a machine-wide service binary: on unix it lands in the
    /// elevation-free user bin dir, NOT the admin-only protected root the daemons use. A dig-app in
    /// the privileged set would demand root to install a tray app.
    #[test]
    fn dig_app_is_not_a_privileged_service_component_912() {
        assert!(!paths::is_privileged_component(
            target::Os::Linux,
            "dig-app"
        ));
        assert!(!paths::is_privileged_component(
            target::Os::MacOs,
            "dig-app"
        ));
        // A dig-app-only plan therefore needs no elevation on unix.
        let mut plan = base_plan();
        plan.with_dig_app = true;
        plan.dry_run = false;
        assert!(!plan.requires_elevation(target::Os::Linux));
    }

    /// The payload actually carries dig-app: resolved from the dig-app release, placed on PATH under
    /// the canonical `dig-app` exe name.
    ///
    /// The load-bearing part is the second hop. The fixture release also contains `dign-*` assets
    /// (as the real one does) and `dign` is the SHORTER name — so a stem-blind selector returns
    /// dig-app's `dign` here and this test fails. Asserting only "a component resolved" would pass
    /// on that wrong implementation.
    #[test]
    fn dig_app_is_carried_in_the_installer_payload_912() {
        let mut plan = base_plan();
        plan.with_dig_app = true;
        let report = run_dry(&plan, all_releases()).expect("dig-app resolves");
        let ids: Vec<&str> = report
            .components
            .iter()
            .map(|c| c.component.as_str())
            .collect();
        assert_eq!(ids, vec!["dig-app"]);

        let app = &report.components[0];
        assert_eq!(app.version, "3.0.0");
        assert_eq!(app.tag, "v3.0.0");
        assert!(
            app.asset.starts_with("dig-app-3.0.0-"),
            "resolved the dig-app asset, not the dign sibling in the same release: {}",
            app.asset
        );
        assert!(app
            .url
            .contains("github.com/DIG-Network/dig-app/releases/download/v3.0.0/"));
        let target = Target::current().expect("supported target");
        assert_eq!(
            std::path::Path::new(&app.dest).file_name().unwrap(),
            std::ffi::OsStr::new(&target.exe_name("dig-app")),
            "placed under the canonical dig-app exe name so it resolves by bare name on PATH"
        );
    }

    /// `dign` keeps coming from the dig-NODE release even though dig-app publishes a `dign` of its
    /// own — the `chia://` scheme handler is wired against `dign open` from the node, so silently
    /// repointing it would change which binary answers every clicked link. Both components are
    /// selected here so the two `dign` sources compete; the version + URL pin which one won.
    #[test]
    fn dign_still_resolves_from_the_dig_node_release_not_dig_app_912() {
        let mut plan = base_plan();
        plan.with_dig_node = true;
        plan.with_dig_app = true;
        let report = run_dry(&plan, all_releases()).expect("node + app resolve");
        let ids: Vec<&str> = report
            .components
            .iter()
            .map(|c| c.component.as_str())
            .collect();
        assert_eq!(ids, vec!["dig-node", "dign", "dig-app"]);

        let dign = &report.components[1];
        assert_eq!(dign.version, "0.2.0", "dign rides dig-node's version pin");
        assert!(
            dign.url.contains("/DIG-Network/dig-node/releases/"),
            "dign comes from the dig-node release: {}",
            dign.url
        );
        assert_eq!(report.components[2].version, "3.0.0");
    }

    /// Installed is not the same as launchable: selecting dig-app also registers the per-user login
    /// autostart, with the mechanism appropriate to the host OS.
    #[test]
    fn dig_app_is_registered_to_start_at_login_912() {
        let mut plan = base_plan();
        plan.with_dig_app = true;
        plan.dig_app_autostart = true;
        let report = run_dry(&plan, all_releases()).expect("dig-app resolves");
        let a = report
            .autostart
            .as_ref()
            .expect("autostart was registered for the tray agent");
        let os = Target::current().expect("supported target").os;
        assert_eq!(a.mechanism, autostart::mechanism_for(os));
        // Dry-run reports the intent without writing; the note is never silent.
        assert!(!a.registered);
        assert!(!a.note.is_empty());
    }

    /// The autostart is declinable (never trap the user) and is not registered at all when dig-app
    /// itself was not selected.
    #[test]
    fn dig_app_autostart_is_declinable_and_absent_without_dig_app_912() {
        let mut plan = base_plan();
        plan.with_dig_app = true;
        plan.dig_app_autostart = false;
        let report = run_dry(&plan, all_releases()).expect("dig-app resolves");
        assert_eq!(report.components.len(), 1, "the binary is still installed");
        assert!(
            report.autostart.is_none(),
            "declining autostart registers nothing"
        );

        let mut off = base_plan();
        off.with_digstore = true;
        let report = run_dry(&off, all_releases()).expect("digstore resolves");
        assert!(report.autostart.is_none());
    }

    /// dig-app publishes nightlies ahead of its first stable release, so a release with no asset for
    /// this OS/arch is SKIPPED gracefully — the rest of the stack still installs. (Same contract the
    /// `dign` alias already has.)
    #[test]
    fn a_dig_app_release_without_an_asset_for_this_target_is_skipped_912() {
        let mut releases = all_releases();
        releases.remove("dig-app");
        let mut plan = base_plan();
        plan.with_digstore = true;
        plan.with_dig_app = true;
        let report = run_dry(&plan, releases).expect("the stack still installs");
        let ids: Vec<&str> = report
            .components
            .iter()
            .map(|c| c.component.as_str())
            .collect();
        assert_eq!(ids, vec!["dig-store", "digs"]);
        assert!(report.autostart.is_none());
    }

    /// An uninstall must remove dig-app too — a stranger who removes DIG should not be left with a
    /// tray agent still launching at every login.
    #[test]
    fn uninstall_covers_the_dig_app_binary_912() {
        assert!(uninstall::COMPONENT_STEMS.contains(&"dig-app"));
    }

    // -- #1748: a GUI app is proven by resolution, a CLI by running ---------------

    /// `dig-app` must NOT be probed with `--version`: it is a tray app with no command-line surface,
    /// and on macOS the probe never returns, which hung an entire install. Real CLIs must still be
    /// RUN, so both arms are asserted — an implementation that exempted everything would be a
    /// regression of #496 and cannot pass this.
    #[test]
    fn only_the_gui_app_is_exempt_from_the_version_probe() {
        // The exemption is unconditional, and is a KNOWN GAP rather than a claim that dig-app is fine
        // (see `answers_version`). Narrowing it to macOS was tried and reverted on evidence: on a
        // headless ubuntu runner `dig-app --version` does not exit either, so the probe stalls 20s and
        // then fails the whole install (run 30400688672).
        assert!(
            !answers_version("dig-app"),
            "dig-app has no --version to answer on any platform"
        );
        for cli in ["dig-node", "dign", "dig-dns", "digd", "dig-store", "digs"] {
            assert!(
                answers_version(cli),
                "{cli} is a real CLI and must be RUN, not just resolved"
            );
        }
    }

    /// Every GUI app must still be a REQUIRED CLI — the exemption changes HOW it is proven, never
    /// whether it is checked at all. A typo here would silently drop dig-app from the verdict.
    #[test]
    fn the_gui_app_is_still_a_required_cli() {
        for app in GUI_APPS {
            assert!(
                REQUIRED_CLIS.contains(app),
                "{app} is exempt from the version probe but is not checked at all"
            );
        }
    }
}
