//! dig-dns OS-service installation (task #177 — Component B of the dig-dns
//! brief, #174).
//!
//! Unlike dig-node/dig-relay (which register THEMSELVES as an OS service via
//! their own `install`/`start` subcommands — see [`crate::service`]), dig-dns
//! ships no such subcommand: it is a plain CLI whose `serve` blocks in the
//! foreground. This module owns the full per-OS wiring instead:
//!
//! * **[`plan`]** — pure content builders (systemd unit, launchd plists, NRPT
//!   commands, policy JSON/plist/registry values, doctor/pac JSON parsing) —
//!   no I/O, fully unit-tested.
//! * **[`windows`]**, **[`macos`]**, **[`linux`]** — the imperative per-OS
//!   apply/reverse layer (file writes, registry, `launchctl`/`systemctl`/the
//!   SCM). Each is gated with `#![cfg(...)]` so it only COMPILES on its target
//!   OS (rustfmt still formats every file regardless of target — CLAUDE.md
//!   §2.4a's fmt gate stays meaningful for all three); real compilation is
//!   verified by the release workflow's per-OS build matrix.
//! * **[`doctor`]** — runs `dig-dns doctor --json` / `dig-dns pac --json`
//!   against the installed binary (the self-verification step every install
//!   ends with) and renders the printed report.
//!
//! One entrypoint per direction: [`install`] and [`uninstall`], both
//! OS-detecting, elevated, idempotent, and — for uninstall — leaving zero
//! residue (only artifacts carrying [`plan::MARKER`] are ever touched/removed;
//! a pre-existing org policy or `.dig` DNS rule is never clobbered).

pub mod doctor;
pub mod linux;
pub mod macos;
pub mod plan;
pub mod service_host;
pub mod windows;

use std::path::Path;

use serde::Serialize;

/// What the caller asked the dig-dns install step to do.
#[derive(Debug, Clone)]
pub struct DnsInstallConfig {
    /// Start the service immediately after registering it.
    pub start: bool,
    /// An explicit dig-node endpoint override forwarded to `dig-dns serve
    /// --node <url>` (highest §5.3 precedence). `None` ⇒ dig-dns's own ladder.
    pub node: Option<String>,
}

impl Default for DnsInstallConfig {
    fn default() -> Self {
        DnsInstallConfig {
            start: true,
            node: None,
        }
    }
}

/// The structured result of installing (or planning to install) dig-dns as an
/// OS service — the `--json` shape for the `dns` field of `InstallReport`.
#[derive(Debug, Clone, Serialize)]
pub struct DnsInstallResult {
    pub installed: bool,
    pub started: bool,
    /// `true` when installation was refused because the process is not
    /// elevated (Administrator/root) — a stable, agent-checkable signal
    /// distinct from parsing `note`'s prose (CLAUDE.md §6.2).
    #[serde(default)]
    pub needs_elevation: bool,
    pub note: String,
    /// `dig-dns doctor --json`, run as the self-verification step once the
    /// service is started (`None` on dry-run, or if the probe itself failed).
    pub doctor: Option<plan::DoctorSummary>,
    /// Which resolution path(s) `doctor` found live (`"dns"`/`"gateway"`).
    pub paths_live: Vec<String>,
    /// The gateway's actually-bound port (`80` or the `8053` fallback), from
    /// `dig-dns pac --json`.
    pub bound_port: Option<u16>,
    /// The PAC URL served by the gateway (Path B fallback).
    pub pac_url: Option<String>,
    /// The one-line browser-fallback instruction printed after install.
    pub fallback_instruction: Option<String>,
}

/// The structured result of uninstalling the dig-dns OS service.
#[derive(Debug, Clone, Serialize)]
pub struct DnsUninstallResult {
    pub uninstalled: bool,
    /// `true` when uninstall was refused because the process is not elevated
    /// (Administrator/root) — see [`DnsInstallResult::needs_elevation`].
    #[serde(default)]
    pub needs_elevation: bool,
    pub note: String,
    /// Every artifact (service, rule, file, registry key) this run removed.
    pub residue_removed: Vec<String>,
}

/// Install dig-dns as an OS service on the current platform: register +
/// (optionally) start the service, wire OS split-DNS / NRPT / resolver, apply
/// the Chrome/Edge DoH policy (best-effort, never clobbering an existing org
/// policy), then self-verify with `dig-dns doctor` + `dig-dns pac` and surface
/// the live path(s), the bound port, and the PAC URL.
///
/// `dig_dns_bin` is the path to the just-downloaded `dig-dns` binary;
/// `persist_bin` is the path THIS installer's own executable should be copied
/// to so it survives as the Windows service's host process (unused on
/// macOS/Linux, where the service execs `dig_dns_bin` directly — see
/// [`windows`]).
pub fn install(
    dig_dns_bin: &Path,
    persist_bin: &Path,
    cfg: &DnsInstallConfig,
    dry_run: bool,
) -> DnsInstallResult {
    #[cfg(windows)]
    {
        windows::install(dig_dns_bin, persist_bin, cfg, dry_run)
    }
    #[cfg(target_os = "macos")]
    {
        macos::install(dig_dns_bin, cfg, dry_run)
    }
    #[cfg(target_os = "linux")]
    {
        linux::install(dig_dns_bin, cfg, dry_run)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (dig_dns_bin, persist_bin, cfg, dry_run);
        DnsInstallResult {
            installed: false,
            started: false,
            needs_elevation: false,
            note: "dig-dns OS-service install is not supported on this platform".to_string(),
            doctor: None,
            paths_live: Vec::new(),
            bound_port: None,
            pac_url: None,
            fallback_instruction: None,
        }
    }
}

/// Reverse [`install`]: stop + remove the service registration, the OS
/// split-DNS/NRPT wiring, and any Chrome/Edge policy this installer created —
/// leaving zero residue. Never touches a pre-existing rule/policy it did not
/// create (matched by [`plan::MARKER`]).
pub fn uninstall(dry_run: bool) -> DnsUninstallResult {
    #[cfg(windows)]
    {
        windows::uninstall(dry_run)
    }
    #[cfg(target_os = "macos")]
    {
        macos::uninstall(dry_run)
    }
    #[cfg(target_os = "linux")]
    {
        linux::uninstall(dry_run)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = dry_run;
        DnsUninstallResult {
            uninstalled: false,
            needs_elevation: false,
            note: "dig-dns OS-service uninstall is not supported on this platform".to_string(),
            residue_removed: Vec::new(),
        }
    }
}
