//! dig-dns OS-service installation (task #177 — Component B of the dig-dns
//! brief, #174).
//!
//! dig-dns (v0.9.0+) exposes its OWN Windows Service Control Protocol
//! entrypoint, `dig-dns run-service`, which reports `SERVICE_RUNNING` to the
//! SCM before any slow startup work — so the installer registers the SCM
//! service to run that binary+arg **directly** (never re-launching an installer
//! host-shim, the #499 `1053` root cause). Unlike dig-node/dig-relay (which
//! register THEMSELVES via their own `install`/`start` subcommands — see
//! [`crate::service`]), the installer still owns the surrounding per-OS wiring
//! (split-DNS/NRPT, the browser DoH policy, `doctor` self-verification):
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
pub mod windows;

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

/// What the caller asked the dig-dns install step to do.
#[derive(Debug, Clone)]
pub struct DnsInstallConfig {
    /// Start the service immediately after registering it.
    pub start: bool,
    /// An explicit dig-node endpoint override baked into the service
    /// environment as `DIG_NODE_URL` for `dig-dns run-service` (highest §5.3
    /// precedence). `None` ⇒ dig-dns resolves its own ladder.
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
    /// `true` iff the dig-dns OS service was polled AND observed RUNNING by the
    /// service manager after install (#493/F7 — the SAME fail-loud gate dig-node
    /// uses via `ServiceResult::health_ok`). A live `paths_live` probe is NOT
    /// sufficient on its own: another process could satisfy the DNS/gateway probe
    /// while OUR service failed to reach RUNNING (the #493 false-success). Readiness
    /// (`evaluate_readiness`) gates on this in addition to `paths_live`.
    #[serde(default)]
    pub service_running: bool,
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
/// `dig_dns_bin` is the path to the just-downloaded `dig-dns` binary; on every
/// OS the registered service runs THAT binary directly (`dig-dns run-service`
/// on Windows, `dig-dns serve` on macOS/Linux — see [`windows`]) — there is no
/// installer host-shim to persist.
pub fn install(dig_dns_bin: &Path, cfg: &DnsInstallConfig, dry_run: bool) -> DnsInstallResult {
    #[cfg(windows)]
    {
        windows::install(dig_dns_bin, cfg, dry_run)
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
        let _ = (dig_dns_bin, cfg, dry_run);
        DnsInstallResult {
            installed: false,
            started: false,
            service_running: false,
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

/// Verify an ALREADY-registered dig-dns service is genuinely still live,
/// WITHOUT touching its registration — the counterpart to [`install`] for
/// issue #309's "already up to date, skip" decision.
///
/// Re-running the full [`install`] on every up-to-date run would needlessly
/// bounce a service whose binary did not change: `install` unconditionally
/// stop→deletes→recreates the registration on every OS (task #494's clean
/// reinstall), rewrites the split-DNS/NRPT rule, and re-applies the browser
/// DoH policy every time it is called. This instead reuses [`doctor`]'s
/// standalone, read-only probes (`doctor --json` / `pac --json`, the same
/// ones [`install`] itself ends with) to build the identical
/// [`DnsInstallResult`] shape a fresh install reports — so the caller's
/// post-registration logging and the `service_running` health-check gate
/// (`lib.rs::register_dig_dns`) work unchanged whether this run installed,
/// updated, or skipped.
pub fn verify_existing(dig_dns_bin: &Path) -> DnsInstallResult {
    let doctor_summary = doctor::wait_for_doctor(dig_dns_bin, 3, Duration::from_millis(200)).ok();
    let pac_info = doctor::run_pac(dig_dns_bin).ok();
    let paths_live: Vec<String> = doctor_summary
        .as_ref()
        .map(|d| {
            plan::live_paths(d)
                .into_iter()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let bound_port = pac_info.as_ref().map(|p| p.port);
    let pac_url = pac_info
        .as_ref()
        .map(|p| plan::pac_url(&p.loopback_ip, p.port));
    let fallback_instruction = pac_url.as_deref().map(plan::browser_fallback_instruction);
    DnsInstallResult {
        installed: true,
        started: !paths_live.is_empty(),
        // The service-manager RUNNING poll happens in `register_dig_dns`
        // (lib.rs), same as a fresh `install` — it overwrites this.
        service_running: false,
        needs_elevation: false,
        note: "already up to date — re-verified the existing registration instead of reinstalling"
            .to_string(),
        doctor: doctor_summary,
        paths_live,
        bound_port,
        pac_url,
        fallback_instruction,
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

#[cfg(test)]
mod tests {
    use super::*;

    const OK_DOCTOR_JSON: &str = r#"{"ok":true,"path_a":true,"path_b":true,"checks":[{"id":"loopback_ip","name":"Loopback IP is up","status":"pass","detail":"up"}]}"#;
    const PAC_JSON: &str = r#"{"loopback_ip":"127.0.0.5","port":80,"tld":"dig","pac":"function FindProxyForURL(url, host) { return \"DIRECT\"; }"}"#;

    /// A stub `dig-dns`-alike whose `doctor --json`/`pac --json` output
    /// depends on the argument it was called with — mirrors `doctor.rs`'s own
    /// `stub_stdout` test helper (this module has no shared test-utils to
    /// import from, so each module keeps its own small self-contained copy,
    /// matching the existing convention in `service.rs`/`doctor.rs`).
    #[cfg(windows)]
    fn stub_dig_dns(dir: &Path, name: &str) -> std::path::PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(format!("{name}.cmd"));
        std::fs::write(
            &p,
            format!(
                "@echo off\r\nif \"%1\"==\"doctor\" (echo {OK_DOCTOR_JSON}) else if \"%1\"==\"pac\" (echo {PAC_JSON})\r\nexit /b 0\r\n"
            ),
        )
        .unwrap();
        p
    }

    #[cfg(not(windows))]
    fn stub_dig_dns(dir: &Path, name: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  doctor) echo '{OK_DOCTOR_JSON}' ;;\n  pac) echo '{PAC_JSON}' ;;\nesac\nexit 0\n"
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
        // Warm up the exec (dodges the doctor.rs-documented ETXTBSY race on a
        // just-`chmod`'d file).
        for _ in 0..50 {
            match std::process::Command::new(&p).arg("doctor").output() {
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => break,
            }
        }
        p
    }

    fn tmp_subdir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dig-installer-dns-mod-{tag}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn verify_existing_reports_installed_true_and_live_when_the_service_answers() {
        let dir = tmp_subdir("verify-live");
        let bin = stub_dig_dns(&dir, "dig-dns-live");
        let result = verify_existing(&bin);
        assert!(result.installed, "verify_existing never re-registers, but always reports the pre-existing service as installed");
        assert!(result.started, "doctor confirmed at least one live path");
        assert_eq!(
            result.paths_live,
            vec!["dns".to_string(), "gateway".to_string()]
        );
        assert_eq!(result.bound_port, Some(80));
        assert!(result.pac_url.as_deref().unwrap().contains("proxy.pac"));
        assert!(
            !result.service_running,
            "left for the caller's own service-manager poll"
        );
        assert!(result.note.contains("already up to date"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_existing_degrades_gracefully_when_the_binary_cannot_be_probed() {
        // A binary that can't even be spawned (never installed, or removed
        // out from under us) must not panic — it reports honestly that
        // nothing was confirmed live, not a synthetic success.
        let missing = std::env::temp_dir().join("definitely-not-a-real-dig-dns-verify-xyz");
        let result = verify_existing(&missing);
        assert!(result.installed);
        assert!(!result.started);
        assert!(result.paths_live.is_empty());
        assert_eq!(result.bound_port, None);
        assert_eq!(result.pac_url, None);
    }
}
