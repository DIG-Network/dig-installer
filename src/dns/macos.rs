#![cfg(target_os = "macos")]
//! macOS dig-dns OS-service install (task #177): a boot-persistent
//! `127.0.0.5` alias on `lo0`, an `/etc/resolver/dig` split-DNS entry, the
//! dig-dns LaunchDaemon (root, `KeepAlive`), and a best-effort Chrome
//! managed-preference DoH policy — NEVER editing the hosts file, NEVER a URL
//! rewrite, NEVER TLS interception.
//!
//! macOS does not persist `ifconfig` aliases across reboot, so a SEPARATE
//! one-shot LaunchDaemon ([`plan::launchd_lo0_alias_plist`]) re-applies the
//! alias at every boot, independent of the dig-dns service's own LaunchDaemon.
//!
//! Chrome's managed-preference plists are normally provisioned by MDM; this
//! module writes a best-effort fallback plist ONLY when no existing managed
//! policy is detected, and always ALSO prints manual instructions (the
//! brief's "don't clobber an existing org policy — print instructions
//! instead").

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

use super::plan;
use super::{doctor, DnsInstallConfig, DnsInstallResult, DnsUninstallResult};
use crate::proc::HideConsole;

fn lo0_label() -> ServiceLabel {
    plan::LO0_ALIAS_LABEL
        .parse()
        .expect("LO0_ALIAS_LABEL is a valid ServiceLabel")
}
fn service_label() -> ServiceLabel {
    plan::SERVICE_LABEL
        .parse()
        .expect("SERVICE_LABEL is a valid ServiceLabel")
}

/// Is the dig-dns LaunchDaemon currently registered with launchd (loaded in
/// the SYSTEM domain, running or not)? Probed via `launchctl print`, which
/// exits non-zero when the label is not bootstrapped.
fn service_registered(label: &str) -> bool {
    Command::new("launchctl")
        .args(["print", &format!("system/{label}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .hide_console()
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Cleanly remove a pre-existing dig-dns LaunchDaemon registration: `launchctl
/// bootout` (the modern replacement for `unload`) then delete its plist file
/// — so a subsequent install always creates fresh rather than reconfiguring
/// in place (task #494). Best-effort: an already-absent registration is a
/// no-op (the commands' errors are ignored — there is nothing to remove).
fn clean_remove_existing(label: &str) {
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("system/{label}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .hide_console()
        .status();
    let _ =
        std::fs::remove_file(Path::new("/Library/LaunchDaemons").join(format!("{label}.plist")));
}

/// Stop the running dig-dns LaunchDaemon so it releases the lock on its binary
/// before an upgrade overwrites it (#544), then bounded-wait for it to leave
/// RUNNING. Called only when [`crate::svc::service_run_state`] already observed
/// it RUNNING; any error is surfaced for the caller to record (the write's
/// delayed-replace fallback is the safety net).
pub fn stop_service() -> Result<(), String> {
    let mgr = service_manager::LaunchdServiceManager::system();
    mgr.stop(ServiceStopCtx {
        label: service_label(),
    })
    .map_err(|e| format!("launchctl stop {}: {e}", plan::SERVICE_LABEL))?;
    wait_until_not_running(Duration::from_secs(10));
    Ok(())
}

/// Poll until the dig-dns service leaves RUNNING (or `max_wait` elapses) — the
/// daemon's process exiting is what releases the binary. A bounded poll lets a
/// fast stop proceed immediately.
fn wait_until_not_running(max_wait: Duration) {
    let start = std::time::Instant::now();
    while crate::svc::service_run_state(crate::svc::DIG_DNS_SERVICE_ID)
        == crate::svc::ServiceRunState::Running
    {
        if start.elapsed() >= max_wait {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Is this process running as root? Writing `/etc/resolver/dig`, a
/// LaunchDaemon under `/Library/LaunchDaemons`, or the Chrome managed plist
/// all require it.
pub fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .hide_console()
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn failed(note: impl Into<String>) -> DnsInstallResult {
    DnsInstallResult {
        installed: false,
        started: false,
        service_running: false,
        needs_elevation: false,
        note: note.into(),
        doctor: None,
        paths_live: Vec::new(),
        bound_port: None,
        pac_url: None,
        fallback_instruction: None,
        reboot_required: false,
        reboot_reason: None,
    }
}

/// Idempotently apply the `lo0` alias immediately (independent of the
/// boot-persistence LaunchDaemon, which only takes effect on the NEXT boot).
/// Returns `Ok(true)` if it just applied the alias, `Ok(false)` if it was
/// already present.
fn ensure_lo0_alias_now(ip: &str) -> Result<bool, String> {
    let out = Command::new("ifconfig")
        .arg("lo0")
        .hide_console()
        .output()
        .map_err(|e| format!("ifconfig lo0: {e}"))?;
    if String::from_utf8_lossy(&out.stdout).contains(ip) {
        return Ok(false);
    }
    let status = Command::new("ifconfig")
        .args(["lo0", "alias", ip, "up"])
        .hide_console()
        .status()
        .map_err(|e| format!("ifconfig lo0 alias {ip} up: {e}"))?;
    if status.success() {
        Ok(true)
    } else {
        Err(format!("ifconfig lo0 alias {ip} up exited non-zero"))
    }
}

/// Install dig-dns as a macOS LaunchDaemon: apply the live `lo0` alias (the
/// binding prerequisite), register + start the dig-dns LaunchDaemon, delegate
/// the resolver/browser wiring to `dig-dns configure-os`, then self-verify with
/// `dig-dns doctor` + `dig-dns pac`.
pub fn install(dig_dns_bin: &Path, cfg: &DnsInstallConfig, dry_run: bool) -> DnsInstallResult {
    if dry_run {
        return DnsInstallResult {
            note: format!(
                "would alias {} on lo0 (the binding prerequisite), ensure a clean reinstall \
                 (bootout + remove any pre-existing LaunchDaemon), register the dig-dns \
                 LaunchDaemon for {}, then run dig-dns configure-os to wire + verify the resolver",
                plan::LOOPBACK_IP,
                dig_dns_bin.display()
            ),
            ..failed(String::new())
        };
    }
    if !is_root() {
        return DnsInstallResult {
            needs_elevation: true,
            ..failed("installing the dig-dns LaunchDaemon requires root (run with sudo)")
        };
    }

    let mut notes = Vec::new();

    // Clean reinstall (task #494): a pre-existing LaunchDaemon registration is
    // booted out + its plist removed BEFORE reinstalling — never reconfigured
    // in place.
    if service_registered(plan::SERVICE_LABEL) {
        clean_remove_existing(plan::SERVICE_LABEL);
        notes.push(
            "removed the pre-existing dig-dns LaunchDaemon for a clean reinstall".to_string(),
        );
    }

    // The `lo0` alias is a FUNCTIONAL PREREQUISITE for the dig-dns service to
    // bind 127.0.0.5:53 (macOS answers only 127.0.0.1 on lo0 by default), so
    // apply it LIVE before starting the service. Boot-persisting the alias and
    // the rest of the resolver wiring is owned by `dig-dns configure-os`, run
    // after the service is up (#627 WU2).
    match ensure_lo0_alias_now(plan::LOOPBACK_IP) {
        Ok(true) => notes.push(format!("aliased {} on lo0", plan::LOOPBACK_IP)),
        Ok(false) => notes.push(format!("{} already aliased on lo0", plan::LOOPBACK_IP)),
        Err(e) => notes.push(format!("lo0 alias failed: {e}")),
    }

    let svc_mgr = service_manager::LaunchdServiceManager::system();
    let mut started = false;
    match svc_mgr.install(ServiceInstallCtx {
        label: service_label(),
        program: dig_dns_bin.to_path_buf(),
        args: vec!["serve".into()],
        contents: Some(plan::launchd_service_plist(
            &dig_dns_bin.to_string_lossy(),
            cfg.node.as_deref(),
        )),
        // No `username` → root, required for a system LaunchDaemon to bind :53/:80.
        username: None,
        working_directory: None,
        environment: None,
        // Boot-start (#301): launchd loads it at boot (paired with the plist's
        // RunAtLoad) — the service comes up on every boot.
        autostart: plan::DNS_SERVICE_AUTOSTART,
    }) {
        Ok(()) => {
            notes.push(format!(
                "registered the dig-dns LaunchDaemon \"{}\"",
                plan::SERVICE_LABEL
            ));
            if cfg.start {
                match svc_mgr.start(ServiceStartCtx {
                    label: service_label(),
                }) {
                    Ok(()) => {
                        started = true;
                        notes.push("started".to_string());
                    }
                    Err(e) => notes.push(format!("start failed: {e}")),
                }
            }
        }
        Err(e) => notes.push(format!("dig-dns LaunchDaemon not registered: {e}")),
    }

    // Resolver activation (#627 WU2): `/etc/resolver/dig`, the boot-persistent
    // lo0-alias LaunchDaemon, the DNS-cache flush, the Chrome managed DoH
    // policy, and the end-to-end resolve VERIFY are owned by `dig-dns
    // configure-os`, invoked by the ABSOLUTE path to the installed binary.
    let (reboot_required, reboot_reason) = apply_os_config(dig_dns_bin, &mut notes);

    let doctor_summary = if started {
        doctor::wait_for_doctor(dig_dns_bin, 10, Duration::from_millis(500)).ok()
    } else {
        None
    };
    let pac_info = if started {
        doctor::run_pac(dig_dns_bin).ok()
    } else {
        None
    };
    let paths_live = doctor_summary
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
        started,
        // Set by the RUNNING poll in `register_dig_dns` (lib.rs) after this returns.
        service_running: false,
        needs_elevation: false,
        note: notes.join("; "),
        doctor: doctor_summary,
        paths_live,
        bound_port,
        pac_url,
        fallback_instruction,
        reboot_required,
        reboot_reason,
    }
}

/// Run `dig-dns configure-os` (via [`super::os_config`]), fold its notes into
/// the install log, and return the `(reboot_required, reboot_reason)` the caller
/// ORs into the #562 restart verdict. A spawn/parse failure is recorded but
/// non-fatal and never synthesizes a reboot prompt.
fn apply_os_config(dig_dns_bin: &Path, notes: &mut Vec<String>) -> (bool, Option<String>) {
    match super::os_config::configure_os(dig_dns_bin) {
        Ok(summary) => {
            notes.extend(summary.notes.iter().cloned());
            match summary.restart_reason() {
                Some(reason) => (true, Some(reason)),
                None => (false, None),
            }
        }
        Err(e) => {
            notes.push(format!("dig-dns configure-os failed: {e}"));
            (false, None)
        }
    }
}

/// Reverse [`install`]: stop + remove the dig-dns LaunchDaemon, then delegate
/// the resolver/lo0-alias/browser-policy teardown to `dig-dns unconfigure-os`
/// ([`super::os_config`]).
pub fn uninstall(dig_dns_bin: Option<&Path>, dry_run: bool) -> DnsUninstallResult {
    if dry_run {
        return DnsUninstallResult {
            uninstalled: false,
            needs_elevation: false,
            service_removed: false,
            note: "would stop + remove the dig-dns LaunchDaemon, then delegate the \
                   resolver/lo0-alias/browser-policy teardown to dig-dns unconfigure-os"
                .to_string(),
            residue_removed: Vec::new(),
        };
    }
    if !is_root() {
        return DnsUninstallResult {
            uninstalled: false,
            needs_elevation: true,
            service_removed: false,
            note: "uninstalling the dig-dns LaunchDaemon requires root (run with sudo)".to_string(),
            residue_removed: Vec::new(),
        };
    }

    let mut removed = Vec::new();
    let svc_mgr = service_manager::LaunchdServiceManager::system();
    let _ = svc_mgr.stop(ServiceStopCtx {
        label: service_label(),
    });
    let service_removed = svc_mgr
        .uninstall(ServiceUninstallCtx {
            label: service_label(),
        })
        .is_ok();
    if service_removed {
        removed.push(format!("dig-dns LaunchDaemon \"{}\"", plan::SERVICE_LABEL));
    }

    // Legacy: a machine wired by the PRE-WU2 installer has the installer's OWN
    // lo0-alias LaunchDaemon (a distinct label from dig-dns's). Tear it down
    // here so an upgrade-then-uninstall never orphans it; the current
    // dig-dns-owned lo0 daemon/alias/resolver file/browser policy are removed by
    // `unconfigure-os` below.
    let lo0_mgr = service_manager::LaunchdServiceManager::system();
    let _ = lo0_mgr.stop(ServiceStopCtx { label: lo0_label() });
    if lo0_mgr
        .uninstall(ServiceUninstallCtx { label: lo0_label() })
        .is_ok()
    {
        removed.push("legacy lo0-alias LaunchDaemon".to_string());
    }

    // Resolver/lo0-alias/browser-policy teardown (#627 WU2) is owned by
    // `dig-dns unconfigure-os` — it removes both dig-dns's own artifacts and the
    // legacy installer's (marker-scoped, incl. the bare `/etc/resolver/dig`).
    removed.extend(super::os_config::unconfigure_removed(dig_dns_bin));

    DnsUninstallResult {
        uninstalled: !removed.is_empty(),
        needs_elevation: false,
        service_removed,
        note: if removed.is_empty() {
            "nothing to remove (dig-dns was not registered by this installer)".to_string()
        } else {
            format!("removed: {}", removed.join(", "))
        },
        residue_removed: removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_root_never_panics() {
        let _ = is_root();
    }

    #[test]
    fn labels_parse() {
        assert_eq!(service_label().application, "dig-dns");
        assert_eq!(lo0_label().application, "dig-dns-lo0");
    }

    /// A label that certainly is not bootstrapped on any test host (task #494).
    const NONEXISTENT_LABEL: &str = "net.dignetwork.dig-dns-test-definitely-not-a-real-service";

    #[test]
    fn service_registered_is_false_for_an_unregistered_label() {
        assert!(!service_registered(NONEXISTENT_LABEL));
    }

    #[test]
    fn clean_remove_existing_never_panics_when_absent() {
        // Best-effort teardown of something that was never there: must not
        // panic or error out (the caller only invokes this after confirming
        // `service_registered`, but the function itself stays a safe no-op).
        clean_remove_existing(NONEXISTENT_LABEL);
    }
}
