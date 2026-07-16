#![cfg(target_os = "linux")]
//! Linux dig-dns OS-service install (task #177): a systemd unit running as a
//! dedicated, unprivileged user with ONLY `CAP_NET_BIND_SERVICE`, split-DNS
//! wired to whichever resolver actually owns `/etc/resolv.conf`
//! (systemd-resolved / NetworkManager-dnsmasq — a plain `resolv.conf` is
//! warned about, never rewritten), and a Chrome/Chromium policy JSON —
//! NEVER editing the hosts file, NEVER a URL rewrite, NEVER TLS interception.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

use super::plan;
use super::{doctor, DnsInstallConfig, DnsInstallResult, DnsUninstallResult};
use crate::proc::HideConsole;

fn service_label() -> ServiceLabel {
    plan::SERVICE_LABEL
        .parse()
        .expect("SERVICE_LABEL is a valid ServiceLabel")
}

/// The directory `service-manager`'s `SystemdServiceManager::system()` writes
/// unit files to (not part of its public API — mirrored here so existence can
/// be probed without an extra `systemctl` spawn).
const SYSTEMD_UNIT_DIR: &str = "/etc/systemd/system";

/// Is a systemd unit named `script_name` registered under `dir` (its
/// `.service` file present)? Pure given the directory, so the real check
/// ([`unit_registered`]) is unit-tested against a temp dir instead of
/// requiring root to touch [`SYSTEMD_UNIT_DIR`].
fn unit_file_exists_under(dir: &Path, script_name: &str) -> bool {
    dir.join(format!("{script_name}.service")).exists()
}

/// Is the dig-dns systemd unit currently registered (its unit file present in
/// [`SYSTEMD_UNIT_DIR`])? A plain file-existence check is sufficient and
/// avoids spawning `systemctl` just to answer "is this registered at all".
fn unit_registered(script_name: &str) -> bool {
    unit_file_exists_under(Path::new(SYSTEMD_UNIT_DIR), script_name)
}

/// Cleanly remove a pre-existing dig-dns systemd unit: `systemctl stop` +
/// `systemctl disable` (via the crate's `stop`/`uninstall`, which also
/// deletes the unit file) — so a subsequent install always creates fresh
/// rather than reconfiguring in place (task #494). Best-effort: an
/// already-absent unit is a no-op (errors are ignored).
fn clean_remove_existing_unit() {
    let mgr = service_manager::SystemdServiceManager::system();
    let _ = mgr.stop(ServiceStopCtx {
        label: service_label(),
    });
    let _ = mgr.uninstall(ServiceUninstallCtx {
        label: service_label(),
    });
}

/// Stop the running dig-dns systemd unit so it releases the lock on its binary
/// before an upgrade overwrites it (#544), then bounded-wait for it to leave
/// RUNNING. Called only when [`crate::svc::service_run_state`] already observed
/// it RUNNING; any error is surfaced for the caller to record (the write's
/// delayed-replace fallback is the safety net).
pub fn stop_service() -> Result<(), String> {
    let mgr = service_manager::SystemdServiceManager::system();
    mgr.stop(ServiceStopCtx {
        label: service_label(),
    })
    .map_err(|e| format!("systemctl stop {}: {e}", plan::service_script_name()))?;
    wait_until_not_running(Duration::from_secs(10));
    Ok(())
}

/// Poll until the dig-dns service leaves RUNNING (or `max_wait` elapses) — the
/// unit's process exiting is what releases the binary. A bounded poll lets a
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

/// Is this process running as root? Creating the dedicated service user,
/// writing the systemd unit, and wiring split-DNS all require it.
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

/// Which resolver owns `/etc/resolv.conf`, decided by inspecting it (and the
/// well-known systemd-resolved/NetworkManager-dnsmasq markers) — never by
/// assuming. Pure given the two probes it's handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvOwner {
    SystemdResolved,
    NetworkManagerDnsmasq,
    Unknown,
}

/// Decide the resolv.conf owner from the target of the `/etc/resolv.conf`
/// symlink (if any) and whether the NetworkManager dnsmasq drop-in directory
/// exists. Pure — the caller supplies the two observations.
pub fn detect_resolv_owner(
    resolv_conf_link_target: Option<&str>,
    nm_dnsmasq_dir_exists: bool,
) -> ResolvOwner {
    if let Some(target) = resolv_conf_link_target {
        if target.contains("systemd") {
            return ResolvOwner::SystemdResolved;
        }
    }
    if nm_dnsmasq_dir_exists {
        return ResolvOwner::NetworkManagerDnsmasq;
    }
    ResolvOwner::Unknown
}

/// Does the dedicated service user already exist? (`id -u <user>`.)
fn user_exists(user: &str) -> bool {
    Command::new("id")
        .arg("-u")
        .arg(user)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .hide_console()
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Idempotently create the dedicated, unprivileged, login-less service user.
fn ensure_service_user(user: &str) -> Result<bool, String> {
    if user_exists(user) {
        return Ok(false);
    }
    let status = Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            user,
        ])
        .hide_console()
        .status()
        .map_err(|e| format!("useradd {user}: {e}"))?;
    if status.success() {
        Ok(true)
    } else {
        Err(format!("useradd {user} exited non-zero"))
    }
}

/// Install dig-dns as a systemd service: create the dedicated user, register +
/// enable the unit, delegate the split-DNS + Chrome/Chromium policy wiring to
/// `dig-dns configure-os`, then self-verify with `dig-dns doctor` + `dig-dns pac`.
pub fn install(dig_dns_bin: &Path, cfg: &DnsInstallConfig, dry_run: bool) -> DnsInstallResult {
    if dry_run {
        return DnsInstallResult {
            note: format!(
                "would create the {} user, ensure a clean reinstall (stop + disable any \
                 pre-existing unit), register the dig-dns systemd unit for {}, wire split-DNS \
                 for the detected resolver, and write the Chrome/Chromium policy",
                plan::LINUX_SERVICE_USER,
                dig_dns_bin.display()
            ),
            ..failed(String::new())
        };
    }
    if !is_root() {
        return DnsInstallResult {
            needs_elevation: true,
            ..failed("installing the dig-dns systemd service requires root (run with sudo)")
        };
    }

    let mut notes = Vec::new();

    // Clean reinstall (task #494): a pre-existing unit is stopped + disabled
    // (and its unit file removed) BEFORE reinstalling — never reconfigured in
    // place.
    if unit_registered(&plan::service_script_name()) {
        clean_remove_existing_unit();
        notes.push(
            "removed the pre-existing dig-dns systemd unit for a clean reinstall".to_string(),
        );
    }

    match ensure_service_user(plan::LINUX_SERVICE_USER) {
        Ok(true) => notes.push(format!(
            "created the {} service user",
            plan::LINUX_SERVICE_USER
        )),
        Ok(false) => notes.push(format!("{} user already exists", plan::LINUX_SERVICE_USER)),
        Err(e) => notes.push(format!("service user not created: {e}")),
    }

    let mgr = service_manager::SystemdServiceManager::system();
    let mut started = false;
    match mgr.install(ServiceInstallCtx {
        label: service_label(),
        program: dig_dns_bin.to_path_buf(),
        args: vec!["serve".into()],
        contents: Some(plan::systemd_unit(
            &dig_dns_bin.to_string_lossy(),
            cfg.node.as_deref(),
        )),
        username: None,
        working_directory: None,
        environment: None,
        // Boot-start (#301): `systemctl enable` (paired with the unit's
        // WantedBy=multi-user.target) — the service comes up on every boot.
        autostart: plan::DNS_SERVICE_AUTOSTART,
    }) {
        Ok(()) => {
            notes.push(format!(
                "registered the systemd unit \"{}\"",
                plan::service_script_name()
            ));
            if cfg.start {
                match mgr.start(ServiceStartCtx {
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
        Err(e) => notes.push(format!("systemd unit not registered: {e}")),
    }

    // Resolver activation (#627 WU2): the split-DNS drop-in (systemd-resolved /
    // NetworkManager-dnsmasq), the resolver-cache flush, the Chrome/Chromium
    // managed policy, and the end-to-end resolve VERIFY are owned by `dig-dns
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

/// Reverse [`install`]: stop + remove the systemd unit, delegate the
/// split-DNS + Chrome/Chromium policy teardown to `dig-dns unconfigure-os`
/// ([`super::os_config`]), and remove the dedicated service user.
pub fn uninstall(dig_dns_bin: Option<&Path>, dry_run: bool) -> DnsUninstallResult {
    if dry_run {
        return DnsUninstallResult {
            uninstalled: false,
            needs_elevation: false,
            service_removed: false,
            note: format!(
                "would stop + remove the dig-dns systemd unit, delegate the split-DNS + \
                 Chrome/Chromium policy teardown to dig-dns unconfigure-os, and remove the {} user",
                plan::LINUX_SERVICE_USER
            ),
            residue_removed: Vec::new(),
        };
    }
    if !is_root() {
        return DnsUninstallResult {
            uninstalled: false,
            needs_elevation: true,
            service_removed: false,
            note: "uninstalling the dig-dns systemd service requires root (run with sudo)"
                .to_string(),
            residue_removed: Vec::new(),
        };
    }

    let mut removed = Vec::new();
    let mgr = service_manager::SystemdServiceManager::system();
    let _ = mgr.stop(ServiceStopCtx {
        label: service_label(),
    });
    let service_removed = mgr
        .uninstall(ServiceUninstallCtx {
            label: service_label(),
        })
        .is_ok();
    if service_removed {
        removed.push(format!("systemd unit \"{}\"", plan::service_script_name()));
    }

    // Split-DNS + browser-policy teardown (#627 WU2) is owned by `dig-dns
    // unconfigure-os` — it removes both dig-dns's own artifacts and the legacy
    // installer's (marker-scoped).
    removed.extend(super::os_config::unconfigure_removed(dig_dns_bin));

    if user_exists(plan::LINUX_SERVICE_USER)
        && Command::new("userdel")
            .arg(plan::LINUX_SERVICE_USER)
            .hide_console()
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    {
        removed.push(format!("{} user", plan::LINUX_SERVICE_USER));
    }

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
    use std::path::PathBuf;

    fn tmp_subdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "dig-installer-dns-linux-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn detects_systemd_resolved_from_the_symlink_target() {
        assert_eq!(
            detect_resolv_owner(Some("/run/systemd/resolve/stub-resolv.conf"), false),
            ResolvOwner::SystemdResolved
        );
        assert_eq!(
            detect_resolv_owner(Some("../run/systemd/resolve/resolv.conf"), true),
            ResolvOwner::SystemdResolved,
            "systemd-resolved wins even if the NM dnsmasq dir also happens to exist"
        );
    }

    #[test]
    fn detects_networkmanager_dnsmasq_when_no_systemd_symlink() {
        assert_eq!(
            detect_resolv_owner(None, true),
            ResolvOwner::NetworkManagerDnsmasq
        );
        assert_eq!(
            detect_resolv_owner(Some("/etc/some-other-target"), true),
            ResolvOwner::NetworkManagerDnsmasq
        );
    }

    #[test]
    fn detects_unknown_for_a_plain_resolv_conf() {
        assert_eq!(detect_resolv_owner(None, false), ResolvOwner::Unknown);
    }

    #[test]
    fn is_root_and_user_exists_never_panic() {
        let _ = is_root();
        let _ = user_exists("root"); // root always exists; just exercises the probe.
    }

    #[test]
    fn service_label_parses() {
        assert_eq!(service_label().application, "dig-dns");
    }

    /// #494: clean-reinstall detection is a plain file-presence check,
    /// parameterized so it's tested against a temp dir (never touching the
    /// real `/etc/systemd/system`, which the test process may not own).
    #[test]
    fn unit_file_exists_under_detects_presence_and_absence() {
        let dir = tmp_subdir("unit-exists");
        assert!(!unit_file_exists_under(&dir, "dig-dns"));
        std::fs::write(dir.join("dig-dns.service"), "fake unit\n").unwrap();
        assert!(unit_file_exists_under(&dir, "dig-dns"));
    }

    #[test]
    fn unit_registered_is_false_in_a_test_environment() {
        // No CI/dev container has a real dig-dns unit registered under the
        // canonical path.
        assert!(!unit_registered("dig-dns-test-definitely-not-real"));
    }
}
