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

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

use super::plan;
use super::{doctor, DnsInstallConfig, DnsInstallResult, DnsUninstallResult};

const RESOLVER_PATH: &str = "/etc/resolver/dig";
/// Where an org's MDM-provisioned Chrome managed preferences normally live —
/// scanned (never written to) to detect an existing policy.
const MANAGED_PREFS_DIR: &str = "/Library/Managed Preferences";
/// The best-effort fallback plist this installer writes when no existing
/// managed policy is found (a per-machine, not per-user, filename so it does
/// not require knowing which user account will run Chrome).
const CHROME_FALLBACK_PLIST: &str = "/Library/Managed Preferences/com.google.Chrome.plist";

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

/// Is this process running as root? Writing `/etc/resolver/dig`, a
/// LaunchDaemon under `/Library/LaunchDaemons`, or the Chrome managed plist
/// all require it.
pub fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn failed(note: impl Into<String>) -> DnsInstallResult {
    DnsInstallResult {
        installed: false,
        started: false,
        needs_elevation: false,
        note: note.into(),
        doctor: None,
        paths_live: Vec::new(),
        bound_port: None,
        pac_url: None,
        fallback_instruction: None,
    }
}

/// Idempotently apply the `lo0` alias immediately (independent of the
/// boot-persistence LaunchDaemon, which only takes effect on the NEXT boot).
/// Returns `Ok(true)` if it just applied the alias, `Ok(false)` if it was
/// already present.
fn ensure_lo0_alias_now(ip: &str) -> Result<bool, String> {
    let out = Command::new("ifconfig")
        .arg("lo0")
        .output()
        .map_err(|e| format!("ifconfig lo0: {e}"))?;
    if String::from_utf8_lossy(&out.stdout).contains(ip) {
        return Ok(false);
    }
    let status = Command::new("ifconfig")
        .args(["lo0", "alias", ip, "up"])
        .status()
        .map_err(|e| format!("ifconfig lo0 alias {ip} up: {e}"))?;
    if status.success() {
        Ok(true)
    } else {
        Err(format!("ifconfig lo0 alias {ip} up exited non-zero"))
    }
}

/// Remove the live `lo0` alias immediately (uninstall). A missing alias is a
/// no-op, not an error.
fn remove_lo0_alias_now(ip: &str) -> Result<bool, String> {
    let out = Command::new("ifconfig")
        .arg("lo0")
        .output()
        .map_err(|e| format!("ifconfig lo0: {e}"))?;
    if !String::from_utf8_lossy(&out.stdout).contains(ip) {
        return Ok(false);
    }
    let status = Command::new("ifconfig")
        .args(["lo0", "-alias", ip])
        .status()
        .map_err(|e| format!("ifconfig lo0 -alias {ip}: {e}"))?;
    Ok(status.success())
}

/// Write `content` to `path` only if it differs from what's already there
/// (idempotent). Returns `Ok(true)` if a write happened.
fn write_if_changed(path: &Path, content: &str) -> Result<bool, String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing == content {
            return Ok(false);
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(true)
}

/// Remove `path` only if it carries [`plan::MARKER`] (never delete a file
/// this installer did not create). A missing file is a no-op.
fn remove_if_ours(path: &Path) -> Result<bool, String> {
    match std::fs::read_to_string(path) {
        Ok(content) if content.contains(plan::MARKER) => {
            std::fs::remove_file(path).map_err(|e| format!("remove {}: {e}", path.display()))?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Does an existing (non-ours) Chrome managed-preferences policy already
/// exist under [`MANAGED_PREFS_DIR`]? Scans plist filenames for
/// `com.google.Chrome`, since real MDM-provisioned policies are per-console-
/// user (`<username>/com.google.Chrome.plist`) and this installer must never
/// clobber one.
fn existing_chrome_managed_policy() -> bool {
    let Ok(entries) = std::fs::read_dir(MANAGED_PREFS_DIR) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.contains("com.google.Chrome") && !is_ours_plist(&entry.path()) {
            return true;
        }
        // A per-user subdirectory (`<user>/com.google.Chrome.plist`).
        if entry.path().is_dir() {
            let nested = entry.path().join("com.google.Chrome.plist");
            if nested.exists() && !is_ours_plist(&nested) {
                return true;
            }
        }
    }
    false
}

fn is_ours_plist(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|c| c.contains(plan::MARKER))
        .unwrap_or(false)
}

/// Apply the best-effort Chrome managed DoH policy, UNLESS an existing
/// (non-ours) managed policy is already present. Returns `Ok(true)` if
/// written.
fn apply_chrome_managed_policy() -> Result<bool, String> {
    if existing_chrome_managed_policy() {
        return Ok(false);
    }
    write_if_changed(
        Path::new(CHROME_FALLBACK_PLIST),
        &plan::chrome_managed_plist(),
    )
}

/// Install dig-dns as a macOS LaunchDaemon: apply + persist the `lo0` alias,
/// write `/etc/resolver/dig`, register + start the dig-dns LaunchDaemon,
/// best-effort apply the Chrome managed policy, then self-verify with
/// `dig-dns doctor` + `dig-dns pac`.
pub fn install(dig_dns_bin: &Path, cfg: &DnsInstallConfig, dry_run: bool) -> DnsInstallResult {
    if dry_run {
        return DnsInstallResult {
            note: format!(
                "would alias {} on lo0 (boot-persistent), write {RESOLVER_PATH}, register the \
                 dig-dns LaunchDaemon for {}, and set the Chrome managed DoH policy",
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

    match ensure_lo0_alias_now(plan::LOOPBACK_IP) {
        Ok(true) => notes.push(format!("aliased {} on lo0", plan::LOOPBACK_IP)),
        Ok(false) => notes.push(format!("{} already aliased on lo0", plan::LOOPBACK_IP)),
        Err(e) => notes.push(format!("lo0 alias failed: {e}")),
    }

    let lo0_mgr = service_manager::LaunchdServiceManager::system();
    match lo0_mgr.install(ServiceInstallCtx {
        label: lo0_label(),
        program: PathBuf::from("/sbin/ifconfig"),
        args: vec![],
        contents: Some(plan::launchd_lo0_alias_plist(plan::LOOPBACK_IP)),
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
    }) {
        Ok(()) => notes.push("registered the boot-persistent lo0-alias LaunchDaemon".to_string()),
        Err(e) => notes.push(format!("lo0-alias LaunchDaemon not registered: {e}")),
    }

    match write_if_changed(
        Path::new(RESOLVER_PATH),
        &plan::resolver_dig_content(plan::LOOPBACK_IP),
    ) {
        Ok(true) => notes.push(format!("wrote {RESOLVER_PATH}")),
        Ok(false) => notes.push(format!("{RESOLVER_PATH} already up to date")),
        Err(e) => notes.push(format!("{RESOLVER_PATH} not written: {e}")),
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
        autostart: true,
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

    match apply_chrome_managed_policy() {
        Ok(true) => notes.push("Chrome managed DoH policy applied (best-effort fallback)".to_string()),
        Ok(false) => notes.push(
            "Chrome policy left untouched (an existing managed policy was found, or is MDM-provisioned)"
                .to_string(),
        ),
        Err(e) => notes.push(format!("Chrome policy not applied: {e}")),
    }
    notes.push(
        "Chrome enterprise policy on macOS is normally provisioned via MDM; if the DoH-off \
         policy does not take effect, set it manually (see the runbook)"
            .to_string(),
    );

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
        needs_elevation: false,
        note: notes.join("; "),
        doctor: doctor_summary,
        paths_live,
        bound_port,
        pac_url,
        fallback_instruction,
    }
}

/// Reverse [`install`]: stop + remove both LaunchDaemons, remove
/// `/etc/resolver/dig` (if ours), remove the live `lo0` alias, and remove the
/// Chrome managed plist ONLY if this installer wrote it.
pub fn uninstall(dry_run: bool) -> DnsUninstallResult {
    if dry_run {
        return DnsUninstallResult {
            uninstalled: false,
            needs_elevation: false,
            note: format!(
                "would stop + remove the dig-dns and lo0-alias LaunchDaemons, {RESOLVER_PATH}, \
                 the lo0 alias, and the Chrome managed plist if this installer wrote it"
            ),
            residue_removed: Vec::new(),
        };
    }
    if !is_root() {
        return DnsUninstallResult {
            uninstalled: false,
            needs_elevation: true,
            note: "uninstalling the dig-dns LaunchDaemon requires root (run with sudo)".to_string(),
            residue_removed: Vec::new(),
        };
    }

    let mut removed = Vec::new();
    let svc_mgr = service_manager::LaunchdServiceManager::system();
    let _ = svc_mgr.stop(ServiceStopCtx {
        label: service_label(),
    });
    if svc_mgr
        .uninstall(ServiceUninstallCtx {
            label: service_label(),
        })
        .is_ok()
    {
        removed.push(format!("dig-dns LaunchDaemon \"{}\"", plan::SERVICE_LABEL));
    }

    let lo0_mgr = service_manager::LaunchdServiceManager::system();
    let _ = lo0_mgr.stop(ServiceStopCtx { label: lo0_label() });
    if lo0_mgr
        .uninstall(ServiceUninstallCtx { label: lo0_label() })
        .is_ok()
    {
        removed.push("lo0-alias LaunchDaemon".to_string());
    }

    if let Ok(true) = remove_if_ours(Path::new(RESOLVER_PATH)) {
        removed.push(RESOLVER_PATH.to_string());
    }
    if let Ok(true) = remove_lo0_alias_now(plan::LOOPBACK_IP) {
        removed.push(format!("live lo0 alias {}", plan::LOOPBACK_IP));
    }
    if let Ok(true) = remove_if_ours(Path::new(CHROME_FALLBACK_PLIST)) {
        removed.push("Chrome managed DoH policy".to_string());
    }

    DnsUninstallResult {
        uninstalled: !removed.is_empty(),
        needs_elevation: false,
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

    fn tmp_subdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "dig-installer-dns-macos-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn write_if_changed_writes_when_absent_and_skips_when_identical() {
        let dir = tmp_subdir("write-changed");
        let p = dir.join("resolver-dig");
        assert!(write_if_changed(&p, "nameserver 127.0.0.5\n").unwrap());
        assert!(
            !write_if_changed(&p, "nameserver 127.0.0.5\n").unwrap(),
            "identical content is a no-op"
        );
        assert!(
            write_if_changed(&p, "nameserver 127.0.0.9\n").unwrap(),
            "changed content re-writes"
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "nameserver 127.0.0.9\n"
        );
    }

    #[test]
    fn remove_if_ours_only_deletes_marked_files() {
        let dir = tmp_subdir("remove-ours");
        let ours = dir.join("ours.txt");
        std::fs::write(&ours, format!("# {}\ncontent\n", plan::MARKER)).unwrap();
        let not_ours = dir.join("not-ours.txt");
        std::fs::write(&not_ours, "someone else's content\n").unwrap();

        assert!(remove_if_ours(&ours).unwrap());
        assert!(!ours.exists());

        assert!(
            !remove_if_ours(&not_ours).unwrap(),
            "must not delete an unmarked file"
        );
        assert!(not_ours.exists());
    }

    #[test]
    fn remove_if_ours_is_a_noop_when_missing() {
        let dir = tmp_subdir("remove-missing");
        let missing = dir.join("does-not-exist.txt");
        assert!(!remove_if_ours(&missing).unwrap());
    }

    #[test]
    fn is_root_never_panics() {
        let _ = is_root();
    }

    #[test]
    fn labels_parse() {
        assert_eq!(service_label().application, "dig-dns");
        assert_eq!(lo0_label().application, "dig-dns-lo0");
    }
}
