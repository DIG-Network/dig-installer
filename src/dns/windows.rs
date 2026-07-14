#![cfg(windows)]
//! Windows dig-dns OS-service install (task #177): a Windows Service (SCM) via
//! `service-manager`'s `ScServiceManager`, the `.dig` NRPT rule
//! (`Add-DnsClientNrptRule -Namespace .dig`), and a Chrome/Edge HKLM DoH
//! policy — NEVER editing the hosts file, NEVER a URL rewrite, NEVER TLS
//! interception.
//!
//! The SCM service is registered to run `dig-dns.exe run-service` **directly**
//! — dig-dns's OWN Windows Service Control Protocol entrypoint (v0.9.0+), which
//! reports `SERVICE_RUNNING` to the SCM before any slow startup work. There is
//! NO re-launching installer host-shim: the previous shim (the installer's own
//! binary child-spawning `dig-dns serve`) added an indirection that missed the
//! SCM start-timeout, producing the field `1053` error (#499); running dig-dns
//! directly removes it. Any dig-node endpoint override is baked into the
//! service ENVIRONMENT (`DIG_NODE_URL`), which `run-service` reads.

use std::path::Path;
use std::time::Duration;

use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

use super::plan;
use super::{doctor, DnsInstallConfig, DnsInstallResult, DnsUninstallResult};

fn label() -> ServiceLabel {
    plan::SERVICE_LABEL
        .parse()
        .expect("SERVICE_LABEL is a valid ServiceLabel")
}

/// Is this process running elevated (Administrator)? Registering a service, an
/// NRPT rule, and an HKLM key all require it. Mirrors dig-node-service's
/// `is_elevated` (probing by attempting `net session`, which only an elevated
/// token can run).
pub fn is_elevated() -> bool {
    std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Is a Windows Service named `service_name` currently registered with the
/// SCM (in any state — running, stopped, etc.)? Probed via `sc query`, whose
/// exit code [`plan::sc_query_means_not_registered`] interprets. Never
/// requires elevation (querying, unlike creating/deleting/configuring, is
/// available to any user).
fn service_exists(service_name: &str) -> bool {
    let output = std::process::Command::new("sc")
        .args(["query", service_name])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    match output {
        Ok(out) => !plan::sc_query_means_not_registered(out.status.code()),
        // `sc.exe` failed to spawn at all — treat as absent (best-effort; the
        // subsequent create attempt will surface the real failure).
        Err(_) => false,
    }
}

/// Poll [`service_exists`] until it reports gone or `max_wait` elapses. A `sc
/// delete` marks a service for deletion, which the SCM can take a moment to
/// fully complete; a bounded poll (not an unconditional sleep) means a fast
/// removal proceeds immediately while a slow one still gets the full budget.
fn wait_for_removal(service_name: &str, max_wait: Duration) {
    let start = std::time::Instant::now();
    while service_exists(service_name) {
        if start.elapsed() >= max_wait {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Stop the running dig-dns Windows service (SCM) so it releases the lock on
/// its `dig-dns.exe` before an upgrade overwrites it (#544), then bounded-wait
/// for it to leave RUNNING (its process must exit to release the file handle).
/// Called only when [`crate::svc::service_run_state`] already observed it
/// RUNNING, so a "service not started" error is not expected; any error is
/// surfaced for the caller to record (the write's delayed-replace fallback is
/// the safety net).
pub fn stop_service() -> Result<(), String> {
    let mgr = service_manager::ScServiceManager::system();
    mgr.stop(ServiceStopCtx { label: label() })
        .map_err(|e| format!("sc stop {}: {e}", plan::SERVICE_LABEL))?;
    wait_until_not_running(Duration::from_secs(10));
    Ok(())
}

/// Poll until the dig-dns service leaves RUNNING (or `max_wait` elapses) — a
/// stopped service's process exiting is what releases the exe's file handle. A
/// bounded poll (not a fixed sleep) lets a fast stop proceed at once.
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

/// Set the Windows Service's human-friendly DISPLAY name (task #494) via
/// `sc config`. `service-manager`'s `ScServiceManager::install` always sets
/// `displayname=` to the qualified service name at create time (no
/// `ServiceInstallCtx` field overrides it), so this is a follow-up call.
fn set_display_name(service_name: &str, display_name: &str) -> Result<(), String> {
    let args = plan::sc_set_display_name_args(service_name, display_name);
    let status = std::process::Command::new("sc")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("spawn sc config: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "sc config exited with {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string())
        ))
    }
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
    }
}

/// Run a PowerShell command line, discarding its stdout (used for `Add-`/`Remove-DnsClientNrptRule`,
/// which report their own errors on stderr). `Ok(())` iff PowerShell exits 0.
fn run_ps(command: &str) -> Result<(), String> {
    let status = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .status()
        .map_err(|e| format!("spawn powershell: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "powershell exited with {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string())
        ))
    }
}

/// Apply the DoH-off + built-in-resolver-off policy under `hive\key_path`, UNLESS the key
/// already exists and was not created by this installer (an existing org policy — never
/// clobbered). Returns `Ok(true)` if applied, `Ok(false)` if left untouched.
fn apply_policy_under(hive: &RegKey, key_path: &str) -> Result<bool, String> {
    if let Ok(existing) = hive.open_subkey(key_path) {
        let ours: u32 = existing.get_value(plan::POLICY_MARKER_NAME).unwrap_or(0);
        if ours != 1 {
            return Ok(false); // a pre-existing (non-ours) policy — leave it alone.
        }
    }
    let (key, _disp) = hive
        .create_subkey(key_path)
        .map_err(|e| format!("open/create {key_path}: {e}"))?;
    key.set_value(plan::POLICY_DOH_NAME, &plan::POLICY_DOH_OFF)
        .map_err(|e| e.to_string())?;
    key.set_value(plan::POLICY_BUILTIN_RESOLVER_NAME, &0u32)
        .map_err(|e| e.to_string())?;
    key.set_value(plan::POLICY_MARKER_NAME, &1u32)
        .map_err(|e| e.to_string())?;
    Ok(true)
}

/// Remove the policy under `hive\key_path` ONLY if this installer created it (the
/// [`plan::POLICY_MARKER_NAME`] marker is present). Returns `Ok(true)` if removed.
///
/// Deletes ONLY the three values THIS installer set (`POLICY_DOH_NAME`,
/// `POLICY_BUILTIN_RESOLVER_NAME`, `POLICY_MARKER_NAME`) — NEVER the whole
/// Chrome/Edge policy key via `delete_subkey_all`. An org (or another tool) may
/// have added its own values to the same `…\Chrome`/`…\Edge` policy key after us;
/// blowing the entire key away would destroy that unrelated managed policy. The
/// (now possibly empty) key itself is left in place — a harmless empty policy key
/// is far safer than nuking a key we do not exclusively own.
fn remove_policy_under(hive: &RegKey, key_path: &str) -> Result<bool, String> {
    match hive.open_subkey_with_flags(key_path, KEY_READ | KEY_SET_VALUE) {
        Ok(existing) => {
            let ours: u32 = existing.get_value(plan::POLICY_MARKER_NAME).unwrap_or(0);
            if ours != 1 {
                return Ok(false); // not ours — never touch someone else's policy.
            }
            // Delete only the values we own; leave any foreign values (and the key)
            // intact. `delete_value` on an absent value is a no-op we can ignore.
            let _ = existing.delete_value(plan::POLICY_DOH_NAME);
            let _ = existing.delete_value(plan::POLICY_BUILTIN_RESOLVER_NAME);
            let _ = existing.delete_value(plan::POLICY_MARKER_NAME);
            Ok(true)
        }
        Err(_) => Ok(false), // nothing there (or not readable) — nothing to remove.
    }
}

fn apply_browser_policy(key_path: &str) -> Result<bool, String> {
    apply_policy_under(&RegKey::predef(HKEY_LOCAL_MACHINE), key_path)
}

fn remove_browser_policy(key_path: &str) -> Result<bool, String> {
    remove_policy_under(&RegKey::predef(HKEY_LOCAL_MACHINE), key_path)
}

/// Install dig-dns as a Windows Service: register + start the SCM service
/// pointing at `dig-dns.exe run-service` DIRECTLY (dig-dns's own SCM
/// entrypoint — no installer host-shim, the #499 `1053` fix), add the `.dig`
/// NRPT rule, apply the Chrome/Edge DoH policy, then self-verify with
/// `dig-dns doctor` + `dig-dns pac`.
pub fn install(dig_dns_bin: &Path, cfg: &DnsInstallConfig, dry_run: bool) -> DnsInstallResult {
    if dry_run {
        return DnsInstallResult {
            note: format!(
                "would ensure a clean reinstall (stop + delete any pre-existing service), \
                 register the Windows service \"{}\" to run \"{} run-service\" directly with \
                 display name \"{}\", add the .dig NRPT rule, and set the Chrome/Edge DoH policy",
                plan::SERVICE_LABEL,
                dig_dns_bin.display(),
                plan::SERVICE_DISPLAY_NAME,
            ),
            ..failed(String::new())
        };
    }

    if !is_elevated() {
        return DnsInstallResult {
            needs_elevation: true,
            ..failed(
                "installing the dig-dns Windows service requires an elevated (Administrator) \
                 console; re-run in a terminal opened with \"Run as administrator\""
                    .to_string(),
            )
        };
    }

    let mgr = service_manager::ScServiceManager::system();
    // Register `dig-dns run-service` directly; bake an explicit dig-node
    // override into the service environment (dig-dns reads DIG_NODE_URL).
    let args = plan::run_service_args();
    let environment = plan::service_node_env(cfg.node.as_deref());

    let mut notes = Vec::new();

    // Clean reinstall (task #494): a pre-existing service is stopped +
    // deregistered BEFORE recreating — never reconfigured in place. Fixes
    // `CreateService 1073` ("already exists") on a second install run.
    if service_exists(plan::SERVICE_LABEL) {
        let _ = mgr.stop(ServiceStopCtx { label: label() });
        match mgr.uninstall(ServiceUninstallCtx { label: label() }) {
            Ok(()) => notes
                .push("removed the pre-existing Windows service for a clean reinstall".to_string()),
            Err(e) => notes.push(format!(
                "could not remove the pre-existing Windows service before reinstall: {e}"
            )),
        }
        wait_for_removal(plan::SERVICE_LABEL, Duration::from_secs(5));
    }

    if let Err(e) = mgr.install(ServiceInstallCtx {
        label: label(),
        program: dig_dns_bin.to_path_buf(),
        args: args.into_iter().map(std::ffi::OsString::from).collect(),
        contents: None,
        // No `username` → LocalSystem, required to bind :53/:80 on the dedicated loopback IP.
        username: None,
        working_directory: None,
        // Bake DIG_NODE_URL when an explicit node override was given (else the
        // service resolves dig-dns's own §5.3 ladder).
        environment: if environment.is_empty() {
            None
        } else {
            Some(environment)
        },
        // Boot-start (#301): SCM `start= auto` — the service comes up on every boot.
        autostart: plan::DNS_SERVICE_AUTOSTART,
    }) {
        return failed(format!("dig-dns service registration failed: {e}"));
    }
    notes.push(format!(
        "registered the Windows service \"{}\"",
        plan::SERVICE_LABEL
    ));

    // Human-friendly Services-panel display name (task #494): service-manager
    // always sets displayname= to the qualified service name at create time,
    // so override it with a follow-up `sc config` call.
    match set_display_name(plan::SERVICE_LABEL, plan::SERVICE_DISPLAY_NAME) {
        Ok(()) => notes.push(format!(
            "set the service display name to \"{}\"",
            plan::SERVICE_DISPLAY_NAME
        )),
        Err(e) => notes.push(format!("service display name not set: {e}")),
    }

    // Verify the display name actually PERSISTED (#494/#499): read it back via
    // `sc qc` DISPLAY_NAME. The bug was `sc config` appearing to succeed while
    // the Services panel still showed the raw reverse-DNS service id — a bare
    // "set" note is not proof it stuck. Never silent (non-gating: a cosmetic
    // label mismatch does not fail the functional install).
    let display_check =
        crate::svc::verify_display_name(plan::SERVICE_LABEL, plan::SERVICE_DISPLAY_NAME);
    if display_check.matches {
        notes.push(format!("verified {}", display_check.note));
    } else {
        notes.push(format!("display name NOT verified: {}", display_check.note));
    }

    let mut started = false;
    if cfg.start {
        match mgr.start(ServiceStartCtx { label: label() }) {
            Ok(()) => {
                started = true;
                notes.push("started".to_string());
            }
            Err(e) => notes.push(format!("start failed: {e}")),
        }
    }

    match run_ps(&plan::nrpt_add_ps_command(plan::LOOPBACK_IP)) {
        Ok(()) => notes.push("added the .dig NRPT rule".to_string()),
        Err(e) => notes.push(format!("NRPT rule not added: {e}")),
    }

    for (browser, key) in [
        ("Chrome", plan::CHROME_POLICY_KEY),
        ("Edge", plan::EDGE_POLICY_KEY),
    ] {
        match apply_browser_policy(key) {
            Ok(true) => notes.push(format!("{browser} DoH policy applied")),
            Ok(false) => notes.push(format!(
                "{browser} policy left untouched (an existing org policy manages it)"
            )),
            Err(e) => notes.push(format!("{browser} policy not applied: {e}")),
        }
    }

    // Self-verify: give the freshly-started service a moment to bind, then run doctor + pac.
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
        // The service-manager RUNNING poll happens in `register_dig_dns`
        // (lib.rs) after this returns; it overwrites this with the observed state.
        service_running: false,
        needs_elevation: false,
        note: notes.join("; "),
        doctor: doctor_summary,
        paths_live,
        bound_port,
        pac_url,
        fallback_instruction,
    }
}

/// Reverse [`install`]: stop + delete the SCM service, remove only the NRPT
/// rule(s) tagged with [`plan::MARKER`], and remove the Chrome/Edge policy
/// keys ONLY if this installer created them.
pub fn uninstall(dry_run: bool) -> DnsUninstallResult {
    if dry_run {
        return DnsUninstallResult {
            uninstalled: false,
            needs_elevation: false,
            note: "would stop + remove the dig-dns Windows service, the .dig NRPT rule, \
                   and any Chrome/Edge policy this installer created"
                .to_string(),
            residue_removed: Vec::new(),
        };
    }
    if !is_elevated() {
        return DnsUninstallResult {
            uninstalled: false,
            needs_elevation: true,
            note: "uninstalling the dig-dns Windows service requires an elevated \
                   (Administrator) console"
                .to_string(),
            residue_removed: Vec::new(),
        };
    }

    let mut removed = Vec::new();
    let mgr = service_manager::ScServiceManager::system();
    let _ = mgr.stop(ServiceStopCtx { label: label() });
    if mgr
        .uninstall(ServiceUninstallCtx { label: label() })
        .is_ok()
    {
        removed.push(format!("Windows service \"{}\"", plan::SERVICE_LABEL));
    }
    if run_ps(&plan::nrpt_remove_ps_command()).is_ok() {
        removed.push(".dig NRPT rule".to_string());
    }
    for (browser, key) in [
        ("Chrome", plan::CHROME_POLICY_KEY),
        ("Edge", plan::EDGE_POLICY_KEY),
    ] {
        if let Ok(true) = remove_browser_policy(key) {
            removed.push(format!("{browser} HKLM DoH policy"));
        }
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
    use winreg::enums::HKEY_CURRENT_USER;

    #[test]
    fn run_ps_succeeds_on_a_harmless_command() {
        run_ps("$null").expect("trivial PS command succeeds");
    }

    #[test]
    fn run_ps_reports_failure_on_an_invalid_command() {
        let err = run_ps("Some-Cmdlet-That-Does-Not-Exist-Xyz").unwrap_err();
        assert!(err.contains("powershell exited with"), "got: {err}");
    }

    /// Registry policy tests run under HKCU (never elevation-gated, never touching the real
    /// Chrome/Edge HKLM policy) at a unique per-test subkey, cleaned up afterward.
    fn test_hive() -> RegKey {
        RegKey::predef(HKEY_CURRENT_USER)
    }

    fn test_key_path(tag: &str) -> String {
        format!(r"Software\dig-installer-test-{tag}-{}", std::process::id())
    }

    #[test]
    fn apply_policy_writes_doh_off_and_marks_it_ours() {
        let hive = test_hive();
        let path = test_key_path("apply-new");
        let applied = apply_policy_under(&hive, &path).expect("applies");
        assert!(applied);
        let key = hive.open_subkey(&path).unwrap();
        let doh: String = key.get_value(plan::POLICY_DOH_NAME).unwrap();
        assert_eq!(doh, plan::POLICY_DOH_OFF);
        let builtin: u32 = key.get_value(plan::POLICY_BUILTIN_RESOLVER_NAME).unwrap();
        assert_eq!(builtin, 0);
        let marker: u32 = key.get_value(plan::POLICY_MARKER_NAME).unwrap();
        assert_eq!(marker, 1);
        hive.delete_subkey_all(&path).unwrap();
    }

    #[test]
    fn apply_policy_never_clobbers_a_pre_existing_non_ours_key() {
        let hive = test_hive();
        let path = test_key_path("apply-existing");
        // Simulate an existing org policy: the key exists WITHOUT our marker.
        let (key, _) = hive.create_subkey(&path).unwrap();
        key.set_value("SomeOrgSetting", &"already-here").unwrap();
        let applied = apply_policy_under(&hive, &path).expect("does not error");
        assert!(!applied, "must leave a pre-existing non-ours key untouched");
        let still_there: String = hive
            .open_subkey(&path)
            .unwrap()
            .get_value("SomeOrgSetting")
            .unwrap();
        assert_eq!(still_there, "already-here");
        assert!(
            hive.open_subkey(&path)
                .unwrap()
                .get_value::<String, _>(plan::POLICY_DOH_NAME)
                .is_err(),
            "must not have written the DoH value into someone else's key"
        );
        hive.delete_subkey_all(&path).unwrap();
    }

    #[test]
    fn apply_policy_is_idempotent_on_a_key_it_owns() {
        let hive = test_hive();
        let path = test_key_path("apply-idem");
        assert!(apply_policy_under(&hive, &path).unwrap());
        assert!(
            apply_policy_under(&hive, &path).unwrap(),
            "re-applying its own key is fine"
        );
        hive.delete_subkey_all(&path).unwrap();
    }

    #[test]
    fn remove_policy_deletes_only_the_values_it_owns_not_the_key() {
        let hive = test_hive();
        let path = test_key_path("remove-owned");
        apply_policy_under(&hive, &path).unwrap();
        // Simulate an org value added to the SAME policy key after us — it must
        // survive (we must NOT `delete_subkey_all` the whole Chrome/Edge key).
        {
            let (key, _) = hive.create_subkey(&path).unwrap();
            key.set_value("OrgSetting", &"keep-me").unwrap();
        }
        let removed = remove_policy_under(&hive, &path).expect("removes");
        assert!(removed);
        let key = hive
            .open_subkey(&path)
            .expect("the policy key itself must survive (an org may share it)");
        // Our three values are gone …
        assert!(key.get_raw_value(plan::POLICY_DOH_NAME).is_err());
        assert!(key
            .get_raw_value(plan::POLICY_BUILTIN_RESOLVER_NAME)
            .is_err());
        assert!(key.get_raw_value(plan::POLICY_MARKER_NAME).is_err());
        // … but the foreign value is untouched.
        let org: String = key.get_value("OrgSetting").expect("org value survives");
        assert_eq!(org, "keep-me");
        hive.delete_subkey_all(&path).unwrap();
    }

    #[test]
    fn remove_policy_never_deletes_a_key_it_does_not_own() {
        let hive = test_hive();
        let path = test_key_path("remove-not-owned");
        let (key, _) = hive.create_subkey(&path).unwrap();
        key.set_value("SomeOrgSetting", &"keep-me").unwrap();
        let removed = remove_policy_under(&hive, &path).expect("does not error");
        assert!(!removed, "must never delete someone else's policy key");
        assert!(
            hive.open_subkey(&path).is_ok(),
            "the org's key must survive"
        );
        hive.delete_subkey_all(&path).unwrap();
    }

    #[test]
    fn remove_policy_is_a_noop_when_absent() {
        let hive = test_hive();
        let path = test_key_path("remove-absent");
        let removed = remove_policy_under(&hive, &path).expect("does not error");
        assert!(!removed);
    }

    #[test]
    fn label_parses_the_stable_service_label() {
        let l = label();
        assert_eq!(l.application, "dig-dns");
    }

    #[test]
    fn is_elevated_never_panics() {
        // No assertion on the value (depends on the test runner's privilege); this only
        // exercises the probe without crashing.
        let _ = is_elevated();
    }

    /// A service name that certainly does not exist on any test host (task #494).
    const NONEXISTENT_SERVICE: &str = "net.dignetwork.dig-dns-test-definitely-not-a-real-service";

    #[test]
    fn service_exists_is_false_for_an_unregistered_service() {
        assert!(!service_exists(NONEXISTENT_SERVICE));
    }

    #[test]
    fn wait_for_removal_returns_immediately_when_already_gone() {
        // The service is already absent, so the poll must not spin for the full
        // budget — it should return well within it.
        let start = std::time::Instant::now();
        wait_for_removal(NONEXISTENT_SERVICE, Duration::from_secs(5));
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "must not wait the full budget when already removed"
        );
    }

    #[test]
    fn set_display_name_errors_for_a_nonexistent_service() {
        // `sc config` on a service that doesn't exist (or without elevation)
        // must fail cleanly, never panic — exercised without requiring a real
        // elevated `sc create` in CI.
        let err = set_display_name(NONEXISTENT_SERVICE, "DIG NETWORK: TEST").unwrap_err();
        assert!(!err.is_empty());
    }
}
