//! Canonical DIG OS-service identity (#494) + a **real** "is this service
//! RUNNING?" query by service id via the OS service manager (#493).
//!
//! Bug #493: the old post-install check probed the loopback RPC port (9778). A
//! dig-node started by SOMETHING ELSE (a manual `dig-node serve`, a stale
//! process) answering on that port produced a FALSE success even though this
//! run registered no service. The fix here asks the OS **service manager**
//! whether the service THIS run was supposed to register — identified by its
//! canonical reverse-DNS id — is actually `RUNNING`. A bare port listener can
//! no longer green-light a non-install.
//!
//! The ids/display names below are the canonical identities (#494) the service
//! binaries (`dig-node install` / `dig-dns install`) register under; this
//! installer queries by exactly those ids. Per-OS query:
//!   * **Windows:** `sc query <id>` → `STATE : 4  RUNNING`.
//!   * **Linux:** `systemctl [--user] is-active <id>` → `active` (see below).
//!   * **macOS:** `launchctl print system/<id>` → `state = running`.
//!
//! **Linux checks BOTH systemd scopes** (dig_ecosystem#502/#524 finding):
//! dig-node's own `install` always prefers a USER-level unit regardless of
//! privilege (its `PREFERS_USER_LEVEL`, a deliberate no-elevation-needed
//! design), while dig-installer registers dig-dns machine-wide (`dns/
//! linux.rs`, #494) — so a single system-scoped `systemctl is-active` can
//! never see a genuinely-running dig-node, permanently reporting "registered
//! but NOT running" even on a healthy install. [`service_run_state_on`]
//! queries `--user` THEN system scope and combines them ([`combine_systemctl_states`]):
//! Running wins if EITHER scope reports it, keeping this agnostic to whichever
//! scope a given service id actually registers at.
//!
//! Layering: the per-OS output PARSERS are pure + unit-tested; the spawns live
//! in [`service_run_state`].

use crate::proc::HideConsole;
use crate::target::Os;

/// Canonical dig-node service id (reverse-DNS) and human display name (#494).
pub const DIG_NODE_SERVICE_ID: &str = "net.dignetwork.dig-node";
pub const DIG_NODE_SERVICE_DISPLAY: &str = "DIG NETWORK: NODE";
/// Canonical dig-dns service id and human display name (#494).
pub const DIG_DNS_SERVICE_ID: &str = "net.dignetwork.dig-dns";
pub const DIG_DNS_SERVICE_DISPLAY: &str = "DIG NETWORK: DNS";
/// Canonical dig-relay service id (reverse-DNS) — the id dig-relay's own
/// `install` verb registers under, and the id the installer stops/deregisters by
/// (never by executing the relay binary, #565).
pub const DIG_RELAY_SERVICE_ID: &str = "net.dignetwork.dig-relay";

/// The state of a named OS service, as reported by the service manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceRunState {
    /// The service exists and is RUNNING.
    Running,
    /// The service exists but is stopped/inactive/failed.
    Stopped,
    /// No service with this id is registered.
    NotFound,
    /// The service manager could not be queried or its output was unrecognised.
    Unknown,
}

impl ServiceRunState {
    /// A short, human-readable phrase for the install log / `note`.
    pub fn describe(self, id: &str) -> String {
        match self {
            ServiceRunState::Running => format!("service '{id}' is RUNNING"),
            ServiceRunState::Stopped => format!("service '{id}' is registered but NOT running"),
            ServiceRunState::NotFound => format!("service '{id}' is not registered"),
            ServiceRunState::Unknown => {
                format!("could not determine the state of service '{id}'")
            }
        }
    }
}

/// Query the OS service manager for the run-state of the service `id`, on the
/// current host OS. Returns [`ServiceRunState::Unknown`] on an unsupported
/// platform or when the query itself fails.
pub fn service_run_state(id: &str) -> ServiceRunState {
    match crate::target::Target::current() {
        Ok(t) => service_run_state_on(t.os, id),
        Err(_) => ServiceRunState::Unknown,
    }
}

/// `true` iff the service `id` is registered AND currently RUNNING per the OS
/// service manager. This is the authoritative post-install health signal
/// (#493) — a bare port probe is NOT sufficient.
pub fn is_service_running(id: &str) -> bool {
    service_run_state(id) == ServiceRunState::Running
}

/// Poll [`service_run_state`] until it reports [`ServiceRunState::Running`] or
/// `attempts` is exhausted, sleeping `interval` between tries — a freshly
/// `start`ed service takes a moment to report RUNNING to the service manager.
/// Returns the LAST observed state (so a persistent NotFound/Stopped is
/// surfaced, not masked).
pub fn wait_for_service_running(
    id: &str,
    attempts: u32,
    interval: std::time::Duration,
) -> ServiceRunState {
    let mut last = ServiceRunState::Unknown;
    for attempt in 0..attempts.max(1) {
        last = service_run_state(id);
        if last == ServiceRunState::Running {
            return last;
        }
        if attempt + 1 < attempts {
            std::thread::sleep(interval);
        }
    }
    last
}

/// Poll [`service_run_state`] until it leaves RUNNING (any of Stopped/NotFound/
/// Unknown) or `max_wait` elapses — a `stop`/`delete` the SCM/systemd/launchd
/// completes asynchronously, so its process must exit (releasing any file
/// handle) before the state settles. Returns the LAST observed state.
fn wait_until_not_running(id: &str, max_wait: std::time::Duration) -> ServiceRunState {
    let start = std::time::Instant::now();
    loop {
        let state = service_run_state(id);
        if state != ServiceRunState::Running || start.elapsed() >= max_wait {
            return state;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// `sc stop <id>` argv (excluding the `sc` executable). Pure. Windows only.
pub fn sc_stop_args(id: &str) -> Vec<String> {
    vec!["stop".to_string(), id.to_string()]
}

/// `sc delete <id>` argv (excluding the `sc` executable). Pure. Windows only.
pub fn sc_delete_args(id: &str) -> Vec<String> {
    vec!["delete".to_string(), id.to_string()]
}

/// The `launchctl bootout system/<id>` target string — deregisters + stops a
/// system-domain LaunchDaemon by its label. Pure.
pub fn launchctl_system_target(id: &str) -> String {
    format!("system/{id}")
}

/// STOP the service `id` via the OS service manager — WITHOUT ever executing the
/// service's own binary (#565: the installer must never elevate-spawn a binary
/// that a non-admin could have replaced in the legacy user-writable dir). Issues
/// the OS stop command by canonical id, then bounded-waits for it to leave
/// RUNNING (its process exiting is what releases the binary's file handle).
/// `Ok(())` when the service is not RUNNING afterward (including "was already
/// stopped" / "not registered"); `Err` only when it is STILL running.
pub fn stop_service(id: &str) -> Result<(), String> {
    // Best-effort issue the OS stop command; the authoritative signal is the
    // state poll below, never the command's exit code (a stop of an
    // already-stopped service exits non-zero on Windows).
    stop_service_command(id);
    match wait_until_not_running(id, std::time::Duration::from_secs(10)) {
        ServiceRunState::Running => Err(format!("service '{id}' is still RUNNING after a stop")),
        _ => Ok(()),
    }
}

/// DEREGISTER (stop + delete/disable) the service `id` via the OS service
/// manager — again WITHOUT executing the service binary (#565). Used by the
/// migration to re-point a service off the legacy user-writable install root:
/// the deregistration is done here by id, then the service is re-registered from
/// the new protected path (by that binary's own `install` verb, executed from
/// the safe location). `Ok(())` when the service is no longer registered.
pub fn deregister_service(id: &str) -> Result<(), String> {
    let _ = stop_service(id);
    deregister_service_command(id);
    match wait_until_not_running(id, std::time::Duration::from_secs(10)) {
        ServiceRunState::Running => Err(format!(
            "service '{id}' is still RUNNING after deregistration"
        )),
        _ => Ok(()),
    }
}

/// Issue the OS "stop this service by id" command. Windows `sc stop`; Linux
/// `systemctl [--user] stop` (BOTH scopes, since dig-node registers user-level
/// while dig-dns is machine-wide — [`service_run_state_on`]); macOS `launchctl
/// bootout`. Best-effort — the authoritative signal is the state poll in
/// [`stop_service`], never these exit codes (a stop of an already-stopped
/// service exits non-zero on Windows, which is not a failure).
fn stop_service_command(id: &str) {
    #[cfg(windows)]
    {
        let _ = run_svc_tool("sc", &sc_stop_args(id));
    }
    #[cfg(target_os = "linux")]
    {
        let unit = linux_unit_name(id);
        let _ = run_svc_tool("systemctl", &["--user".into(), "stop".into(), unit.clone()]);
        let _ = run_svc_tool("systemctl", &["stop".into(), unit]);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = run_svc_tool(
            "launchctl",
            &["bootout".into(), launchctl_system_target(id)],
        );
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = id;
    }
}

/// Issue the OS "deregister this service by id" command. Windows `sc delete`;
/// Linux `systemctl [--user] disable`; macOS `launchctl bootout` (which both
/// stops AND deregisters). Best-effort — [`deregister_service`] polls the state.
fn deregister_service_command(id: &str) {
    #[cfg(windows)]
    {
        let _ = run_svc_tool("sc", &sc_delete_args(id));
    }
    #[cfg(target_os = "linux")]
    {
        let unit = linux_unit_name(id);
        let _ = run_svc_tool(
            "systemctl",
            &[
                "--user".into(),
                "disable".into(),
                "--now".into(),
                unit.clone(),
            ],
        );
        let _ = run_svc_tool("systemctl", &["disable".into(), "--now".into(), unit]);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = run_svc_tool(
            "launchctl",
            &["bootout".into(), launchctl_system_target(id)],
        );
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = id;
    }
}

/// Spawn an OS service-control tool, discarding its output (the authoritative
/// signal is always the subsequent [`service_run_state`] poll, not the tool's
/// exit code — a stop of an already-stopped service exits non-zero). `Ok(())`
/// iff the tool exited 0.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn run_svc_tool(tool: &str, args: &[String]) -> Result<(), String> {
    std::process::Command::new(tool)
        .args(args)
        .hide_console()
        .output()
        .map_err(|e| format!("spawn {tool}: {e}"))
        .and_then(|o| {
            if o.status.success() {
                Ok(())
            } else {
                Err(format!("{tool} exited non-zero"))
            }
        })
}

/// The result of verifying a Windows service's Services-panel DISPLAY name
/// matches its canonical value (#494/#499): proof the human-friendly name
/// persisted rather than silently reverting to the raw reverse-DNS service id
/// (the exact #499 symptom — `services.msc` showing `net.dignetwork.dig-dns`
/// instead of "DIG NETWORK: DNS"). Never silent — carries a human note either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayNameCheck {
    /// The DISPLAY name matches the expected canonical value.
    pub matches: bool,
    /// What `sc qc` actually reported (`None` when it could not be read, or on a
    /// non-Windows host where the Services-panel display name does not apply).
    pub actual: Option<String>,
    /// Human-readable detail behind [`Self::matches`].
    pub note: String,
}

/// Classify an observed DISPLAY name against the `expected` canonical value for
/// service `id` (#494/#499). Pure — the `sc qc` spawn is in
/// [`service_display_name`], so the match/mismatch/absent verdict + its human
/// note are unit-tested directly without touching the SCM.
pub fn classify_display_name(actual: Option<&str>, expected: &str, id: &str) -> DisplayNameCheck {
    match actual {
        Some(a) if a == expected => DisplayNameCheck {
            matches: true,
            actual: Some(a.to_string()),
            note: format!("display name is \"{expected}\""),
        },
        Some(a) => DisplayNameCheck {
            matches: false,
            actual: Some(a.to_string()),
            note: format!("display name is \"{a}\", expected \"{expected}\" (it did not persist)"),
        },
        None => DisplayNameCheck {
            matches: false,
            actual: None,
            note: format!("could not read the display name for '{id}' via `sc qc`"),
        },
    }
}

/// The DISPLAY name `sc qc <id>` reports for a Windows service, or `None` if the
/// query failed, the service is absent, or there is no DISPLAY_NAME line. The
/// Services-panel display name is a Windows concept (#494/#499), so this is
/// always `None` on other platforms.
pub fn service_display_name(id: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let out = std::process::Command::new("sc")
            .arg("qc")
            .arg(id)
            .hide_console()
            .output()
            .ok()?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        parse_sc_qc_display_name(&text)
    }
    #[cfg(not(windows))]
    {
        let _ = id;
        None
    }
}

/// Verify service `id` reports the canonical DISPLAY name `expected` via
/// `sc qc` (#494/#499) — the health-check read-back that proves the
/// `sc config … displayname=` override actually persisted (the #499 fix). Never
/// silent: returns a [`DisplayNameCheck`] with a human note in every case.
pub fn verify_display_name(id: &str, expected: &str) -> DisplayNameCheck {
    classify_display_name(service_display_name(id).as_deref(), expected, id)
}

/// Parse the DISPLAY_NAME value from `sc qc <id>` output. The line reads
/// `        DISPLAY_NAME       : DIG NETWORK: DNS`; the value is everything
/// after the FIRST colon on that line (so a display name that itself contains a
/// colon — like "DIG NETWORK: DNS" — is preserved intact), trimmed. `None` when
/// there is no DISPLAY_NAME line or its value is empty. Pure.
pub fn parse_sc_qc_display_name(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        let is_display_key = trimmed
            .split(':')
            .next()
            .map(|k| k.trim().eq_ignore_ascii_case("DISPLAY_NAME"))
            .unwrap_or(false);
        if is_display_key {
            if let Some((_, value)) = trimmed.split_once(':') {
                let v = value.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// [`service_run_state`] for an explicit [`Os`] — spawns the OS-appropriate
/// query and parses it. Split out so the OS dispatch is explicit.
fn service_run_state_on(os: Os, id: &str) -> ServiceRunState {
    use std::process::Command;
    match os {
        Os::Windows => {
            let out = Command::new("sc")
                .arg("query")
                .arg(id)
                .hide_console()
                .output();
            match out {
                Ok(o) => {
                    let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
                    text.push_str(&String::from_utf8_lossy(&o.stderr));
                    parse_sc_query(&text)
                }
                Err(_) => ServiceRunState::Unknown,
            }
        }
        Os::Linux => {
            let unit = linux_unit_name(id);
            let user = query_systemctl_is_active(&["--user", "is-active", &unit]);
            let system = query_systemctl_is_active(&["is-active", &unit]);
            combine_systemctl_states(user, system)
        }
        Os::MacOs => {
            let out = Command::new("launchctl")
                .arg("print")
                .arg(format!("system/{id}"))
                .hide_console()
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    parse_launchctl_print(&String::from_utf8_lossy(&o.stdout))
                }
                // A non-zero exit from `launchctl print` means the label is not
                // loaded in the system domain.
                Ok(_) => ServiceRunState::NotFound,
                Err(_) => ServiceRunState::Unknown,
            }
        }
    }
}

/// Parse Windows `sc query <id>` output. `STATE : 4  RUNNING` → Running;
/// any other explicit STATE (STOPPED/START_PENDING/…) → Stopped; the
/// `1060 does not exist` error → NotFound; anything unrecognised → Unknown.
/// Pure.
pub fn parse_sc_query(text: &str) -> ServiceRunState {
    let upper = text.to_uppercase();
    // `sc` reports a missing service with error 1060 / "does not exist".
    if upper.contains("1060") || upper.contains("DOES NOT EXIST") {
        return ServiceRunState::NotFound;
    }
    if let Some(idx) = upper.find("STATE") {
        let after = &upper[idx..];
        if after.contains("RUNNING") {
            return ServiceRunState::Running;
        }
        // STOPPED, START_PENDING, STOP_PENDING, PAUSED, … — all "not running".
        if after.contains("STOP") || after.contains("PENDING") || after.contains("PAUSE") {
            return ServiceRunState::Stopped;
        }
    }
    ServiceRunState::Unknown
}

/// Parse Linux `systemctl is-active <id>` output. ONLY exactly `active` →
/// Running: `activating`/`reloading` are NOT healthy — a crash-looping unit that
/// systemd is auto-restarting reports `activating`, and treating it as RUNNING
/// would be a false-success (the #493 class of bug). `failed`/`inactive`/
/// `deactivating`/`activating`/`reloading` → Stopped (not yet, or no longer,
/// actually serving); `unknown` (unit not loaded) → NotFound; anything else →
/// Unknown. Pure.
pub fn parse_systemctl_is_active(text: &str) -> ServiceRunState {
    match text.trim() {
        "active" => ServiceRunState::Running,
        "failed" | "inactive" | "deactivating" | "activating" | "reloading" => {
            ServiceRunState::Stopped
        }
        "unknown" | "" => ServiceRunState::NotFound,
        _ => ServiceRunState::Unknown,
    }
}

/// Map a canonical reverse-DNS service id to the systemd unit name it is
/// ACTUALLY registered under on Linux (dig_ecosystem#502/#524 finding).
///
/// Windows (`sc`) and macOS (`launchctl`) both address a service by the FULL
/// canonical id verbatim — confirmed by [`parse_sc_query`]/
/// [`parse_launchctl_print`]'s own tests and the 3-OS installer-e2e job.
/// Linux does not: EVERY dig-node/dig-dns systemd registration in this
/// workspace goes through the `service-manager` crate's [`ServiceLabel`]
/// (dig-node's own `install`, and this installer's OWN `dns::plan`/
/// `dns::linux` for dig-dns), whose systemd backend names the unit via
/// `ServiceLabel::to_script_name()` — which DROPS the reverse-DNS qualifier
/// and hyphen-joins `{organization}-{application}`, so
/// `net.dignetwork.dig-node` registers as `dignetwork-dig-node` and
/// `net.dignetwork.dig-dns` as `dignetwork-dig-dns` (verified directly
/// against a real install — the "registered but NOT running" false-negative
/// this fixes; `dns::plan::service_script_name` derives the identical value
/// for dig-dns's own registration, so the two can't drift apart).
///
/// Applying the SAME parse+derive here (rather than hardcoding either
/// result) means this needs no per-service knowledge at all, and stays
/// correct even if a THIRD service adopts the same reverse-DNS convention.
/// A canonical id that fails to parse (never expected — [`DIG_NODE_SERVICE_ID`]/
/// [`DIG_DNS_SERVICE_ID`] are both fixed, valid `owner.org.app` strings) is
/// returned unchanged rather than panicking.
///
/// `pub(crate)`: [`crate::regaudit`] reuses this to resolve the systemd unit a
/// privileged service registers under when reading its `ExecStart` binary path
/// (the #565 binPath audit), so the two derive the identical name by construction.
pub(crate) fn linux_unit_name(id: &str) -> String {
    id.parse::<service_manager::ServiceLabel>()
        .map(|label| label.to_script_name())
        .unwrap_or_else(|_| id.to_string())
}

/// Spawn `systemctl <extra_args>` (e.g. `["--user", "is-active", id]` or
/// `["is-active", id]`) and parse the result. A spawn failure — including
/// `--user` finding no reachable systemd/D-Bus session (the exact state a
/// process with no user-session, like a bare `sudo` shell, is in) — resolves
/// to [`ServiceRunState::Unknown`], never a panic; [`combine_systemctl_states`]
/// treats that as "uninformative" and defers to the other scope's result.
fn query_systemctl_is_active(extra_args: &[&str]) -> ServiceRunState {
    match std::process::Command::new("systemctl")
        .args(extra_args)
        .hide_console()
        .output()
    {
        Ok(o) => parse_systemctl_is_active(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => ServiceRunState::Unknown,
    }
}

/// Combine a Linux service id's `--user`-scope and system-scope
/// `systemctl is-active` results into one verdict (dig_ecosystem#502/#524):
/// a given id might be registered USER-level (dig-node's own `install`,
/// unconditionally) or machine-wide (dig-installer's own dig-dns wiring,
/// #494) — this stays agnostic to which, rather than hardcoding a
/// per-service assumption that would break the moment either side's
/// registration model changes. Pure — the two spawns live in
/// [`service_run_state_on`].
///
/// **Running wins** if EITHER scope reports it (the service genuinely is up,
/// wherever it's registered). Otherwise prefer the more INFORMATIVE result:
/// `Stopped` (a real registration exists there, just not running) beats
/// `NotFound` (nothing registered at that scope) beats `Unknown` (the scope
/// couldn't even be queried, e.g. no user-session available).
fn combine_systemctl_states(user: ServiceRunState, system: ServiceRunState) -> ServiceRunState {
    if user == ServiceRunState::Running || system == ServiceRunState::Running {
        return ServiceRunState::Running;
    }
    for candidate in [ServiceRunState::Stopped, ServiceRunState::NotFound] {
        if user == candidate || system == candidate {
            return candidate;
        }
    }
    ServiceRunState::Unknown
}

/// Parse macOS `launchctl print system/<id>` output for the daemon state.
/// `state = running` → Running; any other `state = …` → Stopped; no state line
/// → Unknown. Pure. (A missing label exits non-zero and is mapped to NotFound
/// by the caller before this runs.)
pub fn parse_launchctl_print(text: &str) -> ServiceRunState {
    let lower = text.to_lowercase();
    if let Some(idx) = lower.find("state = ") {
        let rest = &lower[idx + "state = ".len()..];
        let word = rest.split_whitespace().next().unwrap_or("");
        return if word == "running" {
            ServiceRunState::Running
        } else {
            ServiceRunState::Stopped
        };
    }
    ServiceRunState::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_ids_are_reverse_dns_and_stable() {
        // #494: the exact ids the service binaries register under + this
        // installer verifies by. A drift here silently breaks the health check.
        assert_eq!(DIG_NODE_SERVICE_ID, "net.dignetwork.dig-node");
        assert_eq!(DIG_NODE_SERVICE_DISPLAY, "DIG NETWORK: NODE");
        assert_eq!(DIG_DNS_SERVICE_ID, "net.dignetwork.dig-dns");
        assert_eq!(DIG_DNS_SERVICE_DISPLAY, "DIG NETWORK: DNS");
    }

    #[test]
    fn sc_query_running_is_running() {
        let out = "SERVICE_NAME: net.dignetwork.dig-node\r\n\
             TYPE               : 10  WIN32_OWN_PROCESS\r\n\
             STATE              : 4  RUNNING\r\n";
        assert_eq!(parse_sc_query(out), ServiceRunState::Running);
    }

    #[test]
    fn sc_query_stopped_is_stopped() {
        let out = "SERVICE_NAME: net.dignetwork.dig-node\r\n\
             STATE              : 1  STOPPED\r\n";
        assert_eq!(parse_sc_query(out), ServiceRunState::Stopped);
        let pending = "STATE : 2  START_PENDING\r\n";
        assert_eq!(parse_sc_query(pending), ServiceRunState::Stopped);
    }

    #[test]
    fn sc_query_missing_service_is_not_found() {
        // The user's real bug scenario: the service was never registered.
        let err = "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\r\n\r\n\
             The specified service does not exist as an installed service.\r\n";
        assert_eq!(parse_sc_query(err), ServiceRunState::NotFound);
    }

    #[test]
    fn sc_query_unrecognised_is_unknown() {
        assert_eq!(parse_sc_query("garbage output"), ServiceRunState::Unknown);
    }

    #[test]
    fn systemctl_is_active_maps_states() {
        assert_eq!(
            parse_systemctl_is_active("active\n"),
            ServiceRunState::Running
        );
        assert_eq!(
            parse_systemctl_is_active("failed\n"),
            ServiceRunState::Stopped
        );
        assert_eq!(
            parse_systemctl_is_active("inactive\n"),
            ServiceRunState::Stopped
        );
        assert_eq!(
            parse_systemctl_is_active("unknown\n"),
            ServiceRunState::NotFound
        );
        // A crash-looping unit systemd is auto-restarting reads `activating` — it
        // must NOT be treated as RUNNING (require exactly `active`).
        assert_eq!(
            parse_systemctl_is_active("activating\n"),
            ServiceRunState::Stopped
        );
        assert_eq!(
            parse_systemctl_is_active("reloading\n"),
            ServiceRunState::Stopped
        );
    }

    // -- combine_systemctl_states: Running wins from EITHER scope (#502/#524) --

    #[test]
    fn combine_reports_running_when_only_the_user_scope_is() {
        // The exact #524 regression: dig-node registers `--user`-scope only;
        // a system-scope-only query alone would report NotFound/Stopped and
        // permanently mask a genuinely-running service.
        assert_eq!(
            combine_systemctl_states(ServiceRunState::Running, ServiceRunState::NotFound),
            ServiceRunState::Running
        );
    }

    #[test]
    fn combine_reports_running_when_only_the_system_scope_is() {
        // dig-dns's mirror case: machine-wide (system-scope) only.
        assert_eq!(
            combine_systemctl_states(ServiceRunState::NotFound, ServiceRunState::Running),
            ServiceRunState::Running
        );
    }

    #[test]
    fn combine_reports_running_when_both_scopes_are() {
        assert_eq!(
            combine_systemctl_states(ServiceRunState::Running, ServiceRunState::Running),
            ServiceRunState::Running
        );
    }

    #[test]
    fn combine_prefers_stopped_over_not_found_when_neither_is_running() {
        // Stopped is more informative (a registration genuinely exists there)
        // than NotFound (nothing registered at that scope) — surface it.
        assert_eq!(
            combine_systemctl_states(ServiceRunState::Stopped, ServiceRunState::NotFound),
            ServiceRunState::Stopped
        );
        assert_eq!(
            combine_systemctl_states(ServiceRunState::NotFound, ServiceRunState::Stopped),
            ServiceRunState::Stopped
        );
    }

    #[test]
    fn combine_reports_not_found_when_neither_scope_has_a_registration() {
        assert_eq!(
            combine_systemctl_states(ServiceRunState::NotFound, ServiceRunState::NotFound),
            ServiceRunState::NotFound
        );
    }

    #[test]
    fn combine_falls_back_to_unknown_when_both_scopes_are_unqueryable() {
        // e.g. neither a user D-Bus session nor the system manager could be
        // reached at all — genuinely indeterminate, never a false Running/Stopped.
        assert_eq!(
            combine_systemctl_states(ServiceRunState::Unknown, ServiceRunState::Unknown),
            ServiceRunState::Unknown
        );
    }

    // -- linux_unit_name: the REAL systemd unit name per canonical id (#502/#524) --

    #[test]
    fn linux_unit_name_maps_dig_node_to_the_service_manager_crates_script_name() {
        // The exact #524 regression: service-manager 0.7.1's systemd backend
        // drops the "net" qualifier and hyphen-joins the rest.
        assert_eq!(linux_unit_name(DIG_NODE_SERVICE_ID), "dignetwork-dig-node");
    }

    #[test]
    fn linux_unit_name_maps_dig_dns_to_the_same_derived_script_name_it_registers_under() {
        // dig-installer registers dig-dns through the SAME ServiceLabel
        // machinery (`dns::plan::service_script_name`) — this must derive the
        // identical value, by construction, not a separately-hardcoded guess.
        assert_eq!(
            linux_unit_name(DIG_DNS_SERVICE_ID),
            crate::dns::plan::service_script_name()
        );
        assert_eq!(linux_unit_name(DIG_DNS_SERVICE_ID), "dignetwork-dig-dns");
    }

    #[test]
    fn linux_unit_name_passes_through_a_single_token_id_unchanged() {
        // A label with no organization/qualifier (a single token, no dots)
        // has nothing to strip or hyphen-join, so it comes back verbatim —
        // the one case `to_script_name()` is genuinely a no-op passthrough.
        assert_eq!(linux_unit_name("standalone"), "standalone");
    }

    #[test]
    fn launchctl_print_reads_state() {
        let running = "system/net.dignetwork.dig-node = {\n\tstate = running\n\tpid = 1234\n}";
        assert_eq!(parse_launchctl_print(running), ServiceRunState::Running);
        let waiting = "system/net.dignetwork.dig-node = {\n\tstate = waiting\n}";
        assert_eq!(parse_launchctl_print(waiting), ServiceRunState::Stopped);
        assert_eq!(
            parse_launchctl_print("no state here"),
            ServiceRunState::Unknown
        );
    }

    #[test]
    fn describe_is_never_silent() {
        for state in [
            ServiceRunState::Running,
            ServiceRunState::Stopped,
            ServiceRunState::NotFound,
            ServiceRunState::Unknown,
        ] {
            assert!(state
                .describe("net.dignetwork.dig-node")
                .contains("net.dignetwork.dig-node"));
        }
    }

    // -- Display-name verification (#494/#499): `sc qc <id>` DISPLAY_NAME. -------

    #[test]
    fn parse_sc_qc_reads_the_display_name_even_when_it_contains_a_colon() {
        // Real `sc qc` output; the display name "DIG NETWORK: DNS" itself has a
        // colon, so the parser must split on the FIRST colon only.
        let out = "[SC] QueryServiceConfig SUCCESS\r\n\r\n\
             SERVICE_NAME: net.dignetwork.dig-dns\r\n        \
             TYPE               : 10  WIN32_OWN_PROCESS\r\n        \
             START_TYPE         : 2   AUTO_START\r\n        \
             BINARY_PATH_NAME   : C:\\Program Files\\DIG\\dig-installer.exe run-dig-dns-service\r\n        \
             DISPLAY_NAME       : DIG NETWORK: DNS\r\n        \
             SERVICE_START_NAME : LocalSystem\r\n";
        assert_eq!(
            parse_sc_qc_display_name(out).as_deref(),
            Some("DIG NETWORK: DNS")
        );
    }

    #[test]
    fn parse_sc_qc_returns_none_when_no_display_name_line() {
        let out = "SERVICE_NAME: x\r\n        TYPE : 10  WIN32_OWN_PROCESS\r\n";
        assert_eq!(parse_sc_qc_display_name(out), None);
        assert_eq!(parse_sc_qc_display_name(""), None);
    }

    #[test]
    fn classify_display_name_matches_when_equal() {
        let c = classify_display_name(
            Some("DIG NETWORK: DNS"),
            DIG_DNS_SERVICE_DISPLAY,
            DIG_DNS_SERVICE_ID,
        );
        assert!(c.matches);
        assert_eq!(c.actual.as_deref(), Some("DIG NETWORK: DNS"));
        assert!(c.note.contains("DIG NETWORK: DNS"));
    }

    #[test]
    fn classify_display_name_flags_the_did_not_persist_symptom() {
        // The exact #499 bug: the panel shows the raw reverse-DNS service id
        // instead of the display name — the config did not persist.
        let c = classify_display_name(
            Some("net.dignetwork.dig-dns"),
            DIG_DNS_SERVICE_DISPLAY,
            DIG_DNS_SERVICE_ID,
        );
        assert!(!c.matches);
        assert!(c.note.contains("did not persist"), "note: {}", c.note);
        assert!(c.note.contains("DIG NETWORK: DNS"), "note: {}", c.note);
    }

    #[test]
    fn classify_display_name_reports_when_unreadable() {
        let c = classify_display_name(None, DIG_NODE_SERVICE_DISPLAY, DIG_NODE_SERVICE_ID);
        assert!(!c.matches);
        assert!(c.note.contains("could not read"), "note: {}", c.note);
    }

    #[test]
    fn verify_display_name_never_panics() {
        // Safe to call on any host; a service that certainly does not exist
        // must NOT verify as matching (never a false positive).
        let c = verify_display_name(
            "net.dignetwork.definitely-not-a-real-dig-service-xyz",
            "DIG NETWORK: TEST",
        );
        assert!(!c.matches);
    }

    #[test]
    fn is_service_running_is_false_for_an_unregistered_service() {
        // A service id that certainly does not exist must NOT report running on
        // any CI host (the false-positive this whole module guards against).
        assert!(!is_service_running(
            "net.dignetwork.definitely-not-a-real-dig-service-xyz"
        ));
    }

    // -- #565: stop/deregister BY ID (never by executing the service binary) ---

    #[test]
    fn sc_control_argv_is_by_id_and_never_a_binary_path() {
        // The whole point: control the service by its canonical id via `sc`,
        // NOT by spawning the (possibly attacker-replaced) service binary.
        assert_eq!(
            sc_stop_args("net.dignetwork.dig-node"),
            vec!["stop".to_string(), "net.dignetwork.dig-node".to_string()]
        );
        assert_eq!(
            sc_delete_args("net.dignetwork.dig-node"),
            vec!["delete".to_string(), "net.dignetwork.dig-node".to_string()]
        );
        // No argument is ever a path to a binary (no ".exe", no path separators).
        for a in sc_stop_args(DIG_NODE_SERVICE_ID)
            .into_iter()
            .chain(sc_delete_args(DIG_NODE_SERVICE_ID))
        {
            assert!(
                !a.contains(".exe") && !a.contains('\\') && !a.contains('/'),
                "got: {a}"
            );
        }
    }

    #[test]
    fn launchctl_target_is_the_system_domain_label() {
        assert_eq!(
            launchctl_system_target("net.dignetwork.dig-dns"),
            "system/net.dignetwork.dig-dns"
        );
    }

    #[test]
    fn stop_and_deregister_an_unregistered_service_are_ok_noops() {
        // Nothing registered → not RUNNING → stop/deregister succeed (idempotent
        // no-op), never an error, and never spawn a binary.
        let ghost = "net.dignetwork.definitely-not-a-real-dig-service-xyz";
        assert!(stop_service(ghost).is_ok());
        assert!(deregister_service(ghost).is_ok());
    }
}
