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

// `Command::new` is denied crate-wide so an unguarded spawn of an INSTALLED binary cannot compile
// (`clippy.toml`, #1748 WU4). The spawns in this module are either trusted SYSTEM tools resolved from a
// fixed directory list (`SPEC.md` §7.6 — a different invariant with its own tests in `elevation`), test
// fixtures, or the guarded wrapper itself.
#![allow(clippy::disallowed_methods)]

use crate::proc::HideConsole;
use crate::svcscope::ServiceScope;
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

/// The `launchctl` per-user (`gui/<uid>/<id>`) domain target string — the
/// LaunchAgent domain, where an UNELEVATED `dig-node install` registers. Pure.
pub fn launchctl_gui_target(uid: u32, id: &str) -> String {
    format!("gui/{uid}/{id}")
}

/// Every macOS `launchctl bootout` target that must be visited to deregister
/// service `id` — BOTH domains, always (dig_ecosystem#526).
///
/// Booting out only `system/<id>` was the uninstall-asymmetry defect: an
/// unelevated (or pre-#526) install registers a `gui/<uid>` LaunchAgent, which a
/// system-only teardown leaves running and re-launching at every login while the
/// installer reports a clean uninstall. `uid` is the TARGET user's
/// ([`crate::invoker::target_user`]) — `None` means the per-user domain could not
/// be addressed, which the caller must REPORT rather than treat as absent.
/// Pure.
pub fn macos_bootout_targets(uid: Option<u32>, id: &str) -> Vec<String> {
    let mut targets = vec![launchctl_system_target(id)];
    if let Some(uid) = uid {
        targets.push(launchctl_gui_target(uid, id));
    }
    targets
}

/// How service `id` is queried at one explicit [`ServiceScope`] on `os`.
///
/// Pure, and the reason this is a value rather than a `cfg`-gated branch: the
/// scope-to-command mapping — including the two arms that ask NOTHING — is then
/// asserted for all three operating systems from any host. A `#[cfg(unix)]`-only
/// test cannot falsify the Windows arm, so the mutation stays green
/// (dig_ecosystem#1774).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeQuery {
    /// This OS has no such domain, so the answer is definitively "not
    /// registered here" without asking anything (the Windows SCM has no
    /// per-user services).
    NoSuchDomain,
    /// The domain exists but could not be ADDRESSED (a macOS per-user domain
    /// with no resolvable uid). Not the same as absent — it resolves to
    /// [`ServiceRunState::Unknown`] so a caller never reads it as "nothing is
    /// registered".
    Unaddressable,
    /// `systemctl <args>` (already including `--user` for the per-user scope).
    Systemctl(Vec<String>),
    /// `launchctl print <target>`.
    LaunchctlPrint(String),
    /// `sc query <id>`.
    ScQuery(String),
}

/// Plan the scope-explicit query for `id` at `scope` on `os`, given the target
/// user's `uid` (macOS per-user domain addressing only). Pure — the spawn is
/// [`registration_in_scope`].
pub fn scope_query(os: Os, scope: ServiceScope, id: &str, uid: Option<u32>) -> ScopeQuery {
    match (os, scope) {
        (Os::Windows, ServiceScope::System) => ScopeQuery::ScQuery(id.to_string()),
        (Os::Windows, ServiceScope::User) => ScopeQuery::NoSuchDomain,
        (Os::Linux, ServiceScope::System) => {
            ScopeQuery::Systemctl(vec!["is-active".to_string(), linux_unit_name(id)])
        }
        (Os::Linux, ServiceScope::User) => ScopeQuery::Systemctl(vec![
            "--user".to_string(),
            "is-active".to_string(),
            linux_unit_name(id),
        ]),
        (Os::MacOs, ServiceScope::System) => {
            ScopeQuery::LaunchctlPrint(launchctl_system_target(id))
        }
        (Os::MacOs, ServiceScope::User) => match uid {
            Some(uid) => ScopeQuery::LaunchctlPrint(launchctl_gui_target(uid, id)),
            None => ScopeQuery::Unaddressable,
        },
    }
}

/// Is a registration PRESENT in one scope — a different question from whether it is RUNNING.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// A registration exists in this scope (running or not).
    Present,
    /// No registration exists in this scope.
    Absent,
    /// The scope could not be asked. NOT the same as absent, and never treated as either
    /// "registered" or "removed" — the caller REPORTS it.
    Unknown,
}

impl Presence {
    /// A short phrase for a note — never silent.
    pub fn describe(self, id: &str) -> String {
        match self {
            Presence::Present => format!("'{id}' is registered here"),
            Presence::Absent => format!("no registration for '{id}' here"),
            Presence::Unknown => format!("could not determine whether '{id}' is registered here"),
        }
    }
}

/// Will a registration be STARTED without a login — the boot/login enablement, which is a DIFFERENT
/// fact from presence.
///
/// Conflating the two is how a `masked` unit — one that can never start at all — came to be reported
/// as "will start again on its own after a reboot". Presence answers "does a registration exist
/// here?"; this answers "will anything start it?". Reboot survival is derived from THIS, never from
/// presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootEnablement {
    /// Linked for automatic start (systemd `enabled`, SCM `AUTO_START`, a loaded system LaunchDaemon).
    Enabled,
    /// The registration exists but nothing will start it automatically — systemd `disabled`,
    /// `static`, `indirect`, or `masked` (which can never start at all); SCM `DEMAND_START`/
    /// `DISABLED`.
    NotEnabled,
    /// Could not be determined. Never silently treated as either — a claim of reboot survival
    /// requires positive evidence.
    Unknown,
}

/// A scope-explicit registration reading: does it exist here, and will anything start it?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeRegistration {
    /// Does a registration exist in this scope?
    pub presence: Presence,
    /// Will it be started without a login?
    pub boot_enabled: BootEnablement,
    /// The raw verdict this was read from (`enabled`, `masked`, `AUTO_START`, the error text) —
    /// carried so every note can say WHY rather than only what.
    pub detail: String,
}

impl ScopeRegistration {
    /// A reading that could not be taken at all.
    pub fn unknown(detail: impl Into<String>) -> Self {
        ScopeRegistration {
            presence: Presence::Unknown,
            boot_enabled: BootEnablement::Unknown,
            detail: detail.into(),
        }
    }

    /// A definitively-present reading for a registration that WILL start on its own.
    pub fn enabled(detail: impl Into<String>) -> Self {
        ScopeRegistration {
            presence: Presence::Present,
            boot_enabled: BootEnablement::Enabled,
            detail: detail.into(),
        }
    }

    /// A definitively-absent reading.
    pub fn absent(detail: impl Into<String>) -> Self {
        ScopeRegistration {
            presence: Presence::Absent,
            boot_enabled: BootEnablement::NotEnabled,
            detail: detail.into(),
        }
    }

    /// Is this registration one that will start on its own, positively established?
    pub fn starts_without_login(&self) -> bool {
        self.boot_enabled == BootEnablement::Enabled
    }
}

/// Is service `id` REGISTERED in one explicit scope, on the current host?
///
/// The scope-blind [`service_run_state`] answers "is it running ANYWHERE?", which is right for a
/// health check and wrong for deciding whether a failed `install` may be tolerated: a leftover
/// user-scope registration would excuse a system-scope registration that never happened
/// (dig_ecosystem#526).
///
/// # Why this is not a RUN-STATE query
///
/// `systemctl is-active <unit>` prints `inactive` for a unit that DOES NOT EXIST, and `inactive`
/// legitimately means "stopped" for one that does — so a run-state query cannot answer "is anything
/// registered here?" at all. Reading `Stopped` as presence would tolerate a failed install against a
/// unit that was never created (the exact false-ready this closes) and would report a successfully
/// completed uninstall as residual. Linux therefore asks `is-enabled`, whose vocabulary distinguishes
/// an existing unit (`enabled`/`disabled`/`static`/`masked`/…) from a missing one ("No such file or
/// directory"). Found by the installer-e2e on ubuntu, run 30645063625.
pub fn registration_in_scope(id: &str, scope: ServiceScope) -> ScopeRegistration {
    let Ok(target) = crate::target::Target::current() else {
        return ScopeRegistration::unknown("this host's OS/arch target could not be detected");
    };
    let uid = crate::invoker::target_user().uid;
    match scope_query(target.os, scope, id, uid) {
        // The Windows SCM has no per-user domain, so "nothing is registered here" is a FACT, not a
        // failure to look.
        ScopeQuery::NoSuchDomain => {
            ScopeRegistration::absent("this OS has no per-user service domain")
        }
        ScopeQuery::Unaddressable => ScopeRegistration::unknown(
            "the per-user domain could not be addressed (no resolvable uid)",
        ),
        ScopeQuery::Systemctl(args) => {
            // Same scope + unit, different verb: registration + enablement, not activity.
            let enabled_args: Vec<String> = args
                .iter()
                .map(|a| {
                    if a == "is-active" {
                        "is-enabled".to_string()
                    } else {
                        a.clone()
                    }
                })
                .collect();
            let borrowed: Vec<&str> = enabled_args.iter().map(String::as_str).collect();
            query_systemctl_registration(&borrowed)
        }
        ScopeQuery::LaunchctlPrint(target) => launchctl_registration(&target, scope),
        ScopeQuery::ScQuery(id) => {
            classify_sc_registration(&sc_query_text(&id), &sc_config_text(&id))
        }
    }
}

/// Classify a `systemctl [--user] is-enabled <unit>` invocation. Pure.
///
/// # The verdict comes from the TOKEN on stdout, never from a substring of an error
///
/// `is-enabled` prints exactly one state word on stdout for a unit it can read. Everything else is
/// an error on stderr, and errors must NOT be pattern-matched into a verdict:
///
/// * `Failed to connect to bus: No such file or directory` is what `--user` prints under `sudo`,
///   where root has no session bus. It contains "No such file or directory" — so a substring match
///   for that phrase classified a scope it could not even ASK as definitively `Absent`, and an
///   uninstall then reported "removed from every scope" for a scope it never reached. That is
///   `Unknown` (dig_ecosystem#526 review, A5).
/// * A missing unit is reported by systemd as a failure to get the unit file state, together with an
///   EMPTY stdout and a non-zero exit — which is `Absent`.
///
/// `masked`, `static`, `indirect` and `disabled` all describe a unit that EXISTS but that nothing
/// will start automatically, so they are `Present` + [`BootEnablement::NotEnabled`] — never
/// `Enabled`. `masked` cannot start at all, which the detail says out loud.
pub fn classify_systemctl_is_enabled(
    stdout: &str,
    stderr: &str,
    exited_zero: bool,
) -> ScopeRegistration {
    let token = stdout.trim();
    let present = |boot_enabled: BootEnablement, detail: String| ScopeRegistration {
        presence: Presence::Present,
        boot_enabled,
        detail,
    };
    match token {
        // systemd's OWN not-found token, printed on stdout by a query that ran fine. This IS the
        // recognised not-found reply, so it is the one error-free reading that means Absent. Found by
        // the #526 system-scope e2e (run 30665680769), where classifying it as an unrecognised
        // verdict made a plainly-empty scope read "could not determine".
        "not-found" => {
            return ScopeRegistration::absent("systemd reports `not-found` — no such unit here")
        }
        "enabled" | "enabled-runtime" | "alias" => {
            return present(
                BootEnablement::Enabled,
                format!("systemd reports `{token}`"),
            )
        }
        "masked" | "masked-runtime" => {
            return present(
                BootEnablement::NotEnabled,
                format!(
                    "systemd reports `{token}` — this unit can NEVER start until it is unmasked"
                ),
            )
        }
        "disabled" | "static" | "indirect" | "generated" | "transient" | "linked"
        | "linked-runtime" => {
            return present(
                BootEnablement::NotEnabled,
                format!("systemd reports `{token}` — the unit exists but nothing starts it"),
            )
        }
        _ => {}
    }

    // No state token, so the answer is in the error — and the only error that means "absent" is one
    // about the UNIT FILE, with nothing on stdout.
    let err = stderr.to_lowercase();
    let bus_failure = err.contains("failed to connect to bus")
        || err.contains("failed to get d-bus connection")
        || err.contains("no medium found")
        || err.contains("host is down");
    if bus_failure {
        return ScopeRegistration::unknown(format!(
            "the scope could not be queried at all: {}",
            stderr.trim()
        ));
    }
    let unit_file_missing = (err.contains("unit file") || err.contains("no such unit"))
        && (err.contains("no such file")
            || err.contains("does not exist")
            || err.contains("not found"));
    if unit_file_missing && token.is_empty() {
        return ScopeRegistration::absent(format!(
            "systemd reports no such unit: {}",
            stderr.trim()
        ));
    }
    // An empty answer WITH a zero exit is systemd saying nothing at all, which is not evidence of
    // absence; a non-empty unrecognised token is a systemd we do not know. Both are Unknown.
    let detail = if token.is_empty() {
        format!("systemctl gave no verdict: {}", stderr.trim())
    } else {
        format!("unrecognised systemd verdict `{token}`")
    };
    let _ = exited_zero;
    ScopeRegistration::unknown(detail)
}

/// Classify Windows `sc query <id>` + `sc qc <id>` output. Pure.
///
/// `sc query` answers presence (a `1060`/"does not exist" reply is definitively absent); `sc qc`
/// answers enablement, because the SCM's `START_TYPE` is what decides whether the service comes up at
/// boot — a `DEMAND_START` service is registered and will NOT start on its own.
pub fn classify_sc_registration(query_text: &str, config_text: &str) -> ScopeRegistration {
    match parse_sc_query(query_text) {
        ServiceRunState::NotFound => {
            ScopeRegistration::absent("`sc query` reports no such service (1060)")
        }
        ServiceRunState::Running | ServiceRunState::Stopped => {
            let (boot_enabled, detail) = parse_sc_start_type(config_text);
            ScopeRegistration {
                presence: Presence::Present,
                boot_enabled,
                detail,
            }
        }
        ServiceRunState::Unknown => {
            ScopeRegistration::unknown("`sc query` gave no recognisable answer")
        }
    }
}

/// Read the SCM `START_TYPE` from `sc qc <id>` output. Pure.
///
/// `AUTO_START` (2) is the only value that comes up at boot; `DEMAND_START` (3) and `DISABLED` (4)
/// do not. An unreadable config is `Unknown`, never assumed enabled.
pub fn parse_sc_start_type(text: &str) -> (BootEnablement, String) {
    for line in text.lines() {
        let upper = line.to_uppercase();
        if !upper.contains("START_TYPE") {
            continue;
        }
        if upper.contains("AUTO_START") {
            return (
                BootEnablement::Enabled,
                "the SCM reports START_TYPE AUTO_START".to_string(),
            );
        }
        if upper.contains("DEMAND_START")
            || upper.contains("DISABLED")
            || upper.contains("BOOT")
            || upper.contains("SYSTEM")
        {
            return (
                BootEnablement::NotEnabled,
                format!("the SCM reports {}", line.trim()),
            );
        }
    }
    (
        BootEnablement::Unknown,
        "the SCM's START_TYPE could not be read".to_string(),
    )
}

/// Spawn `systemctl <args>` and classify it, keeping the exit status rather than discarding it.
fn query_systemctl_registration(args: &[&str]) -> ScopeRegistration {
    match std::process::Command::new("systemctl")
        .args(args)
        .hide_console()
        .output()
    {
        Ok(o) => classify_systemctl_is_enabled(
            &String::from_utf8_lossy(&o.stdout),
            &String::from_utf8_lossy(&o.stderr),
            o.status.success(),
        ),
        // The tool itself could not be run — the one thing that is certainly not evidence of absence.
        Err(e) => ScopeRegistration::unknown(format!("systemctl could not be run: {e}")),
    }
}

/// `launchctl print <target>` succeeds only for a label loaded in that domain.
///
/// Enablement follows the DOMAIN, which is what launchd's boot behaviour actually turns on: a job
/// loaded in the SYSTEM domain is bootstrapped by launchd at boot, while one in `gui/<uid>` is
/// bootstrapped when that user's GUI session starts — by definition a login. A domain that could not
/// be printed is `Unknown`, never absent.
fn launchctl_registration(target: &str, scope: ServiceScope) -> ScopeRegistration {
    match std::process::Command::new("launchctl")
        .arg("print")
        .arg(target)
        .hide_console()
        .output()
    {
        Ok(o) if o.status.success() => ScopeRegistration {
            presence: Presence::Present,
            boot_enabled: match scope {
                ServiceScope::System => BootEnablement::Enabled,
                ServiceScope::User => BootEnablement::NotEnabled,
            },
            detail: format!("launchd has `{target}` loaded"),
        },
        Ok(_) => ScopeRegistration::absent(format!("launchd has no `{target}` loaded")),
        Err(e) => ScopeRegistration::unknown(format!("launchctl could not be run: {e}")),
    }
}

/// The combined stdout+stderr of `sc qc <id>`, for [`parse_sc_start_type`].
fn sc_config_text(id: &str) -> String {
    match std::process::Command::new(crate::proc::system_tool("sc"))
        .arg("qc")
        .arg(id)
        .hide_console()
        .output()
    {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            text
        }
        Err(_) => String::new(),
    }
}

/// The combined stdout+stderr of `sc query <id>`, for [`parse_sc_query_presence`].
fn sc_query_text(id: &str) -> String {
    match std::process::Command::new(crate::proc::system_tool("sc"))
        .arg("query")
        .arg(id)
        .hide_console()
        .output()
    {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            text
        }
        Err(_) => String::new(),
    }
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
        for target in macos_bootout_targets(crate::invoker::target_user().uid, id) {
            let _ = run_svc_tool("launchctl", &["bootout".into(), target]);
        }
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = id;
    }
}

/// Issue the OS "deregister this service by id" command. Windows `sc delete`;
/// Linux `systemctl [--user] disable`; macOS `launchctl bootout` (which both
/// stops AND deregisters) in BOTH the system and `gui/<uid>` domains
/// ([`macos_bootout_targets`], dig_ecosystem#526). Best-effort —
/// [`deregister_service`] polls the state.
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
        for target in macos_bootout_targets(crate::invoker::target_user().uid, id) {
            let _ = run_svc_tool("launchctl", &["bootout".into(), target]);
        }
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = id;
    }
}

/// Build the [`std::process::Command`] for an OS service-control tool, resolving
/// a Windows system tool (`sc`) to its absolute `System32\sc.exe` path via the
/// single hardened [`crate::proc::system_tool`] resolver (#657) — the identity on
/// the unix `systemctl`/`launchctl` names, so cross-platform behaviour is
/// unchanged. Split out so the resolved program can be asserted directly (via
/// [`std::process::Command::get_program`]) without spawning.
///
/// Without this, an elevated `sc stop`/`sc delete` teardown launched with an
/// attacker-controlled CWD could execute a planted `sc.exe` from the current
/// directory (Windows' bare-name search order places the CWD before System32) —
/// the exact search-order hijack #657 closes, mirroring [`crate::regaudit::spawn`].
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn svc_tool_command(tool: &str) -> std::process::Command {
    std::process::Command::new(crate::proc::system_tool(tool))
}

/// Spawn an OS service-control tool, discarding its output (the authoritative
/// signal is always the subsequent [`service_run_state`] poll, not the tool's
/// exit code — a stop of an already-stopped service exits non-zero). `Ok(())`
/// iff the tool exited 0.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn run_svc_tool(tool: &str, args: &[String]) -> Result<(), String> {
    svc_tool_command(tool)
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
        let out = std::process::Command::new(crate::proc::system_tool("sc"))
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
    match os {
        Os::Windows => query_sc(id),
        Os::Linux => {
            let unit = linux_unit_name(id);
            let user = query_systemctl_is_active(&["--user", "is-active", &unit]);
            let system = query_systemctl_is_active(&["is-active", &unit]);
            combine_systemctl_states(user, system)
        }
        Os::MacOs => query_launchctl_print(&launchctl_system_target(id)),
    }
}

/// Spawn `sc query <id>` and parse it. Windows-only in effect; the spawn simply
/// fails elsewhere, resolving to [`ServiceRunState::Unknown`].
fn query_sc(id: &str) -> ServiceRunState {
    match std::process::Command::new(crate::proc::system_tool("sc"))
        .arg("query")
        .arg(id)
        .hide_console()
        .output()
    {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            parse_sc_query(&text)
        }
        Err(_) => ServiceRunState::Unknown,
    }
}

/// Spawn `launchctl print <target>` (e.g. `system/<id>` or `gui/<uid>/<id>`) and
/// parse it. A non-zero exit means the label is not loaded in THAT domain.
fn query_launchctl_print(target: &str) -> ServiceRunState {
    match std::process::Command::new("launchctl")
        .arg("print")
        .arg(target)
        .hide_console()
        .output()
    {
        Ok(o) if o.status.success() => parse_launchctl_print(&String::from_utf8_lossy(&o.stdout)),
        Ok(_) => ServiceRunState::NotFound,
        Err(_) => ServiceRunState::Unknown,
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

    // -- Scope-explicit addressing (dig_ecosystem#526) ----------------------
    //
    // Every assertion below is over the PURE plan, for all three operating
    // systems, from any host: a `#[cfg(unix)]`-only test would leave the
    // Windows arms unfalsifiable on CI's Windows runner and on this repo's
    // dev boxes alike (#1774).

    #[test]
    fn a_macos_deregister_boots_out_both_the_system_and_the_per_user_domain() {
        // The uninstall-asymmetry defect: a system-only bootout leaves an
        // unelevated install's `gui/<uid>` LaunchAgent running and relaunching
        // at every login while the installer reports a clean uninstall.
        let targets = macos_bootout_targets(Some(501), DIG_NODE_SERVICE_ID);
        assert_eq!(
            targets,
            vec![
                "system/net.dignetwork.dig-node".to_string(),
                "gui/501/net.dignetwork.dig-node".to_string(),
            ]
        );
    }

    #[test]
    fn an_unresolvable_uid_still_boots_out_the_system_domain() {
        // Nothing addressable in the per-user domain, so only the system target
        // is issued — and the caller REPORTS the unreachable scope rather than
        // claiming a complete uninstall (`uninstall::scope_report`).
        assert_eq!(
            macos_bootout_targets(None, DIG_DNS_SERVICE_ID),
            vec!["system/net.dignetwork.dig-dns".to_string()]
        );
    }

    #[test]
    fn scope_query_addresses_the_right_domain_on_every_os() {
        let id = DIG_NODE_SERVICE_ID;
        let unit = linux_unit_name(id);
        assert_eq!(
            scope_query(Os::Windows, ServiceScope::System, id, None),
            ScopeQuery::ScQuery(id.to_string())
        );
        // The Windows SCM has NO per-user services, so the answer is known
        // without asking — never an Unknown that a caller might read as "maybe".
        assert_eq!(
            scope_query(Os::Windows, ServiceScope::User, id, Some(1000)),
            ScopeQuery::NoSuchDomain
        );
        assert_eq!(
            scope_query(Os::Linux, ServiceScope::System, id, None),
            ScopeQuery::Systemctl(vec!["is-active".to_string(), unit.clone()])
        );
        assert_eq!(
            scope_query(Os::Linux, ServiceScope::User, id, None),
            ScopeQuery::Systemctl(vec!["--user".to_string(), "is-active".to_string(), unit])
        );
        assert_eq!(
            scope_query(Os::MacOs, ServiceScope::System, id, Some(501)),
            ScopeQuery::LaunchctlPrint("system/net.dignetwork.dig-node".to_string())
        );
        assert_eq!(
            scope_query(Os::MacOs, ServiceScope::User, id, Some(501)),
            ScopeQuery::LaunchctlPrint("gui/501/net.dignetwork.dig-node".to_string())
        );
    }

    #[test]
    fn an_unaddressable_macos_user_domain_is_unknown_not_absent() {
        // "Could not ask" must never collapse into "nothing is registered":
        // tolerating a failed install on that answer is exactly the #526
        // false-ready.
        assert_eq!(
            scope_query(Os::MacOs, ServiceScope::User, DIG_NODE_SERVICE_ID, None),
            ScopeQuery::Unaddressable
        );
    }

    #[test]
    fn is_enabled_distinguishes_an_existing_unit_from_a_missing_one() {
        // THE trap this replaced: `is-active` prints `inactive` for a unit that does not exist, and
        // `parse_systemctl_is_active` maps `inactive` to Stopped — "registered but not running".
        assert_eq!(
            parse_systemctl_is_active("inactive"),
            ServiceRunState::Stopped,
            "documenting the trap: is-active says `inactive` for a unit that is not there"
        );
        let missing = classify_systemctl_is_enabled(
            "",
            "Failed to get unit file state for dignetwork-dig-node.service: No such file or \
             directory",
            false,
        );
        assert_eq!(missing.presence, Presence::Absent);
        assert_eq!(missing.boot_enabled, BootEnablement::NotEnabled);
    }

    /// A5: a D-Bus failure is `Unknown`, NEVER `Absent`.
    ///
    /// `systemctl --user is-enabled` under `sudo` prints "Failed to connect to bus: No such file or
    /// directory" — which CONTAINS the missing-unit phrase. A substring match therefore classified a
    /// scope it could not even ask as definitively empty, and the uninstall reported "removed from
    /// every scope" with nothing listed as unverified. The fixture is the real message, because a
    /// synthetic "bus error" string would not exhibit the collision that caused the bug.
    #[test]
    fn a_bus_failure_is_unknown_never_absent() {
        for stderr in [
            "Failed to connect to bus: No such file or directory",
            "Failed to get D-Bus connection: Operation not permitted",
            "Failed to connect to bus: Host is down",
        ] {
            let r = classify_systemctl_is_enabled("", stderr, false);
            assert_eq!(
                r.presence,
                Presence::Unknown,
                "a scope that could not be asked is not empty: {stderr}"
            );
            assert_eq!(r.boot_enabled, BootEnablement::Unknown);
            assert!(r.detail.contains("could not be queried"), "{}", r.detail);
        }
    }

    /// A4: presence is not boot-enablement.
    ///
    /// A `masked` unit exists and can NEVER start; `disabled`/`static` exist and nothing starts them.
    /// Reporting any of them as reboot-surviving is the false-ready this PR exists to remove, so the
    /// two facts are read separately and only `enabled` licenses the claim.
    #[test]
    fn presence_does_not_imply_boot_enablement() {
        for token in ["enabled", "enabled-runtime", "alias"] {
            let r = classify_systemctl_is_enabled(token, "", true);
            assert_eq!(r.presence, Presence::Present, "{token}");
            assert_eq!(r.boot_enabled, BootEnablement::Enabled, "{token}");
            assert!(r.starts_without_login(), "{token}");
        }
        for token in [
            "masked",
            "masked-runtime",
            "disabled",
            "static",
            "indirect",
            "generated",
            "transient",
            "linked",
        ] {
            let r = classify_systemctl_is_enabled(token, "", true);
            assert_eq!(
                r.presence,
                Presence::Present,
                "`{token}` describes a unit that EXISTS"
            );
            assert_eq!(
                r.boot_enabled,
                BootEnablement::NotEnabled,
                "`{token}` starts nothing on its own"
            );
            assert!(!r.starts_without_login(), "{token}");
        }
        // A masked unit says so, because "registered but nothing starts it" understates it.
        assert!(classify_systemctl_is_enabled("masked", "", true)
            .detail
            .contains("NEVER start"));
    }

    /// `not-found` on stdout is systemd ANSWERING "there is no such unit", not failing to answer.
    ///
    /// Distinguishing it from the two neighbours is the whole point, so all three are asserted
    /// together: a real state token is Present, `not-found` is Absent, and a token systemd has never
    /// printed is Unknown. Reading `not-found` as Unknown made an empty scope report "could not
    /// determine" and turned a clean install failure into an unreadable one (run 30665680769).
    #[test]
    fn the_not_found_token_is_a_successful_answer_meaning_absent() {
        let r = classify_systemctl_is_enabled("not-found", "", false);
        assert_eq!(r.presence, Presence::Absent);
        assert_eq!(r.boot_enabled, BootEnablement::NotEnabled);
        assert!(r.detail.contains("no such unit"), "{}", r.detail);

        // The neighbours, on the same shape of input, so this cannot pass by treating everything
        // alike.
        assert_eq!(
            classify_systemctl_is_enabled("disabled", "", false).presence,
            Presence::Present,
            "a real state token is a unit that EXISTS"
        );
        assert_eq!(
            classify_systemctl_is_enabled("not-found-ish", "", false).presence,
            Presence::Unknown,
            "only the exact token systemd prints is a verdict"
        );
    }

    #[test]
    fn an_unrecognised_or_silent_systemctl_answer_is_unknown() {
        // A future systemd word, and a zero-exit empty answer: neither is evidence of absence.
        assert_eq!(
            classify_systemctl_is_enabled("something-new", "", true).presence,
            Presence::Unknown
        );
        assert_eq!(
            classify_systemctl_is_enabled("", "", true).presence,
            Presence::Unknown
        );
    }

    #[test]
    fn sc_registration_reads_presence_from_query_and_enablement_from_the_config() {
        let missing = "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\r\n\r\nThe specified \
                       service does not exist as an installed service.\r\n";
        assert_eq!(
            classify_sc_registration(missing, "").presence,
            Presence::Absent
        );

        // A STOPPED service is still REGISTERED, and AUTO_START is what makes it boot-start.
        let auto = classify_sc_registration(
            "STATE : 1  STOPPED\r\n",
            "        START_TYPE         : 2   AUTO_START\r\n",
        );
        assert_eq!(auto.presence, Presence::Present);
        assert!(auto.starts_without_login());

        // The row that separates presence from enablement on Windows: registered, but manual.
        let demand = classify_sc_registration(
            "STATE : 4  RUNNING\r\n",
            "        START_TYPE         : 3   DEMAND_START\r\n",
        );
        assert_eq!(demand.presence, Presence::Present);
        assert!(
            !demand.starts_without_login(),
            "a DEMAND_START service does not come up at boot"
        );

        // An unreadable config never licenses a survival claim.
        let unreadable = classify_sc_registration("STATE : 4  RUNNING\r\n", "");
        assert_eq!(unreadable.presence, Presence::Present);
        assert_eq!(unreadable.boot_enabled, BootEnablement::Unknown);
    }

    #[test]
    fn presence_is_never_silent() {
        for p in [Presence::Present, Presence::Absent, Presence::Unknown] {
            assert!(p.describe("net.dignetwork.dig-node").contains("dig-node"));
        }
    }

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

    // -- #657: the service-control tool resolves to an ABSOLUTE System32 path ---

    #[test]
    fn service_teardown_sc_resolves_through_the_system32_hardened_resolver() {
        // #657 completeness: the `sc stop`/`sc delete` teardown spawn is an
        // elevated path reachable via `stop_service`/`deregister_service`, so the
        // ACTUAL program of the command it builds MUST be the absolute
        // `System32\sc.exe` — never a bare `sc` a current-directory search-order
        // hijack could substitute. Observing `get_program()` makes this RED if the
        // helper reverts to a bare `Command::new(tool)` (the missed #657 site).
        let program = svc_tool_command("sc").get_program().to_owned();
        #[cfg(windows)]
        {
            let s = program.to_string_lossy().to_lowercase();
            assert!(
                s.ends_with(r"system32\sc.exe"),
                "the service-teardown `sc` command must resolve to an absolute \
                 System32 path, not a bare name: {s}"
            );
            assert!(std::path::Path::new(&program).is_absolute());
        }
        #[cfg(not(windows))]
        {
            // Identity on the unix service-control names — cross-platform behaviour
            // is unchanged (mirrors `regaudit::spawn`).
            assert_eq!(program, std::ffi::OsString::from("sc"));
            assert_eq!(
                svc_tool_command("systemctl").get_program().to_owned(),
                std::ffi::OsString::from("systemctl")
            );
            assert_eq!(
                svc_tool_command("launchctl").get_program().to_owned(),
                std::ffi::OsString::from("launchctl")
            );
        }
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
