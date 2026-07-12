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
//!   * **Linux:** `systemctl is-active <id>` → `active`.
//!   * **macOS:** `launchctl print system/<id>` → `state = running`.
//!
//! Layering: the per-OS output PARSERS are pure + unit-tested; the spawns live
//! in [`service_run_state`].

use crate::target::Os;

/// Canonical dig-node service id (reverse-DNS) and human display name (#494).
pub const DIG_NODE_SERVICE_ID: &str = "net.dignetwork.dig-node";
pub const DIG_NODE_SERVICE_DISPLAY: &str = "DIG NETWORK: NODE";
/// Canonical dig-dns service id and human display name (#494).
pub const DIG_DNS_SERVICE_ID: &str = "net.dignetwork.dig-dns";
pub const DIG_DNS_SERVICE_DISPLAY: &str = "DIG NETWORK: DNS";

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

/// [`service_run_state`] for an explicit [`Os`] — spawns the OS-appropriate
/// query and parses it. Split out so the OS dispatch is explicit.
fn service_run_state_on(os: Os, id: &str) -> ServiceRunState {
    use std::process::Command;
    match os {
        Os::Windows => {
            let out = Command::new("sc").arg("query").arg(id).output();
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
            let out = Command::new("systemctl").arg("is-active").arg(id).output();
            match out {
                Ok(o) => parse_systemctl_is_active(&String::from_utf8_lossy(&o.stdout)),
                Err(_) => ServiceRunState::Unknown,
            }
        }
        Os::MacOs => {
            let out = Command::new("launchctl")
                .arg("print")
                .arg(format!("system/{id}"))
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
        if after.contains("STOP")
            || after.contains("PENDING")
            || after.contains("PAUSE")
        {
            return ServiceRunState::Stopped;
        }
    }
    ServiceRunState::Unknown
}

/// Parse Linux `systemctl is-active <id>` output. `active` (or `activating`) →
/// Running; `failed`/`inactive`/`deactivating` → Stopped; `unknown` (unit not
/// loaded) → NotFound; anything else → Unknown. Pure.
pub fn parse_systemctl_is_active(text: &str) -> ServiceRunState {
    match text.trim() {
        "active" | "activating" | "reloading" => ServiceRunState::Running,
        "failed" | "inactive" | "deactivating" => ServiceRunState::Stopped,
        "unknown" | "" => ServiceRunState::NotFound,
        _ => ServiceRunState::Unknown,
    }
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
        assert_eq!(parse_systemctl_is_active("active\n"), ServiceRunState::Running);
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
    }

    #[test]
    fn launchctl_print_reads_state() {
        let running = "system/net.dignetwork.dig-node = {\n\tstate = running\n\tpid = 1234\n}";
        assert_eq!(parse_launchctl_print(running), ServiceRunState::Running);
        let waiting = "system/net.dignetwork.dig-node = {\n\tstate = waiting\n}";
        assert_eq!(parse_launchctl_print(waiting), ServiceRunState::Stopped);
        assert_eq!(parse_launchctl_print("no state here"), ServiceRunState::Unknown);
    }

    #[test]
    fn describe_is_never_silent() {
        for state in [
            ServiceRunState::Running,
            ServiceRunState::Stopped,
            ServiceRunState::NotFound,
            ServiceRunState::Unknown,
        ] {
            assert!(state.describe("net.dignetwork.dig-node").contains("net.dignetwork.dig-node"));
        }
    }

    #[test]
    fn is_service_running_is_false_for_an_unregistered_service() {
        // A service id that certainly does not exist must NOT report running on
        // any CI host (the false-positive this whole module guards against).
        assert!(!is_service_running("net.dignetwork.definitely-not-a-real-dig-service-xyz"));
    }
}
