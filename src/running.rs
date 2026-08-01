//! Stopping a running DIG **user-session** process before its binary is deleted (#854).
//!
//! # Why an uninstall has to do this
//!
//! The daemons are stopped through the service manager, but `dig-app` (the per-user tray agent, #912)
//! and the `dign` CLI are ordinary user processes with no service registration. Windows holds an open
//! image section for a running executable, so deleting a running `dig-app.exe` fails with
//! `os error 5` — and that single failure is enough to make the whole uninstall exit non-zero and
//! report residue it cannot clear. dig-app entered the installer payload in 0.30.0, after the teardown
//! was written, so nothing stopped it.
//!
//! # Absent is the desired end state
//!
//! "No such process" is what an uninstall WANTS, so it is reported as success — the same idempotence
//! rule the rest of the teardown follows. Only a process that is still running afterwards, or a
//! killer that could not be run at all, is a failure.

use serde::Serialize;

/// The outcome of asking the OS to stop a process image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StopOutcome {
    /// A running process was terminated.
    Terminated,
    /// No process of that name was running — the desired end state.
    NotRunning,
    /// The stop could not be completed, carrying the raw exit code.
    Failed(i32),
}

impl StopOutcome {
    /// Did the image reach the desired end state (not running)?
    pub fn ok(&self) -> bool {
        !matches!(self, StopOutcome::Failed(_))
    }
}

/// The Windows `taskkill` argv that force-terminates every process of `image`, and its child tree.
///
/// `/T` matters for dig-app: a tray agent that has spawned a helper leaves that child holding the
/// image open, and the delete fails for exactly the reason the kill was supposed to remove. Pure.
pub fn taskkill_args(image: &str) -> Vec<String> {
    vec![
        "/IM".to_string(),
        image.to_string(),
        "/T".to_string(),
        "/F".to_string(),
    ]
}

/// Classify a Windows `taskkill` exit code.
///
/// `128` is `ERROR_WAIT_NO_CHILDREN` — taskkill's "the process is not running", which is the desired
/// end state and must never fail the run. Pure.
pub fn classify_taskkill_exit(code: i32) -> StopOutcome {
    match code {
        0 => StopOutcome::Terminated,
        128 => StopOutcome::NotRunning,
        other => StopOutcome::Failed(other),
    }
}

/// Classify a `pkill` exit code: `0` matched and signalled, `1` matched nothing (the desired end
/// state), anything else is a real error. Pure.
pub fn classify_pkill_exit(code: i32) -> StopOutcome {
    match code {
        0 => StopOutcome::Terminated,
        1 => StopOutcome::NotRunning,
        other => StopOutcome::Failed(other),
    }
}

/// Stop every running process whose image is `exe_name` (e.g. `dig-app.exe` / `dig-app`).
///
/// The killer is resolved to an absolute system path — `taskkill` through
/// [`crate::proc::system_tool`], `pkill` through [`crate::elevation::resolve_system_tool`] — never
/// looked up on `PATH`: this runs elevated, and a `PATH`/current-directory hijack of the tool would
/// hand an attacker an elevated execution (#1791/#1748).
pub fn stop_image(exe_name: &str) -> StopOutcome {
    #[cfg(windows)]
    {
        use crate::proc::HideConsole;
        use std::process::Command;
        // A trusted SYSTEM tool resolved to its absolute System32 path by `proc::system_tool`
        // (never `PATH`, never the current directory) — not an installed binary, so it does not go
        // through the `GuardedCommand` exec guard (#1748 WU4 / SPEC.md §7.6).
        #[allow(clippy::disallowed_methods)]
        let out = Command::new(crate::proc::system_tool("taskkill"))
            .args(taskkill_args(exe_name))
            .hide_console()
            .output();
        match out {
            Ok(o) => classify_taskkill_exit(o.status.code().unwrap_or(-1)),
            Err(_) => StopOutcome::Failed(-1),
        }
    }
    #[cfg(not(windows))]
    {
        use std::process::Command;
        // No `pkill` on this system ⇒ nothing we can signal; treat as not-running rather than
        // failing an uninstall over a tool the platform does not ship.
        let Some(pkill) = crate::elevation::resolve_system_tool("pkill") else {
            return StopOutcome::NotRunning;
        };
        // `-x`: match the executable NAME exactly. A substring/`-f` match would sweep in unrelated
        // processes whose command line merely mentions the name.
        // `pkill` is resolved to an absolute path from the trusted system-tool directory list
        // (`elevation::resolve_system_tool`), for the same reason: this runs as root.
        #[allow(clippy::disallowed_methods)]
        let out = Command::new(pkill).arg("-x").arg(exe_name).output();
        match out {
            Ok(o) => classify_pkill_exit(o.status.code().unwrap_or(-1)),
            Err(_) => StopOutcome::Failed(-1),
        }
    }
}

/// Summarise a set of `(image, outcome)` stops into the uninstall step's `(ok, note)`. Pure.
pub fn summarise(stops: &[(String, StopOutcome)]) -> (bool, String) {
    let ok = stops.iter().all(|(_, o)| o.ok());
    let notes: Vec<String> = stops
        .iter()
        .map(|(image, o)| match o {
            StopOutcome::Terminated => format!("{image}: stopped"),
            StopOutcome::NotRunning => format!("{image}: not running"),
            StopOutcome::Failed(c) => format!("{image}: could not stop (exit {c})"),
        })
        .collect();
    (ok, notes.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taskkill_force_kills_the_whole_process_tree_of_one_image() {
        assert_eq!(
            taskkill_args("dig-app.exe"),
            vec![
                "/IM".to_string(),
                "dig-app.exe".to_string(),
                "/T".to_string(),
                "/F".to_string()
            ]
        );
    }

    /// Both sides of the exit-code contract. "Not running" is the state an uninstall is TRYING to
    /// reach, so reading taskkill's 128 as a failure would fail every clean uninstall of a machine
    /// where dig-app simply was not open — while a genuine error (access denied, 1) must still fail.
    #[test]
    fn not_running_is_success_and_a_real_error_is_not() {
        assert_eq!(classify_taskkill_exit(0), StopOutcome::Terminated);
        assert_eq!(classify_taskkill_exit(128), StopOutcome::NotRunning);
        assert!(classify_taskkill_exit(128).ok());
        assert_eq!(classify_taskkill_exit(1), StopOutcome::Failed(1));
        assert!(!classify_taskkill_exit(1).ok());

        assert_eq!(classify_pkill_exit(0), StopOutcome::Terminated);
        assert_eq!(classify_pkill_exit(1), StopOutcome::NotRunning);
        assert!(classify_pkill_exit(1).ok());
        assert!(!classify_pkill_exit(2).ok());
    }

    /// One failed image must fail the step even when its neighbours succeeded — an "any ok" summary
    /// would hide the process that is still holding a binary open.
    #[test]
    fn one_failed_stop_fails_the_summary_and_names_the_image() {
        let stops = vec![
            ("dign.exe".to_string(), StopOutcome::NotRunning),
            ("dig-app.exe".to_string(), StopOutcome::Failed(1)),
        ];
        let (ok, note) = summarise(&stops);
        assert!(!ok);
        assert!(note.contains("dig-app.exe: could not stop"));
        assert!(note.contains("dign.exe: not running"));
    }

    #[test]
    fn all_absent_is_a_clean_success() {
        let stops = vec![("dig-app.exe".to_string(), StopOutcome::NotRunning)];
        assert!(summarise(&stops).0);
    }
}
