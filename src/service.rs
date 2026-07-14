//! dig-node OS-service setup, by **delegating to dig-node's own service
//! subcommands** rather than reimplementing systemd/launchd/SCM wiring.
//!
//! dig-node (the local DIG node, renamed from dig-companion) already knows how
//! to register itself as a Windows service / systemd unit / launchd agent — it
//! exposes `install`/`uninstall`/`start`/`stop`/`status` and uses the
//! `service-manager` crate internally (see SYSTEM.md). The universal installer
//! therefore just downloads that binary and runs `dig-node install` (+ `start`),
//! passing the loopback port via `DIG_NODE_PORT` so the service serves on
//! the configured endpoint. This module builds those invocations; the pure
//! arg/env construction is unit-tested without spawning anything.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use crate::proc::HideConsole;

/// Configuration for the dig-node service the installer will register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Loopback port dig-node should serve on (default
    /// [`dig_constants::DIG_NODE_PORT`], per dig-node).
    pub port: u16,
    /// Start the service immediately after installing it.
    pub start: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        // dig_constants::DIG_NODE_PORT (9778) matches dig-node's own default
        // (config.rs DEFAULT_PORT) — an uncommon high port deliberately clear
        // of the collision-prone common-dev ports
        // (80/443/3000/5000/8000/8080/8888/9000), the sibling of the
        // dig-wallet HTTP API's 9777 (task #132). `dig.local` on
        // `127.0.0.2:80` is unaffected — only this localhost port moves.
        ServiceConfig {
            port: dig_constants::DIG_NODE_PORT,
            start: true,
        }
    }
}

/// The subcommand passed to the dig-node binary (`dig-node <subcommand>`).
///
/// Plain `install` — dig-node's own `install` verb registers a **boot-start**
/// OS service (`autostart: true` in dig-node-service's `service::install`, i.e.
/// Windows SCM `start= auto` / systemd `enable` / launchd `RunAtLoad`), so the
/// node comes up on every boot (#301). We deliberately pass NO manual-start
/// variant here; boot-start is the intended, tested default.
pub fn install_args() -> Vec<String> {
    vec!["install".to_string()]
}

/// The subcommand to start the installed service.
pub fn start_args() -> Vec<String> {
    vec!["start".to_string()]
}

/// The subcommand to remove the installed service (task #140). dig-node's own
/// `uninstall` best-effort stops the service first, so this installer only
/// needs to invoke the one subcommand.
pub fn uninstall_args() -> Vec<String> {
    vec!["uninstall".to_string()]
}

/// The subcommand to stop a running service (task #232 — stop-before-write).
pub fn stop_args() -> Vec<String> {
    vec!["stop".to_string()]
}

/// The subcommand to query service state (task #232).
fn status_json_args() -> Vec<String> {
    vec!["status".to_string(), "--json".to_string()]
}

/// Environment variables to pass to `dig-node install` so the registered
/// service serves on the configured port. dig-node's `install` snapshots its
/// effective config into the service definition, so setting the env here is what
/// pins the service's port.
///
/// Sorted (`BTreeMap`) so the output is deterministic and testable.
pub fn install_env(cfg: &ServiceConfig) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    // dig-node reads the canonical DIG_NODE_* names (its config.rs stable env
    // contract, SPEC 3.1) — DIG_NODE_PORT is what pins the service's port.
    env.insert("DIG_NODE_PORT".to_string(), cfg.port.to_string());
    env
}

/// Run `dig-node install` (and, if `cfg.start`, `dig-node start`) using the
/// downloaded binary at `bin`. Returns a human note on success.
///
/// On Windows, installing a service needs an elevated console; dig-node detects
/// this and returns a clear message, which we surface verbatim.
///
/// `install` is NOT idempotent (task #232): re-running it over an
/// already-registered service hard-fails on Windows SCM / macOS launchd
/// ("already exists"-style errors) even though the registration is still
/// perfectly usable. Since the registration always points at the SAME on-disk
/// path this installer writes to, a failed re-`install` does not prevent
/// `start` from picking up the binary this run just wrote — so an `install`
/// failure is tolerated (recorded in the note) and `start` is still attempted
/// when `cfg.start` is set. Only a `start` failure is a hard error: that is
/// the actual "the service isn't running" outcome the caller cares about.
pub fn install_service(bin: &Path, cfg: &ServiceConfig) -> Result<String, String> {
    let mut note = match run_dig_node(bin, &install_args(), &install_env(cfg)) {
        Ok(()) => String::from("dig-node installed as an OS service"),
        Err(e) => format!(
            "dig-node install did not complete cleanly ({e}); continuing since a service may \
             already be registered at this path — the start attempt below is the real signal"
        ),
    };
    if cfg.start {
        run_dig_node(bin, &start_args(), &BTreeMap::new())
            .map_err(|e| format!("dig-node start failed: {e}"))?;
        note.push_str(" and started");
    }
    Ok(note)
}

/// The outcome of [`stop_running_dig_node`] (task #232 — stop a running
/// service BEFORE this run overwrites its binary; Windows locks a running
/// exe's file, so overwriting it in place fails with a sharing violation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopOutcome {
    /// A binary already existed at the destination path — i.e. this is an
    /// upgrade over a prior install, not a first install.
    pub bin_existed: bool,
    /// The service was found serving and a stop was attempted.
    pub attempted: bool,
    /// The attempted stop succeeded. Always `false` when `attempted` is
    /// `false` (nothing to stop is not a stop failure).
    pub stopped: bool,
    /// Human-readable detail — never silent (mirrors the rest of this crate's
    /// `note` convention).
    pub note: String,
}

/// Parse a dig-node `status --json` response for its flat top-level
/// `"serving"` boolean. Pure — unit-tested without spawning anything. `None`
/// means "could not determine" (malformed/unexpected JSON, or the binary
/// predates the `status` verb); callers treat that as "not serving", the
/// safe default when there is no evidence otherwise.
fn parse_dig_node_serving(status_stdout: &[u8]) -> Option<bool> {
    serde_json::from_slice::<serde_json::Value>(status_stdout)
        .ok()?
        .get("serving")?
        .as_bool()
}

/// Spawn `<bin> status --json` and read whether dig-node is currently
/// serving. Never hard-fails: a spawn failure or unparseable output resolves
/// to "not serving" (see [`parse_dig_node_serving`]).
fn dig_node_is_serving(bin: &Path) -> bool {
    Command::new(bin)
        .args(status_json_args())
        .hide_console()
        .output()
        .ok()
        .and_then(|out| parse_dig_node_serving(&out.stdout))
        .unwrap_or(false)
}

/// Stop a currently-serving dig-node service before its binary is
/// overwritten (task #232). Delegates to dig-node's own `stop` verb — never
/// hand-rolls OS service control. Skip-when-absent (no error) when `bin`
/// doesn't exist yet (first install) or `status` reports it isn't serving.
/// If it IS serving and the stop attempt itself fails, this returns `Err` so
/// the caller ABORTS this artifact's write rather than risk a half-written
/// binary underneath a still-running service.
pub fn stop_running_dig_node(bin: &Path) -> Result<StopOutcome, String> {
    stop_running_dig_node_with(bin, dig_node_is_serving)
}

/// [`stop_running_dig_node`] with an injectable "is currently serving" check
/// — production code passes [`dig_node_is_serving`] (a real `status --json`
/// probe); tests inject a fixed answer so the skip-vs-attempt branching is
/// exercised without a JSON-emitting stub process.
fn stop_running_dig_node_with(
    bin: &Path,
    is_serving: impl Fn(&Path) -> bool,
) -> Result<StopOutcome, String> {
    if !bin.exists() {
        return Ok(StopOutcome {
            bin_existed: false,
            attempted: false,
            stopped: false,
            note: "no existing dig-node binary — first install, nothing to stop".to_string(),
        });
    }
    if !is_serving(bin) {
        return Ok(StopOutcome {
            bin_existed: true,
            attempted: false,
            stopped: false,
            note: "existing dig-node service is not currently serving — nothing to stop"
                .to_string(),
        });
    }
    run_dig_node(bin, &stop_args(), &BTreeMap::new())
        .map(|()| StopOutcome {
            bin_existed: true,
            attempted: true,
            stopped: true,
            note: "stopped the running dig-node service before replacing its binary".to_string(),
        })
        .map_err(|e| {
            format!("could not stop the running dig-node service before replacing its binary: {e}")
        })
}

/// Run `dig-node uninstall` (task #140) using the previously-installed binary
/// at `bin`, removing the OS service registration. dig-node's own `uninstall`
/// best-effort stops the service first (see its README/service.rs), so this is
/// a single subcommand invocation — the counterpart to [`install_service`].
/// Returns a human note on success; the caller pairs this with removing the
/// `dig.local` hosts entry ([`crate::hosts::remove_dig_local`]).
pub fn uninstall_service(bin: &Path) -> Result<String, String> {
    run_dig_node(bin, &uninstall_args(), &BTreeMap::new())
        .map_err(|e| format!("dig-node uninstall failed: {e}"))?;
    Ok(String::from("dig-node service uninstalled"))
}

// ---------------------------------------------------------------------------
// Run-your-own-relay service (component `relay`).
//
// The relay is OPTIONAL and for advanced users: the default node points at the
// canonical relay.dig.net out of the box, so most users never run one. When a
// user opts in (`--with-relay`), we register the downloaded dig-relay binary as
// an OS service by delegating to ITS OWN `install`/`start` subcommands — the same
// pattern as dig-node (see SYSTEM.md), so the installer never reimplements
// systemd/launchd/SCM wiring. The relay's listen/health ports are pinned via the
// DIG_RELAY_* env the relay's `install` snapshots into the service definition.
// ---------------------------------------------------------------------------

/// Configuration for the run-your-own-relay service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayServiceConfig {
    /// Relay WebSocket listen port (default 9450, matching dig-relay).
    pub port: u16,
    /// HTTP /health listen port (default 9451).
    pub health_port: u16,
    /// Start the service immediately after installing it.
    pub start: bool,
}

impl Default for RelayServiceConfig {
    fn default() -> Self {
        RelayServiceConfig {
            port: 9450,
            health_port: 9451,
            start: true,
        }
    }
}

/// Environment passed to `dig-relay install` so the registered service binds the configured
/// addresses (the relay's `install` snapshots its effective config into the service definition).
/// Sorted (`BTreeMap`) so the output is deterministic and testable.
pub fn relay_install_env(cfg: &RelayServiceConfig) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert(
        "DIG_RELAY_LISTEN".to_string(),
        format!("0.0.0.0:{}", cfg.port),
    );
    env.insert(
        "DIG_RELAY_HEALTH_LISTEN".to_string(),
        format!("0.0.0.0:{}", cfg.health_port),
    );
    env
}

/// Run `dig-relay install` (and, if `cfg.start`, `dig-relay start`) using the downloaded binary at
/// `bin`. Returns a human note. On Windows, installing a service needs an elevated console;
/// dig-relay detects this and returns a clear message, surfaced verbatim.
///
/// Mirrors [`install_service`]'s tolerance (task #232): `install` is not
/// idempotent (a re-install over an already-registered service can hard-fail
/// on Windows/macOS), but the registration points at the same on-disk path
/// this run just wrote, so a failed re-`install` does not block `start` from
/// picking up the new binary. Only a `start` failure is a hard error.
pub fn install_relay_service(bin: &Path, cfg: &RelayServiceConfig) -> Result<String, String> {
    let mut note = match run_relay(bin, &install_args(), &relay_install_env(cfg)) {
        Ok(()) => String::from("dig-relay installed as an OS service"),
        Err(e) => format!(
            "dig-relay install did not complete cleanly ({e}); continuing since a service may \
             already be registered at this path — the start attempt below is the real signal"
        ),
    };
    if cfg.start {
        run_relay(bin, &start_args(), &BTreeMap::new())
            .map_err(|e| format!("dig-relay start failed: {e}"))?;
        note.push_str(" and started");
    }
    Ok(note)
}

/// Parse a dig-relay `status --json` response for its NESTED
/// `result.serving` boolean (dig-relay's envelope shape differs from
/// dig-node's flat `serving` — see [`parse_dig_node_serving`]). Pure —
/// unit-tested without spawning anything.
fn parse_dig_relay_serving(status_stdout: &[u8]) -> Option<bool> {
    serde_json::from_slice::<serde_json::Value>(status_stdout)
        .ok()?
        .get("result")?
        .get("serving")?
        .as_bool()
}

/// Spawn `<bin> status --json` and read whether dig-relay is currently
/// serving. Never hard-fails: a spawn failure or unparseable output resolves
/// to "not serving".
fn dig_relay_is_serving(bin: &Path) -> bool {
    Command::new(bin)
        .args(status_json_args())
        .hide_console()
        .output()
        .ok()
        .and_then(|out| parse_dig_relay_serving(&out.stdout))
        .unwrap_or(false)
}

/// Stop a currently-serving dig-relay service before its binary is
/// overwritten (task #232) — the dig-relay counterpart to
/// [`stop_running_dig_node`]; same skip-when-absent / skip-when-not-serving /
/// abort-on-stop-failure contract.
pub fn stop_running_dig_relay(bin: &Path) -> Result<StopOutcome, String> {
    stop_running_dig_relay_with(bin, dig_relay_is_serving)
}

/// [`stop_running_dig_relay`] with an injectable "is currently serving" check
/// (mirrors [`stop_running_dig_node_with`]).
fn stop_running_dig_relay_with(
    bin: &Path,
    is_serving: impl Fn(&Path) -> bool,
) -> Result<StopOutcome, String> {
    if !bin.exists() {
        return Ok(StopOutcome {
            bin_existed: false,
            attempted: false,
            stopped: false,
            note: "no existing dig-relay binary — first install, nothing to stop".to_string(),
        });
    }
    if !is_serving(bin) {
        return Ok(StopOutcome {
            bin_existed: true,
            attempted: false,
            stopped: false,
            note: "existing dig-relay service is not currently serving — nothing to stop"
                .to_string(),
        });
    }
    run_relay(bin, &stop_args(), &BTreeMap::new())
        .map(|()| StopOutcome {
            bin_existed: true,
            attempted: true,
            stopped: true,
            note: "stopped the running dig-relay service before replacing its binary".to_string(),
        })
        .map_err(|e| {
            format!("could not stop the running dig-relay service before replacing its binary: {e}")
        })
}

/// Spawn the dig-relay binary with args + env, CAPTURING its stdio (never
/// inheriting — see [`run_dig_node`] for why). Errors if it can't be
/// launched or exits non-zero, folding the captured output into the error.
fn run_relay(bin: &Path, args: &[String], env: &BTreeMap<String, String>) -> Result<(), String> {
    run_capturing(bin, args, env)
}

/// Spawn the dig-node binary with args + env, CAPTURING its stdio rather
/// than inheriting it. Errors if the process can't be launched or exits
/// non-zero, folding the captured output (e.g. an elevation hint dig-node
/// itself printed) into the error message so it's still surfaced — via
/// dig-installer's OWN reporting, in EITHER pretty or `--json` mode.
///
/// Earlier this inherited stdio directly so a human running the pretty CLI
/// saw dig-node's own prose live. That silently broke the `--json` contract
/// (dig_ecosystem#502/#524 finding, via the 3-OS installer e2e job): a
/// child's stdout writes bypass this crate's `log`/`println!` plumbing
/// entirely, landing raw on the SAME stdout fd `--json` mode reserves for
/// exactly one structured line — corrupting it for any consumer (`jq`, an
/// agent) expecting well-formed JSON. Capturing instead is correct in BOTH
/// modes: a success no longer needs dig-node's own duplicate confirmation
/// (dig-installer already logs its own "✓ …" line for the same event), and a
/// failure keeps every diagnostic detail, just relayed through the error
/// string instead of a raw, un-capturable stdio pass-through.
fn run_dig_node(bin: &Path, args: &[String], env: &BTreeMap<String, String>) -> Result<(), String> {
    run_capturing(bin, args, env)
}

/// Spawn `bin args env`, capturing combined stdout+stderr. `Ok(())` on a
/// zero exit (the captured output is discarded — nothing useful is lost, see
/// [`run_dig_node`]); `Err` on a spawn failure or non-zero exit, with the
/// captured output (trimmed, or "(no output)") folded into the message.
///
/// `pub(crate)`: [`crate::beacon`] reuses this exact spawn-capture convention
/// to delegate to dig-updater's own `schedule install`/`schedule uninstall`
/// verbs (#514), rather than re-implementing the same stdio-capture care.
pub(crate) fn run_capturing(
    bin: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd
        .hide_console()
        .output()
        .map_err(|e| format!("could not run {}: {e}", bin.display()))?;
    if !output.status.success() {
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        let combined = combined.trim();
        let detail = if combined.is_empty() {
            "(no output)".to_string()
        } else {
            combined.to_string()
        };
        return Err(format!(
            "{} {} exited with {}: {detail}",
            bin.display(),
            args.join(" "),
            output.status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_service_config() {
        let c = ServiceConfig::default();
        // #132: the installer's default localhost port must match dig-node's
        // own uncommon-high-port default (9778), not the stale collision-prone
        // 8080.
        assert_eq!(c.port, 9778);
        assert!(c.start);
    }

    #[test]
    fn subcommands_are_dig_node_verbs() {
        assert_eq!(install_args(), vec!["install".to_string()]);
        assert_eq!(start_args(), vec!["start".to_string()]);
        assert_eq!(uninstall_args(), vec!["uninstall".to_string()]);
    }

    #[test]
    fn install_env_pins_the_port() {
        let env = install_env(&ServiceConfig {
            port: 9090,
            start: false,
        });
        assert_eq!(env.get("DIG_NODE_PORT").map(String::as_str), Some("9090"));
        // Only the port is pinned (host/upstream keep dig-node defaults).
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn install_env_default_port() {
        let env = install_env(&ServiceConfig::default());
        assert_eq!(env.get("DIG_NODE_PORT").map(String::as_str), Some("9778"));
    }

    #[test]
    fn default_relay_service_config() {
        let c = RelayServiceConfig::default();
        assert_eq!(c.port, 9450, "matches dig-relay DEFAULT_RELAY_PORT");
        assert_eq!(c.health_port, 9451);
        assert!(c.start);
    }

    #[test]
    fn relay_install_env_pins_listen_addrs() {
        let env = relay_install_env(&RelayServiceConfig {
            port: 9550,
            health_port: 9551,
            start: false,
        });
        assert_eq!(
            env.get("DIG_RELAY_LISTEN").map(String::as_str),
            Some("0.0.0.0:9550")
        );
        assert_eq!(
            env.get("DIG_RELAY_HEALTH_LISTEN").map(String::as_str),
            Some("0.0.0.0:9551")
        );
        // Exactly the two listen addrs are pinned.
        assert_eq!(env.len(), 2);
    }

    // -- Service spawn tests: exercise install_service / install_relay_service /
    //    run_dig_node / run_relay against a HARMLESS local stub binary (a tiny
    //    script that exits with a chosen code, ignoring its args/env). No network,
    //    no real service registration — just the spawn + status + note/error
    //    assembly logic these functions own. --------------------------------------

    /// A harmless stub binary that exits 0 (`success = true`) or non-zero
    /// (`success = false`), ignoring its args/env — used to drive the service
    /// spawn logic (`run_dig_node` / `run_relay`) without registering a real
    /// service. The exact exit code doesn't matter to the code under test: it
    /// branches only on `status.success()`, so a stub only needs to choose
    /// success vs failure.
    ///
    /// On unix we point at the pre-existing `/bin/true` / `/bin/false` (or the
    /// `/usr/bin` fallbacks) rather than writing + immediately exec'ing a fresh
    /// script. A just-written, just-`chmod`'d file can transiently fail exec with
    /// `ETXTBSY` ("Text file busy", `os error 26`) on Linux — the kernel refuses
    /// to exec a file that is (or was just) open for writing — which made these
    /// tests flaky in CI (the regression this guards). Using a pre-existing
    /// system binary has no such write/exec race. On Windows `Command` runs a
    /// `.cmd` via the shell (not `execve`), so there is no `ETXTBSY` and no
    /// `/bin/true`; we write a tiny batch file into `dir`.
    #[cfg(windows)]
    fn stub_exit(dir: &std::path::Path, success: bool) -> std::path::PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(if success { "ok.cmd" } else { "fail.cmd" });
        let code = if success { 0 } else { 1 };
        // @echo off so the batch text doesn't pollute output; exit /b sets the
        // process exit code.
        std::fs::write(&p, format!("@echo off\r\nexit /b {code}\r\n")).unwrap();
        p
    }

    /// See the Windows variant above. On unix we return a pre-existing system
    /// binary (`true`/`false`) to dodge the `ETXTBSY` write-then-exec race.
    #[cfg(not(windows))]
    fn stub_exit(_dir: &std::path::Path, success: bool) -> std::path::PathBuf {
        let base = if success { "true" } else { "false" };
        for cand in [format!("/bin/{base}"), format!("/usr/bin/{base}")] {
            let p = std::path::PathBuf::from(&cand);
            if p.exists() {
                return p;
            }
        }
        // Fallback to the conventional path; every CI runner / POSIX system
        // ships `/bin/true` and `/bin/false`.
        std::path::PathBuf::from(format!("/bin/{base}"))
    }

    fn tmp_subdir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("dig-installer-svc-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn install_service_installs_and_starts_on_success() {
        let dir = tmp_subdir("node-ok");
        let bin = stub_exit(&dir, true);
        let note = install_service(
            &bin,
            &ServiceConfig {
                port: 8080,
                start: true,
            },
        )
        .expect("stub exits 0 → ok");
        assert!(note.contains("installed as an OS service"));
        assert!(note.contains("and started"));
    }

    #[test]
    fn install_service_without_start_omits_started_note() {
        let dir = tmp_subdir("node-nostart");
        let bin = stub_exit(&dir, true);
        let note = install_service(
            &bin,
            &ServiceConfig {
                port: 8080,
                start: false,
            },
        )
        .expect("ok");
        assert!(note.contains("installed as an OS service"));
        assert!(!note.contains("started"));
    }

    #[test]
    fn install_service_surfaces_a_nonzero_start_exit_when_install_and_start_both_fail() {
        // task #232: install() failing no longer aborts before start() is
        // attempted (a re-install over an already-registered service hard-fails
        // on Windows/macOS even though the registration is fine) — so when
        // EVERYTHING fails, the surfaced error is now attributed to the START
        // attempt (the actual "is it running" signal), not the install step.
        let dir = tmp_subdir("node-fail");
        let bin = stub_exit(&dir, false);
        let err = install_service(
            &bin,
            &ServiceConfig {
                port: 8080,
                start: true,
            },
        )
        .unwrap_err();
        assert!(err.contains("dig-node start failed"), "got: {err}");
    }

    #[test]
    fn install_service_tolerates_an_install_failure_when_start_is_not_requested() {
        // task #232: an install failure alone (e.g. "already registered") is no
        // longer fatal — only a START failure is, and with start:false there is
        // no start attempt at all, so this must succeed with an explanatory note.
        let dir = tmp_subdir("node-install-fail-no-start");
        let bin = stub_exit(&dir, false);
        let note = install_service(
            &bin,
            &ServiceConfig {
                port: 8080,
                start: false,
            },
        )
        .expect("install failure alone must not be fatal when start isn't requested");
        assert!(note.contains("did not complete cleanly"), "got: {note}");
        assert!(!note.contains("and started"));
    }

    #[test]
    fn install_service_errors_when_binary_is_missing() {
        let missing = std::env::temp_dir().join("definitely-not-a-real-dig-node-binary-xyz");
        let err = install_service(&missing, &ServiceConfig::default()).unwrap_err();
        // start:true (the default) is still attempted (and still fails) against
        // the same missing binary, so the surfaced error is the start failure.
        assert!(err.contains("dig-node start failed"), "got: {err}");
        assert!(err.contains("could not run"), "got: {err}");
    }

    #[test]
    fn uninstall_service_succeeds_when_dig_node_exits_zero() {
        let dir = tmp_subdir("node-uninstall-ok");
        let bin = stub_exit(&dir, true);
        let note = uninstall_service(&bin).expect("stub exits 0 → ok");
        assert!(note.contains("uninstalled"), "got: {note}");
    }

    #[test]
    fn uninstall_service_surfaces_a_nonzero_exit() {
        let dir = tmp_subdir("node-uninstall-fail");
        let bin = stub_exit(&dir, false);
        let err = uninstall_service(&bin).unwrap_err();
        assert!(err.contains("dig-node uninstall failed"), "got: {err}");
    }

    #[test]
    fn uninstall_service_errors_when_binary_is_missing() {
        let missing = std::env::temp_dir().join("definitely-not-a-real-dig-node-binary-abc");
        let err = uninstall_service(&missing).unwrap_err();
        assert!(err.contains("dig-node uninstall failed"), "got: {err}");
        assert!(err.contains("could not run"), "got: {err}");
    }

    #[test]
    fn install_relay_service_installs_and_starts_on_success() {
        let dir = tmp_subdir("relay-ok");
        let bin = stub_exit(&dir, true);
        let note = install_relay_service(
            &bin,
            &RelayServiceConfig {
                port: 9450,
                health_port: 9451,
                start: true,
            },
        )
        .expect("ok");
        assert!(note.contains("dig-relay installed as an OS service"));
        assert!(note.contains("and started"));
    }

    #[test]
    fn install_relay_service_surfaces_a_nonzero_start_exit_when_install_and_start_both_fail() {
        // Mirrors install_service's task #232 tolerance: install() failing alone
        // is no longer fatal, so when everything fails the surfaced error is
        // attributed to the start attempt.
        let dir = tmp_subdir("relay-fail");
        let bin = stub_exit(&dir, false);
        let err = install_relay_service(&bin, &RelayServiceConfig::default()).unwrap_err();
        assert!(err.contains("dig-relay start failed"), "got: {err}");
    }

    #[test]
    fn install_relay_service_tolerates_an_install_failure_when_start_is_not_requested() {
        let dir = tmp_subdir("relay-install-fail-no-start");
        let bin = stub_exit(&dir, false);
        let note = install_relay_service(
            &bin,
            &RelayServiceConfig {
                port: 9450,
                health_port: 9451,
                start: false,
            },
        )
        .expect("install failure alone must not be fatal when start isn't requested");
        assert!(note.contains("did not complete cleanly"), "got: {note}");
        assert!(!note.contains("and started"));
    }

    // -- task #232: stop-before-write --------------------------------------

    #[test]
    fn stop_args_is_the_stop_verb() {
        assert_eq!(stop_args(), vec!["stop".to_string()]);
    }

    /// #301 boot-start guarantee (dig-node). The installer registers dig-node by
    /// delegating to its own `install` verb, which registers a boot-start
    /// (auto-start-on-boot) service. This locks that we invoke plain `install`
    /// (the boot-start path) and `start` — never a manual-start variant — so a
    /// regression to manual registration fails here.
    #[test]
    fn dig_node_is_registered_boot_start_via_the_install_verb() {
        assert_eq!(
            install_args(),
            vec!["install".to_string()],
            "dig-node must be registered via its boot-start `install` verb (#301)"
        );
        assert_eq!(start_args(), vec!["start".to_string()]);
        // No manual/no-boot token is ever forwarded to the install verb.
        assert!(!install_args()
            .iter()
            .any(|a| a.contains("manual") || a.contains("no-boot") || a.contains("no-autostart")));
    }

    #[test]
    fn parse_dig_node_serving_reads_the_flat_field() {
        assert_eq!(
            parse_dig_node_serving(br#"{"ok":true,"serving":true,"addr":"127.0.0.1:9778"}"#),
            Some(true)
        );
        assert_eq!(
            parse_dig_node_serving(br#"{"ok":true,"serving":false}"#),
            Some(false)
        );
    }

    #[test]
    fn parse_dig_node_serving_is_none_on_malformed_or_missing_field() {
        assert_eq!(parse_dig_node_serving(b"not json"), None);
        assert_eq!(parse_dig_node_serving(b""), None);
        assert_eq!(parse_dig_node_serving(br#"{"ok":true}"#), None);
    }

    #[test]
    fn parse_dig_relay_serving_reads_the_nested_field() {
        assert_eq!(
            parse_dig_relay_serving(br#"{"ok":true,"result":{"serving":true,"health_url":"x"}}"#),
            Some(true)
        );
        assert_eq!(
            parse_dig_relay_serving(br#"{"ok":true,"result":{"serving":false}}"#),
            Some(false)
        );
    }

    #[test]
    fn parse_dig_relay_serving_is_none_on_malformed_or_missing_field() {
        assert_eq!(parse_dig_relay_serving(b"not json"), None);
        assert_eq!(parse_dig_relay_serving(br#"{"ok":true}"#), None);
        // Flat "serving" (dig-node's shape) at the top level does NOT satisfy
        // dig-relay's nested contract — proves the two parsers aren't
        // accidentally interchangeable.
        assert_eq!(parse_dig_relay_serving(br#"{"serving":true}"#), None);
    }

    #[test]
    fn stop_running_dig_node_skips_when_binary_is_absent() {
        // First install: no prior binary at this path, so there is nothing to
        // stop — must succeed (not an error) with attempted:false.
        let missing = std::env::temp_dir().join(format!(
            "dig-installer-stop-node-absent-{}",
            std::process::id()
        ));
        let outcome = stop_running_dig_node_with(&missing, |_| true).expect("skip is not an error");
        assert!(!outcome.bin_existed);
        assert!(!outcome.attempted);
        assert!(!outcome.stopped);
    }

    #[test]
    fn stop_running_dig_node_skips_when_not_serving() {
        let dir = tmp_subdir("stop-node-not-serving");
        let bin = stub_exit(&dir, true); // exists on disk; injected as not-serving
        let outcome =
            stop_running_dig_node_with(&bin, |_| false).expect("not serving is not an error");
        assert!(outcome.bin_existed);
        assert!(!outcome.attempted);
        assert!(!outcome.stopped);
    }

    #[test]
    fn stop_running_dig_node_stops_when_serving_and_stop_succeeds() {
        let dir = tmp_subdir("stop-node-serving-ok");
        let bin = stub_exit(&dir, true); // `stop` (any arg) exits 0 on this stub
        let outcome = stop_running_dig_node_with(&bin, |_| true).expect("stop succeeds");
        assert!(outcome.bin_existed);
        assert!(outcome.attempted);
        assert!(outcome.stopped);
    }

    #[test]
    fn stop_running_dig_node_aborts_when_serving_and_stop_fails() {
        let dir = tmp_subdir("stop-node-serving-fail");
        let bin = stub_exit(&dir, false); // `stop` exits non-zero on this stub
        let err = stop_running_dig_node_with(&bin, |_| true).unwrap_err();
        assert!(err.contains("could not stop"), "got: {err}");
    }

    #[test]
    fn stop_running_dig_relay_skips_when_binary_is_absent() {
        let missing = std::env::temp_dir().join(format!(
            "dig-installer-stop-relay-absent-{}",
            std::process::id()
        ));
        let outcome =
            stop_running_dig_relay_with(&missing, |_| true).expect("skip is not an error");
        assert!(!outcome.bin_existed);
        assert!(!outcome.attempted);
    }

    #[test]
    fn stop_running_dig_relay_skips_when_not_serving() {
        let dir = tmp_subdir("stop-relay-not-serving");
        let bin = stub_exit(&dir, true);
        let outcome =
            stop_running_dig_relay_with(&bin, |_| false).expect("not serving is not an error");
        assert!(outcome.bin_existed);
        assert!(!outcome.attempted);
    }

    #[test]
    fn stop_running_dig_relay_stops_when_serving_and_stop_succeeds() {
        let dir = tmp_subdir("stop-relay-serving-ok");
        let bin = stub_exit(&dir, true);
        let outcome = stop_running_dig_relay_with(&bin, |_| true).expect("stop succeeds");
        assert!(outcome.bin_existed);
        assert!(outcome.attempted);
        assert!(outcome.stopped);
    }

    #[test]
    fn stop_running_dig_relay_aborts_when_serving_and_stop_fails() {
        let dir = tmp_subdir("stop-relay-serving-fail");
        let bin = stub_exit(&dir, false);
        let err = stop_running_dig_relay_with(&bin, |_| true).unwrap_err();
        assert!(err.contains("could not stop"), "got: {err}");
    }

    // -- run_capturing: stdio is CAPTURED, never inherited (dig_ecosystem#502/#524) --
    //
    // Regression: run_dig_node/run_relay used to `.status()` the child, INHERITING
    // its stdio — a child's own prose then landed raw on THIS process's stdout,
    // corrupting `--json` mode's "exactly one JSON line on stdout" contract the
    // moment a real (non-dry-run) install/uninstall/start actually ran the binary
    // (found via the 3-OS installer e2e job, #502). Drives a pre-existing shell
    // interpreter with an inline `-c`/`/C` command (never a freshly-written script
    // file — dodges the `ETXTBSY` write-then-exec race `stub_exit`'s own doc
    // comment already flags) so these are exec-race-free on every CI runner.

    #[cfg(unix)]
    fn shell_stub(inline: &str) -> (std::path::PathBuf, Vec<String>) {
        (
            std::path::PathBuf::from("/bin/sh"),
            vec!["-c".to_string(), inline.to_string()],
        )
    }
    #[cfg(windows)]
    fn shell_stub(inline: &str) -> (std::path::PathBuf, Vec<String>) {
        (
            std::path::PathBuf::from("cmd"),
            vec!["/C".to_string(), inline.to_string()],
        )
    }

    #[test]
    fn run_capturing_folds_the_childs_own_output_into_the_error_on_failure() {
        let (bin, args) = shell_stub(if cfg!(windows) {
            "echo DIG_NODE_MARKER & exit /b 3"
        } else {
            "echo DIG_NODE_MARKER; exit 3"
        });
        let err = run_capturing(&bin, &args, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("DIG_NODE_MARKER"), "got: {err}");
        assert!(err.contains("exited with 3"), "got: {err}");
    }

    #[test]
    fn run_capturing_succeeds_on_a_zero_exit_regardless_of_what_the_child_printed() {
        let (bin, args) = shell_stub(if cfg!(windows) {
            "echo NOISE_ON_SUCCESS & exit /b 0"
        } else {
            "echo NOISE_ON_SUCCESS; exit 0"
        });
        // `Command::output()` (used by run_capturing) always captures — never
        // inherits — so nothing the child prints ever reaches OUR stdout; a
        // zero exit is Ok regardless of what it printed.
        run_capturing(&bin, &args, &BTreeMap::new()).expect("zero exit is Ok");
    }
}
