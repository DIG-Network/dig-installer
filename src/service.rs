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

use crate::svc;
use crate::svcscope::{self, ServiceScope};
use crate::target::Os;

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
/// `scope` names the service-manager domain to register in
/// ([`crate::svcscope::engine_scope`] chooses it); `None` omits the flag
/// entirely, which is ONLY for the compat retry against a build that predates
/// `--scope` ([`crate::svcscope::is_unknown_scope_flag_rejection`]).
pub fn install_args(scope: Option<ServiceScope>) -> Vec<String> {
    verb_args("install", scope)
}

/// The subcommand to start the installed service, in `scope`.
pub fn start_args(scope: Option<ServiceScope>) -> Vec<String> {
    verb_args("start", scope)
}

/// The subcommand to remove the installed service (task #140), from `scope`.
/// dig-node's own `uninstall` best-effort stops the service first, so this
/// installer only needs to invoke the one subcommand per scope.
pub fn uninstall_args(scope: Option<ServiceScope>) -> Vec<String> {
    verb_args("uninstall", scope)
}

/// `<verb> [--scope <scope>]` — the one place the scope flag is appended, so no
/// verb can drift out of the cross-repo argument contract.
fn verb_args(verb: &str, scope: Option<ServiceScope>) -> Vec<String> {
    let mut args = vec![verb.to_string()];
    if let Some(scope) = scope {
        args.extend(svcscope::scope_args(scope));
    }
    args
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

/// What a scoped engine registration actually achieved — the record every
/// surface (`--json`, the CLI verdict, readiness) reads instead of guessing from
/// a note string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServiceInstallOutcome {
    /// Human-readable detail — never silent.
    pub note: String,
    /// The scope this run ASKED for.
    pub requested_scope: ServiceScope,
    /// Did the component accept `--scope`? `false` means an older build chose
    /// its own (per-user-preferring) domain, so the requested scope was NOT
    /// honoured — which is why this is reported rather than inferred.
    pub scope_flag_accepted: bool,
    /// Will the registration start after a reboot with NOBODY logged in? The
    /// property dig_ecosystem#526 is about, and the one a "service installed"
    /// note has never been able to promise on its own.
    pub reboot_survival: bool,
    /// Was the service started as part of this call?
    pub started: bool,
}

/// Run `dig-node install` (and, if `cfg.start`, `dig-node start`) at `scope`,
/// using the downloaded binary at `bin`.
///
/// On Windows, installing a service needs an elevated console; dig-node detects
/// this and returns a clear message, which we surface verbatim.
///
/// # Why an `install` failure is no longer freely tolerated (dig_ecosystem#526)
///
/// `install` is NOT idempotent (task #232): re-running it over an
/// already-registered service hard-fails on Windows SCM / macOS launchd
/// ("already exists"-style errors) even though the registration is still
/// perfectly usable — so a failure used to be swallowed, with only a `start`
/// failure treated as fatal. That is precisely how a user-level-under-root
/// registration failure reached "✓ DIG is ready": nothing ever asked whether a
/// registration existed WHERE this run needed one, and a leftover user-scope
/// unit could even answer `start` successfully.
///
/// The contract now: an `install` failure is tolerated ONLY when a registration
/// already exists at the REQUESTED scope, which `probe` answers scope-explicitly
/// ([`svc::service_run_state_in_scope`]). Nothing there → `Err`, and readiness
/// fails.
pub fn install_service(
    bin: &Path,
    cfg: &ServiceConfig,
    os: Os,
    scope: ServiceScope,
) -> Result<ServiceInstallOutcome, String> {
    install_engine_service(
        "dig-node",
        cfg.start,
        os,
        scope,
        &install_env(cfg),
        &mut |args, env| run_dig_node(bin, args, env),
        &mut |scope| svc::service_run_state_in_scope(svc::DIG_NODE_SERVICE_ID, scope),
    )
}

/// A component invocation, with the binary already bound — the seam that lets
/// the scope/compat/tolerance branching be driven by a mock runner instead of a
/// real service manager.
type Runner<'a> = dyn FnMut(&[String], &BTreeMap<String, String>) -> Result<(), String> + 'a;

/// A scope-explicit "is anything registered here?" probe.
type ScopeProbe<'a> = dyn FnMut(ServiceScope) -> svc::ServiceRunState + 'a;

/// The shared scoped registration for the engine components (dig-node,
/// dig-relay) — one implementation of the scope contract, the compat fallback
/// and the install-failure tolerance rule, so the two cannot drift apart.
fn install_engine_service(
    label: &str,
    start: bool,
    os: Os,
    scope: ServiceScope,
    env: &BTreeMap<String, String>,
    run: &mut Runner<'_>,
    probe: &mut ScopeProbe<'_>,
) -> Result<ServiceInstallOutcome, String> {
    let mut scope_flag_accepted = true;
    let mut note = match run_with_scope_compat(install_args, scope, env, run) {
        Ok(accepted) => {
            scope_flag_accepted = accepted;
            format!("{label} installed as an OS service in {}", scope.describe())
        }
        Err(e) => tolerate_install_failure_only_if_already_registered(label, scope, &e, probe)?,
    };

    let mut started = false;
    if start {
        run_with_scope_compat(start_args, scope, &BTreeMap::new(), run)
            .map_err(|e| format!("{label} start failed: {e}"))?;
        note.push_str(" and started");
        started = true;
    }

    let reboot_survival = scope_flag_accepted && svcscope::survives_reboot_without_login(os, scope);
    if !scope_flag_accepted {
        note.push_str(&format!(
            " — but this {label} build does not understand `--scope`, so it registered wherever it \
             defaults to (a per-user registration, which only starts once someone LOGS IN). The \
             service will NOT come back on its own after a reboot until {label} is updated"
        ));
    }
    Ok(ServiceInstallOutcome {
        note,
        requested_scope: scope,
        scope_flag_accepted,
        reboot_survival,
        started,
    })
}

/// Invoke `args_for(Some(scope))`, retrying WITHOUT the flag iff the component
/// rejected `--scope` as an unknown argument.
///
/// The retry is safe precisely because clap rejects an unknown flag with a
/// non-zero exit BEFORE running any subcommand body — so the first attempt had
/// no side effect to undo. Returns whether the scope flag was ACCEPTED, which is
/// the caller's only honest basis for claiming reboot survival. Any other
/// failure propagates: silently retrying unflagged would downgrade a system-scope
/// install to a login-gated one and still report success.
fn run_with_scope_compat(
    args_for: fn(Option<ServiceScope>) -> Vec<String>,
    scope: ServiceScope,
    env: &BTreeMap<String, String>,
    run: &mut Runner<'_>,
) -> Result<bool, String> {
    match run(&args_for(Some(scope)), env) {
        Ok(()) => Ok(true),
        Err(e) if svcscope::is_unknown_scope_flag_rejection(&e) => {
            run(&args_for(None), env).map(|()| false)
        }
        Err(e) => Err(e),
    }
}

/// Decide whether a failed `install` may be tolerated, per the dig_ecosystem#526
/// contract: ONLY when a registration already exists at the REQUESTED scope.
///
/// Returns the note to carry on with, or the error that must fail the step. An
/// `Unknown` probe result is NOT tolerance: "could not ask" is not "it is
/// there", and treating it as such is the false-ready this replaces.
fn tolerate_install_failure_only_if_already_registered(
    label: &str,
    scope: ServiceScope,
    error: &str,
    probe: &mut ScopeProbe<'_>,
) -> Result<String, String> {
    let existing = probe(scope);
    match existing {
        svc::ServiceRunState::Running | svc::ServiceRunState::Stopped => Ok(format!(
            "{label} install did not complete cleanly ({error}); tolerated because a registration \
             already exists in {} ({})",
            scope.describe(),
            existing.describe(label)
        )),
        svc::ServiceRunState::NotFound | svc::ServiceRunState::Unknown => Err(format!(
            "{label} could not be registered in {} ({error}), and no existing registration was \
             found there ({}). {label} will NOT start on this machine",
            scope.describe(),
            existing.describe(label)
        )),
    }
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

/// Stop a currently-running dig-node service before its binary is overwritten
/// (task #232). Stops it via the OS service manager by canonical id
/// ([`crate::svc::stop_service`], `net.dignetwork.dig-node`) — it MUST NEVER
/// execute the on-disk binary to stop it (#565: the installer runs elevated, and
/// the pre-#565 `<bin> stop`/`<bin> status` path would elevate-spawn a binary a
/// non-admin could have replaced in the legacy user-writable dir → user→SYSTEM
/// escalation). Skip-when-absent (no error) when `bin` doesn't exist yet (first
/// install) or the service isn't running. If it IS running and the stop fails,
/// returns `Err` so the caller ABORTS the write rather than overwrite a binary
/// underneath a still-running service.
pub fn stop_running_dig_node(bin: &Path) -> Result<StopOutcome, String> {
    stop_running_service_by_id_with(
        bin,
        "dig-node",
        || svc::service_run_state(svc::DIG_NODE_SERVICE_ID),
        || svc::stop_service(svc::DIG_NODE_SERVICE_ID),
    )
}

/// The shared stop-before-write for the self-registering services
/// (dig-node/dig-relay), with the "current state" probe and the "stop it" action
/// injected — production passes the real [`crate::svc::service_run_state`] +
/// [`crate::svc::stop_service`] (both BY canonical id, never executing `bin`);
/// tests inject fixed answers so the skip-vs-attempt-vs-abort branching is
/// exercised without a real service manager (and without depending on whatever
/// DIG services the test host happens to have). Mirrors
/// [`crate::dns::stop_before_replace_with`].
///
/// The #565 guarantee lives in what this does NOT do: it never runs `bin`, so
/// an elevated installer can never be tricked into executing a binary a
/// non-admin replaced in the legacy user-writable dir.
fn stop_running_service_by_id_with(
    bin: &Path,
    label: &str,
    state: impl Fn() -> svc::ServiceRunState,
    stop: impl Fn() -> Result<(), String>,
) -> Result<StopOutcome, String> {
    if !bin.exists() {
        return Ok(StopOutcome {
            bin_existed: false,
            attempted: false,
            stopped: false,
            note: format!("no existing {label} binary — first install, nothing to stop"),
        });
    }
    if state() != svc::ServiceRunState::Running {
        return Ok(StopOutcome {
            bin_existed: true,
            attempted: false,
            stopped: false,
            note: format!("existing {label} service is not currently running — nothing to stop"),
        });
    }
    stop()
        .map(|()| StopOutcome {
            bin_existed: true,
            attempted: true,
            stopped: true,
            note: format!(
                "stopped the running {label} service (by id, via the service manager) before \
                 replacing its binary"
            ),
        })
        .map_err(|e| {
            format!("could not stop the running {label} service before replacing its binary: {e}")
        })
}

/// Run `dig-node uninstall` (task #140) using the previously-installed binary
/// at `bin`, removing the OS service registration. dig-node's own `uninstall`
/// best-effort stops the service first (see its README/service.rs), so this is
/// a single subcommand invocation — the counterpart to [`install_service`].
/// Returns a human note on success; the caller pairs this with removing the
/// `dig.local` hosts entry ([`crate::hosts::remove_dig_local`]).
pub fn uninstall_service(bin: &Path, os: Os) -> Result<String, String> {
    uninstall_engine_service(
        "dig-node",
        os,
        &mut |args, env| run_dig_node(bin, args, env),
        &mut |scope| svc::service_run_state_in_scope(svc::DIG_NODE_SERVICE_ID, scope),
    )
}

/// Deregister an engine service from EVERY scope, on every OS
/// (dig_ecosystem#526).
///
/// Visiting only the scope THIS run would have installed into leaves behind any
/// registration an earlier run made in the other one — an unelevated install, a
/// pre-`--scope` build that only knew user scope, a `--bin-dir` run — which then
/// keeps starting a node the user believes they removed.
///
/// The authoritative signal is the scope-explicit END STATE, never the verbs'
/// exit codes: `uninstall` of an absent registration exits non-zero on some
/// platforms, and that is not a failure. A scope still holding a registration
/// afterwards IS a failure, and is named — never a silent success.
fn uninstall_engine_service(
    label: &str,
    os: Os,
    run: &mut Runner<'_>,
    probe: &mut ScopeProbe<'_>,
) -> Result<String, String> {
    let mut attempt_errors = Vec::new();
    for scope in svcscope::deregister_scopes(os) {
        if let Err(e) = run_with_scope_compat(uninstall_args, scope, &BTreeMap::new(), run) {
            attempt_errors.push(format!("{}: {e}", scope.describe()));
        }
    }

    let residual: Vec<String> = svcscope::deregister_scopes(os)
        .into_iter()
        .filter_map(|scope| match probe(scope) {
            svc::ServiceRunState::Running | svc::ServiceRunState::Stopped => {
                Some(scope.describe().to_string())
            }
            _ => None,
        })
        .collect();
    if !residual.is_empty() {
        return Err(format!(
            "{label} is still registered in {} after the uninstall{}",
            residual.join(" and "),
            format_attempt_errors(&attempt_errors)
        ));
    }
    Ok(format!(
        "{label} service uninstalled from every scope{}",
        format_attempt_errors(&attempt_errors)
    ))
}

/// Fold the per-scope command errors into a parenthetical, or nothing when there
/// were none — reported even on success, because a scope that could not be
/// REACHED is a fact the operator needs even when the end state is clean.
fn format_attempt_errors(errors: &[String]) -> String {
    if errors.is_empty() {
        return String::new();
    }
    format!(" (per-scope command errors — {})", errors.join("; "))
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
pub fn install_relay_service(
    bin: &Path,
    cfg: &RelayServiceConfig,
    os: Os,
    scope: ServiceScope,
) -> Result<ServiceInstallOutcome, String> {
    install_engine_service(
        "dig-relay",
        cfg.start,
        os,
        scope,
        &relay_install_env(cfg),
        &mut |args, env| run_relay(bin, args, env),
        &mut |scope| svc::service_run_state_in_scope(svc::DIG_RELAY_SERVICE_ID, scope),
    )
}

/// Stop a currently-running dig-relay service before its binary is overwritten
/// (task #232) — the dig-relay counterpart to [`stop_running_dig_node`], same
/// contract and the same #565 rule: stop it via the OS service manager by
/// canonical id ([`crate::svc::DIG_RELAY_SERVICE_ID`]), NEVER by executing the
/// on-disk relay binary.
pub fn stop_running_dig_relay(bin: &Path) -> Result<StopOutcome, String> {
    stop_running_service_by_id_with(
        bin,
        "dig-relay",
        || svc::service_run_state(svc::DIG_RELAY_SERVICE_ID),
        || svc::stop_service(svc::DIG_RELAY_SERVICE_ID),
    )
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
    // The single choke point for every privileged delegation this crate performs — dig-node's and
    // dig-relay's own `install`/`start` verbs and dig-updater's `schedule` verbs (`crate::beacon`) — so
    // the no-root-exec-of-a-user-writable-binary invariant is enforced once, here, for all of them
    // rather than per call site. Unlike the version probe this cannot degrade: a service that must be
    // registered by running a binary we do not trust has no safe fallback, so it fails LOUDLY (#1748 F1).
    let mut guarded = crate::guardedcmd::GuardedCommand::for_installed_binary(bin)?;
    guarded.args(args);
    for (k, v) in env {
        guarded.command_mut().env(k, v);
    }
    let output = guarded
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
    fn subcommands_are_dig_node_verbs_with_an_explicit_scope() {
        // `None` is the compat retry ONLY (a build that predates `--scope`); every production
        // invocation names its scope, because "whatever the component defaults to" is what
        // dig_ecosystem#526 is about.
        assert_eq!(install_args(None), vec!["install".to_string()]);
        assert_eq!(start_args(None), vec!["start".to_string()]);
        assert_eq!(uninstall_args(None), vec!["uninstall".to_string()]);
        assert_eq!(
            install_args(Some(ServiceScope::System)),
            vec!["install", "--scope", "system"]
        );
        assert_eq!(
            start_args(Some(ServiceScope::User)),
            vec!["start", "--scope", "user"]
        );
        assert_eq!(
            uninstall_args(Some(ServiceScope::System)),
            vec!["uninstall", "--scope", "system"]
        );
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

    // -- Scoped registration: driven by a MOCK RUNNER, never a real service manager -----------
    //
    // Every property below — the scope argument surface, the `--scope` compat fallback, the
    // install-failure tolerance rule, and the both-scopes uninstall — is decided by
    // `install_engine_service`/`uninstall_engine_service` from their PARAMETERS. So these tests
    // pass an OS as data and record the argv the runner is handed: no spawn, no elevation, no
    // dependence on which OS the runner happens to be (dig_ecosystem#1774/#1865), and no
    // `#[cfg(unix)]` gate that would leave an arm unfalsifiable on this repo's Windows dev boxes.

    /// A recording component stub: answers each invocation from `answers` (keyed by the verb the
    /// argv starts with) and remembers every argv it was handed.
    /// How a mock answers ONE invocation, decided from its argv.
    type MockAnswer = dyn Fn(&[String]) -> Result<(), String>;

    struct MockComponent {
        /// argv → result: the component's canned behaviour for this test.
        answer: Box<MockAnswer>,
        calls: Vec<Vec<String>>,
    }

    impl MockComponent {
        fn new(answer: impl Fn(&[String]) -> Result<(), String> + 'static) -> Self {
            MockComponent {
                answer: Box::new(answer),
                calls: Vec::new(),
            }
        }

        /// Always succeeds — the "modern binary, everything works" baseline.
        fn ok() -> Self {
            Self::new(|_| Ok(()))
        }

        fn run(&mut self, args: &[String], _env: &BTreeMap<String, String>) -> Result<(), String> {
            self.calls.push(args.to_vec());
            (self.answer)(args)
        }

        /// The argv of every call whose first token is `verb`.
        fn calls_to(&self, verb: &str) -> Vec<&Vec<String>> {
            self.calls
                .iter()
                .filter(|c| c.first().map(String::as_str) == Some(verb))
                .collect()
        }
    }

    /// Real clap-4 wording for an unknown flag — what a `dig-node` build that predates `--scope`
    /// actually prints, with a non-zero exit and BEFORE any registration side effect.
    const PRE_SCOPE_REJECTION: &str = "error: unexpected argument '--scope' found\n\nUsage: dig-node install\n\nFor more information, try '--help'.";

    #[test]
    fn a_scoped_install_passes_the_scope_flag_to_install_and_start() {
        let mut node = MockComponent::ok();
        let outcome = install_engine_service(
            "dig-node",
            true,
            Os::Linux,
            ServiceScope::System,
            &BTreeMap::new(),
            &mut |a, e| node.run(a, e),
            &mut |_| panic!("the probe is only consulted when `install` FAILS"),
        )
        .expect("a clean install is Ok");

        assert_eq!(
            node.calls_to("install"),
            vec![&vec![
                "install".to_string(),
                "--scope".to_string(),
                "system".to_string()
            ]]
        );
        assert_eq!(
            node.calls_to("start"),
            vec![&vec![
                "start".to_string(),
                "--scope".to_string(),
                "system".to_string()
            ]]
        );
        assert!(outcome.scope_flag_accepted);
        assert!(outcome.started);
        assert!(
            outcome.reboot_survival,
            "a system-scope registration survives a reboot with nobody logged in"
        );
    }

    #[test]
    fn a_user_scope_install_reports_that_it_will_not_survive_a_reboot() {
        // The `--bin-dir`/unelevated path: the flag WAS accepted, the registration is real, and it
        // still only starts at login. Reported, never silent.
        let mut node = MockComponent::ok();
        let outcome = install_engine_service(
            "dig-node",
            false,
            Os::Linux,
            ServiceScope::User,
            &BTreeMap::new(),
            &mut |a, e| node.run(a, e),
            &mut |_| panic!("install succeeded; the probe must not be consulted"),
        )
        .unwrap();
        assert!(outcome.scope_flag_accepted);
        assert!(!outcome.reboot_survival);
        assert!(!outcome.started, "start was not requested");
        assert!(node.calls_to("start").is_empty());
    }

    #[test]
    fn a_binary_that_predates_the_scope_flag_is_retried_without_it_and_loses_reboot_survival() {
        // dig-installer downloads the LATEST dig-node with no version pin, so an older binary is a
        // real state. clap rejects the unknown flag with a non-zero exit BEFORE any side effect, so
        // the unflagged retry is safe — but the requested scope was NOT honoured, and claiming
        // reboot survival anyway is exactly the #526 false-ready.
        let mut node = MockComponent::new(|args| {
            if args.iter().any(|a| a == "--scope") {
                Err(PRE_SCOPE_REJECTION.to_string())
            } else {
                Ok(())
            }
        });
        let outcome = install_engine_service(
            "dig-node",
            true,
            Os::Linux,
            ServiceScope::System,
            &BTreeMap::new(),
            &mut |a, e| node.run(a, e),
            &mut |_| {
                panic!("the flagged attempt is a compat rejection, not a registration failure")
            },
        )
        .expect("the unflagged retry succeeds, so the install is Ok");

        assert_eq!(
            node.calls_to("install"),
            vec![
                &vec![
                    "install".to_string(),
                    "--scope".to_string(),
                    "system".to_string()
                ],
                &vec!["install".to_string()],
            ],
            "the flagged attempt must come FIRST, and the retry must drop ONLY the flag"
        );
        assert!(!outcome.scope_flag_accepted);
        assert!(
            !outcome.reboot_survival,
            "an older binary chose its own (per-user) scope, so nothing may promise reboot survival"
        );
        assert_eq!(outcome.requested_scope, ServiceScope::System);
        assert!(
            outcome.note.contains("does not understand `--scope`")
                && outcome.note.contains("reboot"),
            "the note must explain the downgrade in plain language, got: {}",
            outcome.note
        );
    }

    #[test]
    fn a_genuine_install_failure_is_never_retried_unflagged() {
        // The nearest wrong implementation retries on ANY failure, which would silently downgrade a
        // system-scope install to a login-gated one. This failure MENTIONS --scope and still is not
        // a compat case: the flag was understood and the operation failed.
        let mut node = MockComponent::new(|_| {
            Err("error: --scope system requires root; run with sudo".to_string())
        });
        let err = install_engine_service(
            "dig-node",
            true,
            Os::Linux,
            ServiceScope::System,
            &BTreeMap::new(),
            &mut |a, e| node.run(a, e),
            &mut |_| svc::ServiceRunState::NotFound,
        )
        .unwrap_err();

        assert_eq!(
            node.calls_to("install").len(),
            1,
            "exactly one install attempt — no unflagged retry"
        );
        assert!(err.contains("requires root"), "got: {err}");
    }

    #[test]
    fn an_install_failure_with_nothing_registered_at_the_requested_scope_is_fatal() {
        // dig_ecosystem#526, the contract this replaces: the OLD code swallowed an `install` error
        // and hard-failed only on `start`, which is exactly how a user-level-under-root
        // registration failure reached "✓ DIG is ready".
        //
        // The probe is asked for the REQUESTED scope and reports a registration in the OTHER one —
        // the shape a pre-#526 host is genuinely in. A scope-BLIND probe would see that leftover
        // user unit and tolerate the failure, so this fixture distinguishes the fix from the bug.
        let mut node = MockComponent::new(|args| {
            if args.first().map(String::as_str) == Some("install") {
                Err("Failed to connect to bus: No such file or directory".to_string())
            } else {
                Ok(())
            }
        });
        let mut probed = Vec::new();
        let err = install_engine_service(
            "dig-node",
            true,
            Os::Linux,
            ServiceScope::System,
            &BTreeMap::new(),
            &mut |a, e| node.run(a, e),
            &mut |scope| {
                probed.push(scope);
                match scope {
                    ServiceScope::System => svc::ServiceRunState::NotFound,
                    ServiceScope::User => svc::ServiceRunState::Running,
                }
            },
        )
        .unwrap_err();

        assert_eq!(
            probed,
            vec![ServiceScope::System],
            "tolerance must be judged at the REQUESTED scope only"
        );
        assert!(err.contains("will NOT start on this machine"), "got: {err}");
        assert!(
            node.calls_to("start").is_empty(),
            "a failed registration must not be followed by a start that could succeed against a \
             leftover user-scope unit and paper over the failure"
        );
    }

    #[test]
    fn an_install_failure_is_tolerated_when_the_requested_scope_already_has_a_registration() {
        // The task #232 case that must SURVIVE the #526 tightening: `install` is not idempotent, so
        // re-running it over a live system registration hard-fails on Windows SCM / macOS launchd
        // even though the registration is perfectly usable.
        let mut node = MockComponent::new(|args| {
            if args.first().map(String::as_str) == Some("install") {
                Err("The specified service already exists".to_string())
            } else {
                Ok(())
            }
        });
        let outcome = install_engine_service(
            "dig-node",
            true,
            Os::Windows,
            ServiceScope::System,
            &BTreeMap::new(),
            &mut |a, e| node.run(a, e),
            &mut |_| svc::ServiceRunState::Running,
        )
        .expect("an existing registration at the requested scope tolerates the failure");
        assert!(outcome
            .note
            .contains("tolerated because a registration already exists"));
        assert!(outcome.reboot_survival);
        assert!(outcome.started);
    }

    #[test]
    fn an_unqueryable_scope_is_not_treated_as_an_existing_registration() {
        // "Could not ask" is not "it is there". Tolerating Unknown is the same false-ready with an
        // extra step, and it is the arm a mock that can only say Running/NotFound cannot express.
        let mut node = MockComponent::new(|args| {
            if args.first().map(String::as_str) == Some("install") {
                Err("launchctl: Operation not permitted".to_string())
            } else {
                Ok(())
            }
        });
        let err = install_engine_service(
            "dig-relay",
            true,
            Os::MacOs,
            ServiceScope::System,
            &BTreeMap::new(),
            &mut |a, e| node.run(a, e),
            &mut |_| svc::ServiceRunState::Unknown,
        )
        .unwrap_err();
        assert!(
            err.contains("no existing registration was found"),
            "got: {err}"
        );
    }

    #[test]
    fn a_start_failure_is_still_fatal() {
        let mut node = MockComponent::new(|args| {
            if args.first().map(String::as_str) == Some("start") {
                Err("exited with 1".to_string())
            } else {
                Ok(())
            }
        });
        let err = install_engine_service(
            "dig-node",
            true,
            Os::Linux,
            ServiceScope::System,
            &BTreeMap::new(),
            &mut |a, e| node.run(a, e),
            &mut |_| panic!("install succeeded"),
        )
        .unwrap_err();
        assert!(err.contains("dig-node start failed"), "got: {err}");
    }

    // -- Uninstall symmetry: EVERY scope, on every OS (dig_ecosystem#526) ----------------------

    #[test]
    fn an_uninstall_deregisters_both_scopes_on_every_os() {
        for os in [Os::Windows, Os::Linux, Os::MacOs] {
            let mut node = MockComponent::ok();
            let note =
                uninstall_engine_service("dig-node", os, &mut |a, e| node.run(a, e), &mut |_| {
                    svc::ServiceRunState::NotFound
                })
                .expect("nothing left registered ⇒ Ok");
            let issued: Vec<Vec<String>> =
                node.calls_to("uninstall").into_iter().cloned().collect();
            assert_eq!(
                issued,
                vec![
                    vec![
                        "uninstall".to_string(),
                        "--scope".to_string(),
                        "system".to_string()
                    ],
                    vec![
                        "uninstall".to_string(),
                        "--scope".to_string(),
                        "user".to_string()
                    ],
                ],
                "os {os:?} must visit BOTH scopes — a scope-of-this-run uninstall leaves an \
                 earlier run's registration starting a node the user believes they removed"
            );
            assert!(note.contains("every scope"), "got: {note}");
        }
    }

    #[test]
    fn a_scope_that_still_holds_a_registration_fails_the_uninstall_and_is_named() {
        // The end STATE is authoritative, not the verbs' exit codes — and only ONE scope is dirty
        // here, so a rule that reported "some scope is dirty" without naming which would read the
        // same on a fixture where both were.
        let mut node = MockComponent::ok();
        let err = uninstall_engine_service(
            "dig-node",
            Os::Linux,
            &mut |a, e| node.run(a, e),
            &mut |scope| match scope {
                ServiceScope::User => svc::ServiceRunState::Stopped,
                ServiceScope::System => svc::ServiceRunState::NotFound,
            },
        )
        .unwrap_err();
        assert!(err.contains("per-user scope"), "got: {err}");
        assert!(
            !err.contains("machine-wide"),
            "the clean scope must not be blamed, got: {err}"
        );
    }

    #[test]
    fn a_nonzero_uninstall_exit_is_reported_but_not_fatal_when_nothing_is_left_registered() {
        // `uninstall` of an absent registration exits non-zero on some platforms; that is not a
        // failure. It is still REPORTED, because a scope that could not be reached is a fact the
        // operator needs even when the end state is clean.
        let mut node = MockComponent::new(|args| {
            if args.contains(&"user".to_string()) {
                Err("no such unit".to_string())
            } else {
                Ok(())
            }
        });
        let note = uninstall_engine_service(
            "dig-node",
            Os::Linux,
            &mut |a, e| node.run(a, e),
            &mut |_| svc::ServiceRunState::NotFound,
        )
        .expect("a clean end state is Ok despite the tool's exit code");
        assert!(note.contains("per-scope command errors"), "got: {note}");
        assert!(note.contains("no such unit"), "got: {note}");
    }

    #[test]
    fn an_uninstall_against_a_pre_scope_binary_falls_back_per_scope() {
        // Same compat rule as install: the unflagged retry runs once per scope, and the resulting
        // (scope-blind) `uninstall` is all an older binary can do.
        let mut node = MockComponent::new(|args| {
            if args.iter().any(|a| a == "--scope") {
                Err(PRE_SCOPE_REJECTION.to_string())
            } else {
                Ok(())
            }
        });
        uninstall_engine_service(
            "dig-node",
            Os::Linux,
            &mut |a, e| node.run(a, e),
            &mut |_| svc::ServiceRunState::NotFound,
        )
        .expect("the unflagged retries succeed");
        let unflagged = node
            .calls_to("uninstall")
            .into_iter()
            .filter(|c| c.len() == 1)
            .count();
        assert_eq!(unflagged, 2, "one unflagged retry per scope");
    }
    // -- task #232 / #565: stop-before-write, by service id ----------------

    /// #301 boot-start guarantee (dig-node). The installer registers dig-node by
    /// delegating to its own `install` verb, which registers a boot-start
    /// (auto-start-on-boot) service. This locks that we invoke plain `install`
    /// (the boot-start path) and `start` — never a manual-start variant — so a
    /// regression to manual registration fails here.
    #[test]
    fn dig_node_is_registered_boot_start_via_the_install_verb() {
        assert_eq!(
            install_args(Some(ServiceScope::System)),
            vec!["install", "--scope", "system"],
            "dig-node must be registered via its boot-start `install` verb (#301), machine-wide              (dig_ecosystem#526)"
        );
        assert_eq!(
            start_args(Some(ServiceScope::System)),
            vec!["start", "--scope", "system"]
        );
        // No manual/no-boot token is ever forwarded to the install verb.
        assert!(!install_args(Some(ServiceScope::System))
            .iter()
            .any(|a| a.contains("manual") || a.contains("no-boot") || a.contains("no-autostart")));
    }

    /// A dedicated, non-world-writable temp subdirectory (never bare `temp_dir()`, which is mode
    /// 01777 — the root-exec guard correctly refuses a world-writable dir, which would fail these
    /// tests for a reason unrelated to what they assert).
    fn tmp_subdir(tag: &str) -> std::path::PathBuf {
        let d = crate::sources::fixture_root()
            .join(format!("dig-installer-svc-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// An on-disk binary the stop path may see (its CONTENT is irrelevant —
    /// #565's whole point is that it is NEVER executed). A plain file is enough.
    fn existing_bin(tag: &str) -> std::path::PathBuf {
        let dir = tmp_subdir(tag);
        let p = dir.join("dig-bin");
        std::fs::write(&p, b"not executed").unwrap();
        p
    }

    #[test]
    fn stop_before_write_skips_when_binary_is_absent() {
        // First install: no prior binary, so nothing to stop — a skip (not an
        // error), even if the (injected) service state claims RUNNING; and the
        // stop action must NEVER be invoked.
        let missing = crate::sources::fixture_root()
            .join(format!("dig-installer-stop-absent-{}", std::process::id()));
        let outcome = stop_running_service_by_id_with(
            &missing,
            "dig-node",
            || svc::ServiceRunState::Running,
            || panic!("must not stop when there is no prior binary"),
        )
        .expect("skip is not an error");
        assert!(!outcome.bin_existed);
        assert!(!outcome.attempted);
        assert!(!outcome.stopped);
    }

    #[test]
    fn stop_before_write_skips_when_the_service_is_not_running() {
        // The binary exists but the service manager reports it is not RUNNING
        // (stopped / not registered) → skip, and NEVER call the stop action
        // (which, crucially, is never "execute the binary").
        for state in [
            svc::ServiceRunState::Stopped,
            svc::ServiceRunState::NotFound,
            svc::ServiceRunState::Unknown,
        ] {
            let bin = existing_bin("stop-not-running");
            let outcome = stop_running_service_by_id_with(
                &bin,
                "dig-relay",
                move || state,
                || panic!("must not stop when the service is not RUNNING"),
            )
            .expect("not running is not an error");
            assert!(outcome.bin_existed);
            assert!(!outcome.attempted, "state {state:?} must skip the stop");
            let _ = std::fs::remove_dir_all(bin.parent().unwrap());
        }
    }

    #[test]
    fn stop_before_write_stops_by_id_when_the_service_is_running() {
        let bin = existing_bin("stop-running");
        let outcome = stop_running_service_by_id_with(
            &bin,
            "dig-node",
            || svc::ServiceRunState::Running,
            || Ok(()),
        )
        .expect("stop succeeds");
        assert!(outcome.attempted);
        assert!(outcome.stopped);
        assert!(outcome.note.contains("by id"), "got: {}", outcome.note);
        let _ = std::fs::remove_dir_all(bin.parent().unwrap());
    }

    #[test]
    fn stop_before_write_aborts_when_a_running_service_cannot_be_stopped() {
        // A stop failure ABORTS the write (dig-node/dig-relay must not overwrite
        // a binary underneath a still-running service).
        let bin = existing_bin("stop-fail");
        let err = stop_running_service_by_id_with(
            &bin,
            "dig-node",
            || svc::ServiceRunState::Running,
            || Err("access denied".to_string()),
        )
        .unwrap_err();
        assert!(err.contains("could not stop"), "got: {err}");
        let _ = std::fs::remove_dir_all(bin.parent().unwrap());
    }

    #[test]
    fn public_stop_wrappers_skip_a_first_install_without_touching_a_binary() {
        // The public entrypoints (real svc probes) must at least handle the
        // first-install case cleanly on any host — the branch that never
        // consults the service manager or a binary.
        let missing = crate::sources::fixture_root()
            .join(format!("dig-installer-stop-pub-{}", std::process::id()));
        assert!(!stop_running_dig_node(&missing).unwrap().attempted);
        assert!(!stop_running_dig_relay(&missing).unwrap().attempted);
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

    /// A shell to run `inline` with, at a path whose whole chain the root-exec guard can verify.
    ///
    /// NOT `/bin/sh`: on any usrmerge distribution (every current Debian/Ubuntu) `/bin` is a SYMLINK to
    /// `usr/bin`, and the guard refuses a symlinked level rather than following it — correctly, since an
    /// inode walk cannot verify what it cannot traverse. That refusal is right in production (DIG's own
    /// roots are real directories) but it made these tests fail as root for a reason unrelated to what
    /// they assert. Found by running the suite as root in a container, which is precisely why that gate
    /// exists (#1748 WU3).
    ///
    /// `/usr/bin/sh` is the real path on those systems and resolves through no link.
    #[cfg(unix)]
    fn shell_stub(inline: &str) -> (std::path::PathBuf, Vec<String>) {
        let real_sh = ["/usr/bin/sh", "/bin/sh"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .find(|p| {
                p.exists()
                    && p.parent()
                        .and_then(|d| std::fs::symlink_metadata(d).ok())
                        .is_some_and(|m| !m.is_symlink())
            })
            .unwrap_or_else(|| std::path::PathBuf::from("/bin/sh"));
        (real_sh, vec!["-c".to_string(), inline.to_string()])
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
