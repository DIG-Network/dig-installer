//! dig-node OS-service setup, by **delegating to dig-node's own service
//! subcommands** rather than reimplementing systemd/launchd/SCM wiring.
//!
//! dig-node (the local DIG node, renamed from dig-companion) already knows how
//! to register itself as a Windows service / systemd unit / launchd agent — it
//! exposes `install`/`uninstall`/`start`/`stop`/`status` and uses the
//! `service-manager` crate internally (see SYSTEM.md). The universal installer
//! therefore just downloads that binary and runs `dig-node install` (+ `start`),
//! passing the loopback port via `DIG_COMPANION_PORT` so the service serves on
//! the configured endpoint. This module builds those invocations; the pure
//! arg/env construction is unit-tested without spawning anything.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// Configuration for the dig-node service the installer will register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Loopback port dig-node should serve on (default 8080, per dig-node).
    pub port: u16,
    /// Start the service immediately after installing it.
    pub start: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        // 8080 matches dig-node's own default (config.rs DIG_COMPANION_PORT).
        ServiceConfig {
            port: 8080,
            start: true,
        }
    }
}

/// The subcommand passed to the dig-node binary (`dig-node <subcommand>`).
pub fn install_args() -> Vec<String> {
    vec!["install".to_string()]
}

/// The subcommand to start the installed service.
pub fn start_args() -> Vec<String> {
    vec!["start".to_string()]
}

/// Environment variables to pass to `dig-node install` so the registered
/// service serves on the configured port. dig-node's `install` snapshots its
/// effective config into the service definition, so setting the env here is what
/// pins the service's port.
///
/// Sorted (`BTreeMap`) so the output is deterministic and testable.
pub fn install_env(cfg: &ServiceConfig) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    // dig-node still reads the DIG_COMPANION_* names across the rename (its
    // config.rs keeps them as the stable env contract).
    env.insert("DIG_COMPANION_PORT".to_string(), cfg.port.to_string());
    env
}

/// Run `dig-node install` (and, if `cfg.start`, `dig-node start`) using the
/// downloaded binary at `bin`. Returns a human note on success.
///
/// On Windows, installing a service needs an elevated console; dig-node detects
/// this and returns a clear message, which we surface verbatim.
pub fn install_service(bin: &Path, cfg: &ServiceConfig) -> Result<String, String> {
    run_dig_node(bin, &install_args(), &install_env(cfg))
        .map_err(|e| format!("dig-node install failed: {e}"))?;
    let mut note = String::from("dig-node installed as an OS service");
    if cfg.start {
        run_dig_node(bin, &start_args(), &BTreeMap::new())
            .map_err(|e| format!("dig-node start failed: {e}"))?;
        note.push_str(" and started");
    }
    Ok(note)
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
pub fn install_relay_service(bin: &Path, cfg: &RelayServiceConfig) -> Result<String, String> {
    run_relay(bin, &install_args(), &relay_install_env(cfg))
        .map_err(|e| format!("dig-relay install failed: {e}"))?;
    let mut note = String::from("dig-relay installed as an OS service");
    if cfg.start {
        run_relay(bin, &start_args(), &BTreeMap::new())
            .map_err(|e| format!("dig-relay start failed: {e}"))?;
        note.push_str(" and started");
    }
    Ok(note)
}

/// Spawn the dig-relay binary with args + env, inheriting stdio (so the user sees the elevation
/// hint on Windows). Errors if it can't be launched or exits non-zero.
fn run_relay(bin: &Path, args: &[String], env: &BTreeMap<String, String>) -> Result<(), String> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .map_err(|e| format!("could not run {}: {e}", bin.display()))?;
    if !status.success() {
        return Err(format!(
            "{} {} exited with {}",
            bin.display(),
            args.join(" "),
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

/// Spawn the dig-node binary with args + env, inheriting stdio so the user sees
/// dig-node's own messages (e.g. the elevation hint on Windows). Errors if the
/// process can't be launched or exits non-zero.
fn run_dig_node(bin: &Path, args: &[String], env: &BTreeMap<String, String>) -> Result<(), String> {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .map_err(|e| format!("could not run {}: {e}", bin.display()))?;
    if !status.success() {
        return Err(format!(
            "{} {} exited with {}",
            bin.display(),
            args.join(" "),
            status.code().unwrap_or(-1)
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
        assert_eq!(c.port, 8080);
        assert!(c.start);
    }

    #[test]
    fn subcommands_are_dig_node_verbs() {
        assert_eq!(install_args(), vec!["install".to_string()]);
        assert_eq!(start_args(), vec!["start".to_string()]);
    }

    #[test]
    fn install_env_pins_the_port() {
        let env = install_env(&ServiceConfig {
            port: 9090,
            start: false,
        });
        assert_eq!(
            env.get("DIG_COMPANION_PORT").map(String::as_str),
            Some("9090")
        );
        // Only the port is pinned (host/upstream keep dig-node defaults).
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn install_env_default_port() {
        let env = install_env(&ServiceConfig::default());
        assert_eq!(
            env.get("DIG_COMPANION_PORT").map(String::as_str),
            Some("8080")
        );
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
}
