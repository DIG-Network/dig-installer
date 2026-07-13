//! App-scoped inbound firewall rule for dig-node's peer-RPC listener (#424).
//!
//! dig-node's ONLY non-loopback listener is its mTLS peer-RPC socket (the P2P
//! transport dig-nat/dig-gossip dial into) — every other surface
//! (`localhost:9778` RPC, `dig-wallet`'s `127.0.0.1:9777`, `dig.local:80`) is
//! loopback-only and never needs a hole punched through the OS firewall. This
//! is a **first-class, toggleable install option**, default ON (mirroring the
//! `chia://` scheme handler, [`crate::scheme`]): opening the port makes a
//! freshly-installed node reachable for direct/relay-free peer connections
//! immediately, but a user who declines it loses nothing beyond a slower
//! relay-mediated path (`dig-relay` fallback still works with the port
//! closed) — so applying it is worth doing by default, and skipping it is
//! always safe.
//!
//! Per-OS behaviour, in the same "best-effort, never abort the install"
//! posture as [`crate::scheme`]/[`crate::hosts`]:
//!
//! * **Windows** — a single named `netsh advfirewall firewall` rule scoped to
//!   the installed dig-node executable (`program=`), `protocol=TCP`,
//!   `localport=<port>`. No `remoteip=`/address-family restriction is set, so
//!   the rule evaluates against BOTH IPv4 and IPv6 traffic — Windows Firewall
//!   treats an omitted `remoteip` as "Any", covering both families with the
//!   ONE rule (§5.2 IPv6-first/IPv4-fallback).
//! * **macOS** — adds the executable to the Application Firewall (ALF)
//!   exception list (`socketfilterfw --add` + `--unblockapp`), but ONLY when
//!   ALF is actually enabled (`--getglobalstate`); if it is off, every inbound
//!   connection is already unfiltered and adding an exception would be a
//!   silent no-op dressed up as a success, so it is skipped and reported as
//!   such.
//! * **Linux** — never auto-applied (too many competing firewall managers —
//!   `ufw`/`firewalld`/bare `iptables` — to safely automate). The installer
//!   prints (and the runbook documents) the one-line manual remedy: `sudo ufw
//!   allow <port>/tcp`.
//!
//! Layering: the port resolution + every per-OS command-line builder are pure
//! functions, unit-tested without spawning a process; [`open`]/[`close`] are
//! the thin imperative layer that actually shells out (skipped entirely on
//! `dry_run`, so they never touch a real system in tests).

use std::path::Path;

/// dig-node's peer-RPC listen port (its own `peer::DEFAULT_P2P_PORT`) — the
/// ONE port this module ever opens a hole for.
pub const DEFAULT_PEER_PORT: u16 = 9444;

/// The env var dig-node itself reads to override its peer-RPC listen port
/// (`peer::listen_port`). The firewall rule MUST track whatever port dig-node
/// is actually configured to listen on, so this module honours the same
/// override rather than hard-coding [`DEFAULT_PEER_PORT`].
pub const ENV_PEER_PORT: &str = "DIG_PEER_PORT";

/// The stable name of the rule this installer creates (Windows) / the
/// identity documented for the manual Linux remedy. A fixed name lets
/// [`close`] remove exactly this rule, idempotently, without needing to
/// remember which port it was opened on.
pub const RULE_NAME: &str = "DIG Network Node (P2P)";

/// Resolve the peer-RPC port a firewall rule should open: `env_override` (the
/// raw `DIG_PEER_PORT` value) if it parses as a `u16`, else
/// [`DEFAULT_PEER_PORT`]. Pure — [`effective_peer_port`] is the thin wrapper
/// that reads the real environment.
pub fn resolve_peer_port(env_override: Option<&str>) -> u16 {
    env_override
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PEER_PORT)
}

/// [`resolve_peer_port`] reading the real [`ENV_PEER_PORT`] environment
/// variable — the one I/O boundary in port resolution.
pub fn effective_peer_port() -> u16 {
    resolve_peer_port(std::env::var(ENV_PEER_PORT).ok().as_deref())
}

/// The outcome of opening (or, on dry-run, planning to open) the firewall
/// rule — or of removing it. Never silent — `note` always explains the state,
/// mirroring [`crate::scheme::SchemeResult`]/[`crate::daemon_dir::DaemonDirResult`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FirewallResult {
    /// Whether THIS call changed the OS firewall state: for [`open`], a new
    /// rule was created; for [`close`], an existing rule was found and
    /// removed. Always `false` on dry-run, on Linux (never auto-applied), and
    /// on an idempotent no-op (nothing there to open/remove) — `note` always
    /// distinguishes a genuine no-op from a real failure.
    pub applied: bool,
    /// The port the rule targets (or would target).
    pub port: u16,
    /// Human-readable detail — never silent.
    pub note: String,
}

// ---------------------------------------------------------------------------
// Windows — netsh argv builders (pure; compiled + tested on every host OS so
// CI catches a regression here regardless of which OS runs the suite).
// ---------------------------------------------------------------------------

/// The `netsh advfirewall firewall add rule …` argv that opens an inbound
/// TCP hole on `port`, scoped to `program` (so nothing else on the host can
/// use this rule to receive traffic). Deliberately carries NO `remoteip=`/
/// `interfacetype=` restriction: an omitted `remoteip` defaults to "Any" in
/// Windows Firewall, which is evaluated against both IPv4 and IPv6 traffic —
/// one rule, both families (§5.2).
pub fn windows_add_rule_args(program: &Path, port: u16) -> Vec<String> {
    vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={RULE_NAME}"),
        "dir=in".to_string(),
        "action=allow".to_string(),
        format!("program={}", program.display()),
        "protocol=TCP".to_string(),
        format!("localport={port}"),
    ]
}

/// The `netsh advfirewall firewall delete rule …` argv removing the rule by
/// its stable [`RULE_NAME`] — no `program=`/port needed, so removal is
/// idempotent even if the port was changed (`DIG_PEER_PORT`) since install.
pub fn windows_remove_rule_args() -> Vec<String> {
    vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "delete".to_string(),
        "rule".to_string(),
        format!("name={RULE_NAME}"),
    ]
}

/// `netsh`'s own text for "nothing matched" on a delete of an absent rule —
/// distinguishes an idempotent no-op from a genuine command failure. Only
/// read from [`windows_close`] (Windows-only), so it must be cfg-gated
/// itself or `-D warnings`/`dead_code` fails the build on every OTHER OS
/// (`build-os-matrix`/`clippy` run on ubuntu-latest, where a plain top-level
/// `const` whose only reader lives behind `#[cfg(windows)]` is invisible —
/// see `DEVELOPMENT_LOG.md`'s `DIG_ICON_ICO` entry for the identical class
/// of bug in the GUI crate).
#[cfg(windows)]
const WINDOWS_NO_RULE_TEXT: &str = "No rules match the specified criteria";

// ---------------------------------------------------------------------------
// macOS — Application Firewall (`socketfilterfw`) argv builders (pure).
// ---------------------------------------------------------------------------

/// `socketfilterfw --getglobalstate` argv — reads whether the Application
/// Firewall (ALF) is currently enabled.
pub fn macos_getglobalstate_args() -> Vec<String> {
    vec!["--getglobalstate".to_string()]
}

/// `socketfilterfw --add <program>` argv — adds `program` to the ALF
/// application list (a prerequisite for `--unblockapp`).
pub fn macos_add_args(program: &Path) -> Vec<String> {
    vec!["--add".to_string(), program.display().to_string()]
}

/// `socketfilterfw --unblockapp <program>` argv — explicitly allows `program`
/// to receive inbound connections despite ALF being on.
pub fn macos_unblock_args(program: &Path) -> Vec<String> {
    vec!["--unblockapp".to_string(), program.display().to_string()]
}

/// `socketfilterfw --remove <program>` argv — removes `program` from the ALF
/// application list, reverting it to ALF's default (unlisted) treatment.
pub fn macos_remove_args(program: &Path) -> Vec<String> {
    vec!["--remove".to_string(), program.display().to_string()]
}

/// Parse `socketfilterfw --getglobalstate`'s stdout (e.g. `"Firewall is
/// enabled. (State = 1)"` / `"Firewall is disabled. (State = 0)"`) into a
/// bool. Pure — matched case-insensitively on the word "enabled" so it is
/// resilient to the exact punctuation/state-number formatting.
pub fn macos_alf_enabled(getglobalstate_output: &str) -> bool {
    getglobalstate_output
        .to_ascii_lowercase()
        .contains("enabled")
        && !getglobalstate_output
            .to_ascii_lowercase()
            .contains("disabled")
}

// ---------------------------------------------------------------------------
// Linux — never auto-applied; a documented manual remedy (pure message).
// ---------------------------------------------------------------------------

/// The manual remedy printed (and mirrored in the runbook) when
/// `open_firewall` is on but the OS is Linux: too many competing firewall
/// managers to safely automate, so this installer never touches Linux
/// firewall state — it only tells the user the one command that opens the
/// same port a Windows/macOS install would.
pub fn linux_instruction(port: u16) -> String {
    format!(
        "Linux: firewall rules are never applied automatically (too many competing managers — \
         ufw/firewalld/iptables — to safely automate). If a firewall is active, allow dig-node's \
         peer-RPC port yourself: `sudo ufw allow {port}/tcp` (or the equivalent for your firewall \
         manager). See runbooks/local-running.md."
    )
}

// ---------------------------------------------------------------------------
// The imperative apply layer — dry-run is pure (no process spawned); the real
// per-OS branches shell out and are exercised by the evidence step (README),
// never by `cargo test` (which must stay side-effect-free on a dev machine).
// ---------------------------------------------------------------------------

/// Open the inbound firewall rule for `program` (the installed dig-node
/// binary) on the effective peer-RPC port ([`effective_peer_port`]). Never
/// aborts the install — a failure is recorded in the result's `note`.
/// `dry_run` reports the intent (port + program) without touching the OS.
pub fn open(program: &Path, dry_run: bool) -> FirewallResult {
    let port = effective_peer_port();
    if dry_run {
        return FirewallResult {
            applied: false,
            port,
            note: format!(
                "would open an inbound TCP {port} rule (\"{RULE_NAME}\") scoped to {} — both \
                 IPv4 and IPv6 (Linux: would print the manual ufw remedy instead)",
                program.display()
            ),
        };
    }
    #[cfg(windows)]
    {
        windows_open(program, port)
    }
    #[cfg(target_os = "macos")]
    {
        macos_open(program, port)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = program;
        FirewallResult {
            applied: false,
            port,
            note: linux_instruction(port),
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = program;
        FirewallResult {
            applied: false,
            port,
            note: "firewall configuration is not supported on this OS".to_string(),
        }
    }
}

/// Remove the rule this installer created (idempotent — an already-absent
/// rule is a clean no-op, never an error). `program` is only needed on macOS
/// (ALF identifies its exception list by app path, not a rule name);
/// Windows/Linux ignore it. `dry_run` reports intent without touching the OS.
pub fn close(program: &Path, dry_run: bool) -> FirewallResult {
    let port = effective_peer_port();
    if dry_run {
        return FirewallResult {
            applied: false,
            port,
            note: format!("would remove the \"{RULE_NAME}\" firewall rule (if present)"),
        };
    }
    #[cfg(windows)]
    {
        let _ = program;
        windows_close(port)
    }
    #[cfg(target_os = "macos")]
    {
        macos_close(program, port)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = program;
        FirewallResult {
            applied: false,
            port,
            note: "Linux: no firewall rule was auto-applied, so there is nothing to remove"
                .to_string(),
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = program;
        FirewallResult {
            applied: false,
            port,
            note: "firewall configuration is not supported on this OS".to_string(),
        }
    }
}

#[cfg(windows)]
fn run_netsh(args: &[String]) -> Result<String, String> {
    let out = std::process::Command::new("netsh")
        .args(args)
        .output()
        .map_err(|e| format!("spawn netsh: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "netsh exited with {:?}: {}",
            out.status.code(),
            stdout.trim()
        ))
    }
}

#[cfg(windows)]
fn windows_open(program: &Path, port: u16) -> FirewallResult {
    match run_netsh(&windows_add_rule_args(program, port)) {
        Ok(_) => FirewallResult {
            applied: true,
            port,
            note: format!(
                "opened inbound TCP {port} for {} (rule \"{RULE_NAME}\", IPv4+IPv6)",
                program.display()
            ),
        },
        Err(e) => FirewallResult {
            applied: false,
            port,
            note: format!("could not open the firewall rule: {e}"),
        },
    }
}

#[cfg(windows)]
fn windows_close(port: u16) -> FirewallResult {
    match run_netsh(&windows_remove_rule_args()) {
        Ok(_) => FirewallResult {
            applied: true,
            port,
            note: format!("removed the \"{RULE_NAME}\" firewall rule"),
        },
        Err(e) if e.contains(WINDOWS_NO_RULE_TEXT) => FirewallResult {
            applied: false,
            port,
            note: "no DIG-owned firewall rule to remove (already absent)".to_string(),
        },
        Err(e) => FirewallResult {
            applied: false,
            port,
            note: format!("could not remove the firewall rule: {e}"),
        },
    }
}

#[cfg(target_os = "macos")]
fn run_socketfilterfw(args: &[String]) -> Result<String, String> {
    let out = std::process::Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .args(args)
        .output()
        .map_err(|e| format!("spawn socketfilterfw: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "socketfilterfw exited with {:?}: {}",
            out.status.code(),
            stdout.trim()
        ))
    }
}

#[cfg(target_os = "macos")]
fn macos_open(program: &Path, port: u16) -> FirewallResult {
    let state = match run_socketfilterfw(&macos_getglobalstate_args()) {
        Ok(s) => s,
        Err(e) => {
            return FirewallResult {
                applied: false,
                port,
                note: format!("could not read the Application Firewall state: {e}"),
            }
        }
    };
    if !macos_alf_enabled(&state) {
        return FirewallResult {
            applied: false,
            port,
            note: "the Application Firewall (ALF) is disabled — every inbound connection is \
                   already unfiltered, so no exception rule is needed; skipped"
                .to_string(),
        };
    }
    let added = run_socketfilterfw(&macos_add_args(program));
    let unblocked = run_socketfilterfw(&macos_unblock_args(program));
    match (added, unblocked) {
        (Ok(_), Ok(_)) => FirewallResult {
            applied: true,
            port,
            note: format!(
                "added {} to the Application Firewall exception list (unblocked inbound)",
                program.display()
            ),
        },
        (Err(e), _) | (_, Err(e)) => FirewallResult {
            applied: false,
            port,
            note: format!("could not add the Application Firewall exception: {e}"),
        },
    }
}

#[cfg(target_os = "macos")]
fn macos_close(program: &Path, port: u16) -> FirewallResult {
    match run_socketfilterfw(&macos_remove_args(program)) {
        Ok(_) => FirewallResult {
            applied: true,
            port,
            note: format!("removed {} from the Application Firewall exception list", program.display()),
        },
        Err(e) => FirewallResult {
            applied: false,
            port,
            note: format!(
                "could not remove the Application Firewall exception (it may already be absent): {e}"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn resolve_peer_port_defaults_when_absent_or_invalid() {
        assert_eq!(resolve_peer_port(None), DEFAULT_PEER_PORT);
        assert_eq!(resolve_peer_port(Some("not-a-port")), DEFAULT_PEER_PORT);
        assert_eq!(resolve_peer_port(Some("")), DEFAULT_PEER_PORT);
        // Out of u16 range also falls back rather than panicking.
        assert_eq!(resolve_peer_port(Some("99999999")), DEFAULT_PEER_PORT);
    }

    #[test]
    fn resolve_peer_port_honors_the_override() {
        assert_eq!(resolve_peer_port(Some("9500")), 9500);
    }

    #[test]
    fn windows_add_rule_args_scopes_to_program_and_port() {
        let args = windows_add_rule_args(&PathBuf::from(r"C:\DIG\bin\dig-node.exe"), 9444);
        assert!(args.contains(&"dir=in".to_string()));
        assert!(args.contains(&"action=allow".to_string()));
        assert!(args.contains(&"protocol=TCP".to_string()));
        assert!(args.contains(&format!("name={RULE_NAME}")));
        assert!(args.contains(&"localport=9444".to_string()));
        assert!(args.iter().any(|a| a == r"program=C:\DIG\bin\dig-node.exe"));
    }

    #[test]
    fn windows_add_rule_args_never_restricts_to_one_ip_family() {
        // §5.2: no `remoteip=`/`interfacetype=` restriction — Windows Firewall
        // evaluates an omitted remoteip against BOTH IPv4 and IPv6 (dual-stack
        // by default), so a single rule must never narrow that.
        let args = windows_add_rule_args(&PathBuf::from("/dig-node"), 9444);
        assert!(!args.iter().any(|a| a.starts_with("remoteip=")));
        assert!(!args.iter().any(|a| a.starts_with("interfacetype=")));
    }

    #[test]
    fn windows_remove_rule_args_targets_the_named_rule_only() {
        let args = windows_remove_rule_args();
        assert_eq!(
            args,
            vec![
                "advfirewall".to_string(),
                "firewall".to_string(),
                "delete".to_string(),
                "rule".to_string(),
                format!("name={RULE_NAME}"),
            ]
        );
    }

    #[test]
    fn macos_args_reference_the_program_path() {
        let p = PathBuf::from("/opt/dig/bin/dig-node");
        assert_eq!(
            macos_add_args(&p),
            vec!["--add".to_string(), "/opt/dig/bin/dig-node".to_string()]
        );
        assert_eq!(
            macos_unblock_args(&p),
            vec![
                "--unblockapp".to_string(),
                "/opt/dig/bin/dig-node".to_string()
            ]
        );
        assert_eq!(
            macos_remove_args(&p),
            vec!["--remove".to_string(), "/opt/dig/bin/dig-node".to_string()]
        );
        assert_eq!(
            macos_getglobalstate_args(),
            vec!["--getglobalstate".to_string()]
        );
    }

    #[test]
    fn macos_alf_enabled_parses_socketfilterfw_output() {
        assert!(macos_alf_enabled("Firewall is enabled. (State = 1)"));
        assert!(!macos_alf_enabled("Firewall is disabled. (State = 0)"));
        assert!(macos_alf_enabled("ENABLED"));
    }

    #[test]
    fn linux_instruction_documents_the_manual_ufw_remedy() {
        let note = linux_instruction(9444);
        assert!(note.contains("ufw allow 9444/tcp"));
        assert!(note
            .to_ascii_lowercase()
            .contains("never applied automatically"));
    }

    #[test]
    fn firewall_result_serializes_with_stable_fields() {
        let r = FirewallResult {
            applied: true,
            port: 9444,
            note: "ok".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["applied"], true);
        assert_eq!(v["port"], 9444);
        assert_eq!(v["note"], "ok");
    }

    #[test]
    fn open_dry_run_reports_intent_without_touching_the_system() {
        let r = open(&PathBuf::from("/bin/dig-node"), true);
        assert!(!r.applied);
        assert_eq!(r.port, DEFAULT_PEER_PORT);
        assert!(r.note.contains("would open"));
        assert!(r.note.contains(RULE_NAME));
    }

    #[test]
    fn close_dry_run_reports_intent_without_touching_the_system() {
        let r = close(&PathBuf::from("/bin/dig-node"), true);
        assert!(!r.applied);
        assert!(r.note.contains("would remove"));
        assert!(r.note.contains(RULE_NAME));
    }

    // Linux never shells out — `open`/`close` with `dry_run: false` are still
    // side-effect-free there, unlike the Windows/macOS branches (which really
    // spawn `netsh`/`socketfilterfw` and are exercised by the evidence step,
    // never by `cargo test`, so a dev/CI run never mutates real OS firewall
    // state). Only compiled on Linux, which is exactly where this repo's CI
    // `test` job runs (ubuntu-latest — see `.github/workflows/ci.yml`).
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn open_on_linux_never_touches_the_os_and_prints_the_manual_remedy() {
        let r = open(&PathBuf::from("/opt/dig/bin/dig-node"), false);
        assert!(!r.applied, "Linux never auto-applies a firewall rule");
        assert!(r.note.contains("ufw allow"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn close_on_linux_is_a_side_effect_free_no_op() {
        let r = close(&PathBuf::from("/opt/dig/bin/dig-node"), false);
        assert!(!r.applied);
        assert!(r.note.contains("nothing to remove"));
    }
}
