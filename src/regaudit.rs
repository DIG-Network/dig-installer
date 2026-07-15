//! Audit of every PRIVILEGED DIG registration — services AND the auto-update
//! beacon's scheduled task — so none runs a binary from a user-writable location
//! (#565, review round: holes H1 + H2).
//!
//! The #565 location fix moves privileged binaries into the admin-only protected
//! root, but two residual escalations survived the first pass:
//!
//! * **H1 — orphaned registrations.** A component omitted from a re-run
//!   (`--no-auto-update`, or a default run that drops `--with-relay`) left its
//!   auto-start service / daily SYSTEM beacon task still registered with a
//!   `binPath` inside the user-writable legacy dir. A non-admin replants that
//!   exact path → code runs as SYSTEM at the next start / daily fire. The
//!   migration only ever deregistered dig-node/dig-relay, only when in-plan, and
//!   NEVER the beacon scheduled task (`svc::deregister_service` speaks
//!   `sc delete`/`systemctl disable`/`launchctl bootout` — never `schtasks
//!   /delete`). This module deregisters EVERY privileged registration whose
//!   binary resolves under a legacy root, INDEPENDENT of the current plan
//!   ([`regs_pointing_under_legacy`]), and the beacon task by its own scheduler
//!   verb ([`PrivilegedReg::deregister`]).
//! * **H2 — a service left at the legacy `binPath`.** A tolerated re-install
//!   ("already exists") could leave a service still pointing at the writable
//!   legacy path while readiness only checked the protected DIR's ACL. This
//!   module reads each registration's ACTUAL configured binary back from the OS
//!   ([`PrivilegedReg::registered_bin_path`], via `sc qc` / `schtasks /query
//!   /xml` / `systemctl show -p ExecStart` / `launchctl print`) and flags any
//!   that still resolves under a legacy/user-writable root — a definitive
//!   [`audit`] finding makes the install NOT ready ([`audit_failures`]).
//!
//! Cardinal #565 rule preserved throughout: the binary is NEVER executed to
//! read or deregister it — only the OS service manager / built-in scheduler
//! tools are invoked, by canonical id / task path.
//!
//! Layering (mirrors [`crate::svc`]/[`crate::secure`]): the argv builders, the
//! per-tool output PARSERS, and the "resolves under a root" prefix test are PURE
//! and unit-tested; the spawns/plist read are the thin per-OS I/O layer,
//! exercised end-to-end by the 3-OS installer-e2e job.

use std::path::{Path, PathBuf};

use crate::paths;
use crate::svc;
use crate::target::Os;

/// The Windows Scheduled Task path the auto-update beacon registers under —
/// byte-identical to dig-updater's own `dig_updater_broker::scheduler`
/// (`content::WINDOWS_TASK_PATH`), so the delete here always targets the exact
/// task `dig-updater schedule install` created.
pub const BEACON_WINDOWS_TASK: &str = r"\DIG\dig-updater";
/// The macOS LaunchDaemon label the beacon registers under (dig-updater's
/// `content::LAUNCHD_LABEL`); its plist lives at
/// `/Library/LaunchDaemons/<label>.plist`.
pub const BEACON_LAUNCHD_LABEL: &str = "net.dignetwork.dig-updater";
/// The systemd unit STEM the beacon registers (`<stem>.service` + `<stem>.timer`
/// share it — dig-updater's `content::SYSTEMD_UNIT_NAME`). The `.timer` is what
/// fires the daily run, so deregistration disables it.
pub const BEACON_SYSTEMD_UNIT: &str = "dig-updater";

/// A DIG registration that runs a binary under a PRIVILEGED identity — the set
/// the #565 migration must vacate off any user-writable legacy root, and the
/// readiness gate asserts now resolve under the protected root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivilegedReg {
    /// An OS service, controlled by its canonical id via [`crate::svc`]
    /// (`sc`/`systemctl`/`launchctl` — never by executing the service binary).
    Service {
        id: &'static str,
        label: &'static str,
    },
    /// The dig-updater beacon's daily scheduled task / systemd timer / macOS
    /// LaunchDaemon, controlled by the built-in scheduler tool (never by
    /// executing dig-updater).
    Beacon,
}

impl PrivilegedReg {
    /// A short human label for the install log / readiness note.
    pub fn label(&self) -> &'static str {
        match self {
            PrivilegedReg::Service { label, .. } => label,
            PrivilegedReg::Beacon => "dig-updater beacon task",
        }
    }

    /// The binary path this registration is CONFIGURED to run, read back from the
    /// OS — NEVER by executing the binary (#565). `None` when the registration is
    /// absent OR its configuration could not be read/parsed: an inconclusive read
    /// is never treated as an escalation (the admin-only LOCATION remains the
    /// primary guarantee), only a DEFINITIVELY-legacy path is.
    pub fn registered_bin_path(&self) -> Option<String> {
        match self {
            PrivilegedReg::Service { id, .. } => service_bin_path(id),
            PrivilegedReg::Beacon => beacon_bin_path(),
        }
    }

    /// DEREGISTER this registration via the OS service manager / built-in
    /// scheduler tool (never by executing the binary — #565). `Ok(())` when it is
    /// no longer registered afterward.
    pub fn deregister(&self) -> Result<(), String> {
        match self {
            PrivilegedReg::Service { id, .. } => svc::deregister_service(id),
            PrivilegedReg::Beacon => deregister_beacon(),
        }
    }
}

/// Every PRIVILEGED DIG registration to audit / vacate on `os` (#565). Windows:
/// all four — the dig-node/dig-relay/dig-dns LocalSystem services + the SYSTEM
/// beacon task. unix: only the machine-wide ones — the dig-dns service + the
/// root-run beacon; the user-level dig-node/dig-relay run AS the user, so a
/// user-writable binary is not an escalation there (mirrors
/// [`paths::is_privileged_component`], the single source of the privileged set).
/// Pure.
pub fn privileged_regs(os: Os) -> Vec<PrivilegedReg> {
    let mut regs = vec![PrivilegedReg::Service {
        id: svc::DIG_DNS_SERVICE_ID,
        label: "dig-dns",
    }];
    if os == Os::Windows {
        regs.push(PrivilegedReg::Service {
            id: svc::DIG_NODE_SERVICE_ID,
            label: "dig-node",
        });
        regs.push(PrivilegedReg::Service {
            id: svc::DIG_RELAY_SERVICE_ID,
            label: "dig-relay",
        });
    }
    regs.push(PrivilegedReg::Beacon);
    regs
}

/// The #565 binPath audit of one privileged registration — part of the `--json`
/// [`crate::InstallReport`]. Never silent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RegistrationAudit {
    /// Which registration this is ([`PrivilegedReg::label`]).
    pub registration: String,
    /// The binary path read back from the OS (`None` when it could not be read —
    /// inconclusive, never flagged).
    pub bin_path: Option<String>,
    /// The registration is present AND its binary resolves under a legacy /
    /// user-writable root — the #565 escalation. Readiness fails on this
    /// ([`audit_failures`]).
    pub under_legacy_root: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// Audit every privileged DIG registration on `os`: for each that is present,
/// read its configured binary path back from the OS and flag any that resolves
/// under a legacy / user-writable root (#565 — the H1 refuse-ready backstop +
/// the H2 post-registration binPath assertion). Only returns an entry for a
/// registration that is actually present (nothing to say about an absent one).
/// I/O — the classification it applies is the pure [`bin_path_under_any`].
pub fn audit(os: Os) -> Vec<RegistrationAudit> {
    let legacy = paths::legacy_privileged_roots(os);
    let mut out = Vec::new();
    for reg in privileged_regs(os) {
        let Some(bin) = reg.registered_bin_path() else {
            continue;
        };
        let under = bin_path_under_any(&bin, &legacy, os);
        let label = reg.label();
        let note = if under {
            format!(
                "{label} runs a binary under a user-writable legacy root ({bin}) — a non-admin \
                 could replace it and gain its privileges"
            )
        } else {
            format!("{label} runs from a protected location ({bin})")
        };
        out.push(RegistrationAudit {
            registration: label.to_string(),
            bin_path: Some(bin),
            under_legacy_root: under,
            note,
        });
    }
    out
}

/// The readiness FAILURE reasons implied by a set of [`RegistrationAudit`]s
/// (#565): every registration whose binary resolves under a legacy/user-writable
/// root. Pure — so the refuse-ready backstop is unit-tested directly.
pub fn audit_failures(audits: &[RegistrationAudit]) -> Vec<String> {
    audits
        .iter()
        .filter(|a| a.under_legacy_root)
        .map(|a| {
            format!(
                "{}: {} — re-run elevated so the migration re-points it into the protected root",
                a.registration, a.note
            )
        })
        .collect()
}

/// The privileged registrations that CURRENTLY resolve to a binary under a legacy
/// user-writable root — the set the migration deregisters INDEPENDENT of the
/// current plan (#565 H1). I/O (reads each registration's binPath).
pub fn regs_pointing_under_legacy(os: Os) -> Vec<PrivilegedReg> {
    let legacy = paths::legacy_privileged_roots(os);
    privileged_regs(os)
        .into_iter()
        .filter(|reg| match reg.registered_bin_path() {
            Some(bin) => bin_path_under_any(&bin, &legacy, os),
            None => false,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Pure classification + parsing.
// ---------------------------------------------------------------------------

/// Does `bin_path` (a registered image path / `ExecStart` / task command,
/// possibly quoted and followed by arguments) resolve UNDER one of `roots`?
/// Compares the leading directory prefix, case-insensitively + separator-agnostic
/// on Windows (matching [`paths::path_append`]), so `<root>\x.exe run` is caught
/// regardless of trailing args. Pure.
///
// #565 follow-up (Fable N1): this is a BLOCKLIST of known legacy roots. A stronger
// posture is an ALLOWLIST — "a privileged binPath MUST resolve under
// `protected_bin_dir`" — which also refuses a binPath under an unknown
// user-writable path (a junction / 8.3 short-name / non-DIG dir). Deferred to keep
// this fix scoped; tracked as a follow-up hardening ticket.
pub fn bin_path_under_any(bin_path: &str, roots: &[PathBuf], os: Os) -> bool {
    let field = strip_leading_quote(bin_path);
    roots.iter().any(|root| path_has_prefix(field, root, os))
}

/// Strip a leading `"` (and surrounding whitespace) from a raw image field, so a
/// quoted `"C:\path\x.exe" args` value prefix-matches its root. Pure.
fn strip_leading_quote(raw: &str) -> &str {
    let t = raw.trim();
    t.strip_prefix('"').unwrap_or(t)
}

/// Is `field` equal to, or a descendant of, `root`? Normalises separators + case
/// per `os` (Windows: `/`→`\`, lower-cased) before a prefix test. Pure.
fn path_has_prefix(field: &str, root: &Path, os: Os) -> bool {
    let sep = if os == Os::Windows { '\\' } else { '/' };
    let norm = |s: &str| {
        if os == Os::Windows {
            s.replace('/', "\\").to_lowercase()
        } else {
            s.to_string()
        }
    };
    let field = norm(field);
    let root = norm(&root.to_string_lossy());
    let root = root.trim_end_matches(sep);
    if root.is_empty() {
        return false;
    }
    field == root || field.starts_with(&format!("{root}{sep}"))
}

/// Extract the image path from Windows `sc qc <id>` output — the
/// `BINARY_PATH_NAME : <path> [args]` line. Splits on the FIRST colon only, so a
/// drive-letter path (`C:\…`) survives intact. Returns the raw value (path +
/// any trailing args) for [`bin_path_under_any`]. `None` if the line is absent or
/// its value is empty. Pure.
pub fn parse_sc_qc_bin_path(text: &str) -> Option<String> {
    for line in text.lines() {
        let Some((key, value)) = line.trim_start().split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("BINARY_PATH_NAME") {
            let v = value.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Extract the `<Command>` element (the "Task To Run" binary) from
/// `schtasks /Query /TN <task> /XML` output. `None` if there is no `<Command>` or
/// it is empty. Pure.
pub fn parse_schtasks_xml_command(xml: &str) -> Option<String> {
    let open = "<Command>";
    let start = xml.find(open)? + open.len();
    let end = xml[start..].find("</Command>")? + start;
    let cmd = xml[start..end].trim();
    if cmd.is_empty() {
        None
    } else {
        Some(cmd.to_string())
    }
}

/// Extract the executable from `systemctl show -p ExecStart <unit>` output.
/// Prefers the structured `ExecStart={ path=… ; argv[]=… }` form's `path=`; falls
/// back to the raw `ExecStart=<exe> <args>` first token (dropping a leading `-`
/// prefix / quote). `None` when neither is present. Pure.
pub fn parse_systemctl_execstart_path(text: &str) -> Option<String> {
    if let Some(i) = text.find("path=") {
        let rest = &text[i + "path=".len()..];
        let end = rest
            .find(|c: char| c == ';' || c.is_whitespace())
            .unwrap_or(rest.len());
        let p = rest[..end].trim();
        if !p.is_empty() {
            return Some(p.to_string());
        }
    }
    for line in text.lines() {
        if let Some(v) = line.trim().strip_prefix("ExecStart=") {
            let v = v.trim().trim_start_matches('-');
            let first = strip_leading_quote(v)
                .split_whitespace()
                .next()
                .unwrap_or("");
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }
    None
}

/// Extract the daemon program path from macOS `launchctl print system/<label>`
/// output — the `program = <path>` line, or the first entry of the
/// `arguments = { … }` block when there is no explicit `program`. `None` if
/// neither is present. Pure.
pub fn parse_launchctl_program(text: &str) -> Option<String> {
    let mut in_arguments = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(p) = t.strip_prefix("program = ") {
            let p = p.trim();
            if !p.is_empty() {
                return Some(p.to_string());
            }
        }
        if t.starts_with("arguments = {") {
            in_arguments = true;
            continue;
        }
        if in_arguments {
            if t == "}" {
                in_arguments = false;
                continue;
            }
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// `schtasks /Delete /TN <task> /F` argv (excluding the `schtasks` executable).
/// Pure. Windows only.
pub fn schtasks_delete_args(task: &str) -> Vec<String> {
    vec![
        "/Delete".to_string(),
        "/TN".to_string(),
        task.to_string(),
        "/F".to_string(),
    ]
}

/// `schtasks /Query /TN <task> /XML` argv (excluding the `schtasks` executable).
/// Pure. Windows only.
pub fn schtasks_query_xml_args(task: &str) -> Vec<String> {
    vec![
        "/Query".to_string(),
        "/TN".to_string(),
        task.to_string(),
        "/XML".to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Thin per-OS I/O: read a registration's binPath + deregister the beacon task,
// always by canonical id / task path — never by executing the binary (#565).
// ---------------------------------------------------------------------------

/// Read a Windows service's `BINARY_PATH_NAME` via `sc qc <id>` / a unix
/// service's `ExecStart`/`program` via `systemctl`/`launchctl`. `None` off-host
/// or when absent/unreadable.
fn service_bin_path(id: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let out = spawn("sc", &["qc".to_string(), id.to_string()])?;
        parse_sc_qc_bin_path(&out)
    }
    #[cfg(target_os = "linux")]
    {
        let unit = svc::linux_unit_name(id);
        for scope in [vec!["--user"], vec![]] {
            let mut args: Vec<String> = scope.into_iter().map(String::from).collect();
            args.extend(["show".into(), "-p".into(), "ExecStart".into(), unit.clone()]);
            if let Some(out) = spawn("systemctl", &args) {
                if let Some(p) = parse_systemctl_execstart_path(&out) {
                    return Some(p);
                }
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let out = spawn("launchctl", &["print".to_string(), format!("system/{id}")])?;
        parse_launchctl_program(&out)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = id;
        None
    }
}

/// Read the beacon scheduled-task/timer/LaunchDaemon's configured binary path.
/// `None` off-host or when the beacon is not registered / unreadable.
fn beacon_bin_path() -> Option<String> {
    #[cfg(windows)]
    {
        let out = spawn("schtasks", &schtasks_query_xml_args(BEACON_WINDOWS_TASK))?;
        parse_schtasks_xml_command(&out)
    }
    #[cfg(target_os = "linux")]
    {
        let unit = format!("{BEACON_SYSTEMD_UNIT}.service");
        for scope in [vec!["--user"], vec![]] {
            let mut args: Vec<String> = scope.into_iter().map(String::from).collect();
            args.extend(["show".into(), "-p".into(), "ExecStart".into(), unit.clone()]);
            if let Some(out) = spawn("systemctl", &args) {
                if let Some(p) = parse_systemctl_execstart_path(&out) {
                    return Some(p);
                }
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let out = spawn(
            "launchctl",
            &[
                "print".to_string(),
                format!("system/{BEACON_LAUNCHD_LABEL}"),
            ],
        )?;
        parse_launchctl_program(&out)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Is the beacon scheduled artifact currently registered?
fn beacon_is_registered() -> bool {
    #[cfg(windows)]
    {
        spawn_status(
            "schtasks",
            &[
                "/Query".to_string(),
                "/TN".to_string(),
                BEACON_WINDOWS_TASK.to_string(),
            ],
        )
        .unwrap_or(false)
    }
    #[cfg(target_os = "linux")]
    {
        for scope in [vec!["--user"], vec![]] {
            let mut args: Vec<String> = scope.into_iter().map(String::from).collect();
            args.extend([
                "show".into(),
                "-p".into(),
                "LoadState".into(),
                format!("{BEACON_SYSTEMD_UNIT}.timer"),
            ]);
            if let Some(out) = spawn("systemctl", &args) {
                if out.contains("LoadState=loaded") {
                    return true;
                }
            }
        }
        false
    }
    #[cfg(target_os = "macos")]
    {
        spawn_status(
            "launchctl",
            &[
                "print".to_string(),
                format!("system/{BEACON_LAUNCHD_LABEL}"),
            ],
        )
        .unwrap_or(false)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Deregister the beacon's daily scheduler artifact by the built-in scheduler
/// tool — Windows `schtasks /Delete`, Linux `systemctl disable --now
/// <unit>.timer` (both scopes), macOS `launchctl bootout` + plist removal. Never
/// executes dig-updater (#565). `Ok(())` when the beacon is no longer registered.
fn deregister_beacon() -> Result<(), String> {
    if !beacon_is_registered() {
        return Ok(());
    }
    #[cfg(windows)]
    {
        let _ = spawn("schtasks", &schtasks_delete_args(BEACON_WINDOWS_TASK));
    }
    #[cfg(target_os = "linux")]
    {
        for scope in [vec!["--user"], vec![]] {
            for unit in [
                format!("{BEACON_SYSTEMD_UNIT}.timer"),
                format!("{BEACON_SYSTEMD_UNIT}.service"),
            ] {
                let mut args: Vec<String> = scope.iter().map(|s| s.to_string()).collect();
                args.extend(["disable".into(), "--now".into(), unit]);
                let _ = spawn("systemctl", &args);
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = spawn(
            "launchctl",
            &[
                "bootout".to_string(),
                format!("system/{BEACON_LAUNCHD_LABEL}"),
            ],
        );
        let _ = std::fs::remove_file(format!(
            "/Library/LaunchDaemons/{BEACON_LAUNCHD_LABEL}.plist"
        ));
    }
    if beacon_is_registered() {
        Err(format!(
            "the beacon scheduled task is still registered after a deregister attempt \
             ({BEACON_WINDOWS_TASK} / {BEACON_SYSTEMD_UNIT}.timer / {BEACON_LAUNCHD_LABEL})"
        ))
    } else {
        Ok(())
    }
}

/// Spawn a query tool and return its combined stdout+stderr, or `None` on a spawn
/// failure. Console hidden (mirrors [`crate::svc`]). The authoritative signal is
/// the PARSE of the captured text, never the exit code.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn spawn(tool: &str, args: &[String]) -> Option<String> {
    use crate::proc::HideConsole;
    let out = std::process::Command::new(tool)
        .args(args)
        .hide_console()
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
}

/// Spawn a query tool and report whether it exited 0 (used only where the exit
/// code IS the "present?" signal — Windows `schtasks /Query`, macOS `launchctl
/// print`). `None` on a spawn failure.
#[cfg(any(windows, target_os = "macos"))]
fn spawn_status(tool: &str, args: &[String]) -> Option<bool> {
    use crate::proc::HideConsole;
    std::process::Command::new(tool)
        .args(args)
        .hide_console()
        .output()
        .ok()
        .map(|o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- the privileged-registration set ---------------------------------------

    #[test]
    fn windows_audits_all_three_services_plus_the_beacon_task() {
        let regs = privileged_regs(Os::Windows);
        let labels: Vec<&str> = regs.iter().map(|r| r.label()).collect();
        assert!(labels.contains(&"dig-node"));
        assert!(labels.contains(&"dig-relay"));
        assert!(labels.contains(&"dig-dns"));
        assert!(
            labels.contains(&"dig-updater beacon task"),
            "the SYSTEM beacon task MUST be in the audited set (#565 H1): {labels:?}"
        );
    }

    #[test]
    fn unix_audits_only_the_machine_wide_dig_dns_and_beacon() {
        for os in [Os::Linux, Os::MacOs] {
            let labels: Vec<&str> = privileged_regs(os).iter().map(|r| r.label()).collect();
            assert!(labels.contains(&"dig-dns"), "{os:?}");
            assert!(labels.contains(&"dig-updater beacon task"), "{os:?}");
            // The user-level services run AS the user on unix — not an escalation.
            assert!(!labels.contains(&"dig-node"), "{os:?}");
            assert!(!labels.contains(&"dig-relay"), "{os:?}");
        }
    }

    #[test]
    fn beacon_deregisters_via_the_scheduler_tool_never_the_binary() {
        // #565 cardinal rule: the delete argv addresses the task by its canonical
        // PATH — never a path to (or an execution of) the dig-updater binary.
        let argv = schtasks_delete_args(BEACON_WINDOWS_TASK);
        assert_eq!(
            argv,
            vec![
                "/Delete".to_string(),
                "/TN".to_string(),
                r"\DIG\dig-updater".to_string(),
                "/F".to_string()
            ]
        );
        assert!(!argv.iter().any(|a| a.to_lowercase().contains(".exe")));
    }

    // -- bin_path_under_any: the H1/H2 escalation predicate --------------------

    #[test]
    fn detects_a_windows_service_binpath_under_the_legacy_appdata_root() {
        // The exact #565 H2 hole: a service still pointing at the user-writable
        // legacy dir (with trailing args) must be flagged.
        let legacy = vec![PathBuf::from(r"C:\Users\me\AppData\Local\Programs\DIG\bin")];
        assert!(bin_path_under_any(
            r"C:\Users\me\AppData\Local\Programs\DIG\bin\dig-node.exe run",
            &legacy,
            Os::Windows
        ));
        // A quoted path with args is equally detected.
        assert!(bin_path_under_any(
            r#""C:\Users\me\AppData\Local\Programs\DIG\bin\dig-updater.exe" run"#,
            &legacy,
            Os::Windows
        ));
        // Case + separator differences do not evade it (Windows is insensitive).
        assert!(bin_path_under_any(
            r"c:/users/me/appdata/local/programs/dig/bin/dig-dns.exe",
            &legacy,
            Os::Windows
        ));
    }

    #[test]
    fn accepts_a_binpath_under_the_protected_root() {
        // A correctly-migrated service in Program Files\DIG\bin is NOT under any
        // legacy root → not flagged (the passed CLI-default posture).
        let legacy = vec![PathBuf::from(r"C:\Users\me\AppData\Local\Programs\DIG\bin")];
        assert!(!bin_path_under_any(
            r"C:\Program Files\DIG\bin\dig-node.exe run",
            &legacy,
            Os::Windows
        ));
    }

    #[test]
    fn unix_binpath_prefix_is_case_sensitive_and_slash_based() {
        let legacy = vec![PathBuf::from("/home/me/.dig/bin")];
        assert!(bin_path_under_any(
            "/home/me/.dig/bin/dig-dns serve",
            &legacy,
            Os::Linux
        ));
        // /opt/dig/bin (the unix protected root) is not under the legacy root.
        assert!(!bin_path_under_any(
            "/opt/dig/bin/dig-dns serve",
            &legacy,
            Os::Linux
        ));
        // A sibling that merely SHARES a prefix segment is not a descendant.
        assert!(!bin_path_under_any(
            "/home/me/.dig/binaries/x",
            &legacy,
            Os::Linux
        ));
    }

    #[test]
    fn an_empty_root_never_matches() {
        assert!(!bin_path_under_any(
            "/anything",
            &[PathBuf::from("")],
            Os::Linux
        ));
    }

    // -- the per-tool binPath parsers ------------------------------------------

    #[test]
    fn parse_sc_qc_reads_the_binary_path_even_with_a_drive_colon_and_args() {
        let out = "[SC] QueryServiceConfig SUCCESS\r\n\r\n\
             SERVICE_NAME: net.dignetwork.dig-node\r\n        \
             TYPE               : 10  WIN32_OWN_PROCESS\r\n        \
             BINARY_PATH_NAME   : C:\\Program Files\\DIG\\bin\\dig-node.exe run\r\n        \
             DISPLAY_NAME       : DIG NETWORK: NODE\r\n";
        assert_eq!(
            parse_sc_qc_bin_path(out).as_deref(),
            Some(r"C:\Program Files\DIG\bin\dig-node.exe run")
        );
    }

    #[test]
    fn parse_sc_qc_is_none_without_a_binary_path_line() {
        assert_eq!(parse_sc_qc_bin_path("SERVICE_NAME: x\r\n"), None);
        assert_eq!(parse_sc_qc_bin_path(""), None);
    }

    #[test]
    fn parse_schtasks_xml_reads_the_command_element() {
        let xml = "<?xml version=\"1.0\"?>\n<Task>\n  <Actions>\n    <Exec>\n      \
             <Command>C:\\Program Files\\DIG\\bin\\dig-updater.exe</Command>\n      \
             <Arguments>run</Arguments>\n    </Exec>\n  </Actions>\n</Task>\n";
        assert_eq!(
            parse_schtasks_xml_command(xml).as_deref(),
            Some(r"C:\Program Files\DIG\bin\dig-updater.exe")
        );
        assert_eq!(parse_schtasks_xml_command("<Task></Task>"), None);
    }

    #[test]
    fn parse_systemctl_execstart_reads_both_forms() {
        let structured = "ExecStart={ path=/opt/dig/bin/dig-updater ; argv[]=/opt/dig/bin/dig-updater run ; ignore_errors=no }";
        assert_eq!(
            parse_systemctl_execstart_path(structured).as_deref(),
            Some("/opt/dig/bin/dig-updater")
        );
        let raw = "ExecStart=/opt/dig/bin/dig-dns serve\n";
        assert_eq!(
            parse_systemctl_execstart_path(raw).as_deref(),
            Some("/opt/dig/bin/dig-dns")
        );
        assert_eq!(parse_systemctl_execstart_path("nope"), None);
    }

    #[test]
    fn parse_launchctl_reads_the_program_then_falls_back_to_arguments() {
        let with_program = "  state = running\n  program = /opt/dig/bin/dig-updater\n";
        assert_eq!(
            parse_launchctl_program(with_program).as_deref(),
            Some("/opt/dig/bin/dig-updater")
        );
        let with_args = "  arguments = {\n    /opt/dig/bin/dig-dns\n    serve\n  }\n";
        assert_eq!(
            parse_launchctl_program(with_args).as_deref(),
            Some("/opt/dig/bin/dig-dns")
        );
        assert_eq!(parse_launchctl_program("state = running"), None);
    }

    // -- the audit → readiness classification (pure) ---------------------------

    #[test]
    fn audit_failures_flags_only_the_legacy_bound_registrations() {
        let audits = vec![
            RegistrationAudit {
                registration: "dig-node".into(),
                bin_path: Some(r"C:\Program Files\DIG\bin\dig-node.exe".into()),
                under_legacy_root: false,
                note: "ok".into(),
            },
            RegistrationAudit {
                registration: "dig-updater beacon task".into(),
                bin_path: Some(
                    r"C:\Users\me\AppData\Local\Programs\DIG\bin\dig-updater.exe".into(),
                ),
                under_legacy_root: true,
                note: "under legacy".into(),
            },
        ];
        let failures = audit_failures(&audits);
        assert_eq!(
            failures.len(),
            1,
            "only the legacy-bound reg fails: {failures:?}"
        );
        assert!(failures[0].contains("dig-updater beacon task"));
    }

    #[test]
    fn audit_failures_is_empty_for_a_clean_protected_install() {
        let audits = vec![RegistrationAudit {
            registration: "dig-dns".into(),
            bin_path: Some("/opt/dig/bin/dig-dns".into()),
            under_legacy_root: false,
            note: "ok".into(),
        }];
        assert!(audit_failures(&audits).is_empty());
    }

    #[test]
    fn registration_audit_serializes_with_stable_fields() {
        let a = RegistrationAudit {
            registration: "dig-node".into(),
            bin_path: Some(r"C:\x\dig-node.exe".into()),
            under_legacy_root: true,
            note: "n".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&a).unwrap();
        assert_eq!(v["registration"], "dig-node");
        assert_eq!(v["under_legacy_root"], true);
        assert_eq!(v["bin_path"], r"C:\x\dig-node.exe");
    }

    // -- host-safe I/O smoke: an absent beacon deregisters as an Ok no-op ------

    #[test]
    fn deregistering_an_absent_beacon_is_an_ok_noop() {
        // No DIG beacon is registered on a CI host, so this must be a clean Ok
        // (idempotent) — and it must never spawn/execute dig-updater.
        assert!(PrivilegedReg::Beacon.deregister().is_ok());
    }

    #[test]
    fn audit_on_the_host_never_panics_and_returns_coherent_entries() {
        // Exercises the real per-OS binPath reads (`sc qc` / `schtasks` /
        // `systemctl` / `launchctl`) against the host. The VERDICT is
        // host-dependent — a clean CI host has no DIG registration (empty audit),
        // while a machine with a real legacy install correctly reports a
        // `under_legacy_root` finding (the exact #565 escalation) — so this
        // asserts only host-agnostic invariants: it never panics, and every entry
        // is self-consistent. `regs_pointing_under_legacy` must be equally safe.
        let os = crate::target::Target::current().expect("supported host").os;
        let audits = audit(os);
        for a in &audits {
            assert!(
                a.bin_path.is_some(),
                "an audited entry always carries the binPath it read"
            );
            assert!(!a.note.is_empty(), "never silent");
            // The failures view agrees with the per-entry flag.
            assert_eq!(
                audit_failures(std::slice::from_ref(a)).is_empty(),
                !a.under_legacy_root
            );
        }
        let _ = regs_pointing_under_legacy(os);
    }
}
