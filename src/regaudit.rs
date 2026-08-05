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

// `Command::new` is denied crate-wide so an unguarded spawn of an INSTALLED binary cannot compile
// (`clippy.toml`, #1748 WU4). The spawns in this module are either trusted SYSTEM tools resolved from a
// fixed directory list (`SPEC.md` §7.6 — a different invariant with its own tests in `elevation`), test
// fixtures, or the guarded wrapper itself.
#![allow(clippy::disallowed_methods)]

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

/// Every PRIVILEGED DIG registration to audit / vacate on `os` (#565) — all four on EVERY OS: the
/// dig-node/dig-relay/dig-dns services plus the machine-wide beacon task.
///
/// # Why dig-node/dig-relay are listed on unix too (dig_ecosystem#1863)
///
/// This used to list them on **Windows only**, on the reasoning that a user-level dig-node "runs AS
/// the user, so a user-writable binary is not an escalation there". Two things are wrong with that.
/// It was never true for the audit's OTHER half — a plan that declines a component still had that
/// component's registration vacated by the migration, which is the #1863 defect and was live on
/// Windows the whole time. And it stops being true at all the moment dig-node registers
/// machine-wide, which is exactly what dig_ecosystem#526 makes it do: a root-run daemon pointed at
/// `~/.dig/bin/dig-node` is a textbook user→root escalation.
///
/// This now genuinely mirrors [`paths::is_privileged_component`] — which already listed dig-node and
/// dig-relay on unix — rather than only claiming to. Pure.
pub fn privileged_regs(_os: Os) -> Vec<PrivilegedReg> {
    vec![
        PrivilegedReg::Service {
            id: svc::DIG_DNS_SERVICE_ID,
            label: "dig-dns",
        },
        PrivilegedReg::Service {
            id: svc::DIG_NODE_SERVICE_ID,
            label: "dig-node",
        },
        PrivilegedReg::Service {
            id: svc::DIG_RELAY_SERVICE_ID,
            label: "dig-relay",
        },
        PrivilegedReg::Beacon,
    ]
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

/// Audit every privileged DIG registration on `os` against the ALLOWLIST
/// invariant (#565 H1/H2 backstop, strengthened per #619): for each present
/// registration, read its configured binary path back from the OS and flag it
/// unless the binary resolves UNDER `expected_root` — the admin-only install
/// root this run placed the privileged binaries in (`protected_bin_dir` by
/// default, or the `--bin-dir`/GUI dir the whole stack was redirected to).
///
/// Why an allowlist, not a blocklist: [`bin_path_under_any`] only knows the
/// KNOWN legacy roots ([`paths::legacy_privileged_roots`]). A privileged
/// registration a prior `--bin-dir` install left in a user-writable directory
/// that is neither a known legacy root nor the current install dir would escape
/// a blocklist entirely (the ACL verify only covers the current dir). Requiring
/// the binPath to resolve under the trusted `expected_root` refuses that residual
/// — including junction / 8.3-short-name / any other non-protected path (#619).
///
/// Only returns an entry for a registration that is actually present (nothing to
/// say about an absent one). I/O — the classification it applies is the pure
/// [`bin_path_under`].
pub fn audit(os: Os, expected_root: &Path) -> Vec<RegistrationAudit> {
    let legacy = paths::legacy_privileged_roots(os);
    let mut out = Vec::new();
    for reg in privileged_regs(os) {
        let Some(bin) = reg.registered_bin_path() else {
            continue;
        };
        // ALLOWLIST: a privileged binary MUST resolve under the trusted install
        // root; anything else is the escalation surface. The read-back path is
        // CANONICALIZED first ([`bin_resolves_under`], #619) so a junction /
        // symlink / 8.3-short-name / `..` traversal at the trusted root cannot
        // spoof the prefix — and a binary that cannot be canonicalized fails
        // CLOSED (treated as outside the protected root).
        let outside_protected = !bin_resolves_under(&bin, expected_root, os);
        let under_legacy = bin_path_under_any(&bin, &legacy, os);
        let label = reg.label();
        let note = if under_legacy {
            format!(
                "{label} runs a binary under a user-writable legacy root ({bin}) — a non-admin \
                 could replace it and gain its privileges"
            )
        } else if outside_protected {
            format!(
                "{label} runs a binary OUTSIDE the protected install root {} ({bin}) — a \
                 privileged binary must live under the admin-only root; this location may be \
                 user-writable, letting a non-admin replace it",
                expected_root.display()
            )
        } else {
            format!("{label} runs from the protected install root ({bin})")
        };
        out.push(RegistrationAudit {
            registration: label.to_string(),
            bin_path: Some(bin),
            // The field name predates #619; it now means "in a location that is
            // NOT the trusted protected root" (a legacy root, or any other
            // non-allowlisted path). A definitive `true` still fails readiness.
            under_legacy_root: outside_protected,
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
    regs_pointing_under(&paths::legacy_privileged_roots(os), os)
}

/// The privileged registrations that CURRENTLY resolve to a binary under any of `roots`. I/O (reads
/// each registration's binPath).
///
/// The general form of [`regs_pointing_under_legacy`]. [`crate::supersede`] asks it about a SUPERSEDED
/// root, where the answer means the opposite thing: a hit there is a reason to REFUSE to remove the
/// directory, not a reason to deregister (dig_ecosystem#2205). Same question, opposite policy — so the
/// query belongs here and the policy stays with each caller.
pub fn regs_pointing_under(roots: &[PathBuf], os: Os) -> Vec<PrivilegedReg> {
    privileged_regs(os)
        .into_iter()
        .filter(|reg| match reg.registered_bin_path() {
            Some(bin) => bin_path_under_any(&bin, roots, os),
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
/// This is the BLOCKLIST predicate the migration uses to find KNOWN legacy roots
/// to deregister ([`regs_pointing_under_legacy`]). The readiness [`audit`] layers
/// the stronger ALLOWLIST ([`bin_path_under`] against the trusted install root)
/// on top of it (#619).
pub fn bin_path_under_any(bin_path: &str, roots: &[PathBuf], os: Os) -> bool {
    let field = strip_leading_quote(bin_path);
    roots.iter().any(|root| path_has_prefix(field, root, os))
}

/// Does `bin_path` resolve UNDER the single directory `root`? The allowlist
/// primitive [`audit`] uses to require a privileged binary live under the trusted
/// install root (#619). Same quote/prefix normalisation as [`bin_path_under_any`].
/// Pure.
pub fn bin_path_under(bin_path: &str, root: &Path, os: Os) -> bool {
    path_has_prefix(strip_leading_quote(bin_path), root, os)
}

/// Strip a leading `"` (and surrounding whitespace) from a raw image field, so a
/// quoted `"C:\path\x.exe" args` value prefix-matches its root. Pure.
fn strip_leading_quote(raw: &str) -> &str {
    let t = raw.trim();
    t.strip_prefix('"').unwrap_or(t)
}

/// Does the read-back binary `bin` (image path + possible trailing args) resolve
/// UNDER the trusted `root` once BOTH are canonicalized to their real filesystem
/// paths (#619 defence-in-depth)? Canonicalization collapses `..` traversal and
/// dereferences junctions / symlinks / 8.3 short names on the untrusted binPath —
/// so a registration that string-prefix-matches the root but physically resolves
/// elsewhere is caught. Fails CLOSED: a binary or root that cannot be
/// canonicalized (missing / unreadable) is reported as NOT under the root, so an
/// unverifiable privileged registration can never green-light readiness. I/O.
fn bin_resolves_under(bin: &str, root: &Path, os: Os) -> bool {
    let (Some(real_bin), Ok(real_root)) =
        (canonical_executable(bin, os), std::fs::canonicalize(root))
    else {
        return false;
    };
    // Both sides are now real, absolute paths (Windows: `\\?\`-verbatim), so the
    // pure prefix test compares like with like.
    bin_path_under(&real_bin.to_string_lossy(), &real_root, os)
}

/// Isolate the executable from a raw registration image field (`"C:\dir\x.exe"
/// args` / `/opt/dig/bin/x`) and canonicalize it to its real filesystem path.
/// On Windows the argv follows the `.exe`, so the field is cut at the first
/// `.exe` boundary (the path itself may contain spaces, e.g. `Program Files`);
/// on unix the per-tool parser already isolated the path. `None` when the
/// executable cannot be canonicalized (missing / unreadable). I/O.
fn canonical_executable(raw: &str, os: Os) -> Option<PathBuf> {
    let field = strip_leading_quote(raw).trim();
    let exe = if os == Os::Windows {
        match field.to_ascii_lowercase().find(".exe") {
            Some(i) => &field[..i + ".exe".len()],
            None => field,
        }
    } else {
        field
    };
    std::fs::canonicalize(exe).ok()
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
    // #619: a `..` path component walks OUT of whatever prefix precedes it, so a
    // value like `<root>\..\..\..\Users\attacker\evil.exe` STRING-prefix-matches
    // the trusted root yet resolves elsewhere entirely — a plain prefix test
    // would wrongly admit it to the allowlist. A legitimate registered binPath is
    // always an already-resolved path with no traversal, so reject any `..`
    // component outright (fail CLOSED for the allowlist; [`audit`] additionally
    // canonicalizes the read-back path as defence-in-depth against junctions /
    // symlinks / 8.3 short names).
    if field.split(sep).any(|component| component == "..") {
        return false;
    }
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

/// The systemctl scopes a beacon query/removal iterates on Linux: the machine scope
/// ONLY. dig-updater installs the beacon system-scope on every OS (Linux writes
/// `/etc/systemd/system` under `require_elevated()`, never `systemctl --user`; Windows a
/// SYSTEM Scheduled Task; macOS a `/Library/LaunchDaemons` root daemon), so a user-scope
/// `dig-updater` unit is NEVER ours (#1873). Querying the user scope both performed
/// root-adjacent file ops inside a user-owned directory AND handed an unprivileged local
/// account a denial primitive: a planted, still-loaded `--user`-scope `dig-updater.timer`
/// made the deregister post-check fail, and a deregister failure is fatal (#565 H2a), so a
/// blameless upgrade became a fatal migration failure.
#[cfg(any(target_os = "linux", test))]
fn beacon_systemctl_scopes() -> [Vec<&'static str>; 1] {
    [vec![]]
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
        for scope in beacon_systemctl_scopes() {
            let mut args: Vec<String> = scope.iter().map(|s| s.to_string()).collect();
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
        for scope in beacon_systemctl_scopes() {
            let mut args: Vec<String> = scope.iter().map(|s| s.to_string()).collect();
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
/// <unit>.timer` (SYSTEM scope only — the beacon is never user-scope, #1873) plus
/// removal of the unit FILE systemd names, macOS `launchctl bootout` + plist
/// removal. Never executes dig-updater (#565).
/// `Ok(())` when the beacon is no longer registered; a refusal to remove a
/// unit file that failed vetting is folded into the error so the (fatal) verdict
/// explains itself.
fn deregister_beacon() -> Result<(), String> {
    if !beacon_is_registered() {
        return Ok(());
    }
    // Every unit-file removal this deregister REFUSED (a path that failed vetting, a
    // vendor-owned unit). Kept so the fatal post-check below can say WHY the beacon is
    // still registered instead of reporting a bare "still registered".
    #[allow(unused_mut)]
    let mut notes: Vec<String> = Vec::new();
    #[cfg(windows)]
    {
        let _ = spawn("schtasks", &schtasks_delete_args(BEACON_WINDOWS_TASK));
    }
    #[cfg(target_os = "linux")]
    {
        // The beacon is installed SYSTEM-scope only (#1873): a `--user`-scope
        // `dig-updater` unit is never ours, so it is neither disabled nor removed.
        // Treating one as ours previously handed an unprivileged local account a denial
        // primitive — a planted, still-loaded user-scope timer made this (fatal, #565 H2a)
        // deregister fail on a blameless upgrade.
        for unit in [
            format!("{BEACON_SYSTEMD_UNIT}.timer"),
            format!("{BEACON_SYSTEMD_UNIT}.service"),
        ] {
            let _ = spawn(
                "systemctl",
                &["disable".into(), "--now".into(), unit.clone()],
            );
            // `disable` only un-links the enablement symlinks — the unit FILE stays on
            // disk, so systemd keeps reporting `LoadState=loaded` and the beacon reads as
            // still registered. Without removing the file the deregister could NEVER
            // succeed on Linux and the (fatal) #565 migration failed every upgrade off a
            // legacy root. Mirrors the macOS branch below, which has always removed its plist.
            if let Some(note) = remove_systemd_unit_file(&unit) {
                eprintln!("    ! {note}");
                notes.push(note);
            }
        }
        let _ = spawn("systemctl", &["daemon-reload".into()]);
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
        let refused = if notes.is_empty() {
            String::new()
        } else {
            format!("; refused unit-file removals: {}", notes.join("; "))
        };
        Err(format!(
            "the beacon scheduled task is still registered after a deregister attempt \
             ({BEACON_WINDOWS_TASK} / {BEACON_SYSTEMD_UNIT}.timer / {BEACON_LAUNCHD_LABEL}){refused}"
        ))
    } else {
        Ok(())
    }
}

/// The unit-file directories a MACHINE-WIDE (system-scope) removal may delete from —
/// the two admin/runtime-owned locations a DIG beacon schedule is ever installed into.
/// Both are root-owned on any sane host, so a path vetted into this set is not one an
/// unprivileged account chose.
pub const SYSTEM_UNIT_DIRS: &[&str] = &["/etc/systemd/system", "/run/systemd/system"];

/// Vendor/package-owned unit directories. A unit here belongs to a package manager, so
/// deleting it would leave the package database inconsistent and `apt install
/// --reinstall` would silently restore the very timer this deregister removed. Such a
/// unit is REFUSED (and reported) rather than unlinked; masking/removing it is an
/// operator action, not an installer's.
pub const VENDOR_UNIT_DIRS: &[&str] = &["/usr/lib/systemd/system", "/lib/systemd/system"];

/// What to do about the unit file systemd named for a unit being deregistered — the
/// decision, separated from the unlink so it is unit-testable on any host. See
/// [`plan_unit_file_removal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitFileRemoval {
    /// systemd reported no backing file — nothing to remove.
    Nothing,
    /// The named path failed vetting; the string says why, for the log + the (fatal)
    /// post-check's error.
    Refused(String),
    /// A vetted path that may be unlinked.
    Remove(String),
}

/// Decide what to do with the `FragmentPath` in `show_output` for `unit`, given the
/// directories a removal is allowed to delete from. Pure.
///
/// The path comes from systemd, but systemd's answer is derived from a unit directory an
/// unprivileged account may control (`~/.config/systemd/user`, possibly reached through a
/// symlinked component — and `sudo -E` leaks `XDG_CONFIG_HOME` into the root process, so a
/// root `systemctl --user` really does read the invoking user's units, see
/// [`crate::userwrite`]). An unlink of "whatever systemd said" is therefore an
/// attacker-chosen deletion primitive running as root. This function is where that is
/// closed: the path must be absolute, must have NO `.`/`..`/empty component, must be named
/// EXACTLY for the unit being deregistered, must be a `.service` or `.timer`, and its
/// parent must be one of `allowed_dirs` — with [`VENDOR_UNIT_DIRS`] refused by name so the
/// refusal explains itself.
pub fn plan_unit_file_removal(
    show_output: &str,
    unit: &str,
    allowed_dirs: &[&str],
) -> UnitFileRemoval {
    let Some(path) = parse_systemctl_fragment_path(show_output) else {
        return UnitFileRemoval::Nothing;
    };
    match vet_unit_file_path(&path, unit, allowed_dirs) {
        Ok(()) => UnitFileRemoval::Remove(path),
        Err(why) => UnitFileRemoval::Refused(why),
    }
}

/// Is `path` safe to unlink as the unit file of `unit`? `Err(why)` names the violated
/// rule. Pure, and deliberately written on POSIX path STRINGS rather than [`Path`] so the
/// rules hold identically wherever the tests run (`Path::is_absolute` is false for
/// `/etc/...` on Windows, which would make a host-run test vacuous).
fn vet_unit_file_path(path: &str, unit: &str, allowed_dirs: &[&str]) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("refusing to remove {path}: not an absolute path"));
    }
    let (dir, base) = path
        .rsplit_once('/')
        .map(|(dir, base)| (if dir.is_empty() { "/" } else { dir }, base))
        .ok_or_else(|| format!("refusing to remove {path}: no parent directory"))?;
    if path
        .split('/')
        .skip(1)
        .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!(
            "refusing to remove {path}: the path has a relative or empty component"
        ));
    }
    if base != unit {
        return Err(format!(
            "refusing to remove {path}: it is not named for the unit being deregistered ({unit})"
        ));
    }
    if !(base.ends_with(".service") || base.ends_with(".timer")) {
        return Err(format!(
            "refusing to remove {path}: not a .service or .timer unit file"
        ));
    }
    if VENDOR_UNIT_DIRS.contains(&dir) {
        return Err(format!(
            "refusing to remove {path}: {dir} is package-owned, so removing the file would leave \
             the package database inconsistent — mask or uninstall the package instead"
        ));
    }
    if !allowed_dirs.contains(&dir) {
        return Err(format!(
            "refusing to remove {path}: {dir} is not one of the unit directories a deregister may \
             delete from ({})",
            allowed_dirs.join(", ")
        ));
    }
    Ok(())
}

/// Delete the on-disk unit file backing `unit`, as named by systemd's own `FragmentPath`
/// property and VETTED by [`plan_unit_file_removal`] before anything is unlinked. `Some(note)`
/// when a removal was refused or failed — the caller logs it and folds it into the (fatal)
/// post-check's verdict; `None` when there was nothing to do or the file is gone.
///
/// The beacon is installed SYSTEM-scope only (#1873), so the only unit file to remove is
/// root's own, bounded to [`SYSTEM_UNIT_DIRS`]. There is deliberately no user-scope path: a
/// `--user`-scope `dig-updater` unit is never ours, so this never performs a file operation
/// inside a user-owned directory.
#[cfg(target_os = "linux")]
fn remove_systemd_unit_file(unit: &str) -> Option<String> {
    let out = spawn(
        "systemctl",
        &[
            "show".into(),
            "-p".into(),
            "FragmentPath".into(),
            unit.to_string(),
        ],
    )?;
    apply_unit_file_removal(&plan_unit_file_removal(&out, unit, SYSTEM_UNIT_DIRS))
}

/// Perform a vetted removal decision: unlink on [`UnitFileRemoval::Remove`], and on
/// anything else touch nothing. `Some(note)` when a refusal must be reported or the unlink
/// failed; an already-absent file is a clean `None` (idempotent, like every other undo
/// here).
///
/// Separated from [`plan_unit_file_removal`] so a test can drive the WHOLE decision →
/// unlink path against a real file and observe that a path failing vetting is not deleted.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn apply_unit_file_removal(plan: &UnitFileRemoval) -> Option<String> {
    match plan {
        UnitFileRemoval::Nothing => None,
        UnitFileRemoval::Refused(why) => Some(why.clone()),
        UnitFileRemoval::Remove(path) => match std::fs::remove_file(path) {
            Ok(()) => None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => Some(format!("could not remove {path}: {e}")),
        },
    }
}

/// Extract the unit-file path from `systemctl show -p FragmentPath <unit>` output —
/// the `FragmentPath=<path>` line. `None` when systemd reported no backing file (an
/// absent or purely-transient unit answers with an empty value). Pure.
pub fn parse_systemctl_fragment_path(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("FragmentPath="))
        .map(str::trim)
        .find(|p| !p.is_empty())
        .map(str::to_string)
}

/// Spawn a query tool and return its combined stdout+stderr, or `None` on a spawn
/// failure. Console hidden (mirrors [`crate::svc`]). The authoritative signal is
/// the PARSE of the captured text, never the exit code.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn spawn(tool: &str, args: &[String]) -> Option<String> {
    use crate::proc::HideConsole;
    // #657: on Windows resolve `sc`/`schtasks` to their absolute System32 path so
    // a current-directory search-order hijack can't substitute the tool (identity
    // for the unix `systemctl`/`launchctl` names — out of this Windows-only scope).
    let out = std::process::Command::new(crate::proc::system_tool(tool))
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
    // #657: absolute System32 resolution for the Windows `schtasks`/`launchctl`
    // present-check spawn (identity on the unix tool names).
    std::process::Command::new(crate::proc::system_tool(tool))
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

    /// AMENDED for dig_ecosystem#1863/#526: unix now audits the SAME four registrations Windows
    /// does. The old expectation ("unix audits only dig-dns + the beacon") rested on dig-node being
    /// user-level on unix, which #526 changes — an elevated install registers it machine-wide, and a
    /// root-run daemon whose binary sits in `~/.dig/bin` is a textbook user→root escalation. It also
    /// left the #1863 defect (a declined component's registration vacated and never restored)
    /// unreachable on unix by construction.
    #[test]
    fn every_os_audits_all_three_services_plus_the_beacon() {
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            let labels: Vec<&str> = privileged_regs(os).iter().map(|r| r.label()).collect();
            for expected in [
                "dig-dns",
                "dig-node",
                "dig-relay",
                "dig-updater beacon task",
            ] {
                assert!(
                    labels.contains(&expected),
                    "{os:?} must audit {expected}: {labels:?}"
                );
            }
        }
    }

    /// The audited set MUST agree with [`paths::is_privileged_component`], which this function's doc
    /// claims to mirror — a claim that was false for two years. Asserted, not asserted-in-prose.
    #[test]
    fn the_audited_set_matches_the_privileged_component_set_on_every_os() {
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            for stem in ["dig-node", "dig-relay", "dig-dns"] {
                assert_eq!(
                    privileged_regs(os).iter().any(|r| r.label() == stem),
                    paths::is_privileged_component(os, stem),
                    "{os:?}/{stem}: the audited set and the privileged-component set disagree"
                );
            }
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

    // -- #619: the allowlist (a privileged binPath MUST be under the trusted root)

    #[test]
    fn bin_path_under_accepts_only_paths_within_the_protected_root() {
        let protected = Path::new(r"C:\Program Files\DIG\bin");
        // A binary in the protected root (with args, quotes, mixed case) is under it.
        assert!(bin_path_under(
            r"C:\Program Files\DIG\bin\dig-dns.exe run",
            protected,
            Os::Windows
        ));
        assert!(bin_path_under(
            r#""c:/program files/dig/bin/dig-node.exe" run"#,
            protected,
            Os::Windows
        ));
        // Anything else is NOT under it — the allowlist rejects it.
        assert!(!bin_path_under(
            r"C:\Users\me\AppData\Local\Programs\DIG\bin\dig-dns.exe",
            protected,
            Os::Windows
        ));
    }

    #[test]
    fn allowlist_flags_an_unknown_user_writable_root_a_blocklist_would_miss() {
        // The exact #619 residual: a privileged binPath in a user-writable dir
        // that is NEITHER a known legacy root NOR the protected root. A blocklist
        // (`bin_path_under_any` over the legacy roots) MISSES it; the allowlist
        // (`bin_path_under` the protected root) CATCHES it.
        let protected = Path::new("/opt/dig/bin");
        let legacy = paths::legacy_privileged_roots(Os::Linux); // ~/.dig/bin
        let rogue = "/home/me/tools/dig-dns serve";
        assert!(
            !bin_path_under_any(rogue, &legacy, Os::Linux),
            "the blocklist does not know this arbitrary dir"
        );
        assert!(
            !bin_path_under(rogue, protected, Os::Linux),
            "the allowlist flags it (not under the protected root)"
        );
    }

    #[test]
    fn allowlist_rejects_a_parent_traversal_binpath_under_the_trusted_root() {
        // #619: a registered binPath that STRING-prefix-matches the trusted root
        // but walks OUT of it via `..` resolves to an attacker-controlled location
        // — it must NOT pass the allowlist. Both the allowlist (`bin_path_under`)
        // and the blocklist (`bin_path_under_any`) reject a `..`-traversal outright.
        let protected = Path::new(r"C:\Program Files\DIG\bin");
        let traversal = r"C:\Program Files\DIG\bin\..\..\..\Users\attacker\evil.exe";
        assert!(
            !bin_path_under(traversal, protected, Os::Windows),
            "a `..`-traversal binPath must be flagged, not admitted to the allowlist"
        );
        // A quoted form with trailing args is equally rejected.
        assert!(!bin_path_under(
            r#""C:\Program Files\DIG\bin\..\..\Windows\System32\cmd.exe" /c evil"#,
            protected,
            Os::Windows
        ));
        // unix mirror (case-sensitive, slash-based).
        let uprotected = Path::new("/opt/dig/bin");
        assert!(!bin_path_under(
            "/opt/dig/bin/../../home/attacker/evil",
            uprotected,
            Os::Linux
        ));
        // The migration blocklist must not treat a traversal as a known legacy root.
        let legacy = vec![PathBuf::from(r"C:\Program Files\DIG\bin")];
        assert!(!bin_path_under_any(traversal, &legacy, Os::Windows));
    }

    #[test]
    fn bin_resolves_under_canonicalizes_and_fails_closed() {
        // Defence-in-depth (#619): the read-back binary is canonicalized before
        // the prefix test, and an unverifiable path fails CLOSED.
        let os = crate::target::Target::current().expect("supported host").os;
        let base =
            crate::sources::fixture_root().join(format!("dig-regaudit-{}", std::process::id()));
        let inside_dir = base.join("bin");
        std::fs::create_dir_all(&inside_dir).expect("create the trusted root");
        let exe = inside_dir.join(if os == Os::Windows { "dig.exe" } else { "dig" });
        std::fs::write(&exe, b"stub").expect("write the stub binary");

        // A real binary physically under the (canonicalized) trusted root passes.
        assert!(
            bin_resolves_under(&exe.to_string_lossy(), &inside_dir, os),
            "a binary genuinely under the canonicalized root must be accepted"
        );

        // A binary that does NOT exist cannot be canonicalized → fails CLOSED.
        let missing = inside_dir.join(if os == Os::Windows {
            "definitely-absent.exe"
        } else {
            "definitely-absent"
        });
        assert!(
            !bin_resolves_under(&missing.to_string_lossy(), &inside_dir, os),
            "an uncanonicalizable (missing) binary must fail closed (flagged)"
        );

        // A real binary OUTSIDE the trusted root is flagged.
        let outside_exe = base.join(if os == Os::Windows {
            "loose.exe"
        } else {
            "loose"
        });
        std::fs::write(&outside_exe, b"stub").expect("write the outside binary");
        assert!(
            !bin_resolves_under(&outside_exe.to_string_lossy(), &inside_dir, os),
            "a binary outside the trusted root must be flagged"
        );

        let _ = std::fs::remove_dir_all(&base);
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

    /// `systemctl disable` only un-links the enablement symlinks — the unit FILE survives,
    /// systemd keeps reporting `LoadState=loaded`, and the #565 beacon deregister could
    /// never report success on Linux (a FATAL migration failure on every upgrade off a
    /// legacy root). Removing the file requires reading systemd's own `FragmentPath`.
    ///
    /// The fixtures are the three answers a real host gives, and each separates the parser
    /// from a nearer-wrong one: an EMPTY value (systemd's answer for a unit with no
    /// backing file) must NOT read as a path to delete; a value embedded in a DIFFERENT
    /// property's text must not be picked up (deleting an attacker-influenced description
    /// string would be a file-removal primitive); and the real answer must be exact.
    #[test]
    fn parse_systemctl_fragment_path_reads_only_a_real_unit_file() {
        assert_eq!(
            parse_systemctl_fragment_path("FragmentPath=/etc/systemd/system/dig-updater.timer\n")
                .as_deref(),
            Some("/etc/systemd/system/dig-updater.timer")
        );
        // A query for a unit that has no backing file on disk.
        assert_eq!(parse_systemctl_fragment_path("FragmentPath=\n"), None);
        assert_eq!(parse_systemctl_fragment_path("FragmentPath=   \n"), None);
        // Only a line that IS the property counts — never one that merely mentions it.
        assert_eq!(
            parse_systemctl_fragment_path("Description=see FragmentPath=/etc/passwd\n"),
            None
        );
        // An empty leading line is skipped; the real FragmentPath is returned.
        assert_eq!(
            parse_systemctl_fragment_path(
                "FragmentPath=\nFragmentPath=/etc/systemd/system/dig-updater.timer\n"
            )
            .as_deref(),
            Some("/etc/systemd/system/dig-updater.timer")
        );
    }

    // -- the vetting that bounds the unit-file removal (#1854 security round) ---
    //
    // The removal target is systemd's own `FragmentPath`, but systemd derives it from a
    // unit directory an unprivileged account may control: `sudo -E` (the elevation this
    // project documents) leaks `XDG_CONFIG_HOME` into the root process, so a root
    // `systemctl --user` reads the invoking user's units (`crate::userwrite`). Unlinking
    // "whatever systemd said" as root is therefore an attacker-chosen deletion primitive.
    // These tests fix the bound; each one distinguishes the vetting from a naive
    // `remove_file(parsed)`, which satisfies none of them.

    /// A `FragmentPath` whose basename is NOT the unit being deregistered must be REFUSED,
    /// and — the property that actually matters — the file must still be there afterwards.
    /// Driven through the real decision → unlink path (`plan` + `apply`), so a guard moved
    /// or dropped anywhere along it fails here.
    #[test]
    #[cfg(unix)]
    fn a_fragment_path_not_named_for_the_unit_is_refused_and_the_file_survives() {
        let dir = std::env::temp_dir().join(format!("regaudit-vet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_s = dir.display().to_string();
        let victim = dir.join("shadow.service");
        std::fs::write(&victim, b"not ours").unwrap();

        let show = format!("FragmentPath={}\n", victim.display());
        let plan = plan_unit_file_removal(&show, "dig-updater.service", &[dir_s.as_str()]);
        let note = apply_unit_file_removal(&plan).expect("a refusal must be reported");

        assert!(
            victim.exists(),
            "a unit file NOT named for the unit being deregistered was deleted — root would \
             unlink an attacker-chosen path"
        );
        assert!(
            note.contains("not named for the unit"),
            "the refusal must name the violated rule: {note}"
        );

        // Control: the SAME directory and the SAME code path do delete the unit that IS
        // being deregistered — so the assertion above is a bound, not a broken fixture.
        let ours = dir.join("dig-updater.service");
        std::fs::write(&ours, b"ours").unwrap();
        let show = format!("FragmentPath={}\n", ours.display());
        let plan = plan_unit_file_removal(&show, "dig-updater.service", &[dir_s.as_str()]);
        assert_eq!(apply_unit_file_removal(&plan), None);
        assert!(!ours.exists(), "the beacon's own unit file must be removed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The decision-level bound, host-independent (the paths are POSIX strings, never
    /// [`Path`], precisely so these hold when the suite runs on Windows too).
    #[test]
    fn only_an_absolute_allowlisted_path_named_for_the_unit_may_be_removed() {
        let unit = "dig-updater.timer";
        let show = |p: &str| format!("FragmentPath={p}\n");

        assert_eq!(
            plan_unit_file_removal(
                &show("/etc/systemd/system/dig-updater.timer"),
                unit,
                SYSTEM_UNIT_DIRS
            ),
            UnitFileRemoval::Remove("/etc/systemd/system/dig-updater.timer".into())
        );

        let refusal = |p: &str, dirs: &[&str]| match plan_unit_file_removal(&show(p), unit, dirs) {
            UnitFileRemoval::Refused(why) => why,
            other => panic!("{p} must be refused, got {other:?}"),
        };

        // The path is inside an allowlisted directory and is a real unit file — but it is
        // NOT the unit being deregistered, so it is somebody else's and must not be
        // unlinked. A naive `remove_file(parsed)` deletes it.
        assert!(
            refusal("/etc/systemd/system/some-other.service", SYSTEM_UNIT_DIRS)
                .contains("not named for the unit"),
        );
        // A relative answer: nothing anchors it, so it could resolve anywhere.
        assert!(
            refusal("etc/systemd/system/dig-updater.timer", SYSTEM_UNIT_DIRS)
                .contains("not an absolute path")
        );
        // Traversal out of an allowlisted directory.
        assert!(refusal(
            "/etc/systemd/system/../../tmp/dig-updater.timer",
            SYSTEM_UNIT_DIRS
        )
        .contains("relative or empty component"));
        // A user-controlled directory, on a SYSTEM-scope removal: the exact escalation.
        assert!(refusal(
            "/home/u/.config/systemd/user/dig-updater.timer",
            SYSTEM_UNIT_DIRS
        )
        .contains("not one of the unit directories"));
        // A path bearing the right name but the wrong kind of file.
        assert!(match plan_unit_file_removal(
            &show("/etc/systemd/system/passwd"),
            "passwd",
            SYSTEM_UNIT_DIRS
        ) {
            UnitFileRemoval::Refused(why) => why,
            other => panic!("a non-unit file must be refused, got {other:?}"),
        }
        .contains("not a .service or .timer"));
        // Package-owned units are refused rather than unlinked (a deleted dpkg-owned unit
        // leaves the package DB inconsistent, and `apt install --reinstall` would silently
        // restore the very timer this deregister removed).
        for vendor in VENDOR_UNIT_DIRS.iter().copied() {
            let path = format!("{vendor}/dig-updater.timer");
            let mut dirs = SYSTEM_UNIT_DIRS.to_vec();
            dirs.push(vendor);
            assert!(
                refusal(&path, &dirs).contains("package-owned"),
                "{path} must be refused even when the caller allowlists it"
            );
        }
        // systemd's answer for a unit with no backing file removes nothing.
        assert_eq!(
            plan_unit_file_removal("FragmentPath=\n", unit, SYSTEM_UNIT_DIRS),
            UnitFileRemoval::Nothing
        );
    }

    /// #1873: the beacon is queried SYSTEM-scope only. dig-updater never registers the
    /// beacon `--user`-scope, so a user-scope `dig-updater` unit is not ours — querying it
    /// both touched a user-owned directory as root and let an unprivileged account plant a
    /// still-loaded user-scope timer that made the (fatal, #565 H2a) deregister fail. This
    /// is the seam every beacon query/removal loop iterates; against the pre-fix
    /// `[vec!["--user"], vec![]]` both-scopes logic it FAILS (two scopes, one of them
    /// `--user`).
    #[test]
    fn the_beacon_is_queried_system_scope_only_never_user_scope() {
        let scopes = beacon_systemctl_scopes();
        assert_eq!(
            scopes.len(),
            1,
            "the beacon is machine-scope only, not both scopes: {scopes:?}"
        );
        assert!(
            scopes.iter().all(|s| !s.contains(&"--user")),
            "a user-scope beacon unit is never ours (#1873): {scopes:?}"
        );
        assert!(
            scopes[0].is_empty(),
            "the only scope is the machine scope (no flag): {scopes:?}"
        );
    }

    /// #1873: no root file operation targets a user directory. The beacon removal planner
    /// is bounded to the root-owned [`SYSTEM_UNIT_DIRS`] and never to a user tree, so a
    /// `~/.config/systemd/user/...` FragmentPath (which `sudo -E` + `systemctl --user`
    /// could once surface) is REFUSED — never `Remove`d — and the file survives. Driven
    /// through the real decision → unlink path with the exact dirs the beacon removal uses.
    #[test]
    #[cfg(unix)]
    fn a_user_scope_beacon_unit_file_is_never_removed_by_root() {
        let dir = std::env::temp_dir().join(format!("regaudit-userdir-{}", std::process::id()));
        let user_units = dir.join(".config/systemd/user");
        std::fs::create_dir_all(&user_units).unwrap();
        let planted = user_units.join("dig-updater.timer");
        std::fs::write(&planted, b"planted by an unprivileged account").unwrap();

        // Exactly what `remove_systemd_unit_file` now feeds the planner: SYSTEM_UNIT_DIRS.
        let show = format!("FragmentPath={}\n", planted.display());
        let plan = plan_unit_file_removal(&show, "dig-updater.timer", SYSTEM_UNIT_DIRS);
        let note = apply_unit_file_removal(&plan).expect("a user-tree path must be refused");

        assert!(
            planted.exists(),
            "a user-owned unit file was deleted with root's authority — the #1873 primitive"
        );
        assert!(
            note.contains("not one of the unit directories"),
            "the refusal must name the out-of-allowlist rule: {note}"
        );

        let _ = std::fs::remove_dir_all(&dir);
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
        let audits = audit(os, &paths::protected_bin_dir());
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
