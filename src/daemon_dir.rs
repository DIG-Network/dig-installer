//! Machine-wide daemon state directory creation + a HARDENED, fail-closed ACL
//! (#501/#499 + the adversarial security review of #501).
//!
//! The dig-node / dig-dns daemons resolve their control/auth state (the
//! control-token the operator CLI reads for `dig-node pair approve …`) from a
//! machine-wide, identity-independent directory. That directory MUST be:
//!   * Windows `%PROGRAMDATA%\DigNode` / `%PROGRAMDATA%\DigDns`
//!   * Linux `/var/lib/dig-node` / `/var/lib/dig-dns`
//!   * macOS `/Library/Application Support/DigNode` / `…/DigDns`
//!
//! Security model (Windows — the hard case). `%PROGRAMDATA%` grants
//! `BUILTIN\Users` "create subfolder", so ANY user can pre-create
//! `C:\ProgramData\DigNode` and become its CREATOR OWNER — and an owner keeps
//! `WRITE_DAC` forever, so a naive `icacls /inheritance:r /grant:r` (which never
//! resets OWNER and never purges foreign explicit ACEs) leaves the squatter able
//! to rewrite the DACL and read the daemon's control-token → local privilege
//! escalation. This module therefore, per directory:
//!   1. resolves the read-grant principal as the interactive user's **token
//!      SID** (`whoami /user`, never the spoofable `%USERNAME%` env), refusing
//!      any well-known group SID (Everyone/Users/Authenticated Users/SYSTEM);
//!   2. resolves `%PROGRAMDATA%` via `SHGetKnownFolderPath` (never `%PROGRAMDATA%`
//!      env, which the launching user controls);
//!   3. if the dir PRE-EXISTS with an untrusted owner (not SYSTEM/Administrators)
//!      → treats it as squatting and PURGES it (take ownership + remove); if the
//!      purge fails → **fails closed** (no dir, recorded failure);
//!   4. FORCES owner = SYSTEM (`icacls /setowner *S-1-5-18 /T`), RESETS the DACL
//!      (`icacls /reset`, dropping every foreign explicit ACE), then applies a
//!      PROTECTED DACL of exactly {SYSTEM:F, Administrators:F, userSID:R}
//!      (`/inheritance:r /grant:r …` by SID, locale-independent);
//!   5. READS THE ACL BACK (`Get-Acl`, SID-based) and asserts inheritance is
//!      disabled, owner is SYSTEM/Administrators, no Everyone/Users/Authenticated
//!      Users ACE exists, and exactly our three principals are present — this is
//!      the acceptance gate. Any failure → **fails closed**: the dir is deleted
//!      and `acl_applied` stays `false`, which `evaluate_readiness` folds into
//!      `report.failures` so the install reports "DIG is NOT ready".
//!
//! On Unix the dir is created by root under root-owned `/var/lib` (not
//! squattable), `chmod 0750`, with a best-effort `setfacl` read ACL for the
//! invoking (`SUDO_USER`) account.
//!
//! Layering: the SID parsing, the `icacls` argv builders, and the `Get-Acl`
//! verification parser are PURE and unit-tested; the create + ACL calls are the
//! thin I/O layer.

use std::path::PathBuf;

use crate::proc::HideConsole;
use crate::target::Os;

/// Well-known SIDs (locale-independent — icacls/Get-Acl accept + emit these).
const SID_SYSTEM: &str = "S-1-5-18";
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
const SID_EVERYONE: &str = "S-1-1-0";
const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
const SID_USERS: &str = "S-1-5-32-545";

/// One daemon's machine-wide state dir: the daemon id + its resolved path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonDir {
    /// The daemon id (`dig-node` / `dig-dns`).
    pub daemon: &'static str,
    /// The machine-wide state directory for it on this OS.
    pub path: PathBuf,
}

/// The result of ensuring one daemon dir exists + is ACL'd. Never silent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DaemonDirResult {
    pub daemon: String,
    pub path: String,
    /// The directory now exists (created or already present + adopted).
    pub created: bool,
    /// The tight ACL was applied AND verified by read-back (SYSTEM+Admins full,
    /// installing user read, inheritance off, no world/group ACE, owner SYSTEM).
    /// When `false`, the install is NOT ready (`evaluate_readiness` fails).
    pub acl_applied: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// The Windows machine-wide data root, resolved via the **known-folder API**
/// (`SHGetKnownFolderPath(FOLDERID_ProgramData)`), NOT the `%PROGRAMDATA%` env
/// (which the launching user can redirect to a dir they control — a control-token
/// relocation attack). Falls back to the literal `C:\ProgramData` (still not the
/// env) only if the API itself fails. On non-Windows hosts (only reached by
/// tests exercising `daemon_dirs(Os::Windows)`) the env/literal is fine.
fn program_data() -> PathBuf {
    #[cfg(windows)]
    {
        program_data_known_folder().unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
    }
}

/// `%PROGRAMDATA%` via `SHGetKnownFolderPath(FOLDERID_ProgramData)` — immune to
/// `%PROGRAMDATA%` env redirection. `None` if the API fails.
#[cfg(windows)]
fn program_data_known_folder() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    unsafe {
        let mut ptr: *mut u16 = std::ptr::null_mut();
        let hr = SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            0,
            std::ptr::null_mut(),
            &mut ptr as *mut *mut u16,
        );
        if hr < 0 || ptr.is_null() {
            if !ptr.is_null() {
                CoTaskMemFree(ptr as *const core::ffi::c_void);
            }
            return None;
        }
        let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
        let os = std::ffi::OsString::from_wide(std::slice::from_raw_parts(ptr, len));
        CoTaskMemFree(ptr as *const core::ffi::c_void);
        let p = PathBuf::from(os);
        if p.as_os_str().is_empty() {
            None
        } else {
            Some(p)
        }
    }
}

/// The writable, app-owned WebView2 user-data directory for the installer GUI
/// (#715).
///
/// The Tauri GUI renders in WebView2, whose user-data-folder otherwise defaults
/// to `%LOCALAPPDATA%\<bundle-id>\EBWebView`. When the GUI runs elevated as
/// **LocalSystem**, `%LOCALAPPDATA%` resolves to
/// `C:\Windows\system32\config\systemprofile\AppData\Local`, where WebView2
/// cannot create its data dir — a fatal "couldn't create the data directory"
/// crash before the UI loads. Pointing `WEBVIEW2_USER_DATA_FOLDER` at this
/// machine-wide dir makes the GUI launch regardless of which account runs it:
/// `%ProgramData%\DigNetwork\installer\webview`, resolved via the same
/// known-folder API [`program_data`] uses (never the systemprofile path).
///
/// This is a browser CACHE dir, NOT a privileged-exec target (§565): nothing the
/// installer runs as SYSTEM ever executes a binary out of it, so its being
/// writable by non-privileged users is not an escalation.
pub fn webview_data_dir() -> PathBuf {
    program_data()
        .join("DigNetwork")
        .join("installer")
        .join("webview")
}

/// The two daemon state directories for `os` (dig-node then dig-dns). Pure
/// given `os` + the resolved data root, so the path contract is unit-tested.
pub fn daemon_dirs(os: Os) -> Vec<DaemonDir> {
    match os {
        Os::Windows => {
            let base = program_data();
            vec![
                DaemonDir {
                    daemon: "dig-node",
                    path: base.join("DigNode"),
                },
                DaemonDir {
                    daemon: "dig-dns",
                    path: base.join("DigDns"),
                },
            ]
        }
        Os::Linux => vec![
            DaemonDir {
                daemon: "dig-node",
                path: PathBuf::from("/var/lib/dig-node"),
            },
            DaemonDir {
                daemon: "dig-dns",
                path: PathBuf::from("/var/lib/dig-dns"),
            },
        ],
        Os::MacOs => {
            let base = PathBuf::from("/Library/Application Support");
            vec![
                DaemonDir {
                    daemon: "dig-node",
                    path: base.join("DigNode"),
                },
                DaemonDir {
                    daemon: "dig-dns",
                    path: base.join("DigDns"),
                },
            ]
        }
    }
}

// ---------------------------------------------------------------------------
// Pure SID / icacls / Get-Acl helpers (unit-tested; `pub` so they are part of
// the crate's testable surface — no dead-code gating needed cross-platform).
// ---------------------------------------------------------------------------

/// A well-known GROUP SID that must NEVER appear in the control-token dir's DACL
/// (world/broad-group readable = the priv-esc the tight ACL exists to prevent).
pub fn is_dangerous_group_sid(sid: &str) -> bool {
    matches!(sid, SID_EVERYONE | SID_AUTHENTICATED_USERS | SID_USERS)
}

/// May `sid` be the READ-grant principal (the interactive user)? Rejects the
/// dangerous groups AND SYSTEM (the interactive identity must be a real user, and
/// a SYSTEM install is already refused upstream by `elevation::guard`). A spoofed
/// `%USERNAME%=Everyone` used to yield `Everyone:(OI)(CI)R` — this is the guard.
pub fn is_forbidden_grant_sid(sid: &str) -> bool {
    is_dangerous_group_sid(sid) || sid == SID_SYSTEM
}

/// Parse the interactive-user SID from `whoami /user /fo csv /nh` output —
/// `"domain\user","S-1-5-21-…"`. The SID comes from the process TOKEN (not env),
/// so it cannot be spoofed by setting `%USERNAME%`. Returns the first `S-1-…`
/// field. Pure.
pub fn parse_whoami_csv_sid(text: &str) -> Option<String> {
    text.split([',', '"', '\r', '\n', ' ', '\t'])
        .map(|f| f.trim())
        .find(|f| f.starts_with("S-1-") && f.len() > 6)
        .map(|s| s.to_string())
}

/// `icacls <dir> /setowner *S-1-5-18 /T /C /Q` — force owner = SYSTEM on the dir
/// and every child, defeating a squatter's owner-based `WRITE_DAC`. Pure argv.
pub fn setowner_system_args(dir: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/setowner".to_string(),
        format!("*{SID_SYSTEM}"),
        "/T".to_string(),
        "/C".to_string(),
        "/Q".to_string(),
    ]
}

/// `icacls <dir> /reset /T /C /Q` — drop ALL explicit ACEs (purging any foreign
/// ACE a squatter added) and restore the parent's inheritable ACEs, so the
/// following `/inheritance:r /grant:r` starts from a known baseline. Pure argv.
pub fn reset_dacl_args(dir: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/reset".to_string(),
        "/T".to_string(),
        "/C".to_string(),
        "/Q".to_string(),
    ]
}

/// `icacls <dir> /inheritance:r /grant:r …` that REPLACES the DACL with exactly
/// {SYSTEM:F, Administrators:F, `user_sid`:R}, inheritable to child files (the
/// control-token), inheritance disabled. All principals by SID (locale-
/// independent). Pure so the exact ACL is unit-tested without touching the FS.
pub fn windows_lockdown_grant_args(dir: &str, user_sid: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        format!("*{SID_SYSTEM}:(OI)(CI)F"),
        "/grant:r".to_string(),
        format!("*{SID_ADMINISTRATORS}:(OI)(CI)F"),
        "/grant:r".to_string(),
        format!("*{user_sid}:(OI)(CI)R"),
    ]
}

/// The PowerShell one-liner that emits the dir's owner + each access ACE as
/// SID-based lines (`OWNER;<sid>` / `ACE;<sid>;<isInherited>`) for the read-back
/// verification. SID-based (not name-based) so parsing is locale-independent.
/// Pure (single-quotes in the path are doubled for PS literal safety).
pub fn acl_verify_ps_command(dir: &str) -> String {
    let dir = dir.replace('\'', "''");
    format!(
        "$ErrorActionPreference='Stop'; \
         $acl = Get-Acl -LiteralPath '{dir}'; \
         'OWNER;' + $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; \
         foreach ($a in $acl.Access) {{ \
           'ACE;' + $a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value + ';' + $a.IsInherited \
         }}"
    )
}

/// Verify a locked-down DACL from [`acl_verify_ps_command`] output against the
/// acceptance gate (the security-review requirement): owner is SYSTEM or
/// Administrators; NO inherited ACE (inheritance disabled); NO Everyone / Users /
/// Authenticated Users ACE; and exactly the three required principals (SYSTEM,
/// Administrators, `user_sid`) are present. `Err` on any violation. Pure.
pub fn parse_acl_verify(output: &str, user_sid: &str) -> Result<(), String> {
    let mut owner: Option<String> = None;
    let mut ace_sids: Vec<String> = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("OWNER;") {
            owner = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("ACE;") {
            let mut parts = rest.split(';');
            let sid = parts.next().unwrap_or("").trim().to_string();
            let inherited = parts.next().unwrap_or("").trim();
            if sid.is_empty() {
                continue;
            }
            if inherited.eq_ignore_ascii_case("true") {
                return Err(format!(
                    "inheritance is NOT disabled — inherited ACE present for {sid}"
                ));
            }
            if is_dangerous_group_sid(&sid) {
                return Err(format!(
                    "DACL grants a world/group principal ({sid}) — the token dir must not be group-readable"
                ));
            }
            ace_sids.push(sid);
        }
    }
    let owner = owner.ok_or_else(|| "could not read the directory owner".to_string())?;
    if owner != SID_SYSTEM && owner != SID_ADMINISTRATORS {
        return Err(format!(
            "owner is {owner}, expected SYSTEM ({SID_SYSTEM}) or Administrators ({SID_ADMINISTRATORS})"
        ));
    }
    for required in [SID_SYSTEM, SID_ADMINISTRATORS, user_sid] {
        if !ace_sids.iter().any(|s| s == required) {
            return Err(format!("DACL is missing the required ACE for {required}"));
        }
    }
    // Exactly-the-trustees: NO principal other than {SYSTEM, Administrators,
    // user_sid} may hold an ACE. A foreign user SID (e.g. a squatter granting
    // their own account read/full) is NOT a well-known group so the group check
    // above misses it — reject it here so the acceptance gate is truly closed.
    for sid in &ace_sids {
        if sid != SID_SYSTEM && sid != SID_ADMINISTRATORS && sid != user_sid {
            return Err(format!(
                "DACL grants an unexpected principal ({sid}) — only SYSTEM, Administrators, and the installing user may have access"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows I/O layer.
// ---------------------------------------------------------------------------

/// The interactive user's TOKEN SID for the read grant (`whoami /user`), or an
/// `Err` when it cannot be resolved or is a forbidden group SID — either way the
/// caller FAILS CLOSED (never grants a spoofable/broad principal).
#[cfg(windows)]
fn current_user_sid() -> Result<String, String> {
    let out = std::process::Command::new(crate::proc::system_tool("whoami"))
        .args(["/user", "/fo", "csv", "/nh"])
        .hide_console()
        .output()
        .map_err(|e| format!("whoami /user failed to run: {e}"))?;
    if !out.status.success() {
        return Err("whoami /user exited non-zero".to_string());
    }
    let sid = parse_whoami_csv_sid(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| "could not parse the interactive-user SID from whoami".to_string())?;
    if is_forbidden_grant_sid(&sid) {
        return Err(format!(
            "refusing to grant read to a well-known/group principal ({sid}) — expected a real interactive-user SID"
        ));
    }
    Ok(sid)
}

/// The dir's current owner SID via `Get-Acl`, or `None` if it can't be read.
#[cfg(windows)]
fn dir_owner_sid(path: &std::path::Path) -> Option<String> {
    let dir = path.to_string_lossy().replace('\'', "''");
    let ps = format!(
        "(Get-Acl -LiteralPath '{dir}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value"
    );
    let out = std::process::Command::new(crate::proc::system_tool("powershell"))
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .hide_console()
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.starts_with("S-1-") {
        Some(s)
    } else {
        None
    }
}

/// Run `icacls` with `args`; `Ok(())` iff it exits 0.
#[cfg(windows)]
fn run_icacls(args: &[String]) -> Result<(), String> {
    let out = std::process::Command::new(crate::proc::system_tool("icacls"))
        .args(args)
        .hide_console()
        .output()
        .map_err(|e| format!("icacls failed to run: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "icacls exited with {}: {}",
            out.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string()),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Read the dir's ACL back and verify it meets the acceptance gate.
#[cfg(windows)]
fn read_and_verify_acl(path: &std::path::Path, user_sid: &str) -> Result<(), String> {
    let ps = acl_verify_ps_command(&path.to_string_lossy());
    let out = std::process::Command::new(crate::proc::system_tool("powershell"))
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .hide_console()
        .output()
        .map_err(|e| format!("Get-Acl read-back failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Get-Acl read-back exited non-zero: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_acl_verify(&String::from_utf8_lossy(&out.stdout), user_sid)
}

/// Create the machine-wide daemon state directories + apply the hardened ACL
/// (#501/#499). `dry_run` reports intent only. Per dir: fail-CLOSED — a dir whose
/// ACL cannot be established + verified is removed and reported `acl_applied:false`
/// (which `evaluate_readiness` treats as a hard failure), never left world-readable.
pub fn ensure(os: Os, dry_run: bool, log: &mut dyn FnMut(&str)) -> Vec<DaemonDirResult> {
    let mut out = Vec::new();
    for d in daemon_dirs(os) {
        let path_str = d.path.to_string_lossy().into_owned();
        if dry_run {
            log(&format!(
                "    (would create {} and lock it down: owner SYSTEM, SYSTEM+Administrators full, the installing user's SID read-only, inheritance off, verified)",
                path_str
            ));
            out.push(DaemonDirResult {
                daemon: d.daemon.to_string(),
                path: path_str,
                created: false,
                acl_applied: false,
                note: "dry run".to_string(),
            });
            continue;
        }
        out.push(ensure_one(os, &d, &path_str, log));
    }
    out
}

fn ensure_one(os: Os, d: &DaemonDir, path_str: &str, log: &mut dyn FnMut(&str)) -> DaemonDirResult {
    #[cfg(windows)]
    {
        let _ = os;
        ensure_one_windows(d, path_str, log)
    }
    #[cfg(unix)]
    {
        ensure_one_unix(os, d, path_str, log)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = os;
        let mut result = DaemonDirResult {
            daemon: d.daemon.to_string(),
            path: path_str.to_string(),
            created: false,
            acl_applied: false,
            note: String::new(),
        };
        match std::fs::create_dir_all(&d.path) {
            Ok(()) => {
                result.created = true;
                result.note = "created (no ACL support on this OS)".to_string();
            }
            Err(e) => result.note = format!("could not create {path_str}: {e}"),
        }
        log(&format!("    ! {} — {}", path_str, result.note));
        result
    }
}

/// Windows: hardened, fail-closed create + lockdown + verify (see module docs).
#[cfg(windows)]
fn ensure_one_windows(d: &DaemonDir, path_str: &str, log: &mut dyn FnMut(&str)) -> DaemonDirResult {
    let mut result = DaemonDirResult {
        daemon: d.daemon.to_string(),
        path: path_str.to_string(),
        created: false,
        acl_applied: false,
        note: String::new(),
    };

    // 1. Resolve the read-grant principal from the process token (NOT env), fail
    //    closed if it is unresolved or a forbidden group SID.
    let user_sid = match current_user_sid() {
        Ok(s) => s,
        Err(e) => {
            result.note = format!("refusing to create the state dir: {e}");
            log(&format!("    ! {} — {}", path_str, result.note));
            return result;
        }
    };

    // 2. Squatting defense: a pre-existing dir with an UNTRUSTED owner is purged
    //    (take ownership so we can delete, then remove). If it can't be purged,
    //    fail closed rather than adopt an attacker-controlled directory.
    if d.path.exists() {
        let trusted = matches!(
            dir_owner_sid(&d.path).as_deref(),
            Some(SID_SYSTEM) | Some(SID_ADMINISTRATORS)
        );
        if !trusted {
            let _ = run_icacls(&setowner_system_args(path_str));
            if let Err(e) = std::fs::remove_dir_all(&d.path) {
                result.note = format!(
                    "state dir pre-existed with an untrusted/unknown owner and could not be purged ({e}); refusing (fail closed)"
                );
                log(&format!("    ! {} — {}", path_str, result.note));
                return result;
            }
        }
    }

    // 3. Create (idempotent if we just adopted a trusted pre-existing dir).
    if let Err(e) = std::fs::create_dir_all(&d.path) {
        result.note = format!("could not create {path_str}: {e}");
        log(&format!("    ! {} — {}", path_str, result.note));
        return result;
    }
    result.created = true;

    // 4. Lock down: owner→SYSTEM, purge foreign ACEs (/reset), then a PROTECTED
    //    DACL of exactly {SYSTEM:F, Admins:F, user:R}.
    let lockdown = run_icacls(&setowner_system_args(path_str))
        .and_then(|_| run_icacls(&reset_dacl_args(path_str)))
        .and_then(|_| run_icacls(&windows_lockdown_grant_args(path_str, &user_sid)));
    if let Err(e) = lockdown {
        // Fail closed: a dir we could not secure must not be left behind
        // (ProgramData inheritance would leave it Users-writable).
        let _ = std::fs::remove_dir_all(&d.path);
        result.created = false;
        result.note = format!("ACL lockdown FAILED ({e}); removed the dir (fail closed)");
        log(&format!("    ! {} — {}", path_str, result.note));
        return result;
    }

    // 5. Read the ACL back and verify the acceptance gate. Fail closed on any
    //    violation.
    match read_and_verify_acl(&d.path, &user_sid) {
        Ok(()) => {
            result.acl_applied = true;
            result.note = format!(
                "created + locked + verified (owner SYSTEM; SYSTEM+Administrators full, {user_sid} read; inheritance off; no world/group ACE)"
            );
            log(&format!("    ✓ {} — {}", path_str, result.note));
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&d.path);
            result.created = false;
            result.note =
                format!("ACL read-back verification FAILED ({e}); removed the dir (fail closed)");
            log(&format!("    ! {} — {}", path_str, result.note));
        }
    }
    result
}

/// Unix: `chmod 0750` + root ownership (the dir is created by root under
/// root-owned `/var/lib`, so it is not squattable), plus a best-effort read ACL
/// for the invoking (`SUDO_USER`) account so the operator CLI can read the
/// control-token without being root.
#[cfg(unix)]
fn ensure_one_unix(
    _os: Os,
    d: &DaemonDir,
    path_str: &str,
    log: &mut dyn FnMut(&str),
) -> DaemonDirResult {
    use std::os::unix::fs::PermissionsExt;

    let mut result = DaemonDirResult {
        daemon: d.daemon.to_string(),
        path: path_str.to_string(),
        created: false,
        acl_applied: false,
        note: String::new(),
    };
    if let Err(e) = std::fs::create_dir_all(&d.path) {
        result.note = format!("could not create {path_str}: {e}");
        log(&format!("    ! {} — {}", path_str, result.note));
        return result;
    }
    result.created = true;

    // Owner rwx, group r-x, other none — never world-readable.
    let mode_ok = std::fs::set_permissions(&d.path, std::fs::Permissions::from_mode(0o750)).is_ok();
    if !mode_ok {
        // Fail closed: a token dir we cannot restrict must not be left behind.
        let _ = std::fs::remove_dir_all(&d.path);
        result.created = false;
        result.note = "could not set 0750 permissions; removed the dir (fail closed)".to_string();
        log(&format!("    ! {} — {}", path_str, result.note));
        return result;
    }
    // Best-effort read ACL for the invoking (sudo) user.
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() {
            let _ = std::process::Command::new("setfacl")
                .args(["-m", &format!("u:{user}:rx"), &d.path.to_string_lossy()])
                .hide_console()
                .status();
        }
    }
    result.acl_applied = true;
    result.note = "created + locked down (root:root 0750 + invoking-user read)".to_string();
    log(&format!("    ✓ {} — {}", path_str, result.note));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_dirs_are_under_program_data() {
        let dirs = daemon_dirs(Os::Windows);
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0].daemon, "dig-node");
        assert!(dirs[0].path.ends_with("DigNode"));
        assert_eq!(dirs[1].daemon, "dig-dns");
        assert!(dirs[1].path.ends_with("DigDns"));
    }

    /// Regression for #715: the WebView2 data dir the elevated GUI hands to
    /// WebView2 MUST be an app-owned dir under ProgramData — NEVER the
    /// systemprofile `%LOCALAPPDATA%` path that fails to create when the GUI
    /// runs as LocalSystem.
    #[test]
    fn webview_data_dir_is_app_owned_never_systemprofile() {
        let dir = webview_data_dir();
        assert!(
            dir.ends_with("DigNetwork/installer/webview")
                || dir.ends_with(r"DigNetwork\installer\webview")
        );
        let lossy = dir.to_string_lossy().to_lowercase();
        assert!(
            !lossy.contains("systemprofile"),
            "webview data dir must not resolve under the SYSTEM profile: {dir:?}"
        );
        assert!(
            !lossy.contains("ebwebview"),
            "resolver returns the parent user-data dir, not WebView2's own EBWebView subfolder: {dir:?}"
        );
    }

    #[test]
    fn linux_dirs_are_under_var_lib() {
        let dirs = daemon_dirs(Os::Linux);
        assert_eq!(dirs[0].path, PathBuf::from("/var/lib/dig-node"));
        assert_eq!(dirs[1].path, PathBuf::from("/var/lib/dig-dns"));
    }

    #[test]
    fn macos_dirs_are_under_application_support() {
        let dirs = daemon_dirs(Os::MacOs);
        assert!(dirs[0]
            .path
            .ends_with("Library/Application Support/DigNode"));
        assert!(dirs[1].path.ends_with("Library/Application Support/DigDns"));
    }

    // -- SID resolution + spoof guard (#501 HIGH: spoofable grant principal) ----

    #[test]
    fn parse_whoami_csv_sid_reads_the_token_sid() {
        // `whoami /user /fo csv /nh` → "domain\user","SID".
        assert_eq!(
            parse_whoami_csv_sid("\"mypc\\alice\",\"S-1-5-21-111-222-333-1001\"\r\n").as_deref(),
            Some("S-1-5-21-111-222-333-1001")
        );
        assert_eq!(parse_whoami_csv_sid("no sid here").as_deref(), None);
        assert_eq!(parse_whoami_csv_sid("").as_deref(), None);
    }

    #[test]
    fn forbidden_grant_sids_are_rejected() {
        // The exact spoof: %USERNAME%=Everyone → Everyone SID must be refused.
        assert!(is_forbidden_grant_sid(SID_EVERYONE));
        assert!(is_forbidden_grant_sid(SID_AUTHENTICATED_USERS));
        assert!(is_forbidden_grant_sid(SID_USERS));
        assert!(is_forbidden_grant_sid(SID_SYSTEM));
        // A real interactive-user SID is allowed.
        assert!(!is_forbidden_grant_sid("S-1-5-21-111-222-333-1001"));
    }

    // -- icacls lockdown argv (#501 CRITICAL: owner reset + foreign-ACE purge) --

    #[test]
    fn setowner_forces_system_by_sid_recursively() {
        let args = setowner_system_args(r"C:\ProgramData\DigNode");
        assert!(args.iter().any(|a| a == "/setowner"));
        assert!(
            args.iter().any(|a| a == "*S-1-5-18"),
            "owner must be SYSTEM by SID"
        );
        assert!(args.iter().any(|a| a == "/T")); // recurse to children
    }

    #[test]
    fn reset_purges_explicit_aces() {
        let args = reset_dacl_args(r"C:\ProgramData\DigNode");
        assert!(args.iter().any(|a| a == "/reset"));
        assert!(args.iter().any(|a| a == "/T"));
    }

    #[test]
    fn lockdown_grants_exactly_system_admins_and_the_user_sid() {
        let args = windows_lockdown_grant_args(r"C:\ProgramData\DigNode", "S-1-5-21-9-9-9-1001");
        assert!(args.contains(&"/inheritance:r".to_string()));
        // SYSTEM by SID (not the localized name "SYSTEM").
        assert!(args.iter().any(|a| a == "*S-1-5-18:(OI)(CI)F"));
        assert!(args.iter().any(|a| a == "*S-1-5-32-544:(OI)(CI)F"));
        // The interactive user gets READ only, by SID.
        assert!(args.iter().any(|a| a == "*S-1-5-21-9-9-9-1001:(OI)(CI)R"));
        // Never the localized "SYSTEM" name, never Everyone/Users.
        assert!(!args.iter().any(|a| a.starts_with("SYSTEM:")));
        assert!(!args
            .iter()
            .any(|a| a.contains("Everyone") || a.contains("Users:") || a.contains("S-1-1-0")));
    }

    // -- read-back ACL verification (#501 HIGH: acceptance gate) ----------------

    fn ok_acl(user: &str) -> String {
        format!("OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;{user};False\n")
    }

    #[test]
    fn verify_accepts_a_correctly_locked_dacl() {
        let user = "S-1-5-21-1-2-3-1001";
        assert!(parse_acl_verify(&ok_acl(user), user).is_ok());
    }

    #[test]
    fn verify_rejects_a_world_readable_ace() {
        // The priv-esc: Everyone/Users in the DACL.
        let bad =
            "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;S-1-5-32-545;False\n";
        let e = parse_acl_verify(bad, "S-1-5-32-545").unwrap_err();
        assert!(e.contains("world/group"), "got: {e}");
    }

    #[test]
    fn verify_rejects_an_inherited_ace() {
        // Inheritance not disabled → the dir can inherit ProgramData's Users ACE.
        let bad = "OWNER;S-1-5-18\nACE;S-1-5-18;True\nACE;S-1-5-32-544;False\nACE;S-1-5-21-1-2-3-1001;False\n";
        let e = parse_acl_verify(bad, "S-1-5-21-1-2-3-1001").unwrap_err();
        assert!(e.contains("inheritance is NOT disabled"), "got: {e}");
    }

    #[test]
    fn verify_rejects_an_untrusted_owner() {
        // A squatter-owned dir (owner = a normal user) must fail: owner keeps WRITE_DAC.
        let bad = "OWNER;S-1-5-21-1-2-3-1001\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;S-1-5-21-1-2-3-1001;False\n";
        let e = parse_acl_verify(bad, "S-1-5-21-1-2-3-1001").unwrap_err();
        assert!(e.contains("owner is"), "got: {e}");
    }

    #[test]
    fn verify_rejects_an_unexpected_extra_principal() {
        // A squatter's own (non-group) user SID granted alongside ours is not a
        // well-known group, so it must be caught by the exactly-the-trustees gate.
        let user = "S-1-5-21-1-2-3-1001";
        let bad = format!(
            "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;{user};False\nACE;S-1-5-21-9-9-9-1337;False\n"
        );
        let e = parse_acl_verify(&bad, user).unwrap_err();
        assert!(e.contains("unexpected principal"), "got: {e}");
    }

    #[test]
    fn verify_rejects_a_missing_required_ace() {
        // No READ ACE for the interactive user → operator CLI can't read the token.
        let bad = "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\n";
        let e = parse_acl_verify(bad, "S-1-5-21-1-2-3-1001").unwrap_err();
        assert!(e.contains("missing the required ACE"), "got: {e}");
    }

    #[test]
    fn acl_verify_ps_command_targets_the_dir_and_emits_sids() {
        let cmd = acl_verify_ps_command(r"C:\ProgramData\DigNode");
        assert!(cmd.contains("Get-Acl"));
        assert!(cmd.contains(r"C:\ProgramData\DigNode"));
        assert!(cmd.contains("SecurityIdentifier"));
        assert!(cmd.contains("OWNER;"));
        assert!(cmd.contains("ACE;"));
    }

    #[test]
    fn dry_run_reports_intent_without_creating() {
        let mut lines = Vec::new();
        let out = ensure(Os::Windows, true, &mut |l| lines.push(l.to_string()));
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| !r.created && !r.acl_applied));
        assert!(lines.iter().any(|l| l.contains("would create")));
    }

    #[test]
    fn daemon_dir_result_serializes_with_stable_fields() {
        let r = DaemonDirResult {
            daemon: "dig-node".into(),
            path: r"C:\ProgramData\DigNode".into(),
            created: true,
            acl_applied: true,
            note: "ok".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["daemon"], "dig-node");
        assert_eq!(v["created"], true);
        assert_eq!(v["acl_applied"], true);
    }
}
