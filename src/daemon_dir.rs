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

/// The app-owned WebView2 user-data directory for the installer GUI (#715): its
/// PATH only. Creation + hardening go through [`ensure_webview_data_dir`], which
/// callers MUST use — a bare `create_dir_all` here would be squattable (below).
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
/// Security (#715, corrected): this dir lives under world-writable
/// `%ProgramData%` and is consumed by a SYSTEM/admin WebView2, so it is NOT a
/// harmless cache. A non-privileged user could pre-create it (becoming CREATOR
/// OWNER with `WRITE_DAC`) or plant a junction, then the elevated process would
/// write the browser profile through an attacker-controlled path — a privileged
/// arbitrary-write / profile-poisoning LPE. [`ensure_webview_data_dir`] therefore
/// SYSTEM-owns + locks + reparse-checks it, fail-closed.
pub fn webview_data_dir() -> PathBuf {
    webview_own_subtree(&program_data())
        .pop()
        .expect("the own-subtree always ends at the webview leaf")
}

/// The SHARED DIG data root `%ProgramData%\DigNetwork` — the machine-wide root
/// under which EVERY DIG service keeps state (dig-logging writes
/// `…\DigNetwork\logs\<service>` here; more services adopt it). It is NOT owned
/// by the installer: the installer only creates + hardens it (owner SYSTEM,
/// protected `{SYSTEM:F, Administrators:F}`) so the parent-delete-child hole is
/// closed — but does so NON-recursively and NEVER deletes it, so sibling
/// subtrees like `logs\<service>` keep their own contents + ACLs. Pure.
pub fn dig_shared_root(program_data: &std::path::Path) -> PathBuf {
    program_data.join("DigNetwork")
}

/// The installer's OWN subtree beneath [`dig_shared_root`] that it fully owns +
/// locks + may purge, shallowest first: `DigNetwork\installer`,
/// `DigNetwork\installer\webview`.
///
/// Hardening only the leaf is insufficient (#715, §565): on Windows a child
/// delete is governed by the PARENT's `FILE_DELETE_CHILD`, and `%ProgramData%`
/// grants `CREATOR OWNER: Full`, so a non-admin who pre-creates the intermediate
/// `installer` ancestor OWNS it and can delete + junction-swap even a SYSTEM-owned
/// leaf after this returns. Every level of the installer's own subtree is
/// therefore SYSTEM-owned + locked. The shared `DigNetwork` root above is locked
/// too (via [`dig_shared_root`]) but NOT part of this purgeable set — deleting it
/// would clobber sibling services' state (`logs\<service>`). Pure.
pub fn webview_own_subtree(program_data: &std::path::Path) -> Vec<PathBuf> {
    let installer = dig_shared_root(program_data).join("installer");
    let webview = installer.join("webview");
    vec![installer, webview]
}

/// Given each EXISTING installer-owned dir (shallowest first) paired with its
/// current owner SID (`None` = unreadable), return the SHALLOWEST that must be
/// PURGED because it is NOT trustably owned (owner is neither SYSTEM nor
/// Administrators, or could not be read). Removing that dir removes every deeper
/// dir with it, so a single purge from the shallowest offender closes the whole
/// squat. `None` when every existing level is admin-owned. Only ever called for
/// the installer's OWN subtree ([`webview_own_subtree`]) — NEVER the shared
/// `DigNetwork` root. Pure — the §565 decision is unit-tested without the FS.
pub fn shallowest_untrusted_managed_dir(owners: &[(PathBuf, Option<String>)]) -> Option<PathBuf> {
    owners
        .iter()
        .find(|(_, owner)| {
            !matches!(
                owner.as_deref(),
                Some(SID_SYSTEM) | Some(SID_ADMINISTRATORS)
            )
        })
        .map(|(path, _)| path.clone())
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

/// `icacls <dir> /setowner *S-1-5-18 /C /Q` — force owner = SYSTEM on the dir
/// ONLY (no `/T`). Used for the shared `DigNetwork` root and each installer-owned
/// level so sibling subtrees (`logs\<service>`) are never recursively re-owned.
/// Pure argv.
pub fn setowner_system_args_here(dir: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/setowner".to_string(),
        format!("*{SID_SYSTEM}"),
        "/C".to_string(),
        "/Q".to_string(),
    ]
}

/// `icacls <dir> /reset /C /Q` — drop the dir's OWN explicit ACEs (no `/T`), so a
/// following `/inheritance:r /grant:r` starts clean WITHOUT touching any child's
/// DACL. Pure argv.
pub fn reset_dacl_args_here(dir: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/reset".to_string(),
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

/// `icacls <dir> /inheritance:r /grant:r …` that REPLACES the WebView2 data
/// dir's DACL with exactly `{SYSTEM:F, Administrators:F}` — inheritance disabled,
/// NO Users/interactive-user grant (the GUI runs as SYSTEM/admin, so its browser
/// profile needs no user ACE; #715). Principals by SID (locale-independent).
/// Pure so the exact ACL is unit-tested without touching the FS.
pub fn webview_lockdown_grant_args(dir: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        format!("*{SID_SYSTEM}:(OI)(CI)F"),
        "/grant:r".to_string(),
        format!("*{SID_ADMINISTRATORS}:(OI)(CI)F"),
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
    verify_locked_dacl(output, &[SID_SYSTEM, SID_ADMINISTRATORS, user_sid])
}

/// Verify the WebView2 data dir's DACL (#715) against a TIGHTER gate than the
/// token dir: owner SYSTEM/Administrators; inheritance disabled; no world/group
/// ACE; and EXACTLY `{SYSTEM, Administrators}` — NO user-read ACE at all. The
/// installer GUI runs as SYSTEM/Administrator, so its WebView2 profile needs no
/// interactive-user grant; withholding one keeps a non-privileged user from even
/// reading the SYSTEM/admin browser profile. `Err` on any violation. Pure.
pub fn parse_webview_acl_verify(output: &str) -> Result<(), String> {
    verify_locked_dacl(output, &[SID_SYSTEM, SID_ADMINISTRATORS])
}

/// The shared acceptance-gate check for a hardened, protected DACL: owner is
/// SYSTEM or Administrators; every ACE is explicit (inheritance disabled); no
/// world/group ACE; and the DACL's trustees are EXACTLY `required` — every
/// required principal present, and no principal beyond them. Pure.
fn verify_locked_dacl(output: &str, required: &[&str]) -> Result<(), String> {
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
    for req in required {
        if !ace_sids.iter().any(|s| s == req) {
            return Err(format!("DACL is missing the required ACE for {req}"));
        }
    }
    // Exactly-the-trustees: NO principal beyond `required` may hold an ACE. A
    // foreign user SID (e.g. a squatter granting their own account read/full) is
    // NOT a well-known group so the group check above misses it — reject it here
    // so the acceptance gate is truly closed.
    for sid in &ace_sids {
        if !required.contains(&sid.as_str()) {
            return Err(format!(
                "DACL grants an unexpected principal ({sid}) — only {required:?} may have access"
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

/// `FILE_ATTRIBUTE_REPARSE_POINT` — set on junctions, symlinks, and mount points.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Is `path` itself (NOT its target) a reparse point? Uses `symlink_metadata` so
/// the entry's own attributes are read without traversing the link, and checks
/// the reparse attribute so NTFS junctions (which are not `is_symlink()`) are
/// caught too. A non-existent component reads as `false`.
#[cfg(windows)]
fn is_reparse_point(path: &std::path::Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .unwrap_or(false)
}

/// Is ANY existing component of `path` a reparse point? Walking every ancestor
/// (not just the leaf) defeats a junction planted on `…\DigNetwork` or
/// `…\installer` that would redirect the privileged WebView2 write elsewhere.
#[cfg(windows)]
fn any_component_is_reparse_point(path: &std::path::Path) -> bool {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        if is_reparse_point(&cur) {
            return true;
        }
    }
    false
}

/// Read the WebView2 dir's ACL back and verify it against the tighter WebView2
/// acceptance gate ([`parse_webview_acl_verify`]).
#[cfg(windows)]
fn read_and_verify_webview_acl(path: &std::path::Path) -> Result<(), String> {
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
    parse_webview_acl_verify(&String::from_utf8_lossy(&out.stdout))
}

/// Own + lock ONE directory NON-recursively: owner→SYSTEM, purge its own explicit
/// ACEs (`/reset`), protected `{SYSTEM:F, Administrators:F}` DACL (`/inheritance:r`),
/// then read-back-verify owner + DACL. No `/T` anywhere, so a child subtree
/// (e.g. `logs\<service>`) is never re-owned or re-ACL'd. `Err` (caller decides
/// how to fail closed) on any icacls/verify failure.
#[cfg(windows)]
fn lock_and_verify_here(dir: &std::path::Path) -> Result<(), String> {
    let s = dir.to_string_lossy().into_owned();
    run_icacls(&setowner_system_args_here(&s))
        .and_then(|_| run_icacls(&reset_dacl_args_here(&s)))
        .and_then(|_| run_icacls(&webview_lockdown_grant_args(&s)))?;
    read_and_verify_webview_acl(dir)
}

/// Ensure the WebView2 user-data dir ([`webview_data_dir`]) exists as a
/// SYSTEM-owned, non-squattable, hardened directory and return its path (#715).
///
/// The installer GUI runs ELEVATED (Administrator, sometimes LocalSystem) and
/// hands this path to WebView2 via `WEBVIEW2_USER_DATA_FOLDER`. `%ProgramData%`
/// grants `BUILTIN\Users` create-subfolder + `CREATOR OWNER: Full`, so without
/// hardening a non-admin could pre-create the subtree (or an intermediate
/// ancestor — a Windows child-delete is governed by the PARENT's
/// `FILE_DELETE_CHILD`, so owning `…\installer` lets them delete + junction-swap
/// even a SYSTEM-owned leaf) → a privileged arbitrary-write / profile-poisoning
/// LPE (§565). See [`ensure_webview_data_dir_in`] for the exact model. Any failure
/// returns `Err` (FAIL CLOSED). Off Windows this is unused (unelevated GUI).
#[cfg(windows)]
pub fn ensure_webview_data_dir() -> Result<PathBuf, String> {
    ensure_webview_data_dir_in(&program_data())
}

/// The hardening body, rooted at `program_data` so it is testable against a temp
/// dir. Distinguishes the SHARED `DigNetwork` root from the installer's OWN
/// subtree so a sibling service's state (`logs\<service>`, written by
/// dig-logging) is never clobbered:
///
/// 1. reject any reparse point on the path (junction/symlink redirection);
/// 2. **shared `DigNetwork` root** — ensure it exists, then own + lock it
///    NON-recursively (owner SYSTEM, protected `{SYSTEM:F, Administrators:F}`,
///    no `/T`); a foreign owner is taken over in place, NEVER `remove_dir_all`'d
///    (that would delete sibling `logs\<service>`). Locking the root's DACL —
///    which removes non-admin `DELETE`/`FILE_DELETE_CHILD`/`WRITE_DAC` — is what
///    keeps the parent-delete-child hole closed; `SYSTEM:F` still lets SYSTEM
///    services create/write `logs\<service>`;
/// 3. **`installer` + `webview` (own subtree)** — purge the shallowest level that
///    is foreign-owned, then create each with a NON-recursive `create_dir` under
///    its now-locked parent (so no planted junction/child can be followed) and
///    own + lock each NON-recursively;
/// 4. re-check reparse, then read-back-verify the root + each own level. Fail
///    closed (removing only the installer's OWN subtree, never `DigNetwork`) on
///    any violation.
#[cfg(windows)]
pub fn ensure_webview_data_dir_in(program_data: &std::path::Path) -> Result<PathBuf, String> {
    let root = dig_shared_root(program_data);
    let own = webview_own_subtree(program_data);
    let leaf = own.last().expect("own-subtree ends at the leaf").clone();
    let leaf_str = leaf.to_string_lossy().into_owned();
    // Fail closed by removing ONLY the installer's own subtree — never the shared
    // DigNetwork root (deleting it would clobber logs\<service>).
    let purge_own = || {
        let _ = std::fs::remove_dir_all(&own[0]);
    };

    // 1. Reject reparse points anywhere on the path BEFORE creating/writing.
    if any_component_is_reparse_point(&leaf) {
        return Err(format!(
            "{leaf_str} (or an ancestor) is a reparse point — refusing to write a privileged WebView2 profile through a redirected path (fail closed)"
        ));
    }

    // 2. Shared DigNetwork root: ensure it exists, take ownership in place if it
    //    is foreign-owned (NEVER delete — siblings live here), then lock its DACL
    //    non-recursively. This closes the parent-delete-child hole for `installer`
    //    without touching `logs\<service>`.
    if let Err(e) = create_dir_if_absent(&root) {
        return Err(format!(
            "could not create the shared root {}: {e}",
            root.display()
        ));
    }
    if !matches!(
        dir_owner_sid(&root).as_deref(),
        Some(SID_SYSTEM) | Some(SID_ADMINISTRATORS)
    ) {
        // Take ownership in place (non-recursive) — do NOT purge the shared root.
        let _ = run_icacls(&setowner_system_args_here(&root.to_string_lossy()));
    }
    if let Err(e) = lock_and_verify_here(&root) {
        // Fail closed WITHOUT deleting the shared tree.
        return Err(format!(
            "could not secure the shared DigNetwork root {} ({e}); refusing (fail closed)",
            root.display()
        ));
    }

    // 3. Installer's own subtree: purge the shallowest foreign-owned level, then
    //    create each level non-recursively under its locked parent and lock it.
    let existing_owners: Vec<(PathBuf, Option<String>)> = own
        .iter()
        .filter(|d| d.exists())
        .map(|d| (d.clone(), dir_owner_sid(d)))
        .collect();
    if let Some(bad) = shallowest_untrusted_managed_dir(&existing_owners) {
        let _ = run_icacls(&setowner_system_args(&bad.to_string_lossy()));
        std::fs::remove_dir_all(&bad).map_err(|e| {
            format!(
                "the installer dir {} pre-existed with an untrusted/unknown owner and could not be purged ({e}); refusing (fail closed)",
                bad.display()
            )
        })?;
    }
    for dir in &own {
        if let Err(e) = create_dir_if_absent(dir) {
            purge_own();
            return Err(format!(
                "could not create {} ({e}); fail closed",
                dir.display()
            ));
        }
        if let Err(e) = lock_and_verify_here(dir) {
            purge_own();
            return Err(format!(
                "ACL lockdown/verify FAILED on {} ({e}); removed the installer subtree (fail closed)",
                dir.display()
            ));
        }
    }

    // 4. Re-check reparse (defense against a create/hardening-time swap). The
    //    per-level read-back in step 3 already verified each own level; the root
    //    was verified in step 2.
    if any_component_is_reparse_point(&leaf) {
        purge_own();
        return Err(format!(
            "{leaf_str} became a reparse point during hardening; refusing (fail closed)"
        ));
    }
    Ok(leaf)
}

/// `create_dir` (NON-recursive) treating an already-existing dir as success — the
/// caller creates each level only after its parent is locked, so a recursive
/// `create_dir_all` (which would happily follow a planted intermediate junction)
/// is deliberately avoided.
#[cfg(windows)]
fn create_dir_if_absent(dir: &std::path::Path) -> std::io::Result<()> {
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
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

    // -- WebView2 data-dir hardening (#715 HIGH: elevated ProgramData squat) -----

    #[test]
    fn webview_lockdown_grants_exactly_system_and_admins_no_user() {
        let args = webview_lockdown_grant_args(r"C:\ProgramData\DigNetwork\installer\webview");
        // Inheritance disabled + SYSTEM/Administrators full, both by SID.
        assert!(args.contains(&"/inheritance:r".to_string()));
        assert!(args.iter().any(|a| a == "*S-1-5-18:(OI)(CI)F"));
        assert!(args.iter().any(|a| a == "*S-1-5-32-544:(OI)(CI)F"));
        // NO Users/Everyone/Authenticated-Users ACE, and NO interactive-user ACE
        // (unlike the token dir, WebView2-as-SYSTEM/admin needs no user grant).
        assert!(!args.iter().any(|a| a.contains("S-1-1-0")
            || a.contains("S-1-5-11")
            || a.contains("S-1-5-32-545")));
        assert!(!args.iter().any(|a| a.contains("S-1-5-21-"))); // no user SID
                                                                // Exactly two grants (SYSTEM + Administrators).
        assert_eq!(args.iter().filter(|a| *a == "/grant:r").count(), 2);
    }

    #[test]
    fn shared_root_and_own_subtree_are_correctly_partitioned() {
        let base = PathBuf::from(r"C:\ProgramData");
        // The shared DigNetwork root is NOT part of the installer's own subtree.
        assert!(dig_shared_root(&base).ends_with("DigNetwork"));
        let own = webview_own_subtree(&base);
        assert_eq!(own.len(), 2);
        assert!(
            own[0].ends_with(r"DigNetwork\installer") || own[0].ends_with("DigNetwork/installer")
        );
        assert_eq!(own[1], webview_data_dir_for(&base));
        // The shared root must never appear in the purgeable own-subtree — deleting
        // it would clobber sibling services' state (logs\<service>).
        assert!(!own.iter().any(|d| d == &dig_shared_root(&base)));
    }

    fn webview_data_dir_for(base: &std::path::Path) -> PathBuf {
        base.join("DigNetwork").join("installer").join("webview")
    }

    #[test]
    fn setowner_here_and_reset_here_are_non_recursive() {
        // The regression guard: the shared-root + per-level lockdown must NOT carry
        // /T, or it would recursively re-own/re-ACL sibling logs\<service>.
        let so = setowner_system_args_here(r"C:\ProgramData\DigNetwork");
        assert!(so.iter().any(|a| a == "/setowner"));
        assert!(so.iter().any(|a| a == "*S-1-5-18"));
        assert!(
            !so.iter().any(|a| a == "/T"),
            "shared-root setowner must not recurse"
        );
        let rs = reset_dacl_args_here(r"C:\ProgramData\DigNetwork");
        assert!(rs.iter().any(|a| a == "/reset"));
        assert!(
            !rs.iter().any(|a| a == "/T"),
            "shared-root reset must not recurse"
        );
    }

    #[test]
    fn attacker_owned_installer_level_is_selected_for_purge() {
        // The §565 parent-delete-child hole: a non-admin owns the INTERMEDIATE
        // `installer` level. It must be the purge target so the whole squatted
        // subtree is removed before we create + lock. (The shared DigNetwork root
        // is handled separately and is never in this set.)
        let own = webview_own_subtree(&PathBuf::from(r"C:\ProgramData"));
        let attacker = "S-1-5-21-9-9-9-1001".to_string();
        let owners = vec![
            (own[0].clone(), Some(attacker)), // installer: ATTACKER
            (own[1].clone(), Some("S-1-5-18".to_string())), // webview: SYSTEM
        ];
        assert_eq!(
            shallowest_untrusted_managed_dir(&owners).as_ref(),
            Some(&own[0]),
            "the attacker-owned installer level must be purged"
        );
    }

    #[test]
    fn all_admin_owned_levels_need_no_purge() {
        let own = webview_own_subtree(&PathBuf::from(r"C:\ProgramData"));
        let owners = vec![
            (own[0].clone(), Some("S-1-5-32-544".to_string())),
            (own[1].clone(), Some("S-1-5-18".to_string())),
        ];
        assert_eq!(shallowest_untrusted_managed_dir(&owners), None);
    }

    #[test]
    fn unreadable_owner_level_is_treated_as_untrusted() {
        // A dir whose owner can't be read is not provably admin-owned → purge it.
        let own = webview_own_subtree(&PathBuf::from(r"C:\ProgramData"));
        let owners = vec![(own[0].clone(), None)];
        assert_eq!(
            shallowest_untrusted_managed_dir(&owners).as_ref(),
            Some(&own[0])
        );
    }

    #[test]
    fn webview_verify_accepts_system_and_admins_only() {
        let ok = "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\n";
        assert!(parse_webview_acl_verify(ok).is_ok());
    }

    #[test]
    fn webview_verify_rejects_a_world_readable_ace() {
        // The squat priv-esc: Users/Everyone in the elevated dir's DACL.
        let bad =
            "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;S-1-5-32-545;False\n";
        let e = parse_webview_acl_verify(bad).unwrap_err();
        assert!(e.contains("world/group"), "got: {e}");
    }

    #[test]
    fn webview_verify_rejects_an_inherited_ace() {
        // Inheritance not disabled → the dir inherits ProgramData's Users ACE.
        let bad = "OWNER;S-1-5-18\nACE;S-1-5-18;True\nACE;S-1-5-32-544;False\n";
        let e = parse_webview_acl_verify(bad).unwrap_err();
        assert!(e.contains("inheritance is NOT disabled"), "got: {e}");
    }

    #[test]
    fn webview_verify_rejects_a_foreign_owner() {
        // A squatter-owned dir keeps WRITE_DAC — must be rejected (fail closed).
        let bad = "OWNER;S-1-5-21-1-2-3-1001\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\n";
        let e = parse_webview_acl_verify(bad).unwrap_err();
        assert!(e.contains("owner is"), "got: {e}");
    }

    #[test]
    fn webview_verify_rejects_any_extra_user_ace() {
        // Tighter than the token gate: even a lone interactive-user read ACE is an
        // unexpected principal for the WebView2 dir (no user grant is allowed).
        let bad = "OWNER;S-1-5-18\nACE;S-1-5-18;False\nACE;S-1-5-32-544;False\nACE;S-1-5-21-9-9-9-1001;False\n";
        let e = parse_webview_acl_verify(bad).unwrap_err();
        assert!(e.contains("unexpected principal"), "got: {e}");
    }

    #[test]
    fn webview_verify_rejects_a_missing_admins_ace() {
        let bad = "OWNER;S-1-5-18\nACE;S-1-5-18;False\n";
        let e = parse_webview_acl_verify(bad).unwrap_err();
        assert!(e.contains("missing the required ACE"), "got: {e}");
    }

    /// Regression for #715 (reparse-point redirection): a junction planted on any
    /// path component must be detected so the elevated write is refused. Creates a
    /// real NTFS junction via `mklink /J`; skips if the environment forbids it.
    #[cfg(windows)]
    #[test]
    fn reparse_point_on_a_component_is_detected() {
        let base = std::env::temp_dir().join(format!("dig-webview-reparse-{}", std::process::id()));
        let target = base.join("real-target");
        let link = base.join("junction");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&target).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !made {
            let _ = std::fs::remove_dir_all(&base);
            return; // environment forbids junction creation — decision logic covered elsewhere
        }
        // A plain dir is not a reparse point; the junction (and any path THROUGH
        // it) is.
        assert!(!is_reparse_point(&target));
        assert!(is_reparse_point(&link));
        assert!(any_component_is_reparse_point(&link.join("child")));
        assert!(!any_component_is_reparse_point(&target.join("child")));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Cross-repo regression (#715): `ensure_webview_data_dir` must NOT clobber
    /// the SHARED `%ProgramData%\DigNetwork` root that dig-logging writes
    /// `logs\<service>` into. Rooted at a temp base: a pre-existing
    /// `DigNetwork\logs\svc\x.log` sibling must SURVIVE, `DigNetwork` must not be
    /// `remove_dir_all`'d, and the installer's own `installer`+`webview` levels
    /// must be created (and, where the runner can set owners, SYSTEM-owned +
    /// {SYSTEM,Admins}-locked). ACL assertions are best-effort — a runner without
    /// `SeRestorePrivilege` can't `setowner` SYSTEM, so `ensure` fails closed; even
    /// then the sibling log must survive (that depends only on non-recursion + not
    /// deleting the root, which need no privilege).
    #[cfg(windows)]
    #[test]
    fn ensure_does_not_clobber_the_shared_dignetwork_logs_sibling() {
        let base = std::env::temp_dir().join(format!("dig-webview-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let log = base
            .join("DigNetwork")
            .join("logs")
            .join("svc")
            .join("x.log");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        std::fs::write(&log, b"pre-existing log line").unwrap();

        let result = ensure_webview_data_dir_in(&base);

        // The anti-clobber invariant observable in ANY environment: the shared
        // `DigNetwork` root dir is NEVER `remove_dir_all`'d (the original bug would
        // delete it recursively). Its dir entry survives regardless of ACL state.
        assert!(
            base.join("DigNetwork").exists(),
            "the shared DigNetwork root must never be deleted"
        );

        match result {
            // Elevated runner with Get-Acl (CI): we retain Admins access after the
            // lock, so the sibling log must be readable + byte-identical, the leaf
            // exists, and the root + each own level pass the read-back gate — while
            // the sibling `logs` subtree was NOT recursively re-owned/re-ACL'd.
            Ok(leaf) => {
                assert_eq!(
                    std::fs::read(&log).unwrap(),
                    b"pre-existing log line",
                    "the sibling log contents must be untouched"
                );
                assert!(leaf.exists());
                assert!(read_and_verify_webview_acl(&dig_shared_root(&base)).is_ok());
                for dir in webview_own_subtree(&base) {
                    assert!(
                        read_and_verify_webview_acl(&dir).is_ok(),
                        "own level {dir:?} must verify"
                    );
                }
            }
            // Sandbox without Get-Acl / `SeRestorePrivilege`: `ensure` failed closed
            // WITHOUT deleting the shared tree (asserted above). icacls only
            // re-ACLs, never removes, so the log was not deleted; if this
            // de-privileged process can still read it, assert it is intact.
            Err(_) => {
                if let Ok(bytes) = std::fs::read(&log) {
                    assert_eq!(bytes, b"pre-existing log line");
                }
            }
        }
        // Best-effort cleanup (a locked root may resist removal in a non-elevated
        // sandbox; harmless temp residue).
        let _ = run_icacls(&setowner_system_args(
            &dig_shared_root(&base).to_string_lossy(),
        ));
        let _ = std::fs::remove_dir_all(&base);
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
