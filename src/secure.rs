//! Install-root hardening + the fail-loud "denies unprivileged write" verify
//! gate (#565).
//!
//! The #565 LPE: the installer used to place binaries a LocalSystem service /
//! the SYSTEM auto-update beacon task later executes into a USER-WRITABLE dir,
//! so any unprivileged user could replace one and get code execution as SYSTEM.
//! The primary fix is the LOCATION — everything privileged now installs into the
//! admin-only [`crate::paths::protected_bin_dir`] (`%ProgramFiles%\DIG\bin` /
//! `/opt/dig/bin`). This module is the defense-in-depth VERIFY on top of that:
//! after placing binaries, it reads the root's effective permissions back and
//! asserts an unprivileged principal cannot WRITE there — the machine-checkable
//! form of the acceptance criterion.
//!
//! Layering (mirrors [`crate::daemon_dir`]): the SID/rights classification and
//! the `Get-Acl` command builder are PURE and unit-tested; the `Get-Acl` /
//! `chmod` / owner-read I/O is the thin per-OS layer. On Windows the check is
//! SID-based (`*S-1-5-32-545` etc., never localized display names); on unix it
//! is the file mode (no group/other write) + root ownership.

use crate::target::Os;

/// Well-known UNPRIVILEGED principal SIDs. An Allow ACE granting WRITE to any of
/// these on the install root is the #565 escalation this gate refuses.
const SID_EVERYONE: &str = "S-1-1-0";
const SID_INTERACTIVE: &str = "S-1-5-4";
const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
const SID_USERS: &str = "S-1-5-32-545";

/// The `FileSystemRights` bits that let a principal MODIFY or REPLACE a file in
/// the directory (so it could swap a service binary): `WriteData`/`CreateFiles`
/// (0x2), `AppendData`/`CreateDirectories` (0x4), `WriteExtendedAttributes`
/// (0x10), `WriteAttributes` (0x100), `Delete` (0x10000), `ChangePermissions`
/// (0x40000), `TakeOwnership` (0x80000), plus the generic `GENERIC_WRITE`
/// (0x40000000) and `GENERIC_ALL` (0x10000000). `Modify`/`FullControl`/`Write`
/// are unions that include these bits, so masking catches them all. Read/execute
/// rights (0x20, 0x80000000 GENERIC_READ, etc.) are deliberately absent — the
/// user reading/running a binary is fine; only WRITING it is the escalation.
const WRITE_MASK: i64 =
    0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x4000_0000 | 0x1000_0000;

/// Is `sid` a well-known UNPRIVILEGED principal (one that any local user's token
/// carries)? A WRITE grant to one of these on the install root is the priv-esc.
pub fn is_unprivileged_write_principal(sid: &str) -> bool {
    matches!(
        sid,
        SID_EVERYONE | SID_INTERACTIVE | SID_AUTHENTICATED_USERS | SID_USERS
    )
}

/// Does `rights` (a Windows `FileSystemRights` integer) include any bit that
/// permits modifying/replacing a file? Pure.
pub fn grants_write(rights: i64) -> bool {
    rights & WRITE_MASK != 0
}

/// The PowerShell one-liner that emits the directory's access ACEs as SID-based
/// `ACE;<sid>;<rightsInt>;<Allow|Deny>` lines for [`parse_acl_write_grants`].
/// SID-based (translating each identity to its `SecurityIdentifier`), so parsing
/// is locale-independent — never the localized `BUILTIN\Users` display name.
/// Pure (single quotes in `dir` are doubled for PowerShell literal safety).
pub fn acl_write_probe_ps_command(dir: &str) -> String {
    let dir = dir.replace('\'', "''");
    format!(
        "$ErrorActionPreference='Stop'; \
         $acl = Get-Acl -LiteralPath '{dir}'; \
         foreach ($a in $acl.Access) {{ \
           'ACE;' + $a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value \
             + ';' + [int64]$a.FileSystemRights + ';' + $a.AccessControlType \
         }}"
    )
}

/// Classify [`acl_write_probe_ps_command`] output: `Err` iff any **Allow** ACE
/// grants a write-capable right ([`grants_write`]) to a well-known unprivileged
/// principal ([`is_unprivileged_write_principal`]) — the #565 escalation. `Deny`
/// ACEs (which only restrict) and read/execute-only Allow ACEs are fine. Pure —
/// so the acceptance criterion ("the install location denies unprivileged
/// write") is unit-tested directly against captured ACL fixtures.
pub fn parse_acl_write_grants(output: &str) -> Result<(), String> {
    for line in output.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("ACE;") else {
            continue;
        };
        let mut parts = rest.split(';');
        let sid = parts.next().unwrap_or("").trim();
        let rights = parts
            .next()
            .and_then(|r| r.trim().parse::<i64>().ok())
            .unwrap_or(0);
        let kind = parts.next().unwrap_or("").trim();
        // Only Allow ACEs GRANT access; a Deny ACE tightens, never a risk.
        if !kind.eq_ignore_ascii_case("Allow") {
            continue;
        }
        if is_unprivileged_write_principal(sid) && grants_write(rights) {
            return Err(format!(
                "the install root grants WRITE to an unprivileged principal ({sid}) — a \
                 non-admin could replace a service binary (local privilege escalation)"
            ));
        }
    }
    Ok(())
}

/// The verdict of verifying the install root denies unprivileged write (#565) —
/// part of the `--json` [`crate::InstallReport`]. Never silent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InstallRootSecurity {
    /// The install root that was checked.
    pub root: String,
    /// The effective permissions were actually read back and evaluated. `false`
    /// on dry-run or when the OS check could not run (indeterminate — a warning,
    /// never a false "secure").
    pub checked: bool,
    /// The root DENIES write to every unprivileged principal (the #565
    /// invariant). Only `true` when [`Self::checked`] and the read-back proved
    /// it. Readiness fails only on a DEFINITIVE `checked && !secure`.
    pub secure: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// Verify the install `root` denies unprivileged write (#565). Windows: read the
/// DACL back via `Get-Acl` and refuse any unprivileged Allow-write ACE. unix:
/// the dir must be root-owned with no group/other write bit (`0o0755` posture).
/// A read-back that cannot run resolves to `checked: false` (a warning, not a
/// false success). Never panics.
pub fn verify_install_root(os: Os, root: &std::path::Path) -> InstallRootSecurity {
    let root_str = root.to_string_lossy().into_owned();
    #[cfg(windows)]
    {
        let _ = os;
        return verify_windows(&root_str, root);
    }
    #[cfg(unix)]
    {
        let _ = os;
        return verify_unix(&root_str, root);
    }
    #[allow(unreachable_code)]
    {
        let _ = os;
        InstallRootSecurity {
            root: root_str,
            checked: false,
            secure: false,
            note: "install-root ACL verification is not supported on this OS".to_string(),
        }
    }
}

#[cfg(windows)]
fn verify_windows(root_str: &str, root: &std::path::Path) -> InstallRootSecurity {
    use crate::proc::HideConsole;
    let ps = acl_write_probe_ps_command(&root.to_string_lossy());
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .hide_console()
        .output();
    match out {
        Ok(o) if o.status.success() => {
            match parse_acl_write_grants(&String::from_utf8_lossy(&o.stdout)) {
                Ok(()) => InstallRootSecurity {
                    root: root_str.to_string(),
                    checked: true,
                    secure: true,
                    note: "the install root denies write to unprivileged principals \
                           (admin-only, no Users/Everyone/Authenticated-Users write ACE)"
                        .to_string(),
                },
                Err(e) => InstallRootSecurity {
                    root: root_str.to_string(),
                    checked: true,
                    secure: false,
                    note: e,
                },
            }
        }
        _ => InstallRootSecurity {
            root: root_str.to_string(),
            checked: false,
            secure: false,
            note: "could not read the install-root ACL back (Get-Acl did not run) — the \
                   admin-only Program Files location is still the primary guarantee"
                .to_string(),
        },
    }
}

#[cfg(unix)]
fn verify_unix(root_str: &str, root: &std::path::Path) -> InstallRootSecurity {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(root) {
        Ok(md) => {
            let mode = md.permissions().mode();
            let group_or_other_write = mode & 0o022 != 0;
            let root_owned = md.uid() == 0;
            if group_or_other_write {
                InstallRootSecurity {
                    root: root_str.to_string(),
                    checked: true,
                    secure: false,
                    note: format!(
                        "the install root is group/other-writable (mode {:o}) — a non-root user \
                         could replace a service binary",
                        mode & 0o777
                    ),
                }
            } else if !root_owned {
                InstallRootSecurity {
                    root: root_str.to_string(),
                    checked: true,
                    secure: false,
                    note: format!(
                        "the install root is owned by uid {} (not root) — its owner could replace \
                         a service binary",
                        md.uid()
                    ),
                }
            } else {
                InstallRootSecurity {
                    root: root_str.to_string(),
                    checked: true,
                    secure: true,
                    note: format!(
                        "the install root is root-owned with no group/other write (mode {:o})",
                        mode & 0o777
                    ),
                }
            }
        }
        Err(e) => InstallRootSecurity {
            root: root_str.to_string(),
            checked: false,
            secure: false,
            note: format!("could not stat the install root to verify its permissions: {e}"),
        },
    }
}

/// Ensure the protected install `root` exists and is hardened to admin-only
/// write before any binary is placed in it (#565). Windows: create it — Program
/// Files' inherited DACL is already admin-write / user-read+execute, so no
/// custom ACL is applied (avoiding the [`crate::daemon_dir`]-style fragility a
/// user-writable PARENT would introduce; Program Files has no such parent). unix:
/// create it root-owned and `chmod 0755` (owner root writes; group/other
/// read+execute only). Best-effort + never panics; the post-place
/// [`verify_install_root`] is the authoritative gate.
pub fn ensure_protected_dir(os: Os, root: &std::path::Path) -> Result<(), String> {
    let _ = os;
    std::fs::create_dir_all(root).map_err(|e| format!("create {}: {e}", root.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod 0755 {}: {e}", root.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_rights_are_detected_across_the_standard_unions() {
        // FullControl / Modify / Write all carry write bits.
        assert!(grants_write(2032127), "FullControl grants write");
        assert!(grants_write(197055), "Modify grants write");
        assert!(grants_write(278), "Write grants write");
        assert!(grants_write(0x2), "bare WriteData grants write");
        assert!(grants_write(0x10000), "Delete grants write");
        assert!(grants_write(0x4000_0000), "GENERIC_WRITE grants write");
        assert!(grants_write(0x1000_0000), "GENERIC_ALL grants write");
    }

    #[test]
    fn read_and_execute_only_rights_do_not_count_as_write() {
        // ReadAndExecute (0x20 0x80000 read?) — the real values: Read = 131209,
        // ReadAndExecute = 131241, ExecuteFile = 0x20, ReadData = 0x1. None carry
        // a write bit, so a user with read+execute must NOT trip the gate.
        assert!(!grants_write(131241), "ReadAndExecute is not write");
        assert!(!grants_write(131209), "Read is not write");
        assert!(!grants_write(0x20), "ExecuteFile is not write");
        assert!(!grants_write(0x1), "ReadData is not write");
        assert!(!grants_write(0), "no rights is not write");
    }

    #[test]
    fn unprivileged_principals_are_the_well_known_broad_sids() {
        assert!(is_unprivileged_write_principal(SID_USERS));
        assert!(is_unprivileged_write_principal(SID_EVERYONE));
        assert!(is_unprivileged_write_principal(SID_AUTHENTICATED_USERS));
        assert!(is_unprivileged_write_principal(SID_INTERACTIVE));
        // SYSTEM + Administrators are PRIVILEGED — a write grant to them is fine.
        assert!(!is_unprivileged_write_principal("S-1-5-18"));
        assert!(!is_unprivileged_write_principal("S-1-5-32-544"));
        // A concrete interactive-user SID is not a broad group.
        assert!(!is_unprivileged_write_principal("S-1-5-21-1-2-3-1001"));
    }

    // -- parse_acl_write_grants: the acceptance-criterion gate ------------------

    /// A realistic Program Files DACL: SYSTEM + Administrators full; Users +
    /// Authenticated Users read+execute only. The #565 invariant holds → Ok.
    fn program_files_style_acl() -> &'static str {
        "ACE;S-1-5-18;2032127;Allow\n\
         ACE;S-1-5-32-544;2032127;Allow\n\
         ACE;S-1-5-11;131241;Allow\n\
         ACE;S-1-5-32-545;131241;Allow\n"
    }

    #[test]
    fn accepts_a_program_files_style_admin_only_dacl() {
        assert!(parse_acl_write_grants(program_files_style_acl()).is_ok());
    }

    #[test]
    fn rejects_users_write() {
        // The exact #565 hole: BUILTIN\Users granted Modify → escalation.
        let bad = "ACE;S-1-5-18;2032127;Allow\nACE;S-1-5-32-545;197055;Allow\n";
        let e = parse_acl_write_grants(bad).unwrap_err();
        assert!(e.contains("S-1-5-32-545"), "got: {e}");
        assert!(e.contains("privilege escalation"), "got: {e}");
    }

    #[test]
    fn rejects_everyone_full_control() {
        let bad = "ACE;S-1-1-0;2032127;Allow\n";
        assert!(parse_acl_write_grants(bad).is_err());
    }

    #[test]
    fn rejects_authenticated_users_write_and_interactive_write() {
        assert!(parse_acl_write_grants("ACE;S-1-5-11;278;Allow\n").is_err());
        assert!(parse_acl_write_grants("ACE;S-1-5-4;0x0;Deny\n").is_ok()); // deny is fine
        assert!(parse_acl_write_grants("ACE;S-1-5-4;278;Allow\n").is_err());
    }

    #[test]
    fn a_deny_write_ace_for_users_is_not_a_grant() {
        // A Deny ACE only RESTRICTS — it must never be read as granting write.
        let ok = "ACE;S-1-5-18;2032127;Allow\nACE;S-1-5-32-545;197055;Deny\n";
        assert!(parse_acl_write_grants(ok).is_ok());
    }

    #[test]
    fn a_users_read_execute_ace_is_allowed() {
        // Users may READ/EXECUTE the installed binaries — only WRITE is refused.
        assert!(parse_acl_write_grants("ACE;S-1-5-32-545;131241;Allow\n").is_ok());
    }

    #[test]
    fn ignores_malformed_and_non_ace_lines() {
        let mixed = "garbage\nACE;S-1-5-18;2032127;Allow\nACE;incomplete\n\n";
        assert!(parse_acl_write_grants(mixed).is_ok());
    }

    #[test]
    fn acl_write_probe_ps_command_targets_the_dir_and_emits_sids() {
        let cmd = acl_write_probe_ps_command(r"C:\Program Files\DIG\bin");
        assert!(cmd.contains("Get-Acl"));
        assert!(cmd.contains(r"C:\Program Files\DIG\bin"));
        assert!(cmd.contains("SecurityIdentifier"));
        assert!(cmd.contains("FileSystemRights"));
        assert!(cmd.contains("AccessControlType"));
        assert!(cmd.contains("ACE;"));
    }

    #[test]
    fn install_root_security_serializes_with_stable_fields() {
        let r = InstallRootSecurity {
            root: r"C:\Program Files\DIG\bin".into(),
            checked: true,
            secure: true,
            note: "ok".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["checked"], true);
        assert_eq!(v["secure"], true);
        assert_eq!(v["root"], r"C:\Program Files\DIG\bin");
    }

    #[cfg(unix)]
    #[test]
    fn unix_verify_flags_a_group_or_other_writable_root() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dig-secure-ug-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 0o777 → group + other write present → NOT secure.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let v = verify_install_root(Os::Linux, &dir);
        assert!(v.checked);
        assert!(
            !v.secure,
            "a world-writable root must be flagged: {}",
            v.note
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unix_verify_accepts_a_0755_owner_writable_root() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dig-secure-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let v = verify_install_root(Os::Linux, &dir);
        assert!(v.checked);
        // The test process owns the dir (uid == its own). In CI that is uid 0
        // (root container) → secure; as a normal dev user (uid != 0) the
        // ownership check correctly reports NOT secure. Assert on whichever
        // ownership the runner has, so the test is deterministic either way.
        if md_uid(&dir) == 0 {
            assert!(v.secure, "root-owned 0755 must be secure: {}", v.note);
        } else {
            assert!(!v.secure, "non-root-owned must be flagged: {}", v.note);
            assert!(v.note.contains("not root"), "got: {}", v.note);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn md_uid(p: &std::path::Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).unwrap().uid()
    }
}
