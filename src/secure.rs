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
///
/// SID-based (so parsing is locale-independent — never the localized
/// `BUILTIN\Users` display name), read DIRECTLY in SID form via
/// `GetAccessRules($true, $true, [SecurityIdentifier])` — NOT by resolving each
/// ACE's identity NAME to a SID with `.Translate([SecurityIdentifier])`. The
/// default protected root (`%ProgramFiles%\DIG\bin`) inherits Program Files'
/// DACL, which carries AppContainer capability ACEs (`APPLICATION PACKAGE
/// AUTHORITY\ALL APPLICATION PACKAGES` = S-1-15-2-1, `...\ALL RESTRICTED
/// APPLICATION PACKAGES` = S-1-15-2-2) whose reverse name→SID lookup throws
/// `IdentityNotMappedException`; under `$ErrorActionPreference='Stop'` that one
/// untranslatable (benign read/execute) ACE aborted the entire probe, so
/// [`verify_windows`] recorded a false-negative `checked:false` on a genuinely
/// admin-only root (#565). Enumerating the rules already in SID form reads the
/// same explicit+inherited DACL without ever translating a name.
///
/// Pure (single quotes in `dir` are doubled for PowerShell literal safety).
pub fn acl_write_probe_ps_command(dir: &str) -> String {
    let dir = dir.replace('\'', "''");
    format!(
        "$ErrorActionPreference='Stop'; \
         $acl = Get-Acl -LiteralPath '{dir}'; \
         foreach ($a in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {{ \
           'ACE;' + $a.IdentityReference.Value \
             + ';' + [int64]$a.FileSystemRights + ';' + $a.AccessControlType \
         }}"
    )
}

/// Count the well-formed `ACE;<sid>;<rights>;<kind>` lines in
/// [`acl_write_probe_ps_command`] output — the number of access rules the probe
/// actually OBSERVED. Pure.
///
/// A read that classifies as `Ok` over ZERO ACEs is VACUOUS, not secure: an
/// empty stdout with a zero exit would otherwise be reported `checked:true,
/// secure:true` without a single rule having been evaluated (#619). A real DACL
/// on any directory always carries at least the owner/SYSTEM/Administrators
/// ACEs, so an observed count of 0 means the read did not genuinely see the ACL
/// and MUST resolve to `checked:false` (indeterminate) rather than a false
/// "secure".
pub fn count_aces(output: &str) -> usize {
    output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("ACE;"))
        // A well-formed ACE carries at least a sid and a rights field.
        .filter(|rest| rest.split(';').nth(1).is_some_and(|r| !r.trim().is_empty()))
        .count()
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
    let out = std::process::Command::new(crate::proc::system_tool("powershell"))
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .hide_console()
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // #619: a successful exit that emitted ZERO ACEs is a VACUOUS read
            // (empty/garbled Get-Acl output), not proof of an admin-only root.
            // Refuse to report `secure` without having observed at least one
            // access rule — resolve to `checked:false` (indeterminate) instead.
            if count_aces(&stdout) == 0 {
                return InstallRootSecurity {
                    root: root_str.to_string(),
                    checked: false,
                    secure: false,
                    note: "the install-root ACL read returned no access rules (Get-Acl produced \
                           no ACE lines) — indeterminate; the admin-only Program Files location \
                           remains the primary guarantee"
                        .to_string(),
                };
            }
            match parse_acl_write_grants(&stdout) {
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

// -- #732: force PRIVILEGED ownership on the created install-root levels --------
//
// dig-node's #712 hardening requires that EVERY ancestor of a privileged binary's
// install root be owned by SYSTEM, Administrators, or TrustedInstaller before it
// will run self-heal (#565), local-HTTPS provisioning (#661), or system-service
// install (#46). On modern Windows a directory created by an elevated admin USER
// is owned by that USER's SID (NOT one of the accepted groups), so a plain
// `create_dir_all` of `%ProgramFiles%\DIG\bin` leaves the two DIG-scoped levels
// owned by the installing user → dig-node's whole-ancestor walk false-rejects and
// those capabilities SILENTLY degrade (an availability regression, not a hole).
// The fix removes the dependency on the token's default-owner behaviour: the
// installer explicitly FORCES owner = SYSTEM on every level it creates. (An MSI
// deferred custom action runs as SYSTEM and would already satisfy this; forcing
// it makes the plain elevated-admin path deterministic too.)

/// SYSTEM's well-known SID.
const SID_SYSTEM: &str = "S-1-5-18";
/// The BUILTIN\Administrators group SID.
const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// `NT SERVICE\TrustedInstaller` — the default owner of the Program Files tree.
/// Windows sets this on the Program Files root and its OS-managed subfolders.
const SID_TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Is `sid` a PRIVILEGED directory owner in the sense dig-node's #712 install-root
/// ancestor walk requires — SYSTEM, Administrators, or TrustedInstaller? A level
/// owned by anything else (e.g. the installing admin USER's own account SID) makes
/// dig-node's whole-ancestor walk false-reject, silently degrading self-heal
/// (#565) / local-HTTPS (#661) / service-install (#46). The installer forces every
/// level it creates to one of these (SYSTEM), so the walk always accepts the tree.
pub fn is_privileged_owner_sid(sid: &str) -> bool {
    matches!(sid, SID_SYSTEM | SID_ADMINISTRATORS | SID_TRUSTED_INSTALLER)
}

/// The DIG-scoped install-root levels, UNDER `program_files`, that the Windows
/// installer creates and must therefore own explicitly (#732): `…\DIG` and then
/// `…\DIG\bin`, ordered shallowest→deepest. The `program_files` root itself and
/// every ancestor above it are EXCLUDED — Windows already owns those as
/// TrustedInstaller/SYSTEM, and re-owning them would be both unnecessary and
/// hostile. Pure, so the exact set of levels is unit-tested without touching the
/// filesystem.
pub fn windows_created_root_levels(
    bin_dir: &std::path::Path,
    program_files: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    let mut levels: Vec<std::path::PathBuf> = bin_dir
        .ancestors()
        .filter(|a| a.starts_with(program_files) && *a != program_files)
        .map(|a| a.to_path_buf())
        .collect();
    // `ancestors()` yields deepest→shallowest; own the parent before the child.
    levels.reverse();
    levels
}

/// Ensure the protected install `root` exists and is hardened to admin-only
/// write before any binary is placed in it (#565 + #732). Windows: create it,
/// then FORCE owner = SYSTEM + a clean inherited DACL on every DIG-scoped level
/// created under Program Files ([`windows_created_root_levels`]) so dig-node's
/// #712 whole-ancestor privileged-path walk accepts the tree — without this the
/// levels are owned by the installing user and self-heal/HTTPS/service-install
/// silently degrade. Program Files' inherited DACL is already admin-write /
/// user-read+execute, so `/reset` (which restores exactly that inheritance) keeps
/// the CLIs runnable by non-admin users while denying them write. unix: create it
/// root-owned and `chmod 0755` (owner root writes; group/other read+execute only)
/// — DIG deliberately roots at `/opt/dig/bin`, NOT a group-writable Homebrew-style
/// `/usr/local`, which [`verify_install_root`] would (correctly) reject.
/// Best-effort + never panics; the post-place [`verify_install_root`] is the
/// authoritative gate.
pub fn ensure_protected_dir(os: Os, root: &std::path::Path) -> Result<(), String> {
    let _ = os;
    std::fs::create_dir_all(root).map_err(|e| format!("create {}: {e}", root.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod 0755 {}: {e}", root.display()))?;
    }
    #[cfg(windows)]
    {
        force_system_ownership(root)?;
    }
    Ok(())
}

/// Force owner = SYSTEM + a clean inherited DACL on each DIG-scoped level the
/// installer created under Program Files, then read the owner back and confirm it
/// is now a privileged principal ([`is_privileged_owner_sid`]) — the #732 fix.
/// Non-recursive (`…_here`) so a binary later placed in `bin` is not re-owned.
/// `Err` (the caller logs + falls back to the per-binary write) on any failure.
#[cfg(windows)]
fn force_system_ownership(root: &std::path::Path) -> Result<(), String> {
    use crate::daemon_dir::{
        dir_owner_sid, reset_dacl_args_here, run_icacls, setowner_system_args_here,
    };

    for level in windows_created_root_levels(root, &crate::paths::program_files()) {
        let s = level.to_string_lossy().into_owned();
        // Owner → SYSTEM, then drop this level's own explicit ACEs so it inherits
        // Program Files' admin-write / user-read+execute DACL (users keep RX; the
        // #565 no-user-write invariant is preserved by that inheritance).
        run_icacls(&setowner_system_args_here(&s))?;
        run_icacls(&reset_dacl_args_here(&s))?;
        match dir_owner_sid(&level) {
            Some(sid) if is_privileged_owner_sid(&sid) => {}
            Some(sid) => {
                return Err(format!(
                    "{s} owner is {sid} after /setowner — expected a privileged principal \
                     (SYSTEM/Administrators/TrustedInstaller) so dig-node's #712 walk accepts it"
                ));
            }
            None => {
                return Err(format!(
                    "could not read the owner of {s} back after /setowner"
                ))
            }
        }
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

    // -- #619: the vacuous-Ok guard (assert ≥1 ACE before trusting a read) ------

    #[test]
    fn count_aces_counts_only_well_formed_ace_lines() {
        // A real DACL: four proper ACEs.
        assert_eq!(count_aces(program_files_style_acl()), 4);
        // Non-ACE noise + an incomplete `ACE;` (no rights field) count as zero.
        assert_eq!(count_aces("garbage\nACE;incomplete\n\n"), 0);
        assert_eq!(count_aces(""), 0);
        assert_eq!(count_aces("[SC] some unrelated tool output\r\n"), 0);
        // One valid ACE among noise is counted.
        assert_eq!(count_aces("noise\nACE;S-1-5-18;2032127;Allow\n"), 1);
    }

    #[test]
    fn a_read_with_no_aces_is_vacuous_not_secure() {
        // The #619 hole: `parse_acl_write_grants` returns Ok over zero ACEs, so a
        // caller must NOT treat "Ok + no observed ACE" as secure. `count_aces`
        // is the guard: empty/garbled output has no ACEs, so `verify_windows`
        // resolves it to `checked:false` (indeterminate) rather than a false
        // `secure:true`. (The parse itself is still vacuously Ok — hence the guard.)
        assert!(parse_acl_write_grants("").is_ok());
        assert_eq!(count_aces(""), 0, "an empty read observed no access rule");
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

    /// Regression for #565 (the seeded-legacy e2e `checked:false` on the default
    /// protected root): the probe MUST read each ACE's SID DIRECTLY (via
    /// `GetAccessRules(..., [SecurityIdentifier])`) and MUST NOT resolve identity
    /// NAMES to SIDs (`.Translate([SecurityIdentifier])`). Program Files inherits
    /// AppContainer capability ACEs (`APPLICATION PACKAGE AUTHORITY\ALL
    /// APPLICATION PACKAGES` = S-1-15-2-1, `...\ALL RESTRICTED APPLICATION
    /// PACKAGES` = S-1-15-2-2) whose name→SID translation throws
    /// `IdentityNotMappedException`; under `$ErrorActionPreference='Stop'` that
    /// terminating error aborted the whole probe → `verify_windows` recorded a
    /// false-negative `checked:false` on a genuinely admin-only root. Enumerating
    /// in SID form never translates a name, so those benign read/execute ACEs no
    /// longer break the read-back.
    #[test]
    fn acl_probe_reads_sids_directly_without_name_translation() {
        let cmd = acl_write_probe_ps_command(r"C:\Program Files\DIG\bin");
        assert!(
            !cmd.contains("Translate"),
            "the probe must not name→SID Translate (throws on Program Files' \
             inherited AppContainer ACEs): {cmd}"
        );
        assert!(
            cmd.contains("GetAccessRules"),
            "the probe must enumerate the DACL already in SID form: {cmd}"
        );
    }

    /// The faithful mechanism reproduction (Windows-only): verifying a real
    /// directory that inherits Program Files' DACL — every Windows box has
    /// `C:\Program Files\Common Files` with the untranslatable AppContainer ACEs —
    /// must actually RUN the read-back (`checked == true`), not fall into the
    /// indeterminate arm. With the pre-fix `.Translate` probe this was
    /// `checked:false`; with SID-form enumeration it reads the DACL and, since
    /// Program Files denies unprivileged write, reports `secure: true`.
    #[cfg(windows)]
    #[test]
    fn windows_verify_runs_on_a_program_files_dir_with_appcontainer_aces() {
        let dir = std::path::Path::new(r"C:\Program Files\Common Files");
        if !dir.is_dir() {
            return; // extraordinarily rare, but never fail on a nonstandard box
        }
        let v = verify_install_root(Os::Windows, dir);
        assert!(
            v.checked,
            "the ACL read-back must run on a Program Files dir (inherited \
             AppContainer ACEs must not abort it): {}",
            v.note
        );
        assert!(
            v.secure,
            "Program Files denies unprivileged write, so it must verify secure: {}",
            v.note
        );
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

    // -- #732: privileged-owner classification + created-level computation ------

    #[test]
    fn privileged_owner_accepts_system_administrators_trustedinstaller() {
        // Exactly dig-node's #712 accept list — the three principals whose
        // ownership lets the whole-ancestor walk pass.
        assert!(is_privileged_owner_sid(SID_SYSTEM));
        assert!(is_privileged_owner_sid(SID_ADMINISTRATORS));
        assert!(is_privileged_owner_sid(SID_TRUSTED_INSTALLER));
    }

    #[test]
    fn privileged_owner_rejects_an_interactive_user_sid() {
        // The exact #732 availability trap: a level owned by the installing admin
        // USER's own account SID must NOT count as privileged (it fails the walk).
        assert!(!is_privileged_owner_sid(
            "S-1-5-21-1004336348-1177238915-682003330-1001"
        ));
        assert!(!is_privileged_owner_sid(SID_USERS)); // BUILTIN\Users is not an owner we accept
        assert!(!is_privileged_owner_sid(SID_EVERYONE));
        assert!(!is_privileged_owner_sid(""));
    }

    // Paths are built with `join` (host-native separators) so the pure path
    // arithmetic is exercised identically on a Windows or a unix CI runner — a
    // literal `C:\…` string is ONE component on unix (backslash is not a
    // separator there) and would make every ancestor check vacuously empty.

    #[test]
    fn created_levels_are_the_two_dig_scoped_dirs_under_program_files() {
        // The installer creates `…/DIG` then `…/DIG/bin`; both must be owned, and
        // Program Files itself (already TrustedInstaller-owned) must NOT be.
        let pf = std::path::Path::new("C_drive").join("Program Files");
        let dig = pf.join("DIG");
        let bin = dig.join("bin");
        let levels = windows_created_root_levels(&bin, &pf);
        assert_eq!(
            levels,
            vec![dig, bin],
            "own the parent DIG level before its bin child, and never Program Files itself"
        );
    }

    #[test]
    fn created_levels_exclude_program_files_and_its_ancestors() {
        let pf = std::path::Path::new("C_drive").join("Program Files");
        let bin = pf.join("DIG").join("bin");
        let levels = windows_created_root_levels(&bin, &pf);
        assert!(
            !levels.contains(&pf),
            "must never re-own the Program Files root"
        );
        assert!(
            !levels.contains(&std::path::PathBuf::from("C_drive")),
            "must never re-own an ancestor above Program Files"
        );
    }

    #[test]
    fn created_levels_ordered_shallowest_first() {
        // Parents must be owned before children so a child is never orphaned under
        // a not-yet-owned parent.
        let pf = std::path::Path::new("C_drive").join("Program Files");
        let bin = pf.join("DIG").join("bin");
        let levels = windows_created_root_levels(&bin, &pf);
        for pair in levels.windows(2) {
            assert!(
                pair[1].starts_with(&pair[0]),
                "{:?} should be a descendant of {:?}",
                pair[1],
                pair[0]
            );
        }
    }
}
