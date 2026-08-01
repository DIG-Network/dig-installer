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

// `Command::new` is denied crate-wide so an unguarded spawn of an INSTALLED binary cannot compile
// (`clippy.toml`, #1748 WU4). The spawns in this module are either trusted SYSTEM tools resolved from a
// fixed directory list (`SPEC.md` §7.6 — a different invariant with its own tests in `elevation`), test
// fixtures, or the guarded wrapper itself.
#![allow(clippy::disallowed_methods)]

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

/// The PowerShell expression that binds the ACL of `path` **without invoking a
/// cmdlet** — `[System.Security.AccessControl.{Directory,File}Security]::new(…)`
/// selected by a `[System.IO.Directory]::Exists` test, so the same expression
/// serves a directory and a file.
///
/// # Why not `Get-Acl` (#1910)
///
/// `Get-Acl` lives in the `Microsoft.PowerShell.Security` MODULE and is reached
/// only by module autoloading, which resolves through the INHERITED
/// `%PSModulePath%`. A pwsh 7 / Git Bash session exports a `PSModulePath` whose
/// entries are the pwsh ones, and Windows PowerShell then fails the autoload
/// outright:
///
/// ```text
/// Get-Acl : The 'Get-Acl' command was found in the module
/// 'Microsoft.PowerShell.Security', but the module could not be loaded.
/// ```
///
/// Every ACL read-back in this crate then returns "could not read" — which is
/// fail-CLOSED, but the closed behaviour is a silently degraded install (the ARP
/// entry skipped, the hardened state dirs removed) for a user whose only mistake
/// was the shell they launched from. Constructing the .NET security object
/// directly needs no module, no autoload, and no `PSModulePath` at all.
///
/// It also removes an elevated-child hijack surface of the same shape as #657: an
/// inherited `PSModulePath` entry that an unprivileged account can write is a
/// module an ELEVATED PowerShell child would autoload. [`crate::proc::powershell`]
/// clears the variable for the same reason; this expression makes the read
/// independent of it either way.
///
/// Pure (single quotes in `path` are doubled for PowerShell literal safety).
pub fn acl_object_expression(path: &str) -> String {
    let path = path.replace('\'', "''");
    format!(
        "$p = '{path}'; \
         $acl = if ([System.IO.Directory]::Exists($p)) \
           {{ [System.Security.AccessControl.DirectorySecurity]::new($p, 'Owner,Access') }} \
           else {{ [System.Security.AccessControl.FileSecurity]::new($p, 'Owner,Access') }}; "
    )
}

/// The PowerShell one-liner that emits the path's owner as `OWNER;<sid>` and its
/// access ACEs as SID-based `ACE;<sid>;<rightsInt>;<Allow|Deny>` lines, for
/// [`parse_acl_write_grants`] (a directory, #565) and
/// [`parse_placed_binary_acl`] (a placed file, #1910).
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
    format!(
        "$ErrorActionPreference='Stop'; {bind}\
         'OWNER;' + $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; \
         foreach ($a in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {{ \
           'ACE;' + $a.IdentityReference.Value \
             + ';' + [int64]$a.FileSystemRights + ';' + $a.AccessControlType \
         }}",
        bind = acl_object_expression(dir)
    )
}

/// The owner SID reported by [`acl_write_probe_ps_command`], if the read produced
/// one. Pure.
pub fn parse_acl_owner(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|l| l.trim().strip_prefix("OWNER;"))
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with("S-1-"))
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

/// Refuse to EXECUTE `bin` while running as root when the directory it sits in is not
/// privilege-safe — the write→exec local privilege escalation, checked at the EXEC rather than only at
/// the placement.
///
/// # Why an exec-time check, when the install root is already verified
///
/// [`verify_install_root`] is applied to [`crate::InstallPlan::privileged_install_root`] — the dir
/// PRIVILEGED binaries land in — and it runs AFTER placement. Neither property covers this: an elevated
/// unix install puts USER CLIs in `paths::UNIX_MACHINE_BIN_DIR` (`/usr/local/bin`), which Homebrew on an
/// Intel Mac leaves `<user>:admin 0775`, and root then executes them — the `--version` probe runs
/// BEFORE any download or write, on every component. No race is needed: unprivileged code running as
/// that user drops an executable at `/usr/local/bin/dig-node` and waits for the next
/// `curl … | sudo sh`, which the documented install path makes routine.
///
/// `SPEC.md` already forbids exactly this (§4.1a "the privileged process never execs the user root's
/// `digstore`", §4.1c "NEVER execs a user-writable binary"), and the GUI honours it via
/// `should_exec_verify`. This is that same rule, enforced in the library the GUI's root child calls into.
///
/// # Placement is the primary defence; this guard covers what an override can still redirect
///
/// The invariant is upheld first by PLACEMENT: an elevated install puts every binary in the root-owned
/// [`crate::paths::protected_bin_dir`], so the directory root execs from is not user-writable at all
/// (`SPEC.md` §7.5). Placement alone is NOT sufficient, because an explicit `--bin-dir` override
/// redirects the whole stack to a directory the invoking user chose.
///
/// **This comment deliberately does not enumerate the call sites.** Two earlier revisions did, and both
/// were wrong — the first claimed placement covered sites it did not, the second listed four sites while a
/// fifth existed and was proved to root code execution. An enumeration in a comment is a claim that rots
/// the moment somebody adds a caller, and a claim the code fails to satisfy is worse than no claim.
///
/// The set is instead closed by CONSTRUCTION: [`crate::guardedcmd::GuardedCommand::for_installed_binary`]
/// is the only way to spawn an installed binary, it calls this guard before yielding a value, and
/// `clippy.toml` denies `std::process::Command::new` outside the modules that spawn trusted system tools.
/// An unguarded root-side exec does not compile, so there is no list to keep current.
///
/// Unelevated it is always `Ok`: executing a binary the user themselves can write is not an escalation,
/// it is their own authority. An INDETERMINATE permission read (`checked: false`) is also `Ok` — the
/// same posture [`verify_install_root`]'s callers take, so an unreadable dir is never a false refusal.
/// Only a DEFINITIVE breach refuses.
pub fn root_exec_guard(bin: &std::path::Path) -> Result<(), String> {
    if !crate::invoker::is_root() {
        return Ok(());
    }
    let Some(dir) = bin.parent() else {
        return Ok(());
    };
    // `os` is vestigial in `verify_install_root` (each arm is selected by `cfg`, not by this value), so
    // the host's own OS is the honest thing to pass.
    let os =
        crate::target::Os::from_consts(std::env::consts::OS).unwrap_or(crate::target::Os::Linux);
    let verdict = verify_install_root(os, dir);
    if verdict.is_blocking() {
        return Err(format!(
            "refusing to run {} as root: {} — a binary in a directory an unprivileged account can \
             write is one they can REPLACE, so running it as root would execute their code with full \
             privilege. Install the privileged components into a root-owned directory (the default \
             {}) and re-run.",
            bin.display(),
            verdict.note,
            crate::paths::protected_bin_dir().display()
        ));
    }
    Ok(())
}

/// The verdict of verifying the install root denies unprivileged write (#565) —
/// part of the `--json` [`crate::InstallReport`]. Never silent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InstallRootSecurity {
    /// The install root that was checked.
    pub root: String,
    /// Were the effective permissions actually read back and evaluated?
    ///
    /// PRIVATE, and it must stay private: this field plus [`Self::posture_is_safe`] are the two halves of
    /// a POLICY, and every site that read them re-derived that policy for itself. Ask
    /// [`Self::is_blocking`] instead.
    ///
    /// Serialized as `checked` so `install.json` is unchanged; named distinctly in Rust so the check that
    /// keeps the policy in one place can name it precisely (`checked` is an ordinary word that other
    /// unrelated report types also use).
    #[serde(rename = "checked")]
    posture_was_read: bool,
    /// Does the root DENY write to every unprivileged principal (the #565 invariant)?
    ///
    /// PRIVATE for the same reason as [`Self::posture_was_read`], and serialized as `secure`. Only `true`
    /// when the read-back proved it.
    #[serde(rename = "secure")]
    posture_is_safe: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

impl InstallRootSecurity {
    /// MUST this verdict stop what the caller was about to do?
    ///
    /// # Why this is the only question callers may ask (#1748)
    ///
    /// `checked` and `secure` are two halves of one policy, and for six rounds every call site
    /// re-derived that policy as `if verdict.checked && !verdict.secure` — "block only on a DEFINITIVE
    /// breach". Seven sites, seven independent copies. The type therefore offered each new caller the
    /// chance to get it wrong, and each round a new caller took it: the same class was found and fixed
    /// five times running, one level over each time, because the fix was always to the SITE.
    ///
    /// The policy is decided once, here, and it INCLUDES the indeterminate case. A verdict that could
    /// not be established is not a pass:
    ///
    /// * the whole-chain walk returns `Err` when a level cannot be inspected — which is also what a
    ///   REFUSAL looks like, and refusals are exactly the interesting answers;
    /// * `if checked && !secure` reads "indeterminate → proceed", so the strongest detection this crate
    ///   can make printed a tick and root went on to exec an attacker's binary.
    ///
    /// # What this costs, and why it is the right trade
    ///
    /// A genuinely unreadable directory now blocks rather than warning. That is the conservative
    /// direction: the failure mode is an install that refuses and says which level it could not verify,
    /// against one that silently grants root execution out of a directory a stranger can write. The
    /// note always names the level, so an operator is never left guessing.
    ///
    /// Unelevated callers do not consult this at all ([`root_exec_guard`] returns early), so an ordinary
    /// per-user install is unaffected.
    pub fn is_blocking(&self) -> bool {
        !self.posture_is_safe
    }

    /// Was the posture positively ESTABLISHED as safe?
    ///
    /// The inverse of [`Self::is_blocking`], for log lines that want to print a tick. Deliberately the
    /// only other question available, so no caller can reconstruct the two-field policy.
    pub fn is_established_safe(&self) -> bool {
        self.posture_is_safe
    }

    /// The posture was READ and every level denies unprivileged write.
    pub fn established_safe(root: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            posture_was_read: true,
            posture_is_safe: true,
            note: note.into(),
        }
    }

    /// A level was positively DETECTED unsafe — writable, wrongly owned, or a symlink.
    pub fn detected_unsafe(root: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            posture_was_read: true,
            posture_is_safe: false,
            note: note.into(),
        }
    }

    /// The posture could not be established at all.
    ///
    /// Named separately from [`Self::detected_unsafe`] because the DISTINCTION is real and worth keeping
    /// in the log — but both BLOCK, which is the whole point of [`Self::is_blocking`]. An outcome nobody
    /// could establish is not evidence of safety.
    pub fn indeterminate(root: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            posture_was_read: false,
            posture_is_safe: false,
            note: note.into(),
        }
    }
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
        InstallRootSecurity::indeterminate(
            root_str,
            "install-root ACL verification is not supported on this OS".to_string(),
        )
    }
}

#[cfg(windows)]
fn verify_windows(root_str: &str, root: &std::path::Path) -> InstallRootSecurity {
    let ps = acl_write_probe_ps_command(&root.to_string_lossy());
    let out = crate::proc::powershell(&ps).output();
    match out {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // #619: a successful exit that emitted ZERO ACEs is a VACUOUS read
            // (empty/garbled Get-Acl output), not proof of an admin-only root.
            // Refuse to report `secure` without having observed at least one
            // access rule — resolve to `checked:false` (indeterminate) instead.
            if count_aces(&stdout) == 0 {
                return InstallRootSecurity::indeterminate(
                    root_str,
                    "the install-root ACL read returned no access rules (Get-Acl produced no ACE \
                     lines) — indeterminate; the admin-only Program Files location remains the \
                     primary guarantee",
                );
            }
            match parse_acl_write_grants(&stdout) {
                Ok(()) => InstallRootSecurity::established_safe(
                    root_str,
                    "the install root denies write to unprivileged principals (admin-only, no \
                     Users/Everyone/Authenticated-Users write ACE)",
                ),
                Err(e) => InstallRootSecurity::detected_unsafe(root_str, e),
            }
        }
        _ => InstallRootSecurity::indeterminate(
            root_str,
            "could not read the install-root ACL back (Get-Acl did not run) — the admin-only \
             Program Files location is still the primary guarantee",
        ),
    }
}

/// The unix verdict: EVERY level of `root`'s path must be root-owned with no group/other write, checked
/// through `O_NOFOLLOW` descriptors ([`crate::rootchain::verify`]).
///
/// # Why not `std::fs::metadata` on the leaf (#1748)
///
/// It was, and both halves of that were exploitable:
///
/// * **the leaf alone is not enough.** Write permission on a PARENT is permission to rename the leaf
///   aside and substitute an attacker-owned directory of the same name, whatever the leaf's own mode
///   says. `create_dir_all` created `/opt/dig` at the process umask, so `umask 000` left it `0777` and
///   this check — reading only `/opt/dig/bin` — printed "root-owned with no group/other write".
/// * **`metadata` FOLLOWS symlinks.** With `--bin-dir /home/alice/bin` where `~/bin` is a symlink to
///   `/etc`, it described `/etc` and reported the install root secure; root then created binaries in
///   `/etc`.
///
/// A refusal to inspect a level — it is a symlink, a non-directory, or unreadable — is `checked: false`,
/// an indeterminate warning, never a false `secure: true`.
#[cfg(unix)]
fn verify_unix(root_str: &str, root: &std::path::Path) -> InstallRootSecurity {
    verdict_from_walk(root_str, crate::rootchain::verify(root))
}

/// Map a [`crate::rootchain::verify`] outcome onto the reported verdict.
///
/// Pure, and separate from the walk, because WHICH FIELD each outcome lands in is the whole of #1748's S3
/// and it must be assertable without needing a root-owned directory tree to test against. The mapping:
///
/// * `Ok(None)` — every level checked and safe → `checked: true, secure: true`;
/// * `Ok(Some(unsafe))` — a level was DETECTED unsafe (writable, wrong owner, **or a symlink**) →
///   `checked: true, secure: false`. Definitive, so the three gates fire;
/// * `Err(note)` — a level could not be inspected at all → `checked: false`, indeterminate.
///
/// A symlink used to take the `Err` arm, and every gate is written `if verdict.checked && !verdict.secure`,
/// so indeterminate is a PASS at all of them: the strongest detection this code can make printed a tick.
#[cfg(unix)]
fn verdict_from_walk(
    root_str: &str,
    walk: Result<Option<crate::rootchain::Unsafe>, String>,
) -> InstallRootSecurity {
    match walk {
        Ok(None) => InstallRootSecurity::established_safe(
            root_str,
            "every level of the install root is root-owned with no group/other write",
        ),
        Ok(Some(bad)) => InstallRootSecurity::detected_unsafe(
            root_str,
            format!(
                "{}: {} — a non-root account could replace a binary this installer places or executes",
                bad.level.display(),
                bad.reason
            ),
        ),
        Err(e) => InstallRootSecurity::indeterminate(
            root_str.to_string(),
            format!("could not verify every level of the install root: {e}"),
        ),
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
    #[cfg(unix)]
    {
        // EVERY DIG-owned level, created and re-moded explicitly — not `create_dir_all` plus a chmod of
        // the leaf, which left `/opt/dig` at the process umask (#1748, `crate::rootchain`).
        crate::rootchain::ensure(root)?;
    }
    #[cfg(windows)]
    {
        std::fs::create_dir_all(root).map_err(|e| format!("create {}: {e}", root.display()))?;
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

// -- #1910: own the FILES the elevated installer creates, not just the dirs ----
//
// #732 (above) forces owner = SYSTEM on every DIRECTORY level the installer
// creates. The FILES placed into those levels were left to Windows' defaults, and
// the defaults do not hold:
//
//   * an elevated process's token default owner is the invoking admin USER, not
//     SYSTEM, so a freshly created file is owned by that user — and an owner holds
//     `WRITE_DAC` implicitly, i.e. can grant itself write whatever the DACL says;
//   * the Program Files DACL that `DIG\bin` inherits carries a
//     `CREATOR OWNER:(OI)(CI)(IO)(F)` ACE, which MATERIALISES on each newly
//     created file as an explicit FullControl grant to that same user.
//
// Observed verbatim on a real machine, on a file created in the default root by an
// elevated shell:
//
//   C:\Program Files\DIG\bin\<new file>  NT AUTHORITY\SYSTEM:(I)(F)
//                                        BUILTIN\Administrators:(I)(F)
//                                        BUILTIN\Users:(I)(RX)
//                                        TDS1\micha:(I)(F)          <-- #1910
//
// dig-node's #565 guard then REFUSES to point a SYSTEM service at that binary,
// which is exactly what it is for: a principal that is not SYSTEM/Administrators
// can rewrite the image a SYSTEM service executes. The guard is right; the
// installer is what is wrong, so the fix is here and the guard is untouched.
//
// The repair is the same two icacls calls the directory levels already use, in the
// same order and for the same reason: `/setowner` to SYSTEM FIRST, so that the
// `/reset` which follows re-derives the inherited DACL with CREATOR OWNER
// resolving to SYSTEM rather than back to the user.

/// Should a file placed at `dest` have privileged ownership forced onto it?
///
/// Only when it lies inside `protected_root`. A `--bin-dir` override installs into
/// a directory the CALLER chose, which may be their own home: re-owning a file
/// there to SYSTEM would take a user's own file away from them, and it buys
/// nothing — a user-writable root is refused by [`verify_install_root`] and
/// [`root_exec_guard`] regardless of who owns the individual file.
///
/// Pure, so the boundary is asserted without a protected directory to write into.
pub fn needs_privileged_ownership(
    dest: &std::path::Path,
    protected_root: &std::path::Path,
) -> bool {
    dest.starts_with(protected_root)
}

/// Classify [`acl_write_probe_ps_command`] output for a FILE the installer placed
/// in the protected root: `Err` unless the owner is a privileged principal
/// ([`is_privileged_owner_sid`]) **and** no Allow ACE grants a write-capable right
/// ([`grants_write`]) to anything else.
///
/// This is deliberately STRICTER than [`parse_acl_write_grants`], which rejects
/// only the well-known broad principals (`Users`, `Everyone`, …). #1910's grant is
/// to a single named user account, whose SID is not well-known — so the broad-group
/// check passes it, and the defect reached a real machine. The bar for a file a
/// SYSTEM service executes is the one dig-node's #565 guard applies: nobody but
/// SYSTEM/Administrators/TrustedInstaller may write it.
///
/// A read that produced no owner line is `Err` (indeterminate, never a silent
/// pass) — the caller reports it rather than claiming the file was adopted.
pub fn parse_placed_binary_acl(output: &str) -> Result<(), String> {
    let owner = parse_acl_owner(output)
        .ok_or_else(|| "could not read the file's owner back".to_string())?;
    if !is_privileged_owner_sid(&owner) {
        return Err(format!(
            "owner is {owner}, expected SYSTEM/Administrators/TrustedInstaller — an owner holds \
             WRITE_DAC implicitly, so a non-privileged owner can grant itself write on a binary a \
             SYSTEM service executes"
        ));
    }
    for line in output.lines() {
        let Some(rest) = line.trim().strip_prefix("ACE;") else {
            continue;
        };
        let mut parts = rest.split(';');
        let sid = parts.next().unwrap_or("").trim();
        let rights = parts
            .next()
            .and_then(|r| r.trim().parse::<i64>().ok())
            .unwrap_or(0);
        let kind = parts.next().unwrap_or("").trim();
        if !kind.eq_ignore_ascii_case("Allow") {
            continue;
        }
        if grants_write(rights) && !is_privileged_owner_sid(sid) {
            return Err(format!(
                "an Allow ACE grants WRITE to {sid}, which is not SYSTEM/Administrators/\
                 TrustedInstaller — dig-node refuses to point a SYSTEM service at a binary a \
                 non-SYSTEM principal can rewrite (#565)"
            ));
        }
    }
    Ok(())
}

/// Force privileged ownership + a clean inherited DACL on a file the elevated
/// installer just created in the protected root, then READ IT BACK and confirm
/// ([`parse_placed_binary_acl`]) — the #1910 fix.
///
/// A no-op for a `dest` outside the protected root ([`needs_privileged_ownership`])
/// and on every non-Windows target. `Err` carries a reportable reason; the caller
/// logs it and continues, because the authoritative gate is dig-node's own refusal
/// rather than a claim made here.
pub fn adopt_placed_file(dest: &std::path::Path) -> Result<(), String> {
    if !needs_privileged_ownership(dest, &crate::paths::protected_bin_dir()) {
        return Ok(());
    }
    #[cfg(windows)]
    {
        force_privileged_ownership(dest)
    }
    #[cfg(not(windows))]
    {
        // unix placement already creates the file as root under a root-owned tree
        // (`crate::rootchain`), which `verify_install_root` verifies level by level.
        Ok(())
    }
}

/// The MECHANISM behind [`adopt_placed_file`], on any path: owner → SYSTEM, DACL
/// → the parent's inheritance, then a read-back that must satisfy
/// [`parse_placed_binary_acl`].
///
/// Separate from the policy gate so the repair can be exercised on a temporary
/// directory in a test, rather than only on the one machine-wide root a test must
/// not touch.
#[cfg(windows)]
pub(crate) fn force_privileged_ownership(path: &std::path::Path) -> Result<(), String> {
    use crate::daemon_dir::{reset_dacl_args_here, run_icacls, setowner_system_args_here};
    let s = path.to_string_lossy().into_owned();
    // Owner FIRST: the `/reset` that follows re-derives the inherited DACL, and the
    // inherited `CREATOR OWNER` entry resolves to whoever owns the file at that
    // moment. Reversed, the user's FullControl ACE comes straight back.
    run_icacls(&setowner_system_args_here(&s))?;
    run_icacls(&reset_dacl_args_here(&s))?;
    parse_placed_binary_acl(&read_acl(&s)?)
}

/// Read `path`'s owner + DACL back in the `OWNER;`/`ACE;` form the pure parsers
/// consume. Windows-only I/O; `Err` when the read did not run or produced nothing.
#[cfg(windows)]
fn read_acl(path: &str) -> Result<String, String> {
    let out = crate::proc::powershell(&acl_write_probe_ps_command(path))
        .output()
        .map_err(|e| format!("the ACL read-back failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "the ACL read-back exited non-zero: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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
        // #1910 amended this from `contains("Get-Acl")`: the probe now binds the ACL
        // through .NET, so it no longer depends on module autoloading. What the probe
        // must EMIT is unchanged, and that is what the rest of this test pins.
        assert!(!cmd.contains("Get-Acl"));
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
        // These two assertions were INVERTED (`is_blocking()` / `!is_established_safe()`)
        // and passed only because the read-back was failing on the developer machine —
        // #1910's `Get-Acl` autoload failure, keeping green a test whose own doc comment
        // says the read must SUCCEED. Corrected here to assert the stated property.
        assert!(
            !v.is_blocking(),
            "the ACL read-back must run on a Program Files dir (inherited \
             AppContainer ACEs must not abort it): {}",
            v.note
        );
        assert!(
            v.is_established_safe(),
            "Program Files denies unprivileged write, so it must verify secure: {}",
            v.note
        );
    }

    #[test]
    fn install_root_security_serializes_with_stable_fields() {
        let r = InstallRootSecurity::established_safe(r"C:\Program Files\DIG\bin", "ok");
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["checked"], true);
        assert_eq!(v["secure"], true);
        assert_eq!(v["root"], r"C:\Program Files\DIG\bin");
    }

    /// `install.json` MUST keep the exact field names a consumer already parses, whatever the Rust fields
    /// are called.
    ///
    /// The Rust fields were renamed to `posture_was_read`/`posture_is_safe` (#1748 WU1) so the check that
    /// keeps the blocking policy in one place can name them precisely — `checked` is an ordinary word other
    /// report types also use. The WIRE names must not move with them: `install.json` is a published,
    /// machine-consumed artifact, and a silent rename there is a breaking change wearing a refactor's
    /// clothes.
    ///
    /// Asserted exhaustively over the serialized KEY SET, not just the values, so ADDING a key is caught
    /// too — an extra field is still a schema change for a strict parser.
    #[test]
    fn install_root_security_keeps_its_published_wire_names() {
        for verdict in [
            InstallRootSecurity::established_safe("/opt/dig/bin", "ok"),
            InstallRootSecurity::detected_unsafe("/opt/dig/bin", "group-writable"),
            InstallRootSecurity::indeterminate("/opt/dig/bin", "could not read"),
        ] {
            let v: serde_json::Value = serde_json::to_value(&verdict).unwrap();
            let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                ["checked", "note", "root", "secure"],
                "the published field names changed - install.json consumers parse these"
            );
            // And the Rust-side rename really is in force, so this test is asserting a MAPPING rather than
            // restating the field names.
            assert!(
                v["checked"].is_boolean() && v["secure"].is_boolean(),
                "both must remain booleans: {v}"
            );
        }

        // The three outcomes must still be distinguishable on the wire, or the rename would have flattened
        // information a consumer relies on.
        let safe = serde_json::to_value(InstallRootSecurity::established_safe("/x", "n")).unwrap();
        let unsafe_ =
            serde_json::to_value(InstallRootSecurity::detected_unsafe("/x", "n")).unwrap();
        let unknown = serde_json::to_value(InstallRootSecurity::indeterminate("/x", "n")).unwrap();
        assert_eq!(
            (safe["checked"].as_bool(), safe["secure"].as_bool()),
            (Some(true), Some(true))
        );
        assert_eq!(
            (unsafe_["checked"].as_bool(), unsafe_["secure"].as_bool()),
            (Some(true), Some(false)),
            "a DETECTED breach was read and found unsafe"
        );
        assert_eq!(
            (unknown["checked"].as_bool(), unknown["secure"].as_bool()),
            (Some(false), Some(false)),
            "an INDETERMINATE posture was never established - distinct on the wire, even though both block"
        );
    }

    /// The fail-open policy MUST exist in exactly one place, and NO caller may reconstruct it.
    ///
    /// # The type this replaces
    ///
    /// `checked` and `secure` are two halves of one decision, and seven call sites each re-derived it as
    /// `if verdict.checked && !verdict.secure`. That is why the same defect was found and fixed FIVE
    /// rounds running: each fix was correct and each left the type free to offer the next caller the same
    /// mistake, one level over. Four doc comments in this crate already narrated the hazard.
    ///
    /// So the fields are private and [`InstallRootSecurity::is_blocking`] is the only question. This test
    /// is what keeps that true: it fails if `checked`/`secure` are read anywhere outside this module, or
    /// if the two-field pattern reappears in any form. A new call site therefore CANNOT re-derive the
    /// policy — it will not compile, and if it somehow spells it in a comment this still catches it.
    #[test]
    fn the_blocking_policy_is_decided_in_exactly_one_place() {
        let mut offenders = Vec::new();
        for (file, src) in crate::sources::all() {
            if file == "secure.rs" {
                continue; // The one module that owns the policy.
            }
            for (number, line) in src.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for needle in [".posture_was_read", ".posture_is_safe"] {
                    if code.contains(needle) {
                        offenders.push(format!("{file}:{}: {}", number + 1, line.trim()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "the install-root verdict's fields are read outside `secure`, which is how the fail-open              policy came to exist in seven copies. Ask `InstallRootSecurity::is_blocking()` instead.              Offending lines:
{}",
            offenders.join("
")
        );

        // Self-check: the scan must be capable of finding what it looks for, or an empty result means
        // nothing. Both spellings are exercised against text that WOULD be reported.
        for planted in [
            "if verdict.posture_was_read && !verdict.posture_is_safe {",
            "let x = sec.posture_is_safe;",
        ] {
            assert!(
                planted.contains(".posture_was_read") || planted.contains(".posture_is_safe"),
                "the needle no longer matches the pattern it exists to catch: {planted}"
            );
        }
    }

    /// Indeterminate BLOCKS, and only established-safe passes — the whole of WU1, on the one method.
    ///
    /// All three outcomes are asserted, because a two-outcome test cannot distinguish "indeterminate
    /// blocks" from "everything blocks", and the second would refuse every install.
    #[test]
    fn only_an_established_safe_posture_is_non_blocking() {
        assert!(
            !InstallRootSecurity::established_safe("/opt/dig/bin", "verified").is_blocking(),
            "a verified-safe root must not block, or no install could ever proceed"
        );
        assert!(
            InstallRootSecurity::detected_unsafe("/opt/dig/bin", "group-writable").is_blocking(),
            "a detected breach must block"
        );
        assert!(
            InstallRootSecurity::indeterminate("/opt/dig/bin", "could not read").is_blocking(),
            "a posture nobody could establish is not evidence of safety - `indeterminate -> proceed`              is the fail-open policy this release removes"
        );
    }

    // -- #1748 F1: root must never EXECUTE a binary out of a user-writable directory ----

    // The source-scanning inventory that used to live here is GONE (#1748 WU4).
    //
    // It was the right instinct and it beat the written-down list it replaced — it found a guard sitting
    // one frame above its spawn. But a scan is a heuristic pretending to be an enumeration: it was
    // measured at 8 of 17 evasion forms caught, and two of the misses were ordinary accidents rather than
    // contrivances (a discarded verdict, `let _ = root_exec_guard(bin);`, and a `pub(super) fn` whose body
    // was attributed to a guarded sibling). Its own `strip_comment` handled only `//`, which falsified the
    // "not satisfiable by a comment mention" guarantee it advertised.
    //
    // The invariant is now enforced by the COMPILER: `guardedcmd::GuardedCommand::for_installed_binary`
    // is the only way to spawn an installed binary, it cannot be constructed without this guard having
    // passed, and `clippy.toml` denies `std::process::Command::new` outside the modules that spawn trusted
    // system tools. An unguarded spawn fails the build rather than failing a test that has to think of it
    // first. `guardedcmd::tests::installed_binaries_are_spawned_only_through_the_guarded_type` states the
    // converse so a `clippy.toml` deletion is caught by `cargo test` too.

    /// The exploit, in the shape it actually has: a Homebrew-style `0775` directory holding a binary
    /// this installer would otherwise run as root. No race is involved — the attacker writes the file
    /// and waits for the next `sudo` install.
    ///
    /// Root-gated because the guard is a no-op unelevated by design (running a binary you can already
    /// write is your own authority, not an escalation), so unprivileged this test would assert nothing.
    /// The unprivileged half of the property — that the guard is WIRED INTO the probe at all — is
    /// asserted by `update::tests`' no-spawn test, which does gate in CI.
    #[cfg(unix)]
    #[test]
    fn root_refuses_to_exec_a_binary_from_a_group_writable_dir() {
        use std::os::unix::fs::PermissionsExt;
        if !crate::invoker::is_root() {
            eprintln!("skipped: the guard is deliberately inert unelevated");
            return;
        }
        let dir =
            crate::sources::fixture_root().join(format!("dig-rootexec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("dig-node");
        std::fs::write(&bin, b"#!/bin/sh\necho pwned\n").unwrap();

        // The Homebrew posture: group+other writable, so an unprivileged account can replace the binary.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = root_exec_guard(&bin).expect_err("a world-writable dir must refuse a root exec");
        assert!(
            err.contains("refusing to run") && err.contains("as root"),
            "the refusal must name what it declined to run: {err}"
        );

        // The truthful control, in the SAME test and on the SAME binary: tighten only the directory's
        // mode and the very same exec is permitted. So the refusal above is about the writability, not
        // about the guard rejecting everything it is shown.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            root_exec_guard(&bin).is_ok(),
            "a root-owned 0755 directory is exactly where a root-executed binary belongs"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The guard must not become a blanket refusal on the unelevated path, where the same directory
    /// posture is normal and harmless — a user's own `~/.dig/bin` is theirs to write.
    #[cfg(unix)]
    #[test]
    fn an_unelevated_process_may_exec_its_own_writable_binary() {
        use std::os::unix::fs::PermissionsExt;
        if crate::invoker::is_root() {
            eprintln!("skipped: asserts the UNELEVATED arm");
            return;
        }
        let dir =
            crate::sources::fixture_root().join(format!("dig-userexec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let bin = dir.join("digstore");
        std::fs::write(&bin, b"x").unwrap();
        assert!(
            root_exec_guard(&bin).is_ok(),
            "unelevated, executing a binary in your own writable dir is not an escalation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unix_verify_flags_a_group_or_other_writable_root() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            crate::sources::fixture_root().join(format!("dig-secure-ug-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 0o777 → group + other write present → NOT secure.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let v = verify_install_root(Os::Linux, &dir);
        assert!(v.is_blocking());
        assert!(
            !v.is_established_safe(),
            "a world-writable root must be flagged: {}",
            v.note
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The walk produces a COHERENT verdict about a real system directory, in whichever direction the
    /// machine's own ownership warrants.
    ///
    /// This used to assert flatly that `/usr/bin` verifies clean, "root-owned `0755` on every supported
    /// platform". That is not true of the GitHub Actions ubuntu image, where **`/usr` is owned by uid 1001**
    /// — so the walk correctly reported it unsafe (uid 1001 can rename `/usr/bin`) and the test failed for
    /// being wrong about the world rather than about the code. It is the third time an assumption about
    /// ambient filesystem posture has broken a fixture in this issue, after `/tmp` being `1777` and `/bin`
    /// being a symlink.
    ///
    /// So the property asserted is the one that holds everywhere: the walk reaches a definite conclusion and
    /// JUSTIFIES it. Both directions are checked, so neither a walk that always passes nor one that always
    /// refuses would satisfy this — the clean arm runs on a correctly-owned box, the refusing arm names the
    /// offending level and says why.
    #[cfg(unix)]
    #[test]
    fn unix_verify_reaches_a_justified_verdict_about_a_real_system_directory() {
        let v = verify_install_root(Os::Linux, std::path::Path::new("/usr/bin"));
        if v.is_established_safe() {
            assert!(
                !v.is_blocking(),
                "established-safe and blocking are opposites: {}",
                v.note
            );
            assert!(
                v.note.contains("root-owned"),
                "a clean verdict must say what it established: {}",
                v.note
            );
        } else {
            // The machine's own posture is not clean — true of the GH runner image. The verdict must then
            // name the offending LEVEL and the reason, which is what an operator needs.
            assert!(v.is_blocking(), "not-safe must block: {}", v.note);
            assert!(
                v.note.contains("/usr")
                    && (v.note.contains("owned by uid") || v.note.contains("write")),
                "a refusal must name the level and why: {}",
                v.note
            );
        }
    }

    /// A DETECTED unsafe level — including a symlink — is `checked: true`, so the gates fire; only a level
    /// that could not be inspected at all is indeterminate.
    ///
    /// This is the whole of S3, asserted on the pure mapping so it needs no root-owned fixture. A symlink
    /// took the `Err` arm and landed in `checked: false`, and all three gates read
    /// `if verdict.checked && !verdict.secure` — so the strongest detection this code can make was a PASS
    /// at every one of them: `root_exec_guard` returned `Ok`, the `/etc/profile.d` write went ahead, and
    /// readiness printed a tick. Proved with the ordinary sysadmin move of symlinking the install root
    /// onto a data volume (`/opt/dig-link -> /data/dig-bin`, alice-owned `0777`).
    ///
    /// That a symlinked level really does produce `Ok(Some(_))` — the input this maps — is asserted by
    /// `rootchain::tests::a_symlinked_level_is_definitively_unsafe_not_indeterminate`.
    #[cfg(unix)]
    #[test]
    fn a_detected_unsafe_level_is_definitive_and_only_an_unreadable_one_is_indeterminate() {
        let detected = verdict_from_walk(
            "/opt/dig-link",
            Ok(Some(crate::rootchain::Unsafe {
                level: std::path::PathBuf::from("/opt/dig-link"),
                reason: "it is a symlink or not a directory".to_string(),
            })),
        );
        assert!(
            detected.is_blocking(),
            "a DETECTION must be definitive, or every gate waves it through: {detected:?}"
        );

        // The other two arms, so the mapping cannot be satisfied by returning one verdict for everything.
        let clean = verdict_from_walk("/opt/dig/bin", Ok(None));
        assert!(clean.is_established_safe() && !clean.is_blocking());

        let unreadable = verdict_from_walk("/opt/dig/bin", Err("permission denied".to_string()));
        assert!(
            unreadable.is_blocking(),
            "a level that could not be READ is indeterminate, and indeterminate BLOCKS (WU1): a posture              nobody could establish is not evidence of safety: {unreadable:?}"
        );
    }

    /// The counterpart, and the property the leaf-only check could not see: a perfectly-moded directory
    /// under a WORLD-WRITABLE ancestor is NOT secure, and the verdict names the ANCESTOR.
    ///
    /// The fixture builds its OWN world-writable ancestor rather than borrowing `/tmp`'s `1777`: the root
    /// gate runs with fixtures on a clean `0755` root precisely so a writable ancestor is a fact the test
    /// STATES rather than one it inherits from the environment (#1748 WU3). Write permission on the parent
    /// is permission to rename the leaf aside and substitute an attacker-owned directory of the same name.
    #[cfg(unix)]
    #[test]
    fn unix_verify_rejects_a_perfect_leaf_under_a_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let ancestor =
            crate::sources::fixture_root().join(format!("dig-secure-chain-{}", std::process::id()));
        let dir = ancestor.join("bin");
        let _ = std::fs::remove_dir_all(&ancestor);
        std::fs::create_dir_all(&dir).unwrap();
        // The leaf is beyond reproach; only the PARENT is writable. A leaf-only check passes this.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();

        let v = verify_install_root(Os::Linux, &dir);
        assert!(v.is_blocking());
        assert!(
            !v.is_established_safe(),
            "a 0755 leaf under a world-writable ancestor must NOT be reported secure: {}",
            v.note
        );
        // The named level is an ANCESTOR, never the innocent leaf. Stated as "not the leaf" rather than as
        // a literal path because the first unsafe level depends on the fixture root: on the container gate
        // it is the ancestor this test created, and on an ordinary runner `/tmp` (1777) is unsafe first.
        // Either way the property under test — a perfect leaf does not save a writable ancestry — holds.
        assert!(
            !v.note.contains(&dir.display().to_string()),
            "the verdict blamed the leaf, which is beyond reproach here: {}",
            v.note
        );
        assert!(
            v.note.contains("write"),
            "the verdict must say WHY the level is unsafe: {}",
            v.note
        );
        let _ = std::fs::remove_dir_all(&ancestor);
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

    // -- #1910: the file the elevated installer creates -----------------------

    /// A file created by an elevated ADMIN USER in `%ProgramFiles%\DIG\bin`, read
    /// back verbatim from a real machine. The `S-1-5-21-...-1002` lines are the
    /// defect: that account owns the file AND holds FullControl (2032127) on it,
    /// because the Program Files DACL the directory inherits carries a
    /// `CREATOR OWNER` full-control entry that materialises for the creator.
    const ELEVATED_USER_CREATED_FILE_ACL: &str = "\
OWNER;S-1-5-21-447225562-1852780552-4040414075-1002
ACE;S-1-5-18;2032127;Allow
ACE;S-1-5-32-544;2032127;Allow
ACE;S-1-5-32-545;1179817;Allow
ACE;S-1-5-21-447225562-1852780552-4040414075-1002;2032127;Allow
ACE;S-1-15-2-1;1179817;Allow
ACE;S-1-15-2-2;1179817;Allow
";

    /// The SAME file after the repair, read back from the same machine: owner is a
    /// privileged principal and the user's ACE is gone, while `Users` keeps the
    /// read+execute (1179817) that makes the CLI runnable by a non-admin.
    const ADOPTED_FILE_ACL: &str = "\
OWNER;S-1-5-18
ACE;S-1-5-18;2032127;Allow
ACE;S-1-5-32-544;2032127;Allow
ACE;S-1-5-32-545;1179817;Allow
ACE;S-1-15-2-1;1179817;Allow
ACE;S-1-15-2-2;1179817;Allow
";

    #[test]
    fn a_file_the_elevated_installer_created_is_rejected_until_it_is_adopted() {
        // The #1910 defect and its repair, on real captured ACLs. Both arms matter:
        // the first is the state a reinstall actually produced (and dig-node's #565
        // guard refused), the second is what the fix must leave behind.
        let before = parse_placed_binary_acl(ELEVATED_USER_CREATED_FILE_ACL)
            .expect_err("a user-owned, user-writable binary must be rejected");
        assert!(
            before.contains("S-1-5-21-447225562-1852780552-4040414075-1002"),
            "the rejection must name the offending principal: {before}"
        );
        parse_placed_binary_acl(ADOPTED_FILE_ACL).expect("the adopted file must pass");
    }

    #[test]
    fn a_privileged_owner_does_not_excuse_a_user_write_ace() {
        // The nearest wrong implementation checks only the OWNER -- which the repair
        // fixes first, and which alone would make this input pass. A binary a named
        // user can still REWRITE is exactly what dig-node refuses to run as SYSTEM,
        // however it is owned.
        let system_owned_but_user_writable = "\
OWNER;S-1-5-18
ACE;S-1-5-18;2032127;Allow
ACE;S-1-5-21-447225562-1852780552-4040414075-1002;2032127;Allow
";
        parse_placed_binary_acl(system_owned_but_user_writable)
            .expect_err("a user write ACE must be rejected even under a privileged owner");
    }

    #[test]
    fn the_broad_group_check_alone_would_have_passed_the_defect() {
        // Why #1910 needed its own classifier, stated as a test: the #565 install-root
        // check rejects only WELL-KNOWN broad principals, and the offending grant is to
        // a single named account whose SID is not well-known. It passes that check --
        // so a fix that reused it would have shipped the defect a second time.
        parse_acl_write_grants(ELEVATED_USER_CREATED_FILE_ACL)
            .expect("the broad-group check does not see a named-account grant");
    }

    #[test]
    fn the_guard_still_refuses_a_genuinely_user_writable_file() {
        // The CONTROL. "Fixed" must not mean "the check was weakened": every
        // unprivileged shape a placed binary can take is still refused.
        for (why, acl) in [
            (
                "Users:(F)",
                "OWNER;S-1-5-18\nACE;S-1-5-32-545;2032127;Allow\n",
            ),
            (
                "Everyone:(M)",
                "OWNER;S-1-5-18\nACE;S-1-1-0;1245631;Allow\n",
            ),
            (
                "Authenticated Users:(W)",
                "OWNER;S-1-5-18\nACE;S-1-5-11;278;Allow\n",
            ),
            (
                "owned by a named user",
                "OWNER;S-1-5-21-447225562-1852780552-4040414075-1002\nACE;S-1-5-18;2032127;Allow\n",
            ),
            ("no owner could be read", "ACE;S-1-5-18;2032127;Allow\n"),
        ] {
            parse_placed_binary_acl(acl).expect_err(&format!("{why} must still be refused"));
        }
    }

    #[test]
    fn a_deny_ace_and_a_read_execute_ace_are_not_write_grants() {
        // The other direction: the classifier must not refuse a healthy file, or the
        // fix would break every install instead of only the broken ones. `Users:(RX)`
        // is what Program Files inheritance gives, and a Deny ACE only restricts.
        parse_placed_binary_acl(
            "OWNER;S-1-5-32-544\nACE;S-1-5-32-545;1179817;Allow\nACE;S-1-5-32-545;2032127;Deny\n",
        )
        .expect("read+execute for Users, and a Deny, are both fine");
    }

    #[test]
    fn only_a_file_inside_the_protected_root_is_re_owned() {
        // A `--bin-dir` override installs where the CALLER chose, possibly their own
        // home: taking their file away from them buys nothing, because a user-writable
        // root is refused wholesale by `verify_install_root` / `root_exec_guard`.
        let protected = std::path::Path::new("C_drive")
            .join("Program Files")
            .join("DIG")
            .join("bin");
        assert!(needs_privileged_ownership(
            &protected.join("dig-node.exe"),
            &protected
        ));
        let in_a_home = std::path::Path::new("C_drive")
            .join("Users")
            .join("alice")
            .join("bin")
            .join("dig-node.exe");
        assert!(!needs_privileged_ownership(&in_a_home, &protected));
        // A sibling directory whose name merely STARTS with the root's is outside it.
        let sibling = std::path::Path::new("C_drive")
            .join("Program Files")
            .join("DIG")
            .join("bin-old")
            .join("dig-node.exe");
        assert!(!needs_privileged_ownership(&sibling, &protected));
    }

    /// The repair, end to end, on the real operating system: reproduce the defect in
    /// a temporary directory that inherits a `CREATOR OWNER` full-control entry the
    /// way Program Files does, prove the created file is refused, then adopt it and
    /// prove it passes.
    ///
    /// The REPRODUCTION half is unconditional -- it needs no privilege, so it fails
    /// loudly if Windows ever stops creating files this way and the fix stops being
    /// load-bearing. Only the repair half needs `SeTakeOwnership`, and a host without
    /// it says so rather than passing quietly.
    #[cfg(windows)]
    #[test]
    fn the_defect_reproduces_on_a_real_directory_and_the_repair_clears_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir_str = dir.path().to_string_lossy().into_owned();
        // Give the directory the Program Files SHAPE, which is what makes this fixture
        // able to see the defect: SYSTEM + Administrators full, Users read+execute, and
        // the inherit-only CREATOR OWNER full-control entry that materialises for
        // whoever creates a file. `/inheritance:r` is load-bearing — a plain temp dir
        // sits under the user profile and grants that user write by INHERITANCE, so the
        // repair could never clear a user write ACE there and the test would report a
        // failure of this fixture as a failure of the fix.
        crate::daemon_dir::run_icacls(&[
            dir_str,
            "/inheritance:r".to_string(),
            "/grant".to_string(),
            "*S-1-5-18:(OI)(CI)F".to_string(),
            "/grant".to_string(),
            "*S-1-5-32-544:(OI)(CI)F".to_string(),
            "/grant".to_string(),
            "*S-1-5-32-545:(OI)(CI)RX".to_string(),
            "/grant".to_string(),
            "*S-1-3-0:(OI)(CI)(IO)F".to_string(),
            "/C".to_string(),
            "/Q".to_string(),
        ])
        .expect("re-shaping the DACL of our own temp dir must work unprivileged");

        let file = dir.path().join("dig-node.exe");
        std::fs::write(&file, b"MZ").expect("create the file the way an install does");
        let file_str = file.to_string_lossy().into_owned();

        let before = read_acl(&file_str).expect("read the ACL back");
        assert!(
            parse_placed_binary_acl(&before).is_err(),
            "a freshly created file must carry its creator's ownership/grant -- if this \
             ever passes, #1910's premise no longer holds and the repair below is no \
             longer proving anything. ACL was:\n{before}"
        );

        match force_privileged_ownership(&file) {
            Ok(()) => {
                let after = read_acl(&file_str).expect("read the ACL back after the repair");
                parse_placed_binary_acl(&after).unwrap_or_else(|e| {
                    panic!("the adopted file must satisfy the #565 bar: {e}\n{after}")
                });
            }
            Err(e) => {
                // Setting an owner to SYSTEM needs SeTakeOwnership/SeRestore. Report it;
                // never let a missing privilege read as a pass.
                assert!(
                    e.contains("icacls"),
                    "an unprivileged host may fail the /setowner, but only there: {e}"
                );
                eprintln!("SKIPPED the repair half -- this host cannot set an owner: {e}");
            }
        }
    }

    /// The ACL read-back must not depend on module autoloading (#1910).
    ///
    /// Both arms run under the SAME poisoned `PSModulePath`, which is the point: the
    /// second proves the poison is genuinely hostile (a `Get-Acl` read really does
    /// fail under it), so the first arm's success is the module-free expression
    /// working rather than a poison that never bit.
    #[cfg(windows)]
    #[test]
    fn the_acl_read_survives_an_inherited_psmodulepath() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().to_string_lossy().into_owned();
        let poison = shadowing_psmodulepath(dir.path());
        let poison = poison.as_str();

        let mut ours = crate::proc::powershell(&acl_write_probe_ps_command(&path));
        let out = ours
            .env("PSModulePath", poison)
            .output()
            .expect("the probe should run");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success() && count_aces(&stdout) > 0,
            "the module-free probe must still read the ACL under a poisoned PSModulePath: \
             {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            parse_acl_owner(&stdout).is_some(),
            "and it must still report an owner: {stdout}"
        );

        let mut cmdlet = crate::proc::powershell(&format!(
            "$ErrorActionPreference='Stop'; (Get-Acl -LiteralPath '{path}').Owner"
        ));
        let control = cmdlet
            .env("PSModulePath", poison)
            .output()
            .expect("the control should run");
        assert!(
            !control.status.success(),
            "the control must FAIL, or the poisoned PSModulePath is not reproducing the \
             reported condition and the arm above proves nothing"
        );
    }

    /// Build a `PSModulePath` that reproduces the REPORTED failure: a directory
    /// holding a `Microsoft.PowerShell.Security` module manifest marked
    /// `CompatiblePSEditions = 'Core'`, which Windows PowerShell finds first and
    /// refuses to load — leaving `Get-Acl` unavailable.
    ///
    /// A merely NON-EXISTENT path is not a usable poison and was tried first: Windows
    /// PowerShell appends `$PSHOME\Modules` when the variable does not name it, so
    /// `Get-Acl` still autoloads and the control arm passes, which would have made the
    /// whole test vacuous. The observed condition is a pwsh 7 / Git Bash session
    /// exporting ITS module directories, i.e. a SHADOWING module — so that is what this
    /// builds.
    #[cfg(windows)]
    fn shadowing_psmodulepath(base: &std::path::Path) -> String {
        let modules = base.join("psmodules");
        let shadow = modules.join("Microsoft.PowerShell.Security");
        std::fs::create_dir_all(&shadow).expect("create the shadow module dir");
        std::fs::write(
            shadow.join("Microsoft.PowerShell.Security.psd1"),
            "@{ ModuleVersion = '7.0.0.0'; \
                GUID = 'a94c8c7e-9810-47c0-b8af-65089c13a35a'; \
                CompatiblePSEditions = @('Core'); \
                CmdletsToExport = @('Get-Acl') }",
        )
        .expect("write the shadow module manifest");
        modules.to_string_lossy().into_owned()
    }

    #[test]
    fn the_probe_reads_the_acl_without_a_cmdlet() {
        // `Get-Acl` is a module-backed cmdlet; reaching it depends on `PSModulePath`.
        let cmd = acl_write_probe_ps_command(r"C:\Program Files\DIG\bin");
        assert!(
            !cmd.contains("Get-Acl"),
            "must not depend on a module: {cmd}"
        );
        assert!(cmd.contains("FileSecurity") && cmd.contains("DirectorySecurity"));
        assert!(cmd.contains(r"C:\Program Files\DIG\bin"));
    }

    #[test]
    fn the_acl_expression_escapes_a_quote_in_the_path() {
        let cmd = acl_object_expression("C:\\od'd");
        assert!(cmd.contains("'C:\\od''d'"), "{cmd}");
    }
}
