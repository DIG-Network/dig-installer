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
/// redirects the whole stack to a directory the invoking user chose — so every root-side exec in the
/// library is gated on this guard as well:
///
/// 1. `crate::update::detect_installed_version` — the `<dest> --version` probe, which runs before
///    anything is downloaded;
/// 2. `crate::service::run_capturing` — the `install`/`uninstall` verb delegation;
/// 3. `crate::pathcheck::run_version`'s direct-exec branch — reached when there is no account to drop
///    to (a root-shell install, or the macOS GUI's `osascript` child);
/// 4. `crate::dns::doctor`'s two `dig-dns` invocations.
///
/// That list is the whole set, and it is asserted by
/// `the_root_exec_guard_is_wired_into_every_root_side_exec`. An earlier revision of this comment claimed
/// placement covered (3) and (4); it did not, and a claim the code fails to satisfy is worse than no
/// claim.
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
            v.is_blocking(),
            "the ACL read-back must run on a Program Files dir (inherited \
             AppContainer ACEs must not abort it): {}",
            v.note
        );
        assert!(
            !v.is_established_safe(),
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

    /// Every root-side exec of an INSTALLER-PLACED binary must call [`root_exec_guard`] — and the site
    /// list is DERIVED from the source, never written down.
    ///
    /// # Why a hardcoded list is not acceptable here
    ///
    /// The previous version of this test named four files and asserted `sites.len() == 4` under the
    /// comment "Every KNOWN root-side exec is listed above". A FIFTH site
    /// (`dns::os_config::run_os_config`, reached on the default plan, on all three OSes, on install AND
    /// uninstall) was absent from the list, so the count made the omission invisible — and it was proved
    /// to root code execution. A hardcoded count can only ever confirm the author's own belief about the
    /// codebase.
    ///
    /// It was also satisfiable by a MENTION: the check was `file.contains("root_exec_guard")`, so a
    /// surviving rustdoc link kept it green with the real call deleted, and a file with two guarded execs
    /// could silently lose one.
    ///
    /// So this walks every `src/**/*.rs` file, strips comments, finds each `Command::new(<binary>)` whose
    /// argument is a PATH-like binding rather than a trusted system tool, and requires a
    /// `root_exec_guard(` CALL inside the enclosing function. It is self-checking: it fails if it stops
    /// finding the sites it is supposed to police.
    #[test]
    fn every_root_side_exec_of_an_installed_binary_is_guarded() {
        let sources = crate::sources::all();
        let mut checked = Vec::new();
        for (file, src) in &sources {
            for (function, body) in production_functions(src) {
                if !spawns_an_installed_binary(&body) {
                    continue;
                }
                checked.push(format!("{file}::{function}"));
                assert!(
                    body.contains("root_exec_guard("),
                    "{file}::{function} executes an installer-placed binary but never CALLS \
                     secure::root_exec_guard - root would run a binary out of whatever directory it \
                     was handed, which under a --bin-dir override can be one an unprivileged account \
                     writes (#1748). Add the guard, or route the spawn through a guarded helper."
                );
            }
        }

        // Self-check: the scan must still SEE the sites it exists to police. A regex that silently
        // stopped matching would otherwise make this test pass by finding nothing at all — the same
        // vacuity as the hardcoded count, one level up.
        for required in [
            "update.rs::spawn_version_probe",
            "service.rs::run_capturing",
            "pathcheck.rs::run_version",
            "dns/doctor.rs::run_doctor",
            "dns/doctor.rs::run_pac",
            "dns/os_config.rs::run_os_config",
        ] {
            assert!(
                checked.iter().any(|c| c == required),
                "the scan no longer detects {required} as a root-side exec, so it is policing less \
                 than it appears to. Found: {checked:?}"
            );
        }
    }

    /// Does this function body spawn a binary identified by a PATH the installer chose, as opposed to a
    /// trusted system tool resolved from a fixed directory list (§7.6)?
    ///
    /// NOT installer-placed, and so not this invariant's business:
    ///
    /// * a string literal (`Command::new("sh")`);
    /// * a `proc::system_tool(..)` / `elevation::resolve_system_tool(..)` result, inline or via a local
    ///   binding — that is the trusted-resolution path, which has its own invariant and its own tests
    ///   (§7.6). `elevation::is_elevated_unix` spawning a resolved `id` is the reference case.
    ///
    /// Anything else — a `&Path` parameter, a `PathBuf`, a struct field — is a binary this installer
    /// placed, and root must not execute it without checking the directory it came from.
    fn spawns_an_installed_binary(body: &str) -> bool {
        body.match_indices("Command::new(")
            .filter_map(|(i, _)| {
                let rest = &body[i + "Command::new(".len()..];
                rest.find(')').map(|end| rest[..end].trim().to_string())
            })
            .any(|arg| !arg.is_empty() && !is_trusted_tool(body, &arg))
    }

    /// Is `arg`, as spawned inside `body`, a TRUSTED system tool rather than an installer-placed binary?
    fn is_trusted_tool(body: &str, arg: &str) -> bool {
        if arg.starts_with('"') || arg.contains("system_tool") {
            return true;
        }
        // A binding resolved from the trusted directory list, then spawned:
        //   `let Some(id) = resolve_system_tool("id")` … `Command::new(id)`
        //   `resolve_system_tool("su").map(|su| Command::new(su))`
        // Requires BOTH that the function resolves a trusted tool at all, and that the spawned name is
        // introduced as a binding here — a `&Path` PARAMETER (which is what every real root-side exec
        // spawns) is neither, so it cannot be laundered by an unrelated `system_tool` call nearby.
        let name = arg.trim_start_matches('&');
        if !body.contains("system_tool") {
            return false;
        }
        body.lines().any(|l| {
            l.contains(&format!("let {name}"))
                || l.contains(&format!("({name})"))
                || l.contains(&format!("|{name}|"))
                || l.contains(&format!("|{name},"))
        })
    }

    /// Split `src` into `(function name, body)` pairs for the PRODUCTION half of the file, with comments
    /// removed.
    ///
    /// Comments are stripped because the check must not be satisfiable by a doc-comment mention of the
    /// guard — that is exactly how the previous version stayed green with the real call deleted. The
    /// `mod tests` half is excluded because test helpers legitimately spawn fixture scripts by path.
    fn production_functions(src: &str) -> Vec<(String, String)> {
        let production = src.split("\nmod tests {").next().unwrap_or("");
        let mut out: Vec<(String, String)> = Vec::new();
        let mut current: Option<(String, String)> = None;
        for line in production.lines() {
            let code = strip_comment(line);
            if let Some(name) = function_name(&code) {
                if let Some(done) = current.take() {
                    out.push(done);
                }
                current = Some((name, String::new()));
            }
            if let Some((_, body)) = current.as_mut() {
                body.push_str(&code);
                body.push('\n');
            }
        }
        if let Some(done) = current.take() {
            out.push(done);
        }
        out
    }

    /// The declared name when `code` opens a function, else `None`.
    fn function_name(code: &str) -> Option<String> {
        let trimmed = code.trim_start();
        let rest = trimmed
            .strip_prefix("pub fn ")
            .or_else(|| trimmed.strip_prefix("pub(crate) fn "))
            .or_else(|| trimmed.strip_prefix("fn "))?;
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }

    /// `line` with any `//` comment removed, ignoring `//` inside a string literal.
    fn strip_comment(line: &str) -> String {
        let bytes = line.as_bytes();
        let mut in_string = false;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' if in_string => i += 1,
                b'"' => in_string = !in_string,
                b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => {
                    return line[..i].to_string()
                }
                _ => {}
            }
            i += 1;
        }
        line.to_string()
    }

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
        let dir = std::env::temp_dir().join(format!("dig-rootexec-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("dig-userexec-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("dig-secure-ug-{}", std::process::id()));
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

    /// A root-owned `0755` directory whose WHOLE CHAIN is root-owned is accepted.
    ///
    /// The fixture is `/usr/bin` — a real directory whose every level (`/`, `/usr`, `/usr/bin`) is
    /// root-owned `0755` on every supported platform. A temp directory cannot express this property any
    /// more: `/tmp` is mode `1777`, so since #1748 the walk correctly refuses anything beneath it, and
    /// the old fixture asserted "secure" about a chain that never was.
    #[cfg(unix)]
    #[test]
    fn unix_verify_accepts_a_root_owned_chain() {
        let v = verify_install_root(Os::Linux, std::path::Path::new("/usr/bin"));
        // A clean chain is ESTABLISHED safe, which is the only non-blocking outcome.
        assert!(
            v.is_established_safe(),
            "every level of /usr/bin is root-owned 0755, so it must verify clean: {}",
            v.note
        );
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
    /// `/tmp` is mode `1777` on every unix box, which makes it a truthful stand-in for the `0777`
    /// `/opt/dig` this release fixes: write permission on the parent is permission to rename the leaf
    /// aside and substitute an attacker-owned directory of the same name.
    #[cfg(unix)]
    #[test]
    fn unix_verify_rejects_a_perfect_leaf_under_a_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dig-secure-chain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let v = verify_install_root(Os::Linux, &dir);
        assert!(v.is_blocking());
        assert!(
            !v.is_established_safe(),
            "a 0755 leaf under a 1777 ancestor must NOT be reported secure: {}",
            v.note
        );
        assert!(
            v.note.contains("/tmp") || v.note.contains(&dir.display().to_string()),
            "the verdict must name the offending level: {}",
            v.note
        );
        let _ = std::fs::remove_dir_all(&dir);
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
