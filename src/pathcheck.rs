//! Post-install PATH verification (#496, corrected in #1748): confirm each required DIG CLI really
//! resolves by bare name **in the target user's own login shell**, and really runs.
//!
//! # The check this replaces, and why it could not fail
//!
//! The original implementation took the install's `bin_dir`, PREPENDED it to the current process's
//! `PATH`, and then spawned the CLI by bare name against that augmented value. That is not a PATH
//! check — it is an executability check wearing a PATH check's name. It answers "does this file run
//! if I put its directory on PATH?", which is true by construction whenever the download succeeded,
//! and it stays true no matter what the user's environment looks like.
//!
//! So when a `sudo` install put the whole stack in `/root/.dig/bin` and wired root's dotfiles, the
//! check reported `✓ 'dig-node --version' resolved on PATH` while the actual user had no `dig-node`
//! at all. Two independent faults compounded: the check ran in root's environment, and it fabricated
//! the very PATH it claimed to verify. Fixing only the first would have left the check green.
//!
//! # The rule now
//!
//! **The PATH consulted is read from the target environment and is never modified.** Two honest
//! sources, one per platform:
//!
//! * **unix** — the PATH of a fresh LOGIN shell belonging to the [target
//!   user](crate::invoker::TargetUser). Under elevation that means `su - <user> -c 'sh -lc …'`, so the
//!   shell sources that user's `/etc/profile` plus `/etc/profile.d/*` on Linux, or runs `path_helper`
//!   over `/etc/paths` and `/etc/paths.d` on macOS, exactly as their next terminal will. The inner
//!   `sh -lc` is load-bearing — see [`PRINT_PATH_VIA_LOGIN_SH`]. Root's environment is never consulted.
//! * **Windows** — the PERSISTED `Path` values (`HKCU\Environment` + the machine `Environment` key),
//!   which is what a newly-opened shell inherits, rather than the current process's `PATH` (which
//!   may carry an in-process modification the user will never see).
//!
//! Resolution against that PATH is a pure function ([`resolve_in_path`]); only [`login_shell_path`]
//! and [`verify_cli`] touch the machine.

// `Command::new` is denied crate-wide so an unguarded spawn of an INSTALLED binary cannot compile
// (`clippy.toml`, #1748 WU4). The spawns in this module are either trusted SYSTEM tools resolved from a
// fixed directory list (`SPEC.md` §7.6 — a different invariant with its own tests in `elevation`), test
// fixtures, or the guarded wrapper itself.
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use crate::invoker::TargetUser;
use crate::proc::HideConsole;

/// The result of verifying one CLI resolves and runs for the target user.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CliPathCheck {
    /// The CLI id (e.g. `dig-node`).
    pub cli: String,
    /// `true` iff the CLI resolved by bare name on the target user's own PATH to the copy this run
    /// placed, **and** — except for a GUI app, whose `--version` probe never returns on any platform —
    /// actually executed. Where the probe is skipped this bit does NOT claim the binary can start.
    pub resolved: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// The PATH list separator for this host.
pub(crate) fn separator() -> char {
    if cfg!(windows) {
        ';'
    } else {
        ':'
    }
}

/// Find `exe` on `path` — the ONLY PATH consulted, used exactly as given.
///
/// Pure: `exists` decides whether a candidate file is there, so the whole resolution matrix is
/// unit-tested without a filesystem. Returns the first match in list order, mirroring how a shell
/// resolves a bare name (earlier entries shadow later ones). Empty entries are skipped rather than
/// treated as the current directory — a shell would search `.` there, but resolving an installed CLI
/// out of the cwd is never the answer we want to report as success.
///
/// There is deliberately no parameter for "a directory to add": the absence of that parameter is the
/// #1748 fix.
pub fn resolve_in_path(
    path: &str,
    exe: &str,
    sep: char,
    exists: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    path.split(sep)
        .map(str::trim)
        .filter(|dir| !dir.is_empty())
        .map(|dir| Path::new(dir).join(exe))
        .find(|candidate| exists(candidate))
}

/// Which directories on `path` come BEFORE `wanted`, in order?
///
/// # Why position and not existence (#1748 F2)
///
/// `verify_cli_resolves` already refuses when a bare name resolves to something other than the copy this
/// install placed — but that only fires when the shadowing file is ALREADY there. A `PATH` on which an
/// unsafe directory merely PRECEDES the protected root is reported ready, and the attacker then creates the
/// name at her leisure: she never has to touch anything DIG planted, she just gets there first.
///
/// So reachability has to be checked positionally. This returns the directories that would win a name
/// against `wanted`, so a caller can ask whether any of them is a directory a non-root account can write.
/// Pure, and separate from the verdict, so both halves are testable without a real `PATH`.
///
/// `wanted` absent from `path` yields every entry: nothing about it wins, because it cannot be reached at
/// all — a caller distinguishes that with [`path_contains`].
pub fn entries_before(path: &str, wanted: &str, sep: char) -> Vec<String> {
    let trail = if sep == ';' { '\\' } else { '/' };
    let normalise = |e: &str| {
        let e = e.trim().trim_end_matches(trail).to_string();
        if sep == ';' {
            e.to_ascii_lowercase()
        } else {
            e
        }
    };
    let want = normalise(wanted);
    let mut before = Vec::new();
    for entry in path.split(sep).map(str::trim).filter(|e| !e.is_empty()) {
        if normalise(entry) == want {
            return before;
        }
        before.push(entry.to_string());
    }
    before
}

/// Is `dir` present on `path`? Case-insensitive and trailing-separator-insensitive on Windows,
/// matching [`crate::paths::path_append`]'s comparison so "did the append take effect?" has one
/// answer. Pure.
pub fn path_contains(path: &str, dir: &str, sep: char) -> bool {
    let trail = if sep == ';' { '\\' } else { '/' };
    let want = dir.trim_end_matches(trail);
    path.split(sep).map(str::trim).any(|e| {
        let e = e.trim_end_matches(trail);
        if sep == ';' {
            e.eq_ignore_ascii_case(want)
        } else {
            e == want
        }
    })
}

/// Read the PATH the target user's next shell will actually carry.
///
/// unix: the `PATH` of a fresh login shell (`-l`), so `/etc/profile`, `/etc/profile.d/*` and the
/// user's own profile are all sourced. Under elevation the shell is entered as the target user via
/// `su -`, which root can do without a password; that is the whole point — the environment being
/// measured is the user's, not ours.
///
/// Windows: the persisted user + machine `Environment` `Path` values concatenated, which is what a
/// newly-launched shell composes.
pub fn login_shell_path(user: &TargetUser) -> Result<String, String> {
    #[cfg(unix)]
    {
        unix_login_shell_path(user)
    }
    #[cfg(not(unix))]
    {
        let _ = user;
        persisted_path()
    }
}

/// Emit `$PATH` and nothing else. `printf` rather than `echo` so the value carries no trailing
/// newline of its own and no shell-specific `echo` flag handling.
#[cfg(unix)]
const PRINT_PATH: &str = r#"printf '%s\n' "$PATH""#;

/// [`PRINT_PATH`] re-entered through an explicit **login** shell.
///
/// The inner `sh -lc` is required, not belt-and-braces: `su - <user> -c CMD` does NOT produce a login
/// shell on BSD/macOS, because `su`'s own `-c` flag takes a login CLASS there, so a `-c` after the
/// login name is handed to the shell verbatim and no profile is read. Measured on a macos-14 runner:
///
/// ```text
/// su - runner -c 'printf "%s\n" "$PATH"'             -> /bin:/usr/bin
/// su - runner -c 'sh -lc '\''printf "%s\n" "$PATH"'\''' -> /usr/local/bin:…:/opt/homebrew/bin:…
/// ```
///
/// The first is `su`'s bare built-in default — a PATH no real login shell ever has — so without the
/// wrapper the elevated PATH check can never be satisfied on macOS, and `path_helper` (which is what
/// makes `/etc/paths.d` effective) never runs (#1748).
#[cfg(unix)]
const PRINT_PATH_VIA_LOGIN_SH: &str = r#"sh -lc 'printf "%s\n" "$PATH"'"#;

/// The unix login-shell PATH for `user` — `su - <user>` under elevation, else our own login shell.
#[cfg(unix)]
fn unix_login_shell_path(user: &TargetUser) -> Result<String, String> {
    // `su`/`sh` are resolved from the trusted system directories, NEVER `$PATH`
    // (`elevation::resolve_system_tool`). This runs as root, and macOS's stock sudoers sets no
    // `secure_path`, so a `$PATH` led by a user-writable Homebrew prefix would let an attacker supply
    // the very shell root spawns. Fail-closed: an unresolvable tool is an error, never a fallback to
    // a `$PATH` lookup.
    // `is_root()`, not the elevation hint: in the macOS GUI's root child there is no hint, and reading
    // OUR OWN login shell there measures ROOT's PATH while reporting it as the user's (#1748).
    let out = if user.acting_for_another_account(crate::invoker::is_root()) {
        let su = crate::elevation::resolve_system_tool("su")
            .ok_or_else(|| "su not found in any trusted system directory".to_string())?;
        Command::new(su)
            .arg("-")
            .arg(&user.name)
            .arg("-c")
            .arg(PRINT_PATH_VIA_LOGIN_SH)
            .hide_console()
            .output()
    } else {
        let sh = crate::elevation::resolve_system_tool("sh")
            .ok_or_else(|| "sh not found in any trusted system directory".to_string())?;
        Command::new(sh)
            .arg("-lc")
            .arg(PRINT_PATH)
            .hide_console()
            .output()
    };
    let out = out.map_err(|e| format!("could not start a login shell for {}: {e}", user.name))?;
    if !out.status.success() {
        return Err(format!(
            "a login shell for {} exited with {} ({})",
            user.name,
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // A login shell may print motd/profile chatter first; the PATH is the LAST non-empty line.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let path = stdout
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("")
        .to_string();
    if path.is_empty() {
        return Err(format!(
            "a login shell for {} reported an empty PATH",
            user.name
        ));
    }
    Ok(path)
}

/// Windows: the PERSISTED `Path` — machine (`Session Manager\Environment`) then user
/// (`HKCU\Environment`) — which is what a new shell inherits. The current process's `PATH` is
/// deliberately not consulted.
#[cfg(windows)]
fn persisted_path() -> Result<String, String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    const MACHINE_ENV: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    let user: String = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags("Environment", KEY_READ)
        .and_then(|k| k.get_value("Path"))
        .unwrap_or_default();
    let machine: String = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(MACHINE_ENV, KEY_READ)
        .and_then(|k| k.get_value("Path"))
        .unwrap_or_default();
    let joined = [machine.trim_end_matches(';'), user.trim_end_matches(';')]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(";");
    if joined.is_empty() {
        Err("could not read the persisted Windows Path".to_string())
    } else {
        // Expand `%SystemRoot%`-style references the persisted REG_EXPAND_SZ values contain, against
        // the PERSISTED environment rather than our own (see `persisted_env_lookup`).
        Ok(expand_env_refs(&joined, persisted_env_lookup))
    }
}

/// Resolve `%NAME%` from the PERSISTED environment — the machine `Environment` key, then the user's —
/// falling back to this process's value only for a name neither key defines.
///
/// # Why the persisted keys come first (dig_ecosystem#2205)
///
/// The fallback is needed at all because the names a persisted `Path` most often references
/// (`SystemRoot`, `ProgramFiles`, `USERPROFILE`) live in the session environment block Windows builds,
/// not in either `Environment` key — so a persisted-only lookup would leave `%SystemRoot%\system32`
/// unexpanded and stop the check finding anything in it. But where a key DOES define the name, that
/// value is the one a new shell will carry, and ours may have been changed in-process or inherited from
/// a launching shell. Persisted state decides; our own environment is the last resort.
#[cfg(windows)]
fn persisted_env_lookup(name: &str) -> Option<String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    const MACHINE_ENV: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    let from = |root, subkey| -> Option<String> {
        RegKey::predef(root)
            .open_subkey_with_flags(subkey, KEY_READ)
            .and_then(|k| k.get_value(name))
            .ok()
    };
    from(HKEY_LOCAL_MACHINE, MACHINE_ENV)
        .or_else(|| from(HKEY_CURRENT_USER, "Environment"))
        .or_else(|| std::env::var(name).ok())
}

/// Expand `%NAME%` references in a persisted `REG_EXPAND_SZ` PATH, resolving each name through
/// `lookup`. An unknown name is left verbatim so a broken reference is visible in the reported PATH
/// rather than silently becoming empty.
///
/// # A `%PATH%` self-reference expands to NOTHING, deliberately (dig_ecosystem#2205)
///
/// A persisted `Path` may contain a literal `%PATH%` entry — this is not hypothetical; it was the
/// second entry of the machine `Path` on the machine that raised #2205. The name it references is the
/// value being composed, so there is no honest persisted answer, and resolving it through the process
/// environment is actively wrong: it splices THIS process's `PATH` into the middle of the value, which
/// is precisely the source this module refuses to consult (see the module header).
///
/// It was measured doing real damage. Expanding that one entry against the installer's inherited
/// environment turned a 63-entry composed session `PATH` into a 151-entry one, and the extra entries
/// carried a copy of the install root — so whether the shadow check saw a genuine shadow depended on
/// which shell had launched the installer:
///
/// * launched from a shell that had already inherited the install root, the spliced entries put it
///   early and the check reported a clean PATH while a stale root really did win a fresh shell — a
///   false NEGATIVE, the failure mode this guard exists to prevent;
/// * launched from a clean context, the same code reported the shadow correctly.
///
/// Dropping the self-reference cannot hide a real shadow: every directory it could contribute is either
/// already an entry of the machine or user `Path` (and therefore still searched), or is a volatile
/// addition made by the launching process, which no new shell will have.
fn expand_env_refs(value: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    /// The name whose expansion is the value being composed — never resolved. Compared
    /// case-insensitively: the registry writes `Path`, shells say `PATH`, and both appear in the wild.
    const SELF_REFERENCE: &str = "PATH";

    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                if name.eq_ignore_ascii_case(SELF_REFERENCE) {
                    // Expands to nothing; the surrounding separators collapse into an empty PATH
                    // entry, which `resolve_in_path` already skips.
                } else if let Some(v) = lookup(name) {
                    out.push_str(&v);
                } else {
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                out.push_str(after);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(not(any(unix, windows)))]
fn persisted_path() -> Result<String, String> {
    Err("no persisted PATH source on this platform".to_string())
}

/// Verify `exe_name` resolves by bare name on `user`'s own PATH, resolves to the binary **this run
/// installed**, and then RUNS.
///
/// Four things must all hold before this reports success, and each is checked against reality rather
/// than against a value we supplied:
///
/// 1. the target user's login-shell PATH can be read;
/// 2. `exe_name` resolves somewhere on that PATH (no directory is added to it);
/// 3. what it resolves to IS `installed_at` — nothing else on PATH shadows this install; and
/// 4. the resolved file executes — `<exe> --version` exits zero.
///
/// Step 3 exists because steps 2 and 4 together are still satisfiable by the WRONG binary. A stale
/// copy left on PATH by an earlier install answers the bare name, runs fine, and reports a version —
/// so a broken install passes while the user is silently running something else. That was observed on
/// a real box: an install redirected into an unreachable directory still verified green, because a
/// previous run's `/usr/local/bin/dig-store` was picked up instead.
///
/// Both sides are canonicalized before comparison, so the deliberate `/usr/local/bin/dig-dns` →
/// `/opt/dig/bin/dig-dns` symlink ([`crate::paths::needs_machine_bin_link`]) is recognised as the same
/// binary rather than reported as a shadow.
///
/// Step 4 runs the resolved ABSOLUTE path, so a component whose binary is present but cannot load (a
/// missing shared library, a wrong-arch download) is reported as a failure instead of earning a `✓`
/// for merely existing.
pub fn verify_cli(
    user: &TargetUser,
    exe_name: &str,
    installed_at: &Path,
) -> Result<String, String> {
    let resolved = verify_cli_resolves(user, exe_name, installed_at)?;
    run_version(&resolved, user)
}

/// Steps 1–3 of [`verify_cli`] on their own: the bare name resolves, on the TARGET user's own login
/// `PATH`, to the copy this run placed — returning that resolved path.
///
/// Used on its own only for a GUI application, whose `--version` probe never returns on any platform
/// (`dig-app` enters its event loop instead of printing and exiting). It is a STRICTLY WEAKER claim
/// than [`verify_cli`]: it says the invoking user can reach the binary this install placed — the #1748
/// property — and says NOTHING about whether that binary can actually start.
///
/// Nothing else in the crate makes up the difference: `autostart` writes a unit file but never enables
/// or starts `dig-app`, so a successful registration is fully consistent with a binary that cannot
/// load. So `crate::answers_version` documents the exemption as a known GAP, and this returning `Ok`
/// must not be read as an executability guarantee.
pub fn verify_cli_resolves(
    user: &TargetUser,
    exe_name: &str,
    installed_at: &Path,
) -> Result<PathBuf, String> {
    let path = login_shell_path(user)?;
    let sep = separator();
    let resolved = resolve_in_path(&path, exe_name, sep, |p| p.is_file()).ok_or_else(|| {
        format!(
            "`{exe_name}` is not on {}'s PATH (a fresh login shell searches: {path})",
            user.name
        )
    })?;
    if !same_binary(&resolved, installed_at) {
        return Err(format!(
            "`{exe_name}` resolves to {} for {}, NOT to the copy this install placed at {} — \
             something already on PATH shadows this install",
            resolved.display(),
            user.name,
            installed_at.display()
        ));
    }
    // The CANONICAL target, not the name that resolved to it (#1748, F5). On an elevated install the
    // PATH hit is `/usr/local/bin/<exe>`, a symlink in a directory Homebrew leaves `<user>:admin 0775`
    // on an Intel Mac — so returning it means the caller goes on to EXECUTE a path whose final
    // component an unprivileged account may control. The canonical form is the placement inside the
    // root-owned protected root, which is the copy whose properties were actually verified.
    Ok(resolved.canonicalize().unwrap_or(resolved))
}

/// Are `a` and `b` the same binary, following symlinks?
///
/// Canonicalization is what makes the intentional `/usr/local/bin/dig-dns` → `/opt/dig/bin/dig-dns`
/// link compare equal. If either path cannot be canonicalized (it vanished mid-check) the raw paths
/// are compared, so an unreadable path is never silently treated as a match.
fn same_binary(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// How long a `--version` probe may take before it is declared hung and killed.
///
/// Generous enough for a cold start of a large binary on a loaded CI runner, and far short of any
/// plausible job or user patience budget. The bound exists because a probe with NO bound once held an
/// entire install for 15 minutes (#1748) — see [`output_within`].
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// Run `cmd` to completion, but never wait longer than `timeout` — on overrun the child is KILLED and
/// an error naming `what` is returned.
///
/// `Command::output` waits forever, which makes any single misbehaving binary able to hang the whole
/// install. That is not theoretical: a GUI application asked for `--version` on macOS enters its event
/// loop and never exits. An install that reports "this binary did not answer" is strictly better than
/// one that appears to freeze, so the deadline is enforced rather than trusted.
///
/// The pipes are deliberately NOT drained on the timeout path: a killed `su` may leave a grandchild
/// holding the write end, and reading it would reintroduce exactly the hang being prevented. Dropping
/// the child closes our read ends.
fn output_within(cmd: &mut Command, timeout: Duration, what: &str) -> Result<Output, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{what} could not start: {e}"))?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{what} did not finish within {}s and was killed — the binary does not answer \
                         `--version`",
                        timeout.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("{what} could not be waited on: {e}")),
        }
    }
    child
        .wait_with_output()
        .map_err(|e| format!("{what} output could not be read: {e}"))
}

/// The `su - <user> -c '<binary> --version'` form, when there is a user boundary to cross.
///
/// `None` means "run it directly" (we genuinely are that user, or this is Windows). `Some(Err(..))` is
/// fail-closed: `su` is resolved from the trusted system directories, never `$PATH`
/// ([`crate::elevation::resolve_system_tool`]), because this spawn happens as root.
///
/// # The question is "am I root, acting for somebody else?" (#1748)
///
/// This used to branch on `user.via_elevation`, which is `true` only when an elevation HINT identified a
/// different account (`SUDO_USER`, `DOAS_USER`, `PKEXEC_UID`) — so it answers how root was REACHED rather
/// than whether root's authority is being held on another account's behalf. The condition that makes this
/// exec dangerous is the latter, so the predicate is
/// [`TargetUser::acting_for_another_account`](crate::invoker::TargetUser::acting_for_another_account).
///
/// It is a real difference wherever a non-root account is resolved with no hint present — `su -m`/`su -p`
/// preserve the environment, and this call then execs the probed binary AS ROOT under the old predicate.
/// It is NOT a difference in the macOS GUI's `osascript` child: no environment is inherited there, so no
/// other account is knowable and both predicates answer `false`. That gap is `SPEC.md` §1.5a /
/// DIG-Network/dig_ecosystem#1779, not something this branch closes.
#[cfg(unix)]
fn as_user_command(binary: &Path, user: &TargetUser) -> Option<Result<Command, String>> {
    if !user.acting_for_another_account(crate::invoker::is_root()) {
        return None;
    }
    Some(
        crate::elevation::resolve_system_tool("su")
            .ok_or_else(|| "su not found in any trusted system directory".to_string())
            .map(|su| {
                let mut c = Command::new(su);
                c.arg("-").arg(&user.name).arg("-c").arg(format!(
                    "{} --version",
                    crate::userwrite::shell_quote(binary)
                ));
                c
            }),
    )
}

/// Windows has no `su` boundary to cross — the probe always runs directly.
#[cfg(not(unix))]
fn as_user_command(_binary: &Path, _user: &TargetUser) -> Option<Result<Command, String>> {
    None
}

/// Run `<binary> --version` and return its trimmed output.
///
/// Under elevation the binary is run AS the target user (`su - <user> -c`), because "root can
/// execute it" is not the claim being made — the claim is that the user can. A binary that is
/// present but unloadable surfaces its loader error here (for example a missing `libxdo.so.3`),
/// which is the detail the failure note must carry.
///
/// When there is no account to drop to — a genuine root-shell install, or the macOS GUI's `osascript`
/// child, where the resolved account IS root — root execs the binary itself, so that branch is gated on
/// [`crate::secure::root_exec_guard`]: the containing directory must not be one an unprivileged account
/// can write. Placement alone does not cover it, because a `--bin-dir` override can aim this call
/// anywhere.
pub(crate) fn run_version(binary: &Path, user: &TargetUser) -> Result<String, String> {
    let mut cmd = match as_user_command(binary, user) {
        Some(c) => c?,
        None => {
            // No boundary to cross means either we are unelevated — executing a binary the user can
            // already write is their own authority — or we are root acting AS root, which is the one
            // case where root really does exec this binary itself. Spawned through `GuardedCommand`,
            // which cannot exist without the root-exec guard having passed: with a `--bin-dir` override
            // the directory can be one an unprivileged account writes, and neither placement nor the
            // `su` drop protects this call then (#1748 F5/WU4).
            let mut guarded = crate::guardedcmd::GuardedCommand::for_installed_binary(binary)?;
            guarded.arg("--version");
            guarded.into_command()
        }
    };
    cmd.hide_console();
    let what = format!("`{} --version`", binary.display());
    let out = output_within(&mut cmd, VERSION_PROBE_TIMEOUT, &what)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            format!("exit {}", out.status.code().unwrap_or(-1))
        } else {
            stderr
        };
        return Err(format!(
            "`{} --version` resolved on PATH but did NOT run: {detail}",
            binary.display()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let reported = if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        stdout.trim().to_string()
    };
    Ok(reported.lines().last().unwrap_or("").trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, elevated: bool) -> TargetUser {
        TargetUser {
            name: name.to_string(),
            home: PathBuf::from(format!("/home/{name}")),
            uid: if elevated { Some(1000) } else { None },
            gid: if elevated { Some(1000) } else { None },
            via_elevation: elevated,
        }
    }

    /// An `exists` oracle that admits exactly the listed paths and nothing else.
    fn only<'a>(present: &'a [&'a str]) -> impl Fn(&Path) -> bool + 'a {
        move |p: &Path| {
            let p = p.to_string_lossy().replace('\\', "/");
            present.iter().any(|q| *q == p)
        }
    }

    // -- #1748: the check must FAIL against the broken layout ------------------

    /// THE regression, stated as the property: a binary that exists on disk but whose directory is
    /// NOT on the PATH being searched must NOT resolve.
    ///
    /// This is the shipped bug's exact shape — the install went to `/root/.dig/bin`, the user's
    /// login PATH was the stock Ubuntu one, and the old check reported success. The fixture keeps a
    /// truthful control in the same test: the same PATH, the same `exists` oracle, and a binary that
    /// IS on PATH resolves fine — so this cannot pass by a resolver that simply always returns
    /// `None`.
    #[test]
    fn a_binary_outside_the_searched_path_does_not_resolve() {
        // The stock Ubuntu login PATH for a non-root user. /root/.dig/bin is not on it, and cannot
        // be: /root is mode 0700.
        let login_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        let exists = only(&["/root/.dig/bin/dig-node", "/usr/local/bin/dig-store"]);

        // The broken layout: present on disk, unreachable from the user's shell.
        assert_eq!(
            resolve_in_path(login_path, "dig-node", ':', &exists),
            None,
            "a CLI only present in /root/.dig/bin must NOT be reported as on the user's PATH"
        );
        // The control: a CLI in a directory that IS on that PATH resolves, so the fixture is
        // capable of returning Some and the assertion above is load-bearing.
        assert_eq!(
            resolve_in_path(login_path, "dig-store", ':', &exists),
            Some(PathBuf::from("/usr/local/bin/dig-store"))
        );
    }

    /// The resolver takes no "directory to add" parameter, and must not acquire one by the back
    /// door: given a PATH that omits the install dir, no amount of the install dir being real makes
    /// the lookup succeed. Expressed over TWO candidate dirs so a fix that merely reorders — rather
    /// than removes — an injection is still caught.
    #[test]
    fn resolution_never_augments_the_path_it_was_given() {
        let exists = only(&["/root/.dig/bin/dign", "/opt/dig/bin/dign"]);
        assert_eq!(resolve_in_path("/usr/bin:/bin", "dign", ':', &exists), None);
        // Only once a searched directory actually holds it does it resolve.
        assert_eq!(
            resolve_in_path("/usr/bin:/opt/dig/bin", "dign", ':', &exists),
            Some(PathBuf::from("/opt/dig/bin/dign"))
        );
    }

    /// Shell semantics: the FIRST match in list order wins, because an earlier entry shadows a later
    /// one. The fixture puts the same name in two searched directories — a resolver that returned
    /// any match, or the last one, is distinguishable here.
    #[test]
    fn the_first_matching_directory_wins_like_a_shell() {
        let exists = only(&["/usr/local/bin/dig-node", "/home/u/.dig/bin/dig-node"]);
        assert_eq!(
            resolve_in_path("/home/u/.dig/bin:/usr/local/bin", "dig-node", ':', &exists),
            Some(PathBuf::from("/home/u/.dig/bin/dig-node")),
            "an earlier PATH entry shadows a later one"
        );
    }

    /// An empty PATH entry must not be searched as the current directory: resolving an installed CLI
    /// out of the cwd is not the success we mean to report.
    #[test]
    fn an_empty_path_entry_is_not_searched_as_the_cwd() {
        let exists = only(&["dig-node"]);
        assert_eq!(
            resolve_in_path("::/usr/bin", "dig-node", ':', &exists),
            None
        );
    }

    #[test]
    fn an_entirely_empty_path_resolves_nothing() {
        assert_eq!(resolve_in_path("", "dig-node", ':', |_| true), None);
    }

    /// Surrounding whitespace on a PATH entry (real profiles contain it) must not defeat resolution.
    #[test]
    fn path_entries_are_trimmed() {
        let exists = only(&["/usr/local/bin/digs"]);
        assert_eq!(
            resolve_in_path("/usr/bin : /usr/local/bin ", "digs", ':', &exists),
            Some(PathBuf::from("/usr/local/bin/digs"))
        );
    }

    // -- #2205: the verdict is a property of PERSISTED state, never of our own env ----

    /// The install root and the superseded root as they were measured on the #2205 machine: the stale
    /// root is an entry of the MACHINE `Path`, the current root only of the USER `Path`, and the
    /// machine value's second entry is a literal `%PATH%` self-reference.
    const STALE_ROOT: &str = r"C:\Program Files\DIG Network\dig-node";
    const CURRENT_ROOT: &str = r"C:\Program Files\DIG\bin";
    const PERSISTED_MACHINE_THEN_USER: &str =
        concat!(r"C:\Windows\system32;%PATH%;C:\Program Files\DIG Network\dig-node\;",
                r"%SystemRoot%\System32\Wbem;C:\Program Files\DIG\bin");

    /// THE #2205 property: which binary the shadow check reports must not depend on the environment
    /// of whatever launched the installer.
    ///
    /// The fixture is the measured one. Both DIG roots hold `dig-node.exe`, so resolution succeeds
    /// either way and only the ORDER decides the verdict — a resolver that simply failed is
    /// distinguishable. The two arms differ in exactly ONE thing, the ambient `PATH` the `%PATH%`
    /// entry would resolve to:
    ///
    /// * arm A — an ambient `PATH` that does NOT carry the current root (a clean/elevated launch);
    /// * arm B — an ambient `PATH` that carries the current root FIRST (launched from a shell that
    ///   had already inherited it).
    ///
    /// Arm B is what makes this load-bearing: under the pre-fix expansion it splices the current root
    /// in ahead of the stale one and the check reports a clean PATH, so the two arms disagree. They
    /// must now agree, and agree on the truth a fresh session shows — the stale root wins.
    #[test]
    fn the_resolution_verdict_does_not_depend_on_the_launching_shells_path() {
        let exists = only(&[
            "C:/Program Files/DIG Network/dig-node/dig-node.exe",
            "C:/Program Files/DIG/bin/dig-node.exe",
            "C:/Windows/system32/where.exe",
        ]);
        let verdict = |ambient: &'static str| {
            let expanded = expand_env_refs(PERSISTED_MACHINE_THEN_USER, move |name| match name {
                "PATH" | "Path" => Some(ambient.to_string()),
                "SystemRoot" => Some(r"C:\Windows".to_string()),
                _ => None,
            });
            resolve_in_path(&expanded, "dig-node.exe", ';', &exists)
        };

        let clean_launch = verdict(r"C:\Windows\system32");
        let launched_from_a_shell_carrying_the_current_root =
            verdict(concat!(r"C:\Program Files\DIG\bin;C:\Windows\system32"));

        assert_eq!(
            clean_launch, launched_from_a_shell_carrying_the_current_root,
            "the shadow verdict changed with the launching shell's PATH — it must be a property of \
             the persisted machine+user Path alone"
        );
        assert_eq!(
            clean_launch,
            Some(PathBuf::from(format!(r"{STALE_ROOT}\dig-node.exe"))),
            "the machine Path's stale root precedes the user Path's current root, so it wins a fresh \
             shell and the check must say so"
        );
    }

    /// The control for the test above: with the self-reference removed from the fixture, the SAME
    /// persisted value must still resolve the stale root first, and the current root must still be
    /// reachable. Without this, an expansion that returned the empty string for everything would
    /// satisfy the agreement assertion while destroying the PATH.
    #[test]
    fn expansion_preserves_every_entry_other_than_the_self_reference() {
        let expanded = expand_env_refs(PERSISTED_MACHINE_THEN_USER, |name| match name {
            "SystemRoot" => Some(r"C:\Windows".to_string()),
            _ => None,
        });
        assert!(path_contains(&expanded, STALE_ROOT, ';'), "got: {expanded}");
        assert!(path_contains(&expanded, CURRENT_ROOT, ';'), "got: {expanded}");
        assert!(
            path_contains(&expanded, r"C:\Windows\System32\Wbem", ';'),
            "an ordinary %VAR% must still expand: {expanded}"
        );
        assert!(
            !expanded.to_ascii_uppercase().contains("%PATH%"),
            "the self-reference must not survive as a literal entry: {expanded}"
        );
    }

    /// A name neither `Environment` key defines is left verbatim, so a broken reference is visible in
    /// the reported PATH instead of silently swallowing the rest of the entry.
    #[test]
    fn an_unresolvable_reference_is_left_verbatim() {
        let expanded = expand_env_refs(r"C:\Windows;%NoSuchVar%\bin", |_| None);
        assert_eq!(expanded, r"C:\Windows;%NoSuchVar%\bin");
    }

    /// An unterminated `%` is not a reference and must be carried through unchanged rather than
    /// consuming the tail of the value.
    #[test]
    fn an_unterminated_percent_is_not_a_reference() {
        let expanded = expand_env_refs(r"C:\Windows;C:\100%bin", |_| {
            panic!("no complete reference exists, so lookup must not be consulted")
        });
        assert_eq!(expanded, r"C:\Windows;C:\100%bin");
    }

    // -- path_contains ---------------------------------------------------------

    /// The membership test used to decide whether a PATH wiring took effect. Both directions
    /// asserted: the dir we wired is found, and a dir we did not wire is not.
    #[test]
    fn path_contains_answers_both_ways() {
        let p = "/usr/local/bin:/usr/bin:/home/u/.dig/bin";
        assert!(path_contains(p, "/home/u/.dig/bin", ':'));
        assert!(path_contains(p, "/usr/local/bin", ':'));
        assert!(
            !path_contains(p, "/root/.dig/bin", ':'),
            "the broken layout's dir must not be reported as present"
        );
    }

    #[test]
    fn path_contains_ignores_a_trailing_separator() {
        assert!(path_contains("/usr/bin:/opt/dig/bin/", "/opt/dig/bin", ':'));
    }

    #[test]
    fn path_contains_is_case_sensitive_on_unix_and_insensitive_on_windows() {
        // unix: different case is a different directory.
        assert!(!path_contains("/home/U/.dig/bin", "/home/u/.dig/bin", ':'));
        // Windows: it is the same directory.
        assert!(path_contains(
            r"C:\PROGRAM FILES\DIG\bin",
            r"C:\Program Files\DIG\bin",
            ';'
        ));
    }

    // Quoting is tested where the one shared quoter lives (`crate::userwrite::shell_quote`).

    // -- the live boundary -----------------------------------------------------

    /// A name that certainly is not installed must be reported unresolved, never panic — the
    /// fail-loud readiness path depends on this returning `Err`.
    #[test]
    fn verify_cli_reports_a_missing_binary_as_unresolved() {
        let err = verify_cli(
            &user("nobody-here", false),
            "definitely-not-a-real-dig-cli-xyz",
            Path::new("/nowhere/definitely-not-a-real-dig-cli-xyz"),
        )
        .unwrap_err();
        assert!(
            err.contains("not on") || err.contains("login shell") || err.contains("PATH"),
            "got: {err}"
        );
    }

    /// A STALE copy on PATH must not vouch for a broken install.
    ///
    /// Observed on a real box: an install redirected into a directory the user could not reach still
    /// verified green, because an earlier run's `/usr/local/bin/dig-store` answered the bare name, ran
    /// fine, and reported a version. "Resolves and runs" is satisfiable by the WRONG binary, so the
    /// identity of what resolved is part of the property.
    ///
    /// The fixture needs TWO real directories — a shadowing one on the searched PATH and the install's
    /// own, off it — because with a single directory the correct and the shadowed outcome are
    /// indistinguishable. Both files exist, so neither existence nor executability is what fails here.
    #[test]
    fn a_stale_copy_on_path_does_not_vouch_for_the_installed_one() {
        let shadow_dir = tempfile::tempdir().expect("tempdir");
        let install_dir = tempfile::tempdir().expect("tempdir");
        let name = if cfg!(windows) { "digx.exe" } else { "digx" };
        let shadow = shadow_dir.path().join(name);
        let installed = install_dir.path().join(name);
        std::fs::write(&shadow, b"stale").expect("write");
        std::fs::write(&installed, b"fresh").expect("write");

        // Only the shadow directory is on the PATH being searched.
        let path = shadow_dir.path().to_string_lossy().to_string();
        let resolved =
            resolve_in_path(&path, name, separator(), |p| p.is_file()).expect("shadow resolves");
        assert_eq!(resolved, shadow);

        // The two are different binaries, so the install must NOT be credited …
        assert!(
            !same_binary(&resolved, &installed),
            "a stale copy elsewhere on PATH is not the binary this run installed"
        );
        // … while the same binary, and a symlink to it, MUST be recognised — otherwise the check would
        // reject the deliberate /usr/local/bin/dig-dns -> /opt/dig/bin/dig-dns link.
        assert!(same_binary(&installed, &installed));
        #[cfg(unix)]
        {
            let link = shadow_dir.path().join("digx-link");
            std::os::unix::fs::symlink(&installed, &link).expect("symlink");
            assert!(
                same_binary(&link, &installed),
                "a symlink to the installed binary is the same binary"
            );
        }
    }

    /// A file that exists but is not a runnable program must be reported as a FAILURE, not a `✓`.
    /// This is the dig-app symptom in miniature: present on disk, cannot execute.
    ///
    /// The fixture writes a file whose *content* is not an executable image, sets the executable bit,
    /// and puts its directory on the PATH being searched — so RESOLUTION succeeds and only EXECUTION
    /// can fail, which is the step under test. An implementation that stopped at "the file is there"
    /// passes the resolve and fails here.
    #[test]
    fn a_present_but_unrunnable_binary_is_a_failure_not_a_tick() {
        let dir = tempfile::tempdir().expect("tempdir");
        let name = if cfg!(windows) {
            "notreal.exe"
        } else {
            "notreal"
        };
        let file = dir.path().join(name);
        std::fs::write(&file, b"this is not an executable image").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Executable bit SET — so the only thing that can fail is actually running it.
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Resolution must succeed against a PATH that really contains the directory …
        let path = dir.path().to_string_lossy().to_string();
        assert!(
            resolve_in_path(&path, name, separator(), |p| p.is_file()).is_some(),
            "the fixture must resolve, so that EXECUTION is the step under test"
        );
        // … and execution must then fail.
        assert!(
            run_version(&file, &user("nobody", false)).is_err(),
            "a present-but-unrunnable binary must not be reported as working"
        );
    }

    // -- #1748: no single binary may hang the whole install -----------------------

    /// A probe that never returns must be KILLED and reported, not waited on forever.
    ///
    /// This is not hypothetical: `dig-app --version` on macos-14 never returns (it is a tray app and
    /// enters its event loop), which held the installer for the full 15-minute job timeout. An install
    /// that hangs is worse than one that reports a failure, so the deadline is enforced.
    #[test]
    fn a_probe_that_never_returns_is_killed_and_reported() {
        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/c", "ping 127.0.0.1 -n 30 > NUL"]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", "sleep 30"]);
            c
        };
        let started = std::time::Instant::now();
        let err = output_within(&mut cmd, Duration::from_millis(600), "the probe").unwrap_err();
        assert!(err.contains("did not finish"), "got: {err}");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the deadline was not enforced — took {:?}",
            started.elapsed()
        );
    }

    /// The deadline must not break the ordinary case: a command that exits promptly still yields its
    /// output. Asserting this stops the timeout from being "fixed" by failing everything.
    #[test]
    fn a_prompt_probe_still_returns_its_output() {
        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/c", "echo hello"]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", "echo hello"]);
            c
        };
        let out = output_within(&mut cmd, Duration::from_secs(30), "the probe").unwrap();
        assert!(out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("hello"),
            "got: {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// THE macOS regression (#1748): the elevated probe must go through an explicit LOGIN shell.
    ///
    /// `su - <user> -c CMD` reads no profile on BSD/macOS, so probing with a bare command measures
    /// `su`'s built-in `/bin:/usr/bin` instead of the user's real login PATH — which made every
    /// `cli_path_checks` entry report "not on PATH" on macos-14 no matter what the installer wired.
    /// Asserted on the constant because the behaviour itself needs a second account to observe.
    #[cfg(unix)]
    #[test]
    fn the_elevated_path_probe_goes_through_a_login_shell() {
        assert!(
            PRINT_PATH_VIA_LOGIN_SH.contains("sh -lc"),
            "without an explicit login shell macOS reports su's bare default PATH: {PRINT_PATH_VIA_LOGIN_SH}"
        );
        assert!(
            PRINT_PATH_VIA_LOGIN_SH.contains("$PATH"),
            "got: {PRINT_PATH_VIA_LOGIN_SH}"
        );
        // The un-wrapped form is what the bug used, so it must NOT be what the elevated probe sends.
        assert_ne!(PRINT_PATH_VIA_LOGIN_SH, PRINT_PATH);
    }

    /// `entries_before` answers WHICH directories win a name against ours, in order.
    ///
    /// The property the shadow check cannot see: a `PATH` on which a writable directory merely PRECEDES the
    /// install dir is reported ready, and the attacker creates the name afterwards. So the ordering itself
    /// has to be inspectable.
    #[test]
    fn entries_before_returns_only_what_precedes_the_wanted_directory() {
        let path = "/usr/local/sbin:/usr/local/bin:/usr/bin:/opt/dig/bin:/sbin";
        assert_eq!(
            entries_before(path, "/opt/dig/bin", ':'),
            vec!["/usr/local/sbin", "/usr/local/bin", "/usr/bin"],
            "everything up to but not including the wanted dir, in PATH order"
        );

        // First on PATH: nothing wins against it. This is what prepending buys.
        assert!(entries_before("/opt/dig/bin:/usr/bin", "/opt/dig/bin", ':').is_empty());

        // Absent: nothing about it wins because it cannot be reached at all, so every entry is returned and
        // the caller distinguishes the case with `path_contains`.
        assert_eq!(
            entries_before("/usr/bin:/bin", "/opt/dig/bin", ':').len(),
            2
        );

        // Trailing separators and duplicates must not defeat the match, or a losing PATH would be reported
        // as winning.
        assert!(entries_before("/usr/bin:/opt/dig/bin/", "/opt/dig/bin", ':').len() == 1);
    }

    // -- #1748: "am I root?", not "was I sudo'd?" --------------------------------    // -- #1748: "am I root?", not "was I sudo'd?" --------------------------------

    /// The predicate must answer "am I root, acting for somebody else?" — and it is asserted over its
    /// three INPUTS directly, not through the ambient uid.
    ///
    /// This replaces a test that could not fail. It called `as_user_command`, which reads the real uid,
    /// and CI runs unprivileged — so only the `is_none()` arm ever ran, and the DEFECTIVE
    /// `!user.via_elevation` predicate satisfies that arm identically for a `via_elevation: false`
    /// fixture. Reverting the fix left the suite GREEN 650/650. The property is now expressed against a
    /// pure function so every combination is reachable on any runner.
    ///
    /// The decisive row is the second: root, no elevation hint, acting for a NON-ROOT account. That state
    /// is reached by `su -m`/`su -p`, which preserve the environment — not by the macOS `osascript` child,
    /// where no account other than root is knowable at all (#1779). `!via_elevation` says "no boundary"
    /// there and execs as root; asking whether we are root acting for another account says "cross it".
    #[test]
    fn the_boundary_is_decided_by_the_uid_and_the_account_never_by_an_elevation_hint() {
        let alice = |via_elevation| TargetUser {
            name: "alice".to_string(),
            home: std::path::PathBuf::from("/home/alice"),
            uid: Some(1000),
            gid: Some(1000),
            via_elevation,
        };
        let root = |via_elevation| TargetUser {
            name: "root".to_string(),
            home: std::path::PathBuf::from("/root"),
            uid: Some(0),
            gid: Some(0),
            via_elevation,
        };

        // (euid_is_root, user, must_cross, why)
        let cases: [(bool, TargetUser, bool, &str); 7] = [
            (
                true,
                alice(true),
                true,
                "sudo: root acting for alice — drop privilege",
            ),
            (
                true,
                alice(false),
                true,
                "root, NO hint, acting for a non-root account (`su -m` preserves the environment):                  the defective predicate reports \"not elevated\" and execs as root",
            ),
            (
                true,
                root(false),
                false,
                "a genuine root install: no other account to drop to",
            ),
            (
                true,
                root(true),
                false,
                "root named as the target by a hint is still root",
            ),
            (
                false,
                alice(false),
                false,
                "unelevated: we already ARE alice",
            ),
            (
                false,
                alice(true),
                false,
                "unelevated with a stale hint in the environment is still not root",
            ),
            (
                true,
                TargetUser {
                    name: "toor".to_string(),
                    home: std::path::PathBuf::from("/root"),
                    uid: Some(0),
                    gid: Some(0),
                    via_elevation: false,
                },
                false,
                "a uid-0 account not literally named `root` is still root - the UID decides, and a name                  comparison would try to `su - toor` and drop nothing",
            ),
        ];

        for (euid_is_root, user, must_cross, why) in cases {
            assert_eq!(
                user.acting_for_another_account(euid_is_root),
                must_cross,
                "euid_is_root={euid_is_root} name={} via_elevation={}: {why}",
                user.name,
                user.via_elevation
            );
        }

        // And the impure wrapper agrees with the pure predicate on this runner, so the two cannot drift
        // apart. unix only: the Windows `as_user_command` is a `None` stub with no boundary to cross.
        #[cfg(unix)]
        {
            let subject = alice(false);
            assert_eq!(
                as_user_command(Path::new("/opt/dig/bin/dign"), &subject).is_some(),
                subject.acting_for_another_account(crate::invoker::is_root())
            );
        }
    }
}
