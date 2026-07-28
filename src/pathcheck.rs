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

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::invoker::TargetUser;
use crate::proc::HideConsole;

/// The result of verifying one CLI resolves and runs for the target user.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CliPathCheck {
    /// The CLI id (e.g. `dig-node`).
    pub cli: String,
    /// `true` iff the CLI resolved by bare name on the target user's own PATH **and** executed.
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
    let out = if user.via_elevation {
        Command::new("su")
            .arg("-")
            .arg(&user.name)
            .arg("-c")
            .arg(PRINT_PATH_VIA_LOGIN_SH)
            .hide_console()
            .output()
    } else {
        Command::new("sh")
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
        // Expand `%SystemRoot%`-style references the persisted REG_EXPAND_SZ values contain.
        Ok(expand_env_refs(&joined))
    }
}

/// Expand `%NAME%` references in a persisted `REG_EXPAND_SZ` PATH. An unknown name is left verbatim
/// so a broken reference is visible in the reported PATH rather than silently becoming empty.
#[cfg(windows)]
fn expand_env_refs(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
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
    run_version(&resolved, user)
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

/// Run `<binary> --version` and return its trimmed output.
///
/// Under elevation the binary is run AS the target user (`su - <user> -c`), because "root can
/// execute it" is not the claim being made — the claim is that the user can. A binary that is
/// present but unloadable surfaces its loader error here (for example a missing `libxdo.so.3`),
/// which is the detail the failure note must carry.
pub(crate) fn run_version(binary: &Path, user: &TargetUser) -> Result<String, String> {
    let out = if user.via_elevation && cfg!(unix) {
        Command::new("su")
            .arg("-")
            .arg(&user.name)
            .arg("-c")
            .arg(format!("{} --version", shell_quote(binary)))
            .hide_console()
            .output()
    } else {
        Command::new(binary)
            .arg("--version")
            .hide_console()
            .output()
    };
    let out = out.map_err(|e| format!("`{} --version` could not start: {e}", binary.display()))?;
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

/// Single-quote `path` for a POSIX shell, escaping any embedded single quote, so a path containing
/// spaces or shell metacharacters is passed to `su -c` as one word.
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
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

    // -- quoting ---------------------------------------------------------------

    /// The default Windows root contains a space and the `su -c` path must survive it as one word;
    /// an embedded single quote must not break out of the quoting.
    #[test]
    fn shell_quote_survives_spaces_and_quotes() {
        assert_eq!(
            shell_quote(Path::new("/opt/dig bin/dig-app")),
            "'/opt/dig bin/dig-app'"
        );
        assert_eq!(
            shell_quote(Path::new("/tmp/it's/dig-app")),
            r"'/tmp/it'\''s/dig-app'"
        );
    }

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
}
