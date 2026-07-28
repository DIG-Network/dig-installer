//! Install-directory resolution and PATH wiring.
//!
//! # Which directory
//!
//! [`default_bin_dir`] answers "where do this run's binaries go?" and the answer depends on WHO is
//! installing, not merely on the OS: an elevated unix install is machine-wide
//! ([`UNIX_MACHINE_BIN_DIR`]), an unelevated one is per-user, and Windows keeps the whole stack in the
//! admin-only [`protected_bin_dir`] (#565). Privileged, service-executed binaries are routed to that
//! protected root on every platform by [`is_privileged_component`], and the one privileged binary a
//! user still runs by name is linked back onto PATH by [`needs_machine_bin_link`].
//!
//! # Which PATH, and whose
//!
//! [`add_to_path`] wires the chosen directory into the shell environment that will actually look for
//! it. The string manipulation is pure and unit-tested ([`path_append`], [`path_remove`],
//! [`profile_d_script`]); only the registry write / profile write / symlink touches the machine.
//!
//! The load-bearing subtlety is the SCOPE (#1748). An elevated install cannot wire PATH through
//! dotfiles, because the only dotfiles it can see are root's — that is precisely how a whole install
//! became invisible to the user who asked for it. So an elevated install works at the scope it has —
//! the system-wide fragment its login shells really read, which is `/etc/profile.d` on Linux but
//! `/etc/paths.d` on macOS ([`login_path_fragment`]) — and, before writing anything, asks the target
//! user's own login shell whether the directory is reachable, then asks again afterwards, so the
//! reported outcome is an observation rather than an assumption.

use std::path::{Path, PathBuf};

use crate::target::Os;

/// The machine-wide unix bin directory for user-facing CLIs — the one an ELEVATED install uses.
///
/// `/usr/local/bin` is on the default login-shell `PATH` of every platform this installer supports
/// (Debian/Ubuntu ship it in `/etc/environment`, and it is in macOS's `/etc/paths`), which is exactly
/// the property a root install needs and the property a per-user directory cannot have. It is also
/// root-owned `0755`, so it is NOT user-writable and satisfies the #565 no-LPE invariant at least as
/// well as the per-user root it replaces.
pub const UNIX_MACHINE_BIN_DIR: &str = "/usr/local/bin";

/// Default install directory for DIG tool binaries.
///   Windows: `%ProgramFiles%\DIG\bin` (the admin-only protected root — #565)
///   unix, elevated: [`UNIX_MACHINE_BIN_DIR`]
///   unix, unelevated: `~/.dig/bin`
///
/// On Windows the ENTIRE stack (services + user CLIs + the installer self-copy)
/// installs into the admin-only [`protected_bin_dir`]: a user-writable bin dir
/// underneath a LocalSystem service / SYSTEM beacon task is a local privilege
/// escalation (#565), so no per-user, user-writable bin dir is used. On unix only
/// the machine-wide PRIVILEGED service binaries go to [`protected_bin_dir`]
/// (`/opt/dig/bin`), classified by [`is_privileged_component`].
///
/// # Why an elevated unix install is machine-wide (#1748)
///
/// The documented install path is `curl -fsSL https://dig.net/install.sh | sudo sh`, i.e. it runs as
/// root. This used to resolve `dirs::home_dir()`, which `sudo` sets to `/root` — so the whole stack
/// landed in `/root/.dig/bin` and the `export PATH` went into `/root/.bashrc`. Mode `0700` on `/root`
/// means the real user could not have reached those binaries even if they had known the path.
///
/// Resolving the invoking user and installing into *their* `~/.dig/bin` would fix reachability but
/// answers the wrong question: a person who typed `sudo` asked for a machine-wide install, and on a
/// multi-user box only one account would get the CLIs. So an elevated install goes to
/// [`UNIX_MACHINE_BIN_DIR`] — already on every login shell's PATH, so there is no PATH wiring left to
/// get wrong. An UNELEVATED install keeps the elevation-free per-user `~/.dig/bin`, resolved against
/// the [invoking user](crate::invoker::target_user) rather than `$HOME`.
pub fn default_bin_dir() -> PathBuf {
    if cfg!(windows) {
        // #565: the whole Windows stack lives in the admin-only Program Files
        // root — there is no separate, user-writable per-user bin dir.
        return protected_bin_dir();
    }
    if crate::invoker::is_root() {
        return PathBuf::from(UNIX_MACHINE_BIN_DIR);
    }
    crate::invoker::target_user().dig_bin_dir()
}

/// The admin-only-writable install root for any binary a PRIVILEGED
/// service/scheduled-task executes (the #565 LPE fix). An unprivileged user MUST
/// NOT be able to replace a binary that a LocalSystem service / the SYSTEM
/// auto-update beacon task later runs as SYSTEM.
///   Windows: `%ProgramFiles%\DIG\bin`, resolved via the known-folder API
///            (`SHGetKnownFolderPath(FOLDERID_ProgramFiles)`), NOT the spoofable
///            `%ProgramFiles%` env. Program Files' inherited DACL is
///            admin-write / user-read+execute — exactly the invariant we need,
///            with no custom-ACL fragility.
///   macOS/Linux: `/opt/dig/bin`, root-owned `0755` (see [`crate::secure`]).
pub fn protected_bin_dir() -> PathBuf {
    if cfg!(windows) {
        program_files().join("DIG").join("bin")
    } else {
        PathBuf::from("/opt/dig/bin")
    }
}

/// The Windows Program Files root, resolved via the **known-folder API**
/// (`SHGetKnownFolderPath(FOLDERID_ProgramFiles)`), NOT the `%ProgramFiles%` env
/// (which a launching process can redirect). Falls back to the literal
/// `C:\Program Files` (still not the env) only if the API itself fails. On
/// non-Windows hosts (reached only by tests exercising the Windows path map) the
/// literal is returned.
pub(crate) fn program_files() -> PathBuf {
    #[cfg(windows)]
    {
        program_files_known_folder().unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(r"C:\Program Files")
    }
}

/// `%ProgramFiles%` via `SHGetKnownFolderPath(FOLDERID_ProgramFiles)` — immune to
/// `%ProgramFiles%` env redirection (mirrors [`crate::daemon_dir`]'s
/// `FOLDERID_ProgramData` resolution). `None` if the API fails.
#[cfg(windows)]
fn program_files_known_folder() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath};

    unsafe {
        let mut ptr: *mut u16 = std::ptr::null_mut();
        let hr = SHGetKnownFolderPath(
            &FOLDERID_ProgramFiles,
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

/// Does `component` run under a PRIVILEGED identity on `os` — Windows
/// LocalSystem/SYSTEM, or a unix machine-wide (root / dedicated-account) service
/// — so its binary MUST live in the admin-only [`protected_bin_dir`] (#565)?
///
/// * **Windows:** every component installs into the single Program Files root,
///   and every service/task DIG registers there (dig-node/dig-dns/dig-relay
///   LocalSystem services, the SYSTEM dig-updater beacon task) executes as a
///   privileged identity — so the whole stack is protected. Returns `true` for
///   all.
/// * **unix:** only the machine-wide privileged binaries must be protected — the
///   dig-dns service (a dedicated-account systemd unit / root LaunchDaemon) and
///   the root-run dig-updater beacon (+ its `dig-updater-worker` sibling the
///   beacon spawns). The user CLIs (`digstore`/`digs`/`digd`) and the
///   user-level dig-node/dig-relay services run AS the user, so a user-writable
///   binary is not an escalation there — they stay in the elevation-free
///   `~/.dig/bin`.
pub fn is_privileged_component(os: Os, component: &str) -> bool {
    match os {
        Os::Windows => true,
        Os::Linux | Os::MacOs => {
            matches!(component, "dig-dns" | "dig-updater" | "dig-updater-worker")
        }
    }
}

/// The historical, USER-WRITABLE bin dirs earlier installer versions placed
/// binaries in, which the #565 migration must vacate of any PRIVILEGED binary:
/// stop + re-point each service off them, remove the moved binaries, and — on
/// Windows — drop the dir from the user PATH so it can no longer SHADOW the new
/// protected root. The current [`protected_bin_dir`] is never returned.
///   Windows: `%LOCALAPPDATA%\Programs\DIG\bin` and the older
///            `%LOCALAPPDATA%\Programs\DigStore\bin`.
///   unix: `~/.dig/bin` — the user CLIs legitimately stay there, so on unix the
///         migration moves only the privileged binaries OUT of it (never the dir
///         itself, which keeps the user CLIs + user-level services).
pub fn legacy_privileged_roots(os: Os) -> Vec<PathBuf> {
    match os {
        Os::Windows => {
            let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("C:/Users/Public"));
            let programs = base.join("Programs");
            vec![
                programs.join("DIG").join("bin"),
                programs.join("DigStore").join("bin"),
            ]
        }
        // Resolved against the INVOKING user (#1748), not `$HOME`: a `sudo` re-run whose `$HOME` is
        // `/root` would otherwise "migrate" root's empty bin dir and leave a real, pre-#565 privileged
        // binary sitting in the user's `~/.dig/bin` where a non-admin could still replace it. Root's
        // own dir is included too, because previous versions of this installer genuinely did put
        // binaries there and an upgrade has to vacate them.
        Os::Linux | Os::MacOs => {
            let mut roots = vec![crate::invoker::target_user().dig_bin_dir()];
            let roots_home = PathBuf::from("/root").join(".dig").join("bin");
            if !roots.contains(&roots_home) {
                roots.push(roots_home);
            }
            roots
        }
    }
}

/// Compute the new user-PATH string after REMOVING every entry equal to `dir`
/// (the mirror of [`path_append`]) — used by the #565 migration to drop a stale,
/// user-writable legacy bin dir so it can no longer shadow the new protected
/// root on `PATH`. Pure (no I/O, no env access). Case-insensitive and
/// trailing-separator-insensitive on Windows, exactly matching [`path_append`]'s
/// comparison. Returns `None` when `dir` was not present (no change needed),
/// `Some(new_path)` otherwise.
pub fn path_remove(current: &str, dir: &str, sep: char) -> Option<String> {
    let trail = if sep == ';' { '\\' } else { '/' };
    let dir_trimmed = dir.trim_end_matches(trail);
    let case_insensitive = sep == ';';
    let matches = |entry: &str| {
        let e = entry.trim().trim_end_matches(trail);
        if case_insensitive {
            e.eq_ignore_ascii_case(dir_trimmed)
        } else {
            e == dir_trimmed
        }
    };
    if !current.split(sep).any(&matches) {
        return None;
    }
    let kept: Vec<&str> = current.split(sep).filter(|e| !matches(e)).collect();
    Some(kept.join(&sep.to_string()))
}

/// Compute the new user-PATH string after appending `dir`.
///
/// Pure (no I/O, no env access). Idempotent and case-insensitive on Windows: if
/// `dir` is already present (ignoring case and trailing separators) the current
/// PATH is returned unchanged so we never double-append. `sep` is the platform
/// PATH separator (`;` on Windows, `:` elsewhere).
///
/// Returns `None` if no change is needed, `Some(new_path)` otherwise.
pub fn path_append(current: &str, dir: &str, sep: char) -> Option<String> {
    let trail = if sep == ';' { '\\' } else { '/' };
    let dir_trimmed = dir.trim_end_matches(trail);
    let case_insensitive = sep == ';';
    let already = current
        .split(sep)
        .map(|p| p.trim().trim_end_matches(trail))
        .any(|p| {
            if case_insensitive {
                p.eq_ignore_ascii_case(dir_trimmed)
            } else {
                p == dir_trimmed
            }
        });
    if already {
        return None;
    }
    if current.is_empty() {
        Some(dir.to_string())
    } else if current.ends_with(sep) {
        Some(format!("{current}{dir}"))
    } else {
        Some(format!("{current}{sep}{dir}"))
    }
}

/// Link `target` (a binary in the protected root) into [`UNIX_MACHINE_BIN_DIR`] under `name`, so a
/// user-facing CLI that must LIVE in the root-owned protected root is still reachable by bare name.
///
/// Replaces an existing link/file at the destination so an upgrade re-points it rather than failing.
/// unix only — on Windows the whole stack shares one root, so there is nothing to link.
#[cfg(unix)]
pub fn link_into_machine_bin(target: &Path, name: &str) -> Result<PathBuf, String> {
    let link = Path::new(UNIX_MACHINE_BIN_DIR).join(name);
    std::fs::create_dir_all(UNIX_MACHINE_BIN_DIR)
        .map_err(|e| format!("create {UNIX_MACHINE_BIN_DIR}: {e}"))?;
    // `symlink` fails on an existing path, and an upgrade legitimately re-points the link.
    match std::fs::remove_file(&link) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("replace {}: {e}", link.display())),
    }
    std::os::unix::fs::symlink(target, &link)
        .map_err(|e| format!("link {} -> {}: {e}", link.display(), target.display()))?;
    Ok(link)
}

/// Can `user` list and traverse `dir`? Asked of the user's own shell, because the answer differs from
/// ours: root can stat every directory on the machine, so a root-side check would say "yes" for a mode
/// `0700` directory the user cannot open.
#[cfg(unix)]
fn user_can_enter(dir: &str, user: &crate::invoker::TargetUser) -> bool {
    use crate::proc::HideConsole;
    // `-x` is traverse, `-r` is list; a bin dir needs both to be useful on PATH.
    let script = format!(
        "test -x '{d}' && test -r '{d}'",
        d = dir.replace('\'', r"'\''")
    );
    let out = if user.via_elevation {
        std::process::Command::new("su")
            .args(["-", &user.name, "-c", &script])
            .hide_console()
            .status()
    } else {
        std::process::Command::new("sh")
            .args(["-c", &script])
            .hide_console()
            .status()
    };
    out.map(|s| s.success()).unwrap_or(false)
}

/// Add `bin_dir` to the user's PATH.
///   Windows: append to HKCU\Environment\Path (REG_EXPAND_SZ, no truncation),
///            then broadcast WM_SETTINGCHANGE. No elevation.
///   macOS/Linux: append an `export PATH` line to the user's shell profile(s)
///            (idempotent), so new shells see it. Returns a human note.
pub fn add_to_path(bin_dir: &Path) -> Result<String, String> {
    #[cfg(windows)]
    {
        windows_add_to_path(bin_dir)
    }
    #[cfg(not(windows))]
    {
        unix_add_to_path(bin_dir)
    }
}

#[cfg(windows)]
fn windows_add_to_path(bin_dir: &Path) -> Result<String, String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_EXPAND_SZ};
    use winreg::{RegKey, RegValue};

    let dir = bin_dir.to_string_lossy().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (env, _disp) = hkcu
        .create_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
        .map_err(|e| format!("open HKCU\\Environment: {e}"))?;

    let current: String = env.get_value("Path").unwrap_or_default();
    let new_path = match path_append(&current, &dir, ';') {
        None => return Ok(format!("user PATH (already present): {dir}")),
        Some(p) => p,
    };

    let bytes = string_to_reg_expand_sz_bytes(&new_path);
    env.set_raw_value(
        "Path",
        &RegValue {
            vtype: REG_EXPAND_SZ,
            bytes,
        },
    )
    .map_err(|e| format!("write HKCU\\Environment\\Path: {e}"))?;
    broadcast_environment_change();
    Ok(format!("user PATH: {dir}"))
}

/// Is `component` a PRIVILEGED component that is ALSO a CLI the user is expected to run by name, so
/// it needs a link from [`UNIX_MACHINE_BIN_DIR`] into [`protected_bin_dir`]?
///
/// `dig-dns` is the case that exists: users really do run `dig-dns doctor`, but the binary must live
/// in the root-owned protected root because a machine-wide service executes it (#565). `/opt/dig/bin`
/// is on no shell's default `PATH`, so before #1748 `dig-dns` was unreachable by name for EVERY user —
/// including root — while the PATH check reported it resolved.
///
/// A symlink is safe here precisely because both ends are root-owned `0755`: it adds reachability
/// without adding an unprivileged-writable path to a service-executed binary, so the #565 invariant is
/// preserved rather than traded away. `dig-updater`/`dig-updater-worker` are deliberately excluded —
/// the beacon invokes them, a user never does, so they stay off PATH entirely.
pub fn needs_machine_bin_link(os: Os, component: &str) -> bool {
    !matches!(os, Os::Windows) && component == "dig-dns"
}

/// The system-wide login-shell snippet an elevated install writes when its bin dir is not already on
/// the login `PATH`. `/etc/profile.d/*.sh` is sourced by `/etc/profile`, i.e. by every LOGIN shell of
/// every account — which is the scope an elevated install is entitled to and the scope a per-user
/// dotfile edit cannot reach (#1748).
pub const PROFILE_D_SCRIPT: &str = "/etc/profile.d/dig-path.sh";

/// Render the `/etc/profile.d` snippet that puts `dir` on the login `PATH`.
///
/// POSIX `sh` only (the file is sourced by `/bin/sh`, which on Debian/Ubuntu is `dash`, so no
/// bash-isms), and idempotent at SOURCE time as well as at write time: the `case` guard means a shell
/// that already has `dir` on `PATH` — because it was inherited, or because the file got sourced twice —
/// does not accumulate a duplicate entry.
pub fn profile_d_script(dir: &str) -> String {
    format!(
        "# added by dig-installer: make the DIG CLIs resolvable in every login shell\n\
         case \":${{PATH}}:\" in\n\
         \x20 *\":{dir}:\"*) ;;\n\
         \x20 *) PATH=\"{dir}:${{PATH}}\"; export PATH ;;\n\
         esac\n"
    )
}

/// The system-wide login-`PATH` fragment an elevated **macOS** install writes.
///
/// macOS has no `/etc/profile.d` at all, so [`PROFILE_D_SCRIPT`] would land in a directory that does
/// not exist and no shell would ever source it. The macOS equivalent is `/usr/libexec/path_helper`,
/// invoked by both `/etc/profile` (bash) and `/etc/zprofile` (zsh), which composes the login `PATH`
/// from `/etc/paths` plus one fragment file per entry in `/etc/paths.d` (#1748).
pub const PATHS_D_FILE: &str = "/etc/paths.d/dig";

/// Render the `/etc/paths.d` fragment for `dir`.
///
/// `path_helper` reads these files as a plain list of directories, one per line — no quoting, no
/// expansion, no shell syntax. A directory containing spaces is therefore written verbatim.
pub fn paths_d_fragment(dir: &str) -> String {
    format!("{dir}\n")
}

/// The file an elevated install writes to put `dir` on every login shell's `PATH`, and its contents,
/// chosen for the platform whose login shells will actually read it.
#[cfg(not(windows))]
fn login_path_fragment(dir: &str) -> (&'static str, String) {
    if cfg!(target_os = "macos") {
        (PATHS_D_FILE, paths_d_fragment(dir))
    } else {
        (PROFILE_D_SCRIPT, profile_d_script(dir))
    }
}

#[cfg(not(windows))]
fn unix_add_to_path(bin_dir: &Path) -> Result<String, String> {
    let user = crate::invoker::target_user();
    if crate::invoker::is_root() {
        return root_add_to_path(bin_dir, user);
    }
    // Unelevated: we ARE the target user, so their own profile is the right place.
    unix_add_to_path_in(bin_dir, &user.home)
}

/// PATH wiring for an ELEVATED unix install: verify, remediate only if needed, then verify again.
///
/// Editing root's dotfiles — what this used to do — cannot help anybody, and editing one user's
/// dotfiles would leave every other account on the box without the CLIs. So an elevated install works
/// at the scope it actually has: `/etc/profile.d`.
///
/// The sequence is deliberately check → remediate → RE-CHECK, against the target user's real login
/// shell each time. The default bin dir ([`UNIX_MACHINE_BIN_DIR`]) is already on that PATH on every
/// supported platform, so the common case writes nothing; and because the final word is a re-read of
/// the user's environment rather than our own belief about it, a remediation that did not take is
/// reported as a FAILURE instead of a success note.
#[cfg(not(windows))]
fn root_add_to_path(bin_dir: &Path, user: &crate::invoker::TargetUser) -> Result<String, String> {
    use crate::pathcheck;

    let dir = bin_dir.to_string_lossy().to_string();
    let reachable = |note: &str| -> Option<String> {
        match pathcheck::login_shell_path(user) {
            Ok(path) if pathcheck::path_contains(&path, &dir, ':') => {
                Some(format!("{dir} is on {}'s login PATH{note}", user.name))
            }
            _ => None,
        }
    };

    if let Some(note) = reachable(" already — no PATH wiring needed") {
        return Ok(note);
    }

    // PATH is wired BEFORE the components are downloaded, so on an install that selects none of the
    // early components (`--no-digstore`) the bin dir does not exist yet. A directory that is merely
    // absent is not a directory the user cannot enter, and reporting it as one made the reachability
    // guard below fire on a perfectly good install root. Create it in the shape the download path
    // would: root-owned and world-traversable, which is also what the #565 install-root ACL verify
    // requires (no group or other write).
    ensure_bin_dir(bin_dir)?;

    // Refuse to wire a directory the target user cannot even enter. The fragment is read by EVERY
    // login shell on the machine, so putting an inaccessible dir on PATH would degrade every
    // account's environment to no purpose — and it would let this function report success (the dir is
    // "on PATH" after all) for an install nobody can run. Checked as the user, by the user's own shell.
    if !user_can_enter(&dir, user) {
        return Err(format!(
            "{dir} is not accessible to {} (a directory the user cannot enter must not be wired \
             into every login shell's PATH) — install into a directory {} can read, or run the \
             installer as that user",
            user.name, user.name
        ));
    }

    let (fragment_file, fragment_body) = login_path_fragment(&dir);
    if let Some(parent) = Path::new(fragment_file).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(fragment_file, fragment_body)
        .map_err(|e| format!("write {fragment_file}: {e}"))?;

    if let Some(note) = reachable(&format!(" (wired via {fragment_file})")) {
        return Ok(note);
    }
    let observed =
        pathcheck::login_shell_path(user).unwrap_or_else(|e| format!("<unreadable: {e}>"));
    Err(format!(
        "wrote {fragment_file} but {dir} is STILL not on {}'s login PATH (it searches: {observed})",
        user.name
    ))
}

/// Create `bin_dir` if it is absent, root-owned and world-traversable (0755).
///
/// Separate from the download path's own creation so PATH wiring — which runs first — can rely on the
/// directory existing without depending on which components a given run happens to install.
#[cfg(not(windows))]
fn ensure_bin_dir(bin_dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    if bin_dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(bin_dir).map_err(|e| format!("create {}: {e}", bin_dir.display()))?;
    // Explicit rather than umask-dependent: every login shell on the box will search this directory,
    // so it must be traversable by every account regardless of the umask the installer inherited.
    std::fs::set_permissions(bin_dir, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod 0755 {}: {e}", bin_dir.display()))
}

/// [`unix_add_to_path`] against an explicit `home` directory. The real call uses
/// `dirs::home_dir()`; tests point `home` at a temp dir so the idempotent
/// profile-append logic (which `.zshrc`/`.bashrc`/`.profile` to touch, the
/// re-run guard) is exercised without writing the developer's real dotfiles.
#[cfg(not(windows))]
fn unix_add_to_path_in(bin_dir: &Path, home: &Path) -> Result<String, String> {
    use std::fs;
    use std::io::Write;

    let dir = bin_dir.to_string_lossy().to_string();
    // Idempotent guard line the installer recognises on re-run.
    let marker = "# added by dig-installer";
    let line = format!("\n{marker}\nexport PATH=\"{dir}:$PATH\"\n");

    let mut touched = Vec::new();
    // Write to whichever profiles exist (plus .profile as the POSIX fallback).
    for name in [".zshrc", ".bashrc", ".profile"] {
        let p = home.join(name);
        let existing = fs::read_to_string(&p).unwrap_or_default();
        // Only create .profile if nothing else existed; always update existing.
        if existing.is_empty() && name != ".profile" {
            continue;
        }
        if existing.contains(&dir) {
            touched.push(name);
            continue;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .map_err(|e| format!("open {}: {e}", p.display()))?;
        f.write_all(line.as_bytes())
            .map_err(|e| format!("write {}: {e}", p.display()))?;
        touched.push(name);
    }
    if touched.is_empty() {
        // Nothing existed at all — create .profile.
        let p = home.join(".profile");
        fs::write(&p, line.trim_start()).map_err(|e| format!("write {}: {e}", p.display()))?;
        touched.push(".profile");
    }
    Ok(format!(
        "added {dir} to PATH in {} (open a new shell to pick it up)",
        touched.join(", ")
    ))
}

#[cfg(windows)]
pub(crate) fn string_to_reg_expand_sz_bytes(s: &str) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut bytes = Vec::with_capacity(wide.len() * 2);
    for w in wide {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    bytes
}

#[cfg(windows)]
pub(crate) fn broadcast_environment_change() {
    use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };
    let param: Vec<u16> = "Environment"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut result: usize = 0;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST as HWND,
            WM_SETTINGCHANGE,
            0 as WPARAM,
            param.as_ptr() as LPARAM,
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_when_absent_windows_style() {
        assert_eq!(
            path_append(r"C:\Windows;C:\Tools", r"C:\Apps\DIG\bin", ';'),
            Some(r"C:\Windows;C:\Tools;C:\Apps\DIG\bin".to_string())
        );
    }

    #[test]
    fn no_change_when_already_present_windows() {
        assert_eq!(
            path_append(r"C:\Windows;C:\Apps\DIG\bin", r"C:\Apps\DIG\bin", ';'),
            None
        );
    }

    #[test]
    fn windows_is_case_insensitive_and_ignores_trailing_backslash() {
        assert_eq!(
            path_append(r"c:\apps\dig\BIN\", r"C:\Apps\DIG\bin", ';'),
            None
        );
    }

    #[test]
    fn creates_value_when_empty() {
        assert_eq!(
            path_append("", r"C:\Apps\DIG\bin", ';'),
            Some(r"C:\Apps\DIG\bin".to_string())
        );
    }

    #[test]
    fn no_blank_entry_after_trailing_separator() {
        assert_eq!(
            path_append("/usr/bin:", "/home/u/.dig/bin", ':'),
            Some("/usr/bin:/home/u/.dig/bin".to_string())
        );
    }

    #[test]
    fn unix_is_case_sensitive() {
        // On unix, different case is a DIFFERENT path → must append.
        assert_eq!(
            path_append("/home/U/.dig/bin", "/home/u/.dig/bin", ':'),
            Some("/home/U/.dig/bin:/home/u/.dig/bin".to_string())
        );
    }

    #[test]
    fn unix_already_present_no_change() {
        assert_eq!(
            path_append("/usr/bin:/home/u/.dig/bin", "/home/u/.dig/bin", ':'),
            None
        );
    }

    #[test]
    fn default_bin_dir_is_under_a_dig_prefix() {
        // The default install dir is a DIG-scoped bin dir on every platform.
        let p = default_bin_dir().to_string_lossy().to_lowercase();
        assert!(
            p.contains("dig"),
            "default bin dir should be DIG-scoped: {p}"
        );
        assert!(
            p.ends_with("bin"),
            "default bin dir should end in /bin: {p}"
        );
    }

    // -- #565: protected (admin-only) install root -----------------------------

    #[cfg(windows)]
    #[test]
    fn windows_default_and_protected_root_are_program_files_dig_bin() {
        // The #565 fix: the Windows default bin dir IS the admin-only Program
        // Files root (no user-writable %LOCALAPPDATA% dir), and equals the
        // protected root — one root for the whole stack.
        let def = default_bin_dir();
        let prot = protected_bin_dir();
        assert_eq!(def, prot, "Windows default must be the protected root");
        let s = prot.to_string_lossy();
        assert!(
            s.ends_with(r"DIG\bin"),
            "protected root must be <ProgramFiles>\\DIG\\bin: {s}"
        );
        // NEVER the old user-writable LOCALAPPDATA\Programs location.
        assert!(
            !s.to_lowercase().contains("appdata"),
            "the Windows install root must NOT be user-writable AppData: {s}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_protected_root_is_opt_dig_bin_and_differs_from_user_root() {
        // unix keeps the elevation-free per-user CLI root, and adds a SEPARATE
        // root-owned root for the privileged service binaries.
        assert_eq!(protected_bin_dir(), PathBuf::from("/opt/dig/bin"));
        assert_ne!(
            default_bin_dir(),
            protected_bin_dir(),
            "unix user CLIs stay in ~/.dig/bin, distinct from /opt/dig/bin"
        );
    }

    #[test]
    fn windows_treats_every_component_as_privileged() {
        // On Windows the whole stack installs into the single admin-only root.
        for c in [
            "digstore",
            "digs",
            "dig-node",
            "dign",
            "dig-dns",
            "digd",
            "dig-relay",
            "dig-updater",
            "dig-updater-worker",
            "dig-installer",
        ] {
            assert!(
                is_privileged_component(Os::Windows, c),
                "{c} must be protected on Windows"
            );
        }
    }

    #[test]
    fn unix_protects_only_the_machine_wide_service_binaries() {
        // Root/dedicated-account service binaries MUST be protected …
        for c in ["dig-dns", "dig-updater", "dig-updater-worker"] {
            assert!(
                is_privileged_component(Os::Linux, c),
                "{c} runs machine-wide on unix and must be protected"
            );
            assert!(is_privileged_component(Os::MacOs, c));
        }
        // … while the user CLIs + user-level services stay in the user root
        // (they run AS the user, so a user-writable binary is not an escalation).
        for c in ["digstore", "digs", "digd", "dig-node", "dign", "dig-relay"] {
            assert!(
                !is_privileged_component(Os::Linux, c),
                "{c} runs as the user on unix — not a protected component"
            );
            assert!(!is_privileged_component(Os::MacOs, c));
        }
    }

    #[test]
    fn legacy_windows_roots_are_the_old_user_writable_appdata_dirs() {
        // Compare by path COMPONENTS (separator-agnostic) so the test is correct
        // whether it runs on a Windows or a unix CI host: `legacy_privileged_roots`
        // is host-based, so on a unix runner the same call yields a forward-slash
        // `<data_local>/Programs/DIG/bin` — the components are what matter.
        let roots = legacy_privileged_roots(Os::Windows);
        assert_eq!(
            roots.len(),
            2,
            "both the DIG and older DigStore AppData dirs"
        );
        assert!(
            roots[0].ends_with("Programs/DIG/bin"),
            "first legacy root must be …/Programs/DIG/bin: {}",
            roots[0].display()
        );
        assert!(
            roots[1].ends_with("Programs/DigStore/bin"),
            "must include the older DigStore location: {}",
            roots[1].display()
        );
    }

    // -- path_remove: mirror of path_append -----------------------------------

    #[test]
    fn path_remove_drops_a_present_entry() {
        assert_eq!(
            path_remove(
                r"C:\Windows;C:\old\DIG\bin;C:\Tools",
                r"C:\old\DIG\bin",
                ';'
            ),
            Some(r"C:\Windows;C:\Tools".to_string())
        );
    }

    #[test]
    fn path_remove_is_none_when_absent() {
        assert_eq!(
            path_remove(r"C:\Windows;C:\Tools", r"C:\old\DIG\bin", ';'),
            None
        );
    }

    #[test]
    fn path_remove_is_case_and_trailing_slash_insensitive_on_windows() {
        // A trailing-backslash, different-case variant is still removed.
        assert_eq!(
            path_remove(r"c:\old\dig\BIN\;C:\Windows", r"C:\old\DIG\bin", ';'),
            Some(r"C:\Windows".to_string())
        );
    }

    #[test]
    fn path_remove_drops_every_duplicate_of_the_entry() {
        // A doubled legacy entry must be fully removed, not just the first.
        assert_eq!(
            path_remove("/opt/dig/bin:/usr/bin:/opt/dig/bin", "/opt/dig/bin", ':'),
            Some("/usr/bin".to_string())
        );
    }

    #[test]
    fn path_remove_is_case_sensitive_on_unix() {
        // Different case is a DIFFERENT path on unix → not removed.
        assert_eq!(
            path_remove("/home/U/.dig/bin:/usr/bin", "/home/u/.dig/bin", ':'),
            None
        );
    }

    // -- unix profile-append tests against a TEMP home (never the real dotfiles).
    //    These run on the Linux CI coverage job (where the unix cfg compiles). ----

    #[cfg(not(windows))]
    fn tmp_home(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("dig-installer-home-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // -- #1748: an elevated unix install is machine-wide, not root-scoped -------

    /// The install root an ELEVATED unix install uses must be a machine-wide directory that is
    /// already on the login PATH — never a per-user home directory, and above all never root's.
    ///
    /// The fixture asserts the constant itself rather than calling `default_bin_dir()`, because the
    /// test process's own euid decides that function's answer and a test runner is not root. The
    /// property under test is which DIRECTORY was chosen for the elevated case, which the constant
    /// carries.
    #[test]
    fn the_elevated_unix_bin_dir_is_machine_wide_and_not_under_any_home() {
        assert_eq!(UNIX_MACHINE_BIN_DIR, "/usr/local/bin");
        assert!(
            !UNIX_MACHINE_BIN_DIR.starts_with("/root"),
            "the shipped bug: an elevated install must not land under root's home"
        );
        assert!(
            !UNIX_MACHINE_BIN_DIR.contains("/home/"),
            "an elevated install must not privilege one account's home over the others"
        );
        // It is on the stock Debian/Ubuntu and macOS login PATH, which is the whole reason it needs
        // no PATH wiring. Asserted against the real stock value so the claim is checkable.
        let stock_ubuntu_login_path =
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        assert!(
            crate::pathcheck::path_contains(stock_ubuntu_login_path, UNIX_MACHINE_BIN_DIR, ':'),
            "the elevated bin dir must already be on the stock login PATH"
        );
        // The directory the bug shipped to is NOT on it — the contrast is the point.
        assert!(!crate::pathcheck::path_contains(
            stock_ubuntu_login_path,
            "/root/.dig/bin",
            ':'
        ));
    }

    /// An UNELEVATED install still uses the per-user root, and resolves it from the invoking account
    /// rather than `$HOME`. Both halves matter: the per-user path is what keeps a non-root install
    /// elevation-free, and the invoker resolution is what stops `sudo` redirecting it to `/root`.
    #[test]
    fn the_unelevated_unix_bin_dir_is_the_invoking_users_own_dig_bin() {
        let sudoing = crate::invoker::TargetUser {
            name: "ubuntu".to_string(),
            home: PathBuf::from("/home/ubuntu"),
            uid: Some(1000),
            gid: Some(1000),
            via_elevation: true,
        };
        assert_eq!(sudoing.dig_bin_dir(), Path::new("/home/ubuntu/.dig/bin"));
        assert!(!sudoing.dig_bin_dir().starts_with("/root"));
    }

    // -- #1748: reachability of the protected-root CLIs -------------------------

    /// `dig-dns` is a user-facing CLI (`dig-dns doctor`) that must LIVE in the root-owned protected
    /// root, which is on no shell's default PATH — so it needs a link into the machine bin dir. The
    /// beacon binaries must NOT get one: a user never invokes them, and putting them on PATH would
    /// widen the surface for no benefit.
    ///
    /// Both directions are asserted, because a predicate that returned `true` for everything would
    /// satisfy the dig-dns half on its own.
    #[test]
    fn only_the_user_facing_privileged_cli_gets_a_machine_bin_link() {
        assert!(needs_machine_bin_link(Os::Linux, "dig-dns"));
        assert!(needs_machine_bin_link(Os::MacOs, "dig-dns"));
        for never in ["dig-updater", "dig-updater-worker"] {
            assert!(
                !needs_machine_bin_link(Os::Linux, never),
                "{never} is invoked by the beacon, never by a user"
            );
        }
        // Windows keeps one root for the whole stack, so there is nothing to link.
        assert!(!needs_machine_bin_link(Os::Windows, "dig-dns"));
    }

    /// The link destination must be the machine bin dir that is already on the login PATH — a link
    /// into a directory no shell searches would restate the bug it fixes.
    #[test]
    fn the_link_target_dir_is_the_one_on_the_login_path() {
        let stock = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        assert!(crate::pathcheck::path_contains(
            stock,
            UNIX_MACHINE_BIN_DIR,
            ':'
        ));
        assert!(
            !crate::pathcheck::path_contains(stock, "/opt/dig/bin", ':'),
            "the protected root is on no default PATH -- which is why the link exists"
        );
    }

    // -- #1748: the /etc/profile.d login-shell snippet --------------------------

    /// The snippet must put the dir on PATH, be POSIX `sh` (it is sourced by `dash` on Debian, so a
    /// bash-ism like `[[` would break every login shell on the box), and be idempotent when sourced
    /// twice.
    #[test]
    fn the_profile_d_snippet_is_posix_sh_and_guards_against_duplicating_the_entry() {
        let s = profile_d_script("/usr/local/bin");
        assert!(s.contains(r#"PATH="/usr/local/bin:${PATH}""#), "got: {s}");
        assert!(s.contains("export PATH"));
        // The source-time guard: a shell that already has the dir does nothing.
        assert!(s.contains(r#"case ":${PATH}:" in"#), "got: {s}");
        assert!(s.contains(r#"*":/usr/local/bin:"*) ;;"#), "got: {s}");
        // POSIX sh only — no bash-only constructs.
        for bashism in ["[[", "function ", "==", "${PATH,,}"] {
            assert!(
                !s.contains(bashism),
                "the snippet is sourced by /bin/sh (dash) — {bashism} would break every login shell"
            );
        }
    }

    /// The snippet is written to `/etc/profile.d`, which every LOGIN shell sources — the scope an
    /// elevated install has and a dotfile edit does not. A `.bashrc` path here would be the shipped
    /// bug again (root's dotfiles), so the location is asserted.
    #[test]
    fn the_profile_d_location_is_system_wide_not_a_dotfile() {
        assert_eq!(PROFILE_D_SCRIPT, "/etc/profile.d/dig-path.sh");
        assert!(PROFILE_D_SCRIPT.starts_with("/etc/profile.d/"));
        assert!(
            !PROFILE_D_SCRIPT.contains(".bashrc") && !PROFILE_D_SCRIPT.contains("/root"),
            "an elevated install must not wire PATH through anybody's dotfiles"
        );
        assert!(
            PROFILE_D_SCRIPT.ends_with(".sh"),
            "/etc/profile only sources *.sh from profile.d"
        );
    }

    // -- #1748: macOS wires the login PATH through /etc/paths.d, not /etc/profile.d ---------------

    /// macOS has **no `/etc/profile.d`** — measured on a macos-14 runner, `ls /etc/profile.d` is
    /// `No such file or directory`, so the Linux snippet is written into a directory that does not
    /// exist and no login shell would ever source it. The macOS mechanism is
    /// `/usr/libexec/path_helper`, run from `/etc/profile` and `/etc/zprofile`, which composes the
    /// login PATH from `/etc/paths` plus one file per fragment in `/etc/paths.d`.
    #[test]
    fn the_macos_login_path_fragment_is_a_paths_d_entry() {
        assert_eq!(PATHS_D_FILE, "/etc/paths.d/dig");
        assert!(
            PATHS_D_FILE.starts_with("/etc/paths.d/"),
            "path_helper only reads fragments from /etc/paths.d"
        );
        assert!(
            !PATHS_D_FILE.ends_with(".sh"),
            "a paths.d fragment is a plain directory list, not a shell script"
        );
    }

    /// `path_helper` parses one DIRECTORY PER LINE and nothing else — a shell snippet here would be
    /// interpreted as a literal directory name and silently corrupt every login shell's PATH.
    #[test]
    fn the_paths_d_fragment_is_one_bare_directory_per_line() {
        let s = paths_d_fragment("/opt/dig bin");
        assert_eq!(s, "/opt/dig bin\n");
        for shellism in ["export", "PATH=", "case", "$"] {
            assert!(
                !s.contains(shellism),
                "path_helper reads paths.d literally — {shellism} would become a directory name"
            );
        }
    }

    /// The two mechanisms must not be confused: each OS gets the file its login shells actually read.
    /// Asserting BOTH arms means an implementation that always returned one of them cannot pass.
    #[cfg(not(windows))]
    #[test]
    fn the_login_path_fragment_target_follows_the_platform() {
        let (file, body) = login_path_fragment("/opt/dig-bin");
        if cfg!(target_os = "macos") {
            assert_eq!(file, PATHS_D_FILE);
            assert_eq!(body, "/opt/dig-bin\n");
        } else {
            assert_eq!(file, PROFILE_D_SCRIPT);
            assert!(body.contains("export PATH"), "got: {body}");
        }
    }

    /// A dir containing a shell metacharacter must not break the generated snippet's `case` guard.
    /// A `--bin-dir` can be anything, and a snippet that fails to parse breaks EVERY login shell on
    /// the machine — a far worse outcome than the bug being fixed.
    #[test]
    fn the_profile_d_snippet_keeps_the_dir_inside_quotes() {
        let s = profile_d_script("/opt/dig bin");
        assert!(s.contains(r#"PATH="/opt/dig bin:${PATH}""#), "got: {s}");
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_creates_profile_when_no_dotfiles_exist() {
        let home = tmp_home("fresh");
        let bin = PathBuf::from("/opt/dig/bin");
        let note = unix_add_to_path_in(&bin, &home).expect("ok");
        // With no existing dotfiles, it creates ~/.profile.
        assert!(note.contains(".profile"), "got: {note}");
        let profile = std::fs::read_to_string(home.join(".profile")).unwrap();
        assert!(profile.contains("/opt/dig/bin"));
        assert!(profile.contains("export PATH"));
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_updates_existing_shell_rc_files() {
        let home = tmp_home("existing");
        // A pre-existing .bashrc → it gets the export appended; .zshrc absent stays
        // absent; .profile (the POSIX fallback) is always touched.
        std::fs::write(home.join(".bashrc"), "# my bashrc\n").unwrap();
        let bin = PathBuf::from("/home/u/.dig/bin");
        let note = unix_add_to_path_in(&bin, &home).expect("ok");
        assert!(note.contains(".bashrc"), "got: {note}");
        let bashrc = std::fs::read_to_string(home.join(".bashrc")).unwrap();
        assert!(bashrc.contains("# my bashrc")); // preserved
        assert!(bashrc.contains("/home/u/.dig/bin")); // appended
        assert!(!home.join(".zshrc").exists()); // absent rc not created
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_is_idempotent_on_rerun() {
        let home = tmp_home("idem");
        std::fs::write(home.join(".bashrc"), "# rc\n").unwrap();
        let bin = PathBuf::from("/home/u/.dig/bin");
        unix_add_to_path_in(&bin, &home).expect("first ok");
        let after_first = std::fs::read_to_string(home.join(".bashrc")).unwrap();
        // Re-running must not append the export a second time.
        unix_add_to_path_in(&bin, &home).expect("second ok");
        let after_second = std::fs::read_to_string(home.join(".bashrc")).unwrap();
        assert_eq!(after_first, after_second, "rerun must be idempotent");
    }
}
