//! Install-directory resolution and PATH wiring.
//!
//! # Which directory
//!
//! [`default_bin_dir`] answers "where do this run's binaries go?" and the answer depends on WHO is
//! installing, not merely on the OS: an ELEVATED install — unix or Windows — puts everything in the
//! root-owned [`protected_bin_dir`], because root must never write to or execute from a directory a
//! non-root account can modify (#1748); an unelevated unix install is per-user (`~/.dig/bin`), where
//! nothing runs as root and the user's own authority is the only one involved.
//!
//! Reachability is then a SEPARATE concern from placement: [`UNIX_MACHINE_BIN_DIR`]
//! (`/usr/local/bin`) is a symlink veneer on the default `PATH`, populated by
//! [`needs_machine_bin_link`], never an install root. [`is_privileged_component`] additionally pins the
//! service-executed and root-executed binaries to the protected root even under a `--bin-dir`
//! override.
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

/// The machine-wide unix directory an elevated install makes its CLIs REACHABLE from — a PATH veneer
/// holding only SYMLINKS, never an install root.
///
/// `/usr/local/bin` is on the default login-shell `PATH` of every platform this installer supports
/// (Debian/Ubuntu ship it in `/etc/environment`, and it is in macOS's `/etc/paths`), which is exactly
/// the property a root install needs and a per-user directory cannot have. That is the ONLY property
/// relied on here.
///
/// # It is NOT root-owned everywhere, and must never be written to or executed from (#1748)
///
/// An earlier revision of this constant claimed `/usr/local/bin` "is also root-owned `0755`, so it is
/// NOT user-writable". That is false on a common configuration: Homebrew on an Intel Mac owns
/// `/usr/local/bin` as `<user>:admin` mode `0775`. It is a system directory by convention only.
///
/// Making it the elevated install root — as this installer briefly did — therefore created a family of
/// root-exec and root-write defects rather than one: three separate paths into it were found (the
/// `--version` probe, the service `install` delegation, and the PATH-check probe), each individually
/// fixable and collectively a signal that the root was wrong. So binaries live in
/// [`protected_bin_dir`], which IS root-owned by construction, and this directory holds only the
/// symlinks that make them reachable by name ([`needs_machine_bin_link`]). Root never writes to it and
/// never executes from it, so the class does not need a guard per surface.
///
/// A user-writable veneer is worth REPORTING — an attacker who can replace a symlink here changes what
/// the USER's shell resolves, which is their own privilege level rather than root's — and it is
/// reported wherever this directory is the one that must be on `PATH`
/// ([`reachable_dir`], `InstallReport::bin_dir_security`). It is NOT independently verified on the
/// default elevated install, where the directory that gets verified is the protected root the binaries
/// live in; an earlier revision of this comment claimed otherwise, and the claim was false.
pub const UNIX_MACHINE_BIN_DIR: &str = "/usr/local/bin";

/// Default install directory for DIG tool binaries.
///   Windows: `%ProgramFiles%\DIG\bin` (the admin-only protected root — #565)
///   unix, elevated: [`protected_bin_dir`] (`/opt/dig/bin`), reached via the
///                   [`UNIX_MACHINE_BIN_DIR`] symlink veneer
///   unix, unelevated: `~/.dig/bin`
///
/// On Windows the ENTIRE stack (services + user CLIs + the installer self-copy)
/// installs into the admin-only [`protected_bin_dir`]: a user-writable bin dir
/// underneath a LocalSystem service / SYSTEM beacon task is a local privilege
/// escalation (#565), so no per-user, user-writable bin dir is used.
///
/// # Why an elevated unix install is machine-wide AND root-owned (#1748)
///
/// The documented install path is `curl -fsSL https://dig.net/install.sh | sudo sh`, i.e. it runs as
/// root. This used to resolve `dirs::home_dir()`, which `sudo` sets to `/root` — so the whole stack
/// landed in `/root/.dig/bin` and the `export PATH` went into `/root/.bashrc`. Mode `0700` on `/root`
/// means the real user could not have reached those binaries even if they had known the path.
///
/// Installing into the invoking user's own `~/.dig/bin` would fix reachability but answers the wrong
/// question: a person who typed `sudo` asked for a machine-wide install, and on a multi-user box only
/// one account would get the CLIs. So an elevated install is machine-wide.
///
/// It goes to the ROOT-OWNED [`protected_bin_dir`], not to [`UNIX_MACHINE_BIN_DIR`]. Placing it in
/// `/usr/local/bin` was tried and reverted: that directory is user-writable under Homebrew on an Intel
/// Mac, and making it the root an ELEVATED process writes to and executes from produced a family of
/// defects — three distinct root paths into it were found and individually patched before it became
/// clear the root itself was wrong. Everything root touches now lives in a directory only root can
/// write, and reachability comes from symlinks ([`needs_machine_bin_link`]) rather than from placement.
///
/// An UNELEVATED install keeps the elevation-free per-user `~/.dig/bin`, resolved against the
/// [invoking user](crate::invoker::target_user) rather than `$HOME`. Nothing runs as root there, so a
/// user-writable directory is the user's own authority, not an escalation.
pub fn default_bin_dir() -> PathBuf {
    if cfg!(windows) {
        // #565: the whole Windows stack lives in the admin-only Program Files
        // root — there is no separate, user-writable per-user bin dir.
        return protected_bin_dir();
    }
    if crate::invoker::is_root() {
        // NOT `UNIX_MACHINE_BIN_DIR`: root must never write to, or execute from, a directory a non-root
        // account can modify (#1748). That directory is a symlink veneer only.
        return protected_bin_dir();
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
/// * **unix:** the machine-wide privileged binaries — the dig-dns service (a
///   dedicated-account systemd unit / root LaunchDaemon) and the root-run
///   dig-updater beacon (+ its `dig-updater-worker` sibling the beacon spawns) —
///   PLUS every binary this installer EXECUTES AS ROOT: `dig-node` and
///   `dig-relay`, which register themselves through their own `install` verb
///   ([`crate::service::run_capturing`]). The user CLIs
///   (`digstore`/`digs`/`dign`/`digd`/`dig-app`) are never run as root and stay
///   in the user root.
///
/// # Why "executed as root" belongs in this classification (#1748)
///
/// The original rule reasoned about who the binary later runs AS: dig-node's
/// unit is user-level, so a user-writable binary looked harmless. But the
/// INSTALLER runs `dig-node install` as root, and an elevated unix install put
/// dig-node in [`UNIX_MACHINE_BIN_DIR`] — which Homebrew on an Intel Mac leaves
/// `<user>:admin 0775`. Anyone able to write there could drop a binary and have
/// root execute it on the next `sudo` install. Placement must therefore follow
/// "does root ever EXECUTE this?", not only "who does it run as afterwards".
/// Reachability on `PATH` is preserved by [`needs_machine_bin_link`], exactly as
/// dig-dns has always done it.
pub fn is_privileged_component(os: Os, component: &str) -> bool {
    match os {
        Os::Windows => true,
        Os::Linux | Os::MacOs => matches!(
            component,
            "dig-dns" | "dig-updater" | "dig-updater-worker" | "dig-node" | "dig-relay"
        ),
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
    // NOT a bare `create_dir_all`: on a minimal image `/usr/local/bin` does not exist, and creating it
    // at the process umask produced mode 777 under `umask 000` — a world-writable directory on every
    // account's default PATH, which is the third instance of this same one-line omission (#1748, F6).
    // A directory that already exists is left exactly as the distribution set it up: this installer owns
    // the LINK it plants, not the system directory holding it, and its posture is reported instead.
    let veneer = Path::new(UNIX_MACHINE_BIN_DIR);
    if !veneer.is_dir() {
        std::fs::create_dir_all(veneer)
            .map_err(|e| format!("create {UNIX_MACHINE_BIN_DIR}: {e}"))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(veneer, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod 0755 {UNIX_MACHINE_BIN_DIR}: {e}"))?;
    }
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
    // `su`/`sh` are resolved from the trusted system directories, NEVER `$PATH`
    // (`elevation::resolve_system_tool`) — this runs as root, and macOS's stock sudoers sets no
    // `secure_path`, so a `$PATH` led by a user-writable Homebrew prefix would let an attacker supply
    // the shell root is about to spawn. Fail-closed: an unresolvable tool answers "cannot enter",
    // which only ever declines to wire PATH.
    // Cross the account boundary whenever we are ROOT acting for somebody else — the effective uid, not
    // whether an elevation HINT exists. The macOS GUI elevates via `osascript`, which inherits no
    // environment, so `via_elevation` is `false` in a root child and this would otherwise have asked
    // ROOT's own shell whether it can enter the directory — the wrong principal, and root can enter
    // almost anything (`crate::pathcheck::as_user_command`, SPEC §7.5).
    let cross_to_user = user.acting_for_another_account(crate::invoker::is_root());
    let out = if cross_to_user {
        let Some(su) = crate::elevation::resolve_system_tool("su") else {
            return false;
        };
        std::process::Command::new(su)
            .args(["-", &user.name, "-c", &script])
            .hide_console()
            .status()
    } else {
        let Some(sh) = crate::elevation::resolve_system_tool("sh") else {
            return false;
        };
        std::process::Command::new(sh)
            .args(["-c", &script])
            .hide_console()
            .status()
    };
    out.map(|s| s.success()).unwrap_or(false)
}

/// What a `PATH`-wiring attempt actually DID, as distinct from whether it succeeded.
///
/// `changed` exists because "we made no change" and "we changed something" are different facts and the
/// `--json` report is consumed by machines (#1748). `InstallReport::path.modified` was hardcoded `true`
/// on the success arm, so the DEFAULT elevated install — whose whole point is that the veneer is already
/// on `PATH` and nothing needs wiring — reported a modification it never made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathWiring {
    /// Did this run actually modify any `PATH` state (a registry value, a profile, a system fragment)?
    pub changed: bool,
    /// Human-readable detail, always populated.
    pub note: String,
}

impl PathWiring {
    /// A run that had nothing to do because the directory was already reachable.
    fn unchanged(note: impl Into<String>) -> Self {
        Self {
            changed: false,
            note: note.into(),
        }
    }

    /// A run that wrote something.
    fn changed(note: impl Into<String>) -> Self {
        Self {
            changed: true,
            note: note.into(),
        }
    }
}

/// Add `bin_dir` to the user's PATH.
///   Windows: append to HKCU\Environment\Path (REG_EXPAND_SZ, no truncation),
///            then broadcast WM_SETTINGCHANGE. No elevation.
///   macOS/Linux: append an `export PATH` line to the user's shell profile(s)
///            (idempotent), so new shells see it. Returns a human note.
pub fn add_to_path(bin_dir: &Path) -> Result<PathWiring, String> {
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
fn windows_add_to_path(bin_dir: &Path) -> Result<PathWiring, String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_EXPAND_SZ};
    use winreg::{RegKey, RegValue};

    let dir = bin_dir.to_string_lossy().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (env, _disp) = hkcu
        .create_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
        .map_err(|e| format!("open HKCU\\Environment: {e}"))?;

    let current: String = env.get_value("Path").unwrap_or_default();
    let new_path = match path_append(&current, &dir, ';') {
        None => {
            return Ok(PathWiring::unchanged(format!(
                "user PATH (already present): {dir}"
            )))
        }
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
    Ok(PathWiring::changed(format!("user PATH: {dir}")))
}

/// Does `component`, having landed in `bin_dir`, need a symlink from [`UNIX_MACHINE_BIN_DIR`] so a user
/// can still run it by name?
///
/// Placement and reachability are separate concerns (#1748). Everything an elevated install places goes
/// into the root-owned [`protected_bin_dir`], which is on no shell's default `PATH` — so the binaries a
/// user invokes by name are linked into `/usr/local/bin`, which is. The LINK sits in the possibly
/// user-writable directory; the TARGET, and every root-side write and exec, stay in the protected one.
/// That is the shape this crate already used for `dig-dns` before the elevated root moved, and it is why
/// hardening the root did not take `dign` off anyone's `PATH`.
///
/// Keyed on `bin_dir` rather than on the component alone, because the answer is a property of WHERE the
/// binary actually landed:
///
/// * **protected root** → link it. This is the elevated install, and the only case that needs one.
/// * **per-user `~/.dig/bin`** (unelevated) → no. That directory is wired onto the user's own `PATH`
///   directly, and an unprivileged run cannot write `/usr/local/bin` anyway, so attempting it would
///   report a failure on every ordinary user install.
/// * **a `--bin-dir` override** → no. The user chose the location and owns making it reachable; the
///   installer does not silently plant links outside what it was asked to do.
///
/// `dig-updater`/`dig-updater-worker` are excluded even in the protected root — the beacon invokes them,
/// a user never does, so they stay off `PATH` entirely.
pub fn needs_machine_bin_link(os: Os, component: &str, bin_dir: &Path) -> bool {
    !matches!(os, Os::Windows)
        && links_out_of(bin_dir)
        && !matches!(component, "dig-updater" | "dig-updater-worker")
}

/// Is `bin_dir` the root-owned protected root — the one placement whose contents are made reachable by
/// SYMLINKS into [`UNIX_MACHINE_BIN_DIR`] rather than by putting the directory itself on `PATH`?
///
/// The single placement decision, shared by [`needs_machine_bin_link`] (which plants the links) and
/// [`reachable_dir`] (which decides what has to be on the user's `PATH`). They must never disagree: a
/// run that wires one directory while linking into another leaves the CLIs unreachable, which is #1748
/// itself.
fn links_out_of(bin_dir: &Path) -> bool {
    bin_dir == protected_bin_dir()
}

/// Which directory must be on the target user's login `PATH` for binaries placed in `bin_dir` to be
/// reachable by bare name?
///
/// Placement and reachability are separate concerns since #1748, so this is NOT always `bin_dir`:
///
/// * **the protected root** → [`UNIX_MACHINE_BIN_DIR`]. `/opt/dig/bin` is on no shell's default `PATH`
///   and is deliberately NOT put on one; what the user resolves is the symlink veneer
///   ([`needs_machine_bin_link`]), which is already on every supported platform's login `PATH`. So the
///   default elevated install has no `PATH` wiring left to get wrong — which is the property
///   `/usr/local/bin` was adopted for, kept now WITHOUT making it a directory root writes to or execs
///   from.
/// * **anything else** (a `--bin-dir` override, an unelevated per-user root) → itself. No links are
///   planted for those, so the directory holding the binaries is the one that has to be searchable.
///
/// Takes `os` for the same reason [`needs_machine_bin_link`] does: on Windows the protected root IS the
/// one install root, nothing is linked, and there is no `/usr/local/bin` — so the answer there is always
/// the directory itself.
pub fn reachable_dir(os: Os, bin_dir: &Path) -> PathBuf {
    if !matches!(os, Os::Windows) && links_out_of(bin_dir) {
        return PathBuf::from(UNIX_MACHINE_BIN_DIR);
    }
    bin_dir.to_path_buf()
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
///
/// # APPENDED, never prepended (#1748)
///
/// This file is read by every LOGIN shell of every account, root's included. Prepending put `dir` in
/// FRONT of `/usr/bin` and `/bin` machine-wide, so whatever `dir` contained won the resolution of every
/// bare command name - `ls`, `cp`, `sudo` - for root as well. Executed: with
/// `--bin-dir /home/alice/digbin`, root's login `PATH` began with alice's directory and `sh -lc 'ls'`
/// ran alice's `ls` as uid 0.
///
/// Appending gives the DIG CLIs the reachability they need (nothing else on the machine is called
/// `dign` or `digs`) while making the fragment unable to shadow a system command. A name COLLISION is
/// then resolved in the system's favour, which is the right direction for a fragment installed
/// machine-wide.
pub fn profile_d_script(dir: &str) -> String {
    format!(
        "# added by dig-installer: make the DIG CLIs resolvable in every login shell\n\
         case \":${{PATH}}:\" in\n\
         \x20 *\":{dir}:\"*) ;;\n\
         \x20 *) PATH=\"${{PATH}}:{dir}\"; export PATH ;;\n\
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

/// Every system-wide login-`PATH` fragment file this installer may have written, so an uninstall can
/// remove them without re-deriving the platform rules.
///
/// Both unix files are listed regardless of host, because a machine can have been installed by an
/// earlier version, or have had its `/etc` copied between systems, and a stale fragment naming a
/// directory that no longer exists is exactly the leftover an uninstall is for. Empty on Windows, whose
/// `PATH` lives in the registry and is handled by the per-user PATH removal.
pub fn login_path_fragment_files() -> Vec<&'static str> {
    if cfg!(windows) {
        Vec::new()
    } else {
        vec![PROFILE_D_SCRIPT, PATHS_D_FILE]
    }
}

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
fn unix_add_to_path(bin_dir: &Path) -> Result<PathWiring, String> {
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
/// shell each time, and because the final word is a re-read of the user's environment rather than our
/// own belief about it, a remediation that did not take is reported as a FAILURE instead of a success
/// note.
///
/// # What gets wired is the REACHABLE dir, not the install dir (#1748)
///
/// The directory the binaries are PLACED in is not necessarily the one that has to be on `PATH`
/// ([`reachable_dir`]). A default elevated install places them in the root-owned protected root and
/// links them into [`UNIX_MACHINE_BIN_DIR`], which is already on every supported platform's login
/// `PATH` — so the common case writes nothing at all. Wiring `/opt/dig/bin` onto every login shell
/// instead would work but would make the veneer pointless and would put the reachability of the whole
/// install back onto a `/etc/profile.d` fragment that some shells (`fish`, `csh`) never read.
///
/// The install dir is still required to be one the user can ENTER: the veneer only holds symlinks, so
/// an unreadable target directory leaves them reachable by name and unusable in fact.
#[cfg(not(windows))]
fn root_add_to_path(
    bin_dir: &Path,
    user: &crate::invoker::TargetUser,
) -> Result<PathWiring, String> {
    use crate::pathcheck;

    // This function is unix-only by `cfg`, and `reachable_dir` distinguishes only Windows from not, so
    // either unix variant gives the same answer.
    let wired = reachable_dir(Os::Linux, bin_dir);
    let dir = wired.to_string_lossy().to_string();
    let reachable = |note: &str| -> Option<String> {
        match pathcheck::login_shell_path(user) {
            Ok(path) if pathcheck::path_contains(&path, &dir, ':') => {
                Some(format!("{dir} is on {}'s login PATH{note}", user.name))
            }
            _ => None,
        }
    };

    // PATH is wired BEFORE the components are downloaded, so on an install that selects none of the
    // early components (`--no-digstore`) the bin dir does not exist yet. A directory that is merely
    // absent is not a directory the user cannot enter, and reporting it as one made the reachability
    // guard below fire on a perfectly good install root. Create it in the shape the download path
    // would: root-owned and world-traversable, which is also what the #565 install-root ACL verify
    // requires (no group or other write).
    ensure_bin_dir(bin_dir)?;

    // Checked even when the veneer is already on PATH, because reachable-by-name is not the same as
    // usable: a symlink in `/usr/local/bin` pointing into a directory the user cannot traverse resolves
    // and then fails to execute. This is the #1748 shape — a check that passes for an environment the
    // user does not have — so it is asserted about the directory the binaries actually live in.
    let install_dir = bin_dir.to_string_lossy().to_string();
    if !user_can_enter(&install_dir, user) {
        return Err(format!(
            "{install_dir} is not accessible to {} (the binaries live there, so linking or wiring them \
             onto PATH would resolve to files the user cannot execute) — install into a directory {} \
             can read, or run the installer as that user",
            user.name, user.name
        ));
    }

    if let Some(note) = reachable(" already — no PATH wiring needed") {
        // Nothing was written, and the report must not claim otherwise: this is the DEFAULT elevated
        // install, whose whole design is that the veneer is already on PATH (#1748, C3).
        return Ok(PathWiring::unchanged(note));
    }

    // Reached only on a platform whose login PATH lacks the veneer, or under a `--bin-dir` override.
    // Either way the directory about to be wired must exist before the user's shell is asked whether it
    // can enter it.
    ensure_bin_dir(&wired)?;

    // REFUSE BEFORE WRITING to put a directory a non-root account can write onto every login shell's
    // PATH, root's included (#1748, F3).
    //
    // The readiness verdict already failed such an install, but only AFTERWARDS — the fragment was
    // already on disk, was never rolled back, and no uninstall removed it. Executed: with
    // `--bin-dir /home/alice/digbin`, `sh -lc 'ls'` as root ran alice's `ls`. So the check moves in
    // front of the write, and the message names the real problem rather than the bin dir's mode.
    //
    // Only under elevation: an unelevated run writes the user's OWN dotfile, which is their authority.
    if crate::invoker::is_root() {
        let verdict = crate::secure::verify_install_root(
            crate::target::Os::from_consts(std::env::consts::OS)
                .unwrap_or(crate::target::Os::Linux),
            &wired,
        );
        if verdict.checked && !verdict.secure {
            return Err(format!(
                "refusing to put {dir} on every login shell's PATH: {} — a directory a non-root                  account can write, placed on root's own PATH, lets that account shadow every system                  command for root",
                verdict.note
            ));
        }
    }

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
        return Ok(PathWiring::changed(note));
    }
    let observed =
        pathcheck::login_shell_path(user).unwrap_or_else(|e| format!("<unreadable: {e}>"));
    Err(format!(
        "wrote {fragment_file} but {dir} is STILL not on {}'s login PATH (it searches: {observed})",
        user.name
    ))
}

/// Ensure `bin_dir` exists and, when it is the protected root, that its mode is `0755` — root writes,
/// everyone else reads and traverses.
///
/// # The mode is ENFORCED, not just set at creation (#1748)
///
/// `create_dir_all` applies the process umask, so the mode of the directory root writes binaries into
/// was inherited from whatever invoked the installer. Measured on a GitHub Actions runner under
/// `sudo -H`, that produced `/opt/dig/bin` at mode **0777** — a WORLD-WRITABLE protected root, which
/// hands every local account the ability to replace a binary root executes. That is the escalation the
/// protected root exists to prevent, arriving through the umask instead of through the path.
///
/// So the mode is set explicitly, and set on an EXISTING directory too. An early return on
/// `is_dir()` would adopt whatever mode a previous run (or anybody else) left behind, which is the
/// same defect one run later.
///
/// Applied only to the protected root. A per-user `~/.dig/bin` or a `--bin-dir` the user chose is
/// theirs, and silently re-moding a directory the caller nominated would be a surprise; its posture is
/// reported instead (`InstallReport::bin_dir_security`).
#[cfg(not(windows))]
pub fn ensure_bin_dir(bin_dir: &Path) -> Result<(), String> {
    // `links_out_of` is "is this the protected root?", the same single decision that drives linking and
    // PATH wiring — so the directory whose mode is pinned is exactly the one root writes into.
    ensure_bin_dir_in(bin_dir, links_out_of(bin_dir))
}

/// [`ensure_bin_dir`] with the "is this the protected root?" decision passed in, so the mode
/// enforcement is exercisable against a temp directory instead of the real `/opt/dig/bin`.
#[cfg(not(windows))]
fn ensure_bin_dir_in(bin_dir: &Path, pin_mode: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    if !bin_dir.is_dir() {
        std::fs::create_dir_all(bin_dir)
            .map_err(|e| format!("create {}: {e}", bin_dir.display()))?;
    }
    if !pin_mode {
        return Ok(());
    }
    std::fs::set_permissions(bin_dir, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod 0755 {}: {e}", bin_dir.display()))
}

/// Windows has no mode bits to enforce; the protected root's guarantee there is its ACL, verified by
/// [`crate::secure::verify_install_root`].
#[cfg(windows)]
pub fn ensure_bin_dir(bin_dir: &Path) -> Result<(), String> {
    if !bin_dir.is_dir() {
        std::fs::create_dir_all(bin_dir)
            .map_err(|e| format!("create {}: {e}", bin_dir.display()))?;
    }
    Ok(())
}

/// [`unix_add_to_path`] against an explicit `home` directory. The real call uses
/// `dirs::home_dir()`; tests point `home` at a temp dir so the idempotent
/// profile-append logic (which `.zshrc`/`.bashrc`/`.profile` to touch, the
/// re-run guard) is exercised without writing the developer's real dotfiles.
#[cfg(not(windows))]
fn unix_add_to_path_in(bin_dir: &Path, home: &Path) -> Result<PathWiring, String> {
    use std::fs;
    use std::io::Write;

    let dir = bin_dir.to_string_lossy().to_string();
    // Idempotent guard line the installer recognises on re-run.
    let marker = "# added by dig-installer";
    let line = format!("\n{marker}\nexport PATH=\"{dir}:$PATH\"\n");

    let mut touched = Vec::new();
    // Distinguish "already had it" from "we appended it" — `touched` alone records both.
    let mut wrote = false;
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
        wrote = true;
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
        wrote = true;
    }
    if !wrote {
        return Ok(PathWiring::unchanged(format!(
            "{dir} is already on PATH in {}",
            touched.join(", ")
        )));
    }
    Ok(PathWiring::changed(format!(
        "added {dir} to PATH in {} (open a new shell to pick it up)",
        touched.join(", ")
    )))
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

    /// The UNELEVATED default install dir is a DIG-scoped bin dir on every platform.
    ///
    /// Scoped to the unelevated case deliberately. `default_bin_dir()` branches on
    /// [`crate::invoker::is_root`], and the elevated unix answer is `/usr/local/bin`, which contains no
    /// "dig" — so an unscoped version of this assertion is a claim about the TEST ENVIRONMENT (that the
    /// runner is not root) dressed up as a claim about the code, and fails outright in a root
    /// container. The elevated arm's real property is asserted by
    /// `the_elevated_unix_bin_dir_is_machine_wide_and_not_under_any_home`.
    #[test]
    fn the_unelevated_default_bin_dir_is_under_a_dig_prefix() {
        let p = if cfg!(windows) {
            default_bin_dir()
        } else {
            // Ask for the unelevated answer directly rather than depending on the runner's uid.
            crate::invoker::target_user().dig_bin_dir()
        }
        .to_string_lossy()
        .to_lowercase();
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
        // unix keeps the elevation-free per-user CLI root, and adds a SEPARATE root-owned root for the
        // binaries root writes or executes.
        assert_eq!(protected_bin_dir(), PathBuf::from("/opt/dig/bin"));
        // Compared against the USER root itself, not `default_bin_dir()`: since #1748 the latter IS the
        // protected root when the process is root, so asserting on it would be a claim about the test
        // runner's uid rather than about the two roots being distinct.
        assert_ne!(
            crate::invoker::target_user().dig_bin_dir(),
            protected_bin_dir(),
            "the unelevated per-user root stays distinct from /opt/dig/bin"
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

    /// The unix protected set is "machine-wide service binaries PLUS everything the installer executes
    /// as root" (#1748 F1) — not merely "binaries that later run under a privileged identity".
    ///
    /// `dig-node` and `dig-relay` are the ones that moved. Their SERVICES are user-level, which is why
    /// they were classified unprotected; but this installer runs their own `install` verb AS ROOT, so a
    /// user-writable location for them is a root-exec surface no matter who the resulting service runs
    /// as. Both halves are asserted here so the set cannot drift in either direction.
    #[test]
    fn unix_protects_the_machine_wide_and_the_root_executed_binaries() {
        // Root/dedicated-account service binaries, and the binaries root EXECUTES, MUST be protected …
        for c in [
            "dig-dns",
            "dig-updater",
            "dig-updater-worker",
            "dig-node",
            "dig-relay",
        ] {
            assert!(
                is_privileged_component(Os::Linux, c),
                "{c} is machine-wide or root-executed on unix and must be protected"
            );
            assert!(is_privileged_component(Os::MacOs, c));
        }
        // … while the CLIs a user runs and root never executes stay in the user root.
        for c in ["digstore", "digs", "digd", "dign", "dig-app"] {
            assert!(
                !is_privileged_component(Os::Linux, c),
                "{c} is only ever run by the user on unix — not a protected component"
            );
            assert!(!is_privileged_component(Os::MacOs, c));
        }
        // And each protected binary a user runs BY NAME is linked back onto PATH, so hardening the
        // exec path cannot silently take `dig-node` off every user's PATH.
        for c in ["dig-dns", "dig-node", "dig-relay"] {
            assert!(
                needs_machine_bin_link(Os::Linux, c, &protected_bin_dir()),
                "{c} is protected AND user-facing, so it must be linked onto PATH"
            );
        }
        // The beacon binaries are protected but deliberately NOT linked — a user never invokes them.
        for c in ["dig-updater", "dig-updater-worker"] {
            assert!(!needs_machine_bin_link(Os::Linux, c, &protected_bin_dir()));
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
    fn only_the_user_facing_binaries_in_the_protected_root_get_a_machine_bin_link() {
        let protected = protected_bin_dir();
        // Every CLI a user runs by name, once it lives in the protected root, needs the link.
        for cli in [
            "dig-dns",
            "digd",
            "dig-node",
            "dign",
            "dig-relay",
            "dig-store",
            "digs",
            "dig-app",
        ] {
            assert!(
                needs_machine_bin_link(Os::Linux, cli, &protected),
                "{cli} lives in a directory on no shell's PATH and must be linked"
            );
            assert!(needs_machine_bin_link(Os::MacOs, cli, &protected));
        }
        for never in ["dig-updater", "dig-updater-worker"] {
            assert!(
                !needs_machine_bin_link(Os::Linux, never, &protected),
                "{never} is invoked by the beacon, never by a user"
            );
        }
        // Windows keeps one root for the whole stack, so there is nothing to link.
        assert!(!needs_machine_bin_link(Os::Windows, "dig-dns", &protected));

        // And the placement half of the predicate: a binary that did NOT land in the protected root is
        // never linked. Without this, an unelevated install would try to write /usr/local/bin on every
        // run and report a failure, and a `--bin-dir` install would get links it never asked for.
        for other in [
            PathBuf::from("/home/alice/.dig/bin"),
            PathBuf::from("/opt/somewhere-else"),
            PathBuf::from(UNIX_MACHINE_BIN_DIR),
        ] {
            assert!(
                !needs_machine_bin_link(Os::Linux, "dig-node", &other),
                "{} is not the protected root, so nothing is linked from it",
                other.display()
            );
        }
    }

    /// The protected root's mode MUST NOT depend on the umask the installer inherited, and MUST be
    /// enforced on a directory that already exists.
    ///
    /// `create_dir_all` applies the process umask, and under `sudo -H` on a GitHub Actions runner that
    /// produced `/opt/dig/bin` at mode **0777** on a real install — a world-writable directory holding
    /// the binaries root wrote and that root-side execs and `/usr/local/bin` links resolve to. The
    /// fixture starts the directory at 0777 EXISTING, because that is the case an early
    /// `if is_dir() { return }` gets wrong: it adopts whatever mode was left behind.
    ///
    /// Runs unprivileged against a redirected protected root, so it gates in CI.
    #[cfg(unix)]
    #[test]
    fn the_protected_root_mode_is_pinned_not_inherited_from_the_umask() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("opt-dig-bin");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        // `ensure_bin_dir` pins the mode of the PROTECTED root specifically, which this temp dir is not
        // — so assert on the shared helper that decides the mode, applied to an existing directory.
        ensure_bin_dir_in(&dir, true).expect("re-moding an existing directory must succeed");

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "the protected root was left at {mode:o} — a group/world-writable directory holding \
             binaries root wrote is the escalation the protected root exists to prevent (#1748)"
        );
    }

    /// A directory the CALLER nominated is not silently re-moded — only the protected root is.
    #[cfg(unix)]
    #[test]
    fn a_user_chosen_bin_dir_is_not_silently_re_moded() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("my-own-bin");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        ensure_bin_dir_in(&dir, links_out_of(&dir)).expect("an existing directory is fine");
        assert!(
            !links_out_of(&dir),
            "the fixture must not be the protected root, or nothing is being asserted"
        );

        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o777,
            "a --bin-dir the user chose is theirs; its posture is REPORTED, not rewritten"
        );
    }

    /// A wiring attempt reports whether it CHANGED anything, not merely whether it succeeded.
    ///
    /// `InstallReport::path.modified` was hardcoded `true` on the success arm, so the default elevated
    /// install — whose entire design is that the veneer is already on `PATH` and nothing needs writing —
    /// claimed a modification it never made, in a field machines consume. Both arms are asserted, because
    /// a `changed` that was always `false` would satisfy the interesting one on its own.
    #[cfg(not(windows))]
    #[test]
    fn path_wiring_reports_whether_it_actually_changed_anything() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::write(
            home.join(".bashrc"),
            "# existing
",
        )
        .unwrap();

        let first = unix_add_to_path_in(Path::new("/opt/somewhere/bin"), home).unwrap();
        assert!(
            first.changed,
            "the first run appends the export, so it DID change PATH state: {}",
            first.note
        );

        // Idempotent re-run: the entry is already there, so nothing is written and nothing is claimed.
        let second = unix_add_to_path_in(Path::new("/opt/somewhere/bin"), home).unwrap();
        assert!(
            !second.changed,
            "a re-run that writes nothing must not report a modification: {}",
            second.note
        );
    }

    /// PATH wiring must target the dir the user RESOLVES from, which after #1748 is not the dir the
    /// binaries are placed in.
    ///
    /// `/opt/dig/bin` is on no shell's default `PATH` and is deliberately never put on one — an elevated
    /// install is reachable through the `/usr/local/bin` symlink veneer. Wiring the install dir instead
    /// would still "work" via `/etc/profile.d`, which is exactly why this needs asserting: the failure is
    /// silent, and it would put every CLI's reachability back onto a fragment `fish`/`csh` never read.
    #[test]
    fn the_dir_that_must_be_on_path_is_the_veneer_for_a_protected_root_install() {
        assert_eq!(
            reachable_dir(Os::Linux, &protected_bin_dir()),
            PathBuf::from(UNIX_MACHINE_BIN_DIR),
            "the protected root is reached through the veneer, never by being put on PATH"
        );
        assert_ne!(
            reachable_dir(Os::Linux, &protected_bin_dir()),
            protected_bin_dir(),
            "wiring /opt/dig/bin onto every login shell defeats the veneer"
        );
        // Every other placement plants no links, so the directory holding the binaries IS the one that
        // has to be searchable. A `reachable_dir` that always returned the veneer would fail here, and
        // would leave a `--bin-dir` install unreachable.
        for owned in [
            PathBuf::from("/home/alice/.dig/bin"),
            PathBuf::from("/opt/somewhere-else"),
        ] {
            assert_eq!(reachable_dir(Os::Linux, &owned), owned);
        }

        // Windows has no veneer: the protected root IS the one install root, nothing is linked, and
        // `/usr/local/bin` does not exist. Without the OS arm this would report a unix path as the
        // directory a Windows install must have on PATH — and `report.path.dir` is machine-consumed.
        assert_eq!(
            reachable_dir(Os::Windows, &protected_bin_dir()),
            protected_bin_dir(),
            "on Windows the install root is what goes on PATH; there is nothing to link"
        );
    }

    /// The linking decision and the wiring decision must be the SAME decision.
    ///
    /// If they ever diverge, a run links its CLIs into one directory while putting a different one on
    /// `PATH` — the install reports success and `dign` is not found, which IS #1748. Asserted as a
    /// coupling rather than two independent constants so the two cannot drift apart.
    #[test]
    fn wiring_and_linking_agree_about_every_placement() {
        for dir in [
            protected_bin_dir(),
            PathBuf::from(UNIX_MACHINE_BIN_DIR),
            PathBuf::from("/home/alice/.dig/bin"),
            PathBuf::from("/opt/somewhere-else"),
        ] {
            let links = needs_machine_bin_link(Os::Linux, "dig-node", &dir);
            let wired_elsewhere = reachable_dir(Os::Linux, &dir) != dir;
            assert_eq!(
                links,
                wired_elsewhere,
                "{}: links are planted into the veneer exactly when the veneer is what gets wired \
                 onto PATH",
                dir.display()
            );
        }
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
        assert!(s.contains(r#"PATH="${PATH}:/usr/local/bin""#), "got: {s}");
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
        assert!(s.contains(r#"PATH="${PATH}:/opt/dig bin""#), "got: {s}");
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
