//! Install-directory resolution and PATH wiring.
//!
//! The pure PATH-append logic (`user_path_append`) is unit-tested without
//! touching the real machine PATH — it is the same idempotent, case-insensitive
//! append that digstore's GUI installer used, migrated here so the universal
//! installer keeps the proven behaviour. The actual registry write / symlink is
//! in [`add_to_path`], which calls the pure helper.

use std::path::{Path, PathBuf};

use crate::target::Os;

/// Default install directory for DIG tool binaries.
///   Windows: `%ProgramFiles%\DIG\bin` (the admin-only protected root — #565)
///   macOS/Linux: `~/.dig/bin`
///
/// On Windows the ENTIRE stack (services + user CLIs + the installer self-copy)
/// installs into the admin-only [`protected_bin_dir`]: a user-writable bin dir
/// underneath a LocalSystem service / SYSTEM beacon task is a local privilege
/// escalation (#565), so no per-user, user-writable bin dir is used. On unix the
/// user CLIs keep the elevation-free per-user `~/.dig/bin` (rather than
/// `/usr/local/bin`), matching the dig-node service's user-level default; only
/// the machine-wide PRIVILEGED service binaries move to [`protected_bin_dir`]
/// (`/opt/dig/bin`), classified by [`is_privileged_component`].
pub fn default_bin_dir() -> PathBuf {
    if cfg!(windows) {
        // #565: the whole Windows stack lives in the admin-only Program Files
        // root — there is no separate, user-writable per-user bin dir.
        protected_bin_dir()
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/usr/local"))
            .join(".dig")
            .join("bin")
    }
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
fn program_files() -> PathBuf {
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
        Os::Linux | Os::MacOs => dirs::home_dir()
            .map(|h| vec![h.join(".dig").join("bin")])
            .unwrap_or_default(),
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

#[cfg(not(windows))]
fn unix_add_to_path(bin_dir: &Path) -> Result<String, String> {
    let home = dirs::home_dir().ok_or("no home directory")?;
    unix_add_to_path_in(bin_dir, &home)
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
