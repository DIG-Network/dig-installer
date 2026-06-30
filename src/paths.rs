//! Install-directory resolution and PATH wiring.
//!
//! The pure PATH-append logic (`user_path_append`) is unit-tested without
//! touching the real machine PATH — it is the same idempotent, case-insensitive
//! append that digstore's GUI installer used, migrated here so the universal
//! installer keeps the proven behaviour. The actual registry write / symlink is
//! in [`add_to_path`], which calls the pure helper.

use std::path::{Path, PathBuf};

/// Default install directory for DIG tool binaries.
///   Windows: `%LOCALAPPDATA%\Programs\DIG\bin`
///   macOS/Linux: `~/.dig/bin`
///
/// `~/.dig/bin` (rather than `/usr/local/bin`) keeps the unix install fully
/// per-user and elevation-free, matching the dig-node service's user-level
/// default; the installer adds it to PATH.
pub fn default_bin_dir() -> PathBuf {
    if cfg!(windows) {
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("C:/Users/Public"));
        base.join("Programs").join("DIG").join("bin")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/usr/local"))
            .join(".dig")
            .join("bin")
    }
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
fn string_to_reg_expand_sz_bytes(s: &str) -> Vec<u8> {
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
fn broadcast_environment_change() {
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
        // The default install dir is the per-user DIG bin dir on every platform.
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
