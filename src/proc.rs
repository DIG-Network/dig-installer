//! Spawning child processes without a flashing console window (issue #564).
//!
//! On Windows a console-subsystem child — `sc`, `net`, `netsh`, `powershell`,
//! `icacls`, `whoami`, `cmd`, and the delegated `dig-node`/`dig-dns`/
//! `dig-updater` verbs — is, by default, given a brand-new console window when
//! its parent has none (as the installer GUI does). That window flashes on
//! screen and steals focus for the fraction of a second the child lives, which
//! during a full install (15+ spawns) reads as a storm of blinking boxes.
//!
//! The Win32 `CREATE_NO_WINDOW` process-creation flag suppresses that console
//! entirely while leaving everything else about the child untouched: it still
//! runs, and its stdio is still captured by `.output()` exactly as before — the
//! flag governs console *allocation*, not stdio redirection.
//!
//! [`HideConsole::hide_console`] is the single, crate-wide way to apply it.
//! EVERY child spawn in this crate is threaded through it — one helper rather
//! than a `creation_flags` literal sprinkled across a dozen call sites — so no
//! spawn site can be missed, now or after a refactor. On non-Windows targets,
//! where there is no console to flash, it is a no-op, so the same call site
//! compiles and behaves identically on every platform.

/// The Win32 [`CREATE_NO_WINDOW`] process-creation flag: run a console child
/// without allocating a console, so no window flashes and the installer keeps
/// foreground focus.
///
/// [`CREATE_NO_WINDOW`]: https://learn.microsoft.com/windows/win32/procthread/process-creation-flags
#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Suppress the transient console window Windows would otherwise allocate for a
/// child [`std::process::Command`].
///
/// The method is chainable, so it drops straight into an existing builder chain
/// immediately before `.output()`/`.status()`/`.spawn()`:
///
/// ```no_run
/// use dig_installer::proc::HideConsole;
///
/// let out = std::process::Command::new("whoami")
///     .arg("/user")
///     .hide_console()
///     .output();
/// ```
///
/// On non-Windows targets this is a no-op (there is no console to hide), so the
/// same call site compiles and behaves identically everywhere.
pub trait HideConsole {
    /// Apply [`CREATE_NO_WINDOW`] on Windows (a no-op elsewhere), returning
    /// `self` so the call chains before the terminal spawn method.
    fn hide_console(&mut self) -> &mut Self;
}

impl HideConsole for std::process::Command {
    fn hide_console(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}

/// Resolve a Windows system tool (`sc`, `netsh`, `powershell`, `icacls`,
/// `schtasks`, `net`, `whoami`, `reg`, …) to its ABSOLUTE
/// `%SystemRoot%\System32\<name>.exe` path — never a bare name (#657).
///
/// Windows resolves a bare program name via a search order that places the
/// **current directory before System32**, so an elevated process launched with
/// an attacker-controlled CWD could execute a planted `sc.exe`/`netsh.exe`
/// instead of the real tool (a search-order hijack). Routing every system-tool
/// spawn through this resolver makes the invocation immune: the System32
/// directory is read from the OS via `GetSystemDirectoryW` (NOT the spoofable
/// `%SystemRoot%` env), and the tool is addressed by its fully-qualified path.
///
/// On non-Windows targets this is the identity (the bare name), so a shared
/// call site compiles and behaves identically everywhere; the hardening applies
/// only where the hijack exists.
pub fn system_tool(name: &str) -> std::ffi::OsString {
    #[cfg(windows)]
    {
        let resolved = system32_join(&system_directory(), name);
        // Defensive: use the absolute path only when it actually exists (it does
        // for every tool we invoke). If a system deviates from the expected
        // layout, fall back to the bare name rather than a guaranteed spawn
        // failure — functionality never regresses; the hardening applies on the
        // overwhelmingly-common correct layout.
        if std::path::Path::new(&resolved).exists() {
            std::ffi::OsString::from(resolved)
        } else {
            std::ffi::OsString::from(name)
        }
    }
    #[cfg(not(windows))]
    {
        std::ffi::OsString::from(name)
    }
}

/// Join a resolved System32 directory and a tool `name` into an absolute
/// executable path. Appends `.exe` when absent, normalises the trailing
/// separator, and maps the tools that do NOT live directly in System32 to their
/// real System32-relative location. Pure — so the path construction is
/// unit-tested on every OS.
///
/// `powershell` is the notable special case: `powershell.exe` is NOT in
/// System32 itself but in `System32\WindowsPowerShell\v1.0\` (which is on the
/// default PATH — the reason a bare `powershell` normally resolves). Addressing
/// it absolutely still closes the search-order hijack (#657).
pub fn system32_join(system_dir: &str, name: &str) -> String {
    let base = system_dir.trim_end_matches(['\\', '/']);
    let lower = name.to_ascii_lowercase();
    let relative = if lower == "powershell" || lower == "powershell.exe" {
        r"WindowsPowerShell\v1.0\powershell.exe".to_string()
    } else if lower.ends_with(".exe") {
        name.to_string()
    } else {
        format!("{name}.exe")
    };
    format!("{base}\\{relative}")
}

/// The absolute Windows System32 directory, read from the OS via
/// `GetSystemDirectoryW` (immune to `%SystemRoot%`/`%SystemDrive%` env
/// redirection). Falls back to the literal `C:\Windows\System32` only if the API
/// itself fails. The one hardened resolver both [`system_tool`] and the
/// machine hosts-file path ([`crate::hosts::hosts_path`]) share (#657).
#[cfg(windows)]
pub fn system_directory() -> String {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 || len > buf.len() {
        return r"C:\Windows\System32".to_string();
    }
    String::from_utf16_lossy(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A hidden child still RUNS and its stdout is still CAPTURED by `.output()`
    /// — the core #564 acceptance that `CREATE_NO_WINDOW` hides only the console
    /// and never disturbs stdio capture. Cross-platform: it also proves the
    /// non-Windows no-op is fully transparent.
    ///
    /// (`std::process::Command` exposes no getter for its creation flags, so the
    /// flag cannot be read back and asserted directly; this behavioural check —
    /// the child runs, exits zero, and its output is captured verbatim — is the
    /// observable contract the flag must preserve.)
    #[test]
    fn hidden_child_runs_and_its_output_is_still_captured() {
        let out = echoing_command("dig-564-token")
            .hide_console()
            .output()
            .expect("the hidden child should still spawn");
        assert!(out.status.success(), "the hidden child should exit zero");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("dig-564-token"),
            "the hidden child's stdout should still be captured"
        );
    }

    /// `hide_console` returns the same `Command` so it composes inside a builder
    /// chain (the property every call site relies on).
    #[test]
    fn is_chainable() {
        let mut cmd = echoing_command("chain");
        // Calling it twice is idempotent and still yields a usable command.
        let out = cmd
            .hide_console()
            .hide_console()
            .output()
            .expect("chained command should spawn");
        assert!(out.status.success());
    }

    /// On Windows the applied flag is exactly the documented Win32 value.
    #[cfg(windows)]
    #[test]
    fn create_no_window_is_the_win32_flag() {
        assert_eq!(CREATE_NO_WINDOW, 0x0800_0000);
    }

    #[test]
    fn system32_join_builds_an_absolute_exe_path() {
        // The #657 invariant: a bare tool name becomes a fully-qualified
        // System32 path (with `.exe`), so no current-directory search-order
        // hijack can substitute a planted binary.
        assert_eq!(
            system32_join(r"C:\Windows\System32", "sc"),
            r"C:\Windows\System32\sc.exe"
        );
        assert_eq!(
            system32_join(r"C:\Windows\System32", "netsh"),
            r"C:\Windows\System32\netsh.exe"
        );
        // An explicit `.exe` (any case) is not doubled.
        assert_eq!(
            system32_join(r"C:\Windows\System32", "ICACLS.EXE"),
            r"C:\Windows\System32\ICACLS.EXE"
        );
    }

    #[test]
    fn system32_join_maps_powershell_to_its_real_subdir() {
        // powershell.exe is NOT directly in System32 — it lives under
        // WindowsPowerShell\v1.0 (on the default PATH). The absolute resolution
        // must point THERE, not System32\powershell.exe (which does not exist).
        let expected = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        assert_eq!(
            system32_join(r"C:\Windows\System32", "powershell"),
            expected
        );
        assert_eq!(
            system32_join(r"C:\Windows\System32", "powershell.exe"),
            expected
        );
    }

    #[test]
    fn system32_join_normalises_a_trailing_separator() {
        // A resolved dir that carries a trailing separator must not double it.
        assert_eq!(
            system32_join(r"C:\Windows\System32\", "reg"),
            r"C:\Windows\System32\reg.exe"
        );
    }

    #[test]
    fn system_tool_is_absolute_on_windows_and_the_bare_name_elsewhere() {
        let sc = system_tool("sc");
        #[cfg(windows)]
        {
            let s = sc.to_string_lossy().to_lowercase();
            assert!(
                s.ends_with(r"system32\sc.exe"),
                "windows must resolve to an absolute System32 path: {s}"
            );
            assert!(std::path::Path::new(&sc).is_absolute());
        }
        #[cfg(not(windows))]
        {
            assert_eq!(sc, std::ffi::OsString::from("sc"));
        }
    }

    /// Build a command that prints `token` to stdout and exits zero, using each
    /// OS's always-present shell so the test needs no fixture on disk.
    fn echoing_command(token: &str) -> Command {
        #[cfg(windows)]
        {
            let mut c = Command::new("cmd");
            c.args(["/C", "echo", token]);
            c
        }
        #[cfg(not(windows))]
        {
            let mut c = Command::new("printf");
            c.args(["%s", token]);
            c
        }
    }
}
