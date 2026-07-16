//! Privilege (elevation) detection + the pre-install elevation gate (#492).
//!
//! The installer registers OS services (dig-node, dig-dns), writes the
//! `dig.local` hosts entry, and registers OS URL-scheme handlers — all of which
//! require **Administrator** on Windows / **root** on macOS/Linux. An
//! UN-elevated run fails those steps, historically leaving a broken, silently
//! "successful" install (bug #493). So the installer REQUIRES elevation and
//! checks it **FIRST**, before downloading or writing anything, failing fast
//! and clear so a non-elevated run leaves NO partial state.
//!
//! Layering: [`gate`] is the pure decision (elevated? + target → `Ok` / a typed
//! `NOT_ELEVATED` error), unit-tested directly; [`is_elevated`] is the per-OS
//! runtime probe. The one-line elevation reason + per-OS remedy live in
//! [`reason`]/[`remedy`] so both the CLI and the GUI surface identical copy.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::InstallError;
use crate::proc::HideConsole;
use crate::target::{Os, Target};

/// The per-OS runtime elevation probe.
///
/// * **Windows:** attempt `net session` — only an elevated (Administrator)
///   token can run it (mirrors dig-node-service's + [`crate::dns`]'s probe).
/// * **Unix:** the effective uid is 0 (root), read via `id -u`.
/// * Any other platform: conservatively `false` (treated as un-elevated).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        is_elevated_windows()
    }
    #[cfg(unix)]
    {
        is_elevated_unix()
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

#[cfg(windows)]
fn is_elevated_windows() -> bool {
    std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .hide_console()
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn is_elevated_unix() -> bool {
    // Resolve `id` to an ABSOLUTE path from a fixed set of trusted system
    // directories — NEVER via `$PATH` (#638, MUST-HONOR from the #637 gate).
    // `should_exec_verify` (the GUI's write→exec LPE gate) TRUSTS this bit: a
    // `$PATH`-shadowed `id` printing a non-root uid under a root process would
    // flip the gate and let the root process exec a user-writable binary. If the
    // real `id` cannot be resolved we FAIL CLOSED (report NOT elevated), which at
    // worst forces the elevation gate to demand elevation again — never the
    // dangerous direction of falsely reporting elevated.
    let Some(id) = resolve_system_tool("id") else {
        return false;
    };
    std::process::Command::new(id)
        .arg("-u")
        .hide_console()
        .output()
        .ok()
        .and_then(|o| parse_id_u(&o.stdout))
        .map(|uid| uid == 0)
        .unwrap_or(false)
}

/// The fixed set of trusted absolute directories a well-known system tool is
/// resolved from. Deliberately NOT `$PATH`: resolving a bare command name via
/// `$PATH` under (or on the way to) elevation is a root-`PATH`-hijack /
/// pwnkit-class surface. Every tool the elevation path spawns — `id`, `pkexec`
/// — is looked up here instead.
#[cfg(unix)]
const TRUSTED_SYSTEM_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin", "/sbin"];

/// Resolve a well-known system tool to an ABSOLUTE path from [`TRUSTED_SYSTEM_DIRS`],
/// NEVER via `$PATH`. Returns `None` (fail-closed) when the tool is absent from
/// every trusted directory.
#[cfg(unix)]
pub fn resolve_system_tool(name: &str) -> Option<PathBuf> {
    TRUSTED_SYSTEM_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

/// The fixed subcommand token the bundled installer recognises to run ONLY the
/// privileged install headlessly (no GUI/WebView) when it is relaunched as root.
///
/// The Linux GUI is unelevated; when the selection needs privilege it relaunches
/// its OWN executable as root via `pkexec` with this token, so the root child
/// runs the scoped privileged install and exits — the GUI/WebView never runs as
/// root (honoring the #637 constraint that elevation lifts only the child, and
/// avoiding the #499-class "GUI as an over-privileged token" hazard).
pub const ELEVATED_INSTALL_ARG: &str = "__dig-elevated-install";

/// Build the FIXED argument vector handed to `pkexec` to relaunch `installer_exe`
/// as root, running ONLY the headless privileged install.
///
/// Structurally immune to the pwnkit class (CVE-2021-4034):
/// * `installer_exe` MUST be ABSOLUTE (pkexec requires a fully-qualified program
///   path) — a relative path returns `None` (fail-closed).
/// * The argv is fixed and fully controlled here: `[<abs installer>, <token>]`.
///   There is no user-controlled `argv[0]`, no shell, and no interpolation of user
///   text. The install selection is NOT an argument at all — it is streamed to the
///   root child over its STDIN (see [`relaunch_elevated`]), so there is no plan
///   file to race and nothing to splice into a command string.
/// * The caller spawns via [`std::process::Command`], which ALWAYS sets a real
///   `argv[0]` (`argc >= 1`), and `pkexec` itself resets the environment
///   (sanitised `PATH`, `LD_*` stripped).
///
/// Pure and cross-platform (path logic only) so every property above is
/// unit-tested on every OS the crate builds on.
pub fn pkexec_argv(installer_exe: &Path) -> Option<Vec<OsString>> {
    if !installer_exe.is_absolute() {
        return None;
    }
    Some(vec![
        installer_exe.as_os_str().to_os_string(),
        OsString::from(ELEVATED_INSTALL_ARG),
    ])
}

/// Resolve the executable `pkexec` should re-exec for the privileged child,
/// given the process's `$APPIMAGE` env value (if any) and its `current_exe()`.
///
/// When the GUI runs as an **AppImage**, `current_exe()` points INSIDE the FUSE
/// mount, which by default is NOT readable by root (`allow_other` is off) — so
/// root's `pkexec` could not exec it and the privileged install would never start.
/// The AppImage runtime exports `$APPIMAGE` = the absolute path of the `.AppImage`
/// FILE itself (a normal on-disk file, root-readable); re-exec THAT so the
/// AppImage bootstrap re-mounts as root and runs our binary with the elevation
/// token. Falls back to `current_exe` when not running as an AppImage (a bare
/// binary is already on a root-readable path). Pure, so the choice is unit-tested.
pub fn relaunch_target(appimage_env: Option<&Path>, current_exe: &Path) -> PathBuf {
    match appimage_env {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        _ => current_exe.to_path_buf(),
    }
}

/// The fail-closed message shown when native elevation is unavailable on Linux
/// (polkit/`pkexec` absent). No partial state is left; the user is pointed at the
/// two supported recoveries (install polkit, or run the CLI under `sudo`).
pub fn pkexec_unavailable_message() -> &'static str {
    "native elevation is unavailable: pkexec (polkit) was not found. Install polkit \
     (e.g. `sudo apt install policykit-1`) and re-launch the installer, or run \
     `sudo dig-installer` in a terminal. Nothing was changed."
}

/// Relaunch this installer as root via `pkexec` to run the headless privileged
/// install, streaming `plan_json` to the root child's STDIN, and block until it
/// exits.
///
/// The selection is handed over the child's stdin rather than a filesystem path
/// on purpose: there is NO shared-namespace plan file, so a co-located local user
/// cannot pre-seed, symlink-swap, or race the plan (the plan-file TOCTOU class is
/// eliminated, not merely hardened). The payload is small (a few hundred bytes),
/// well under the pipe buffer, and stdin is closed before `wait()` so the child's
/// read-to-EOF completes without deadlock.
///
/// Fail-closed: [`RelaunchError::PolkitMissing`] when `pkexec` is absent from the
/// [trusted system dirs](TRUSTED_SYSTEM_DIRS) (NO setuid fallback), [`RelaunchError::BadPath`]
/// when the installer path is not absolute, [`RelaunchError::Spawn`] when the spawn
/// or stdin write fails. On a clean run it returns the child's
/// [`std::process::ExitStatus`] (a non-zero status — e.g. the user dismissing the
/// polkit auth dialog — is a normal, honest failure the caller surfaces).
#[cfg(unix)]
pub fn relaunch_elevated(
    installer_exe: &Path,
    plan_json: &[u8],
) -> Result<std::process::ExitStatus, RelaunchError> {
    use std::io::Write;
    use std::process::Stdio;

    let pkexec = resolve_system_tool("pkexec").ok_or(RelaunchError::PolkitMissing)?;
    let argv = pkexec_argv(installer_exe).ok_or(RelaunchError::BadPath)?;

    let mut child = std::process::Command::new(pkexec)
        .args(&argv)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| RelaunchError::Spawn(e.to_string()))?;

    // Write the plan, then CLOSE stdin (drop the handle) so the child's
    // read-to-EOF returns — before we wait(), to avoid a write/read deadlock.
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| RelaunchError::Spawn("pkexec child stdin unavailable".to_string()))?;
        stdin
            .write_all(plan_json)
            .map_err(|e| RelaunchError::Spawn(e.to_string()))?;
    }

    child
        .wait()
        .map_err(|e| RelaunchError::Spawn(e.to_string()))
}

/// Why a [`relaunch_elevated`] attempt could not even start the root child.
#[cfg(unix)]
#[derive(Debug)]
pub enum RelaunchError {
    /// `pkexec` (polkit) is not installed — fail closed, no setuid workaround.
    PolkitMissing,
    /// The installer path was not absolute (pkexec requires an abs program path).
    BadPath,
    /// The `pkexec` process could not be spawned, or its stdin could not be fed.
    Spawn(String),
}

#[cfg(unix)]
impl std::fmt::Display for RelaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelaunchError::PolkitMissing => f.write_str(pkexec_unavailable_message()),
            RelaunchError::BadPath => {
                f.write_str("internal error: the installer path was not absolute")
            }
            RelaunchError::Spawn(e) => write!(f, "could not start pkexec: {e}"),
        }
    }
}

/// Parse the numeric uid printed by `id -u` (e.g. `0\n` for root). Pure — split
/// out so the "am I root" decision is unit-tested without spawning `id`.
/// `None` when the output is not a bare integer.
#[cfg(unix)]
fn parse_id_u(stdout: &[u8]) -> Option<u32> {
    std::str::from_utf8(stdout).ok()?.trim().parse::<u32>().ok()
}

/// The one-line reason the installer needs elevation — identical across the CLI
/// and GUI so the user always sees the same honest explanation (§6.0: no dark
/// pattern; the ask is understood).
pub fn reason() -> &'static str {
    "dig-installer installs OS services (dig-node, dig-dns), writes the dig.local hosts entry, \
     and registers URL-scheme handlers — all of which require administrative privileges"
}

/// The per-OS remedy: how to re-run with elevation.
pub fn remedy(os: Os) -> &'static str {
    match os {
        Os::Windows => {
            "re-run from a console opened as Administrator (right-click Windows Terminal / \
             PowerShell → \"Run as administrator\"), then run the installer again"
        }
        Os::Linux | Os::MacOs => "re-run with sudo (e.g. `sudo dig-installer …`)",
    }
}

/// The pre-install elevation gate (#492). Given whether the process is elevated
/// and the resolved [`Target`], return `Ok(())` to proceed, or a typed
/// `NOT_ELEVATED` [`InstallError`] (recoverable — re-run elevated) carrying the
/// reason + the per-OS remedy hint.
///
/// Pure: the caller supplies the `elevated` bit (production: [`is_elevated`];
/// tests: a fixed value), so the decision + messaging are unit-tested without a
/// real privilege probe and without spawning anything.
pub fn gate(elevated: bool, target: &Target) -> Result<(), InstallError> {
    guard(elevated, false, target)
}

/// The full pre-install privilege guard (#492 + #499). Rejects TWO bad states,
/// in order, before any download/write:
///
/// 1. **Running as LocalSystem/SYSTEM** (`is_system`, Windows) → `RUN_AS_SYSTEM`.
///    A SYSTEM token breaks the GUI (WebView2 writes to `…\systemprofile\…`) and
///    lands per-user state in the wrong profile. Elevation must be a UAC
///    elevation of the SAME interactive user — never a service/scheduled-task
///    relaunch that yields SYSTEM. Refuse with a clear "run as yourself" remedy.
/// 2. **Not elevated at all** (`!elevated`) → `NOT_ELEVATED` (re-run elevated).
///
/// Pure: the caller supplies both bits (production: [`is_elevated`]/[`is_system`];
/// tests: fixed values), so the decision + messaging are unit-tested directly.
pub fn guard(elevated: bool, is_system: bool, target: &Target) -> Result<(), InstallError> {
    if is_system {
        return Err(InstallError::run_as_system(
            "the installer is running as LocalSystem/SYSTEM, not your user account. A SYSTEM \
             token cannot run the installer UI and writes settings to the wrong profile. Run the \
             installer as your OWN user and approve the Administrator (UAC) prompt — do NOT launch \
             it via a service, scheduled task, or psexec -s."
                .to_string(),
        )
        .with_hint(
            "close this, then re-launch the installer normally as your user (it will prompt for \
             Administrator via UAC, elevating YOUR account — not SYSTEM)",
        ));
    }
    if elevated {
        return Ok(());
    }
    let privilege = match target.os {
        Os::Windows => "Administrator",
        Os::Linux | Os::MacOs => "root (sudo)",
    };
    Err(InstallError::not_elevated(format!(
        "elevation required ({privilege}): {}. The installer was launched WITHOUT elevation, so \
         it stopped before making any changes — nothing was installed and no partial state was \
         left behind.",
        reason()
    ))
    .with_hint(remedy(target.os)))
}

/// Is this process running as Windows **LocalSystem/SYSTEM** (well-known SID
/// `S-1-5-18`)? A SYSTEM token is over-elevated in the wrong way for an
/// interactive installer (#499). Probed via `whoami /user`. Always `false` on
/// non-Windows (SYSTEM is a Windows concept; root on Unix is the intended
/// elevated identity).
pub fn is_system() -> bool {
    #[cfg(windows)]
    {
        match std::process::Command::new("whoami")
            .arg("/user")
            .hide_console()
            .output()
        {
            Ok(o) if o.status.success() => parse_whoami_is_system(&o.stdout),
            // FAIL CLOSED: if the identity cannot be determined (whoami failed to
            // spawn or exited non-zero) we must NOT proceed as an interactive user
            // — treat the indeterminate result as SYSTEM so `guard` aborts. A
            // mis-detected interactive SYSTEM install is the bug this guards (#499);
            // failing open here would let it through on any transient whoami error.
            _ => true,
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Does `whoami /user` output show the LocalSystem SID `S-1-5-18`? Pure — the
/// SYSTEM decision is unit-tested without spawning `whoami`.
pub fn parse_whoami_is_system(stdout: &[u8]) -> bool {
    String::from_utf8_lossy(stdout).contains("S-1-5-18")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{Arch, Os, Target};

    fn win() -> Target {
        Target {
            os: Os::Windows,
            arch: Arch::X64,
        }
    }
    fn linux() -> Target {
        Target {
            os: Os::Linux,
            arch: Arch::X64,
        }
    }
    fn mac() -> Target {
        Target {
            os: Os::MacOs,
            arch: Arch::Arm64,
        }
    }

    #[test]
    fn gate_passes_when_elevated() {
        // Elevated → proceed, on every OS.
        for t in [win(), linux(), mac()] {
            assert!(gate(true, &t).is_ok(), "elevated must proceed on {t}");
        }
    }

    #[test]
    fn gate_fails_loud_with_not_elevated_code_when_unprivileged() {
        // The core #492 regression: an un-elevated run is a typed, recoverable
        // failure — NOT a silent continue.
        let e = gate(false, &win()).unwrap_err();
        assert_eq!(e.code(), "NOT_ELEVATED");
        assert_eq!(e.exit_code(), 11);
        // Honest messaging: it names the privilege + that nothing was changed.
        assert!(
            e.message().contains("Administrator"),
            "got: {}",
            e.message()
        );
        assert!(
            e.message().contains("no partial state"),
            "must promise no partial state: {}",
            e.message()
        );
    }

    #[test]
    fn gate_remedy_is_per_os() {
        // Windows says "Run as administrator"; Unix says sudo.
        let win_hint = gate(false, &win()).unwrap_err();
        assert!(
            win_hint.hint().unwrap().contains("Administrator"),
            "got: {:?}",
            win_hint.hint()
        );
        for unix in [linux(), mac()] {
            let e = gate(false, &unix).unwrap_err();
            assert!(
                e.hint().unwrap().contains("sudo"),
                "unix remedy must mention sudo: {:?}",
                e.hint()
            );
        }
    }

    #[test]
    fn reason_names_the_privileged_actions() {
        // The reason must enumerate WHY (services + hosts + handlers), so the
        // user understands the ask (§6.0, no dark pattern).
        let r = reason();
        assert!(r.contains("services"));
        assert!(r.contains("dig.local"));
        assert!(r.contains("URL-scheme"));
    }

    #[test]
    fn guard_rejects_running_as_system() {
        // #499 core regression: running as LocalSystem/SYSTEM is refused — even
        // though a SYSTEM token IS "elevated", it breaks the GUI/profile — with
        // its own distinct code + a "run as yourself" remedy (never a silent OK).
        let e = guard(true, true, &win()).unwrap_err();
        assert_eq!(e.code(), "RUN_AS_SYSTEM");
        assert_eq!(e.exit_code(), 13);
        assert!(
            e.message().contains("SYSTEM"),
            "must name the SYSTEM token: {}",
            e.message()
        );
        assert!(
            e.hint().unwrap().to_lowercase().contains("uac")
                || e.hint().unwrap().contains("your user"),
            "remedy must tell the user to run as themselves via UAC: {:?}",
            e.hint()
        );
    }

    #[test]
    fn guard_system_check_precedes_elevation_check() {
        // A SYSTEM process is refused as RUN_AS_SYSTEM regardless of the elevated
        // bit — the SYSTEM state is the more specific, more dangerous one.
        assert_eq!(
            guard(false, true, &win()).unwrap_err().code(),
            "RUN_AS_SYSTEM"
        );
    }

    #[test]
    fn guard_passes_for_an_elevated_non_system_user() {
        // The intended state: an elevated (UAC) interactive user, not SYSTEM.
        assert!(guard(true, false, &win()).is_ok());
    }

    #[test]
    fn guard_falls_through_to_not_elevated_when_unprivileged_and_not_system() {
        assert_eq!(
            guard(false, false, &win()).unwrap_err().code(),
            "NOT_ELEVATED"
        );
    }

    #[test]
    fn parse_whoami_is_system_detects_the_localsystem_sid() {
        let sys = b"USER INFORMATION\r\n----------------\r\n\
            User Name           SID\r\n\
            =================== ========\r\n\
            nt authority\\system S-1-5-18\r\n";
        assert!(parse_whoami_is_system(sys));
        let user = b"User Name    SID\r\ndesktop\\alice S-1-5-21-111-222-333-1001\r\n";
        assert!(!parse_whoami_is_system(user));
        assert!(!parse_whoami_is_system(b""));
    }

    #[test]
    fn is_system_never_panics() {
        // Safe to call on any host (CI is not SYSTEM).
        let _ = is_system();
    }

    #[cfg(unix)]
    #[test]
    fn parse_id_u_reads_the_uid() {
        assert_eq!(parse_id_u(b"0\n"), Some(0));
        assert_eq!(parse_id_u(b"1000\n"), Some(1000));
        assert_eq!(parse_id_u(b"   501  "), Some(501));
        assert_eq!(parse_id_u(b"root"), None);
        assert_eq!(parse_id_u(b""), None);
    }

    #[test]
    fn is_elevated_never_panics() {
        // The real probe must be safe to call on any host (CI runs un-elevated).
        let _ = is_elevated();
    }

    // ---- #638: Linux pkexec relaunch mechanism ----------------------------

    use std::path::Path;

    // Unix-only: `Path::is_absolute()` uses platform semantics, and a POSIX
    // absolute path (`/opt/…`) is only recognised as absolute on unix — which is
    // the only platform this argv is ever built on (pkexec is Linux).
    #[cfg(unix)]
    #[test]
    fn pkexec_argv_has_the_fixed_pwnkit_safe_shape() {
        // The argv is exactly [<abs installer>, <token>] — a real argv[0], a fixed
        // token, no shell, no user-controlled argv[0], and (critically) NO plan
        // argument: the selection goes over stdin, so there is nothing to splice
        // and no plan file to race. Structural immunity to the pwnkit class.
        let installer = Path::new("/opt/DIG Installer.AppImage");
        let argv = pkexec_argv(installer).expect("an absolute path must build an argv");
        assert_eq!(argv.len(), 2, "fixed 2-element argv (no plan arg)");
        assert_eq!(
            argv[0],
            installer.as_os_str(),
            "argv[0] is the ABSOLUTE program"
        );
        assert_eq!(argv[1], OsString::from(ELEVATED_INSTALL_ARG));
    }

    #[test]
    fn pkexec_argv_fails_closed_on_a_relative_installer_path() {
        // pkexec requires a fully-qualified program path; a relative one (which a
        // hostile cwd could influence) is rejected rather than resolved.
        assert!(pkexec_argv(Path::new("relative/installer")).is_none());
    }

    #[test]
    fn relaunch_target_falls_back_to_current_exe_when_not_an_appimage() {
        // No $APPIMAGE (a bare binary, already on a root-readable path) → current_exe.
        let current = Path::new("/usr/lib/dig/dig-installer");
        assert_eq!(
            relaunch_target(None, current),
            current.to_path_buf(),
            "without $APPIMAGE the current executable is used"
        );
    }

    // Unix-only: absolute-path semantics (see the argv test above).
    #[cfg(unix)]
    #[test]
    fn relaunch_target_prefers_the_appimage_file_over_the_fuse_current_exe() {
        // Running as an AppImage: `current_exe()` is inside the (root-unreadable)
        // FUSE mount; $APPIMAGE is the .AppImage FILE (root-readable). Re-exec THAT.
        let appimage = Path::new("/home/alice/Downloads/DIG-Installer.AppImage");
        let fuse_exe = Path::new("/tmp/.mount_DIG-InXYZ/usr/bin/dig-installer");
        assert_eq!(
            relaunch_target(Some(appimage), fuse_exe),
            appimage.to_path_buf(),
            "the root-readable .AppImage file must be preferred over the FUSE path"
        );
        // A non-absolute $APPIMAGE (never expected) is ignored → current_exe.
        assert_eq!(
            relaunch_target(Some(Path::new("relative.AppImage")), fuse_exe),
            fuse_exe.to_path_buf()
        );
    }

    #[test]
    fn pkexec_argv_carries_no_shell_metacharacters_of_its_own() {
        // The token we inject is a plain identifier — no shell will ever interpret
        // it because we exec pkexec directly (no `sh -c`). Guards against a future
        // edit that turns the token into something shell-sensitive.
        assert!(!ELEVATED_INSTALL_ARG
            .chars()
            .any(|c| " \t\n;|&$`\"'\\<>(){}".contains(c)));
    }

    #[test]
    fn pkexec_unavailable_message_is_fail_closed_and_actionable() {
        let m = pkexec_unavailable_message();
        assert!(m.contains("polkit"), "names the missing dependency: {m}");
        assert!(
            m.contains("sudo dig-installer"),
            "offers the terminal recovery: {m}"
        );
        assert!(
            m.contains("Nothing was changed"),
            "promises no partial state: {m}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_system_tool_is_absolute_and_trusted_or_none() {
        // A tool that exists nowhere resolves to None (fail-closed).
        assert!(resolve_system_tool("definitely-not-a-real-tool-xyz-638").is_none());
        // Any resolved tool is absolute AND under a trusted system dir — never $PATH.
        if let Some(p) = resolve_system_tool("sh") {
            assert!(p.is_absolute());
            assert!(
                TRUSTED_SYSTEM_DIRS.iter().any(|d| p.starts_with(d)),
                "resolved tool must live under a trusted dir: {}",
                p.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn is_elevated_unix_resolves_id_from_a_trusted_absolute_path() {
        // The hardening (#638): `id` is resolved from a trusted absolute dir, so a
        // real `id` MUST be present for the probe to even attempt the check. On any
        // normal Linux/macOS host `id` exists under a trusted dir; assert the probe
        // is wired to that resolution rather than a bare $PATH lookup.
        assert!(
            resolve_system_tool("id").is_some(),
            "the elevation probe depends on a trusted absolute `id`"
        );
        // And the public probe stays panic-free + honest (CI is not root).
        assert!(!is_elevated_unix(), "CI runs unprivileged");
    }
}
