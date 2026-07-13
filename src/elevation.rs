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

use crate::error::InstallError;
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
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn is_elevated_unix() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| parse_id_u(&o.stdout))
        .map(|uid| uid == 0)
        .unwrap_or(false)
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
        std::process::Command::new("whoami")
            .arg("/user")
            .output()
            .ok()
            .map(|o| parse_whoami_is_system(&o.stdout))
            .unwrap_or(false)
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
}
