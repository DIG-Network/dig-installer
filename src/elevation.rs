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
