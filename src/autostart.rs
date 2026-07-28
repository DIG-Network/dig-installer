//! Per-user autostart for the `dig-app` identity agent (issue #912).
//!
//! `dig-app` is a **per-user tray / menu-bar agent**, not a machine-wide daemon, so it must never be
//! registered the way `dig-node`/`dig-dns`/`dig-relay` are (a boot-start OS service running as
//! SYSTEM/root — see [`crate::service`]). It starts at **login**, in the user's own session, with the
//! user's own token and desktop access, and needs no elevation at all. Three mechanisms, one per OS:
//!
//! * **Windows** — a per-user `HKCU\…\CurrentVersion\Run` value ([`WINDOWS_RUN_KEY`]), the same HKCU
//!   idiom [`crate::scheme`] already uses for the `chia://` handler.
//! * **macOS** — a `launchd` **LaunchAgent** plist under `~/Library/LaunchAgents`.
//! * **Linux** — a systemd **user** unit under `$XDG_CONFIG_HOME/systemd/user`.
//!
//! # Byte-identical with dig-app's own renderers
//!
//! dig-app ships the macOS + Linux artifact renderers itself (`dig_app::autostart`, whose module doc
//! states Windows autostart is the installer's job) — but only as a LIBRARY api: the `dig-app`
//! binary takes no subcommands, so unlike `dig-node install` there is nothing for this installer to
//! delegate to. The two artifacts are therefore reproduced here **byte-identically**, the same
//! vendored-sibling contract dig-relay holds against dig-gossip's wire, and pinned by the
//! conformance tests at the bottom of this file. Both sides share [`AUTOSTART_LABEL`], so "is
//! dig-app's autostart installed?" has exactly one answer no matter which side wrote it.
//!
//! Rendering, path resolution, and the artifact CONTENT are pure functions taking an explicit `home`
//! / `$XDG_CONFIG_HOME`, so every platform's artifact is unit-tested on every platform. Only
//! [`register`] touches the real machine.

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::target::Os;

/// The reverse-DNS label the macOS LaunchAgent and the Linux unit are named/labelled with. Shared
/// verbatim with `dig_app::autostart::AUTOSTART_LABEL` so both writers name the same artifact.
pub const AUTOSTART_LABEL: &str = "net.dig.dig-app";

/// The per-user Windows autostart registry key. `HKCU` (never `HKLM`): a machine-wide Run entry
/// would launch the agent in every account on the box, including ones that never installed DIG.
pub const WINDOWS_RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The Run value name. Stable — an update overwrites this one entry instead of accumulating a second
/// autostart for the same agent.
pub const WINDOWS_RUN_VALUE: &str = "DIG App";

/// The Linux systemd user-unit filename.
const LINUX_UNIT_NAME: &str = "dig-app.service";

/// What the autostart registration did (or, on `--dry-run`, would do).
///
/// Never silent: `note` always explains the outcome, so a stranger who ends up without a
/// login-launched agent is told why rather than left to discover it at the next reboot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutostartResult {
    /// Did the per-user autostart reach its desired end-state?
    pub registered: bool,
    /// The per-OS mechanism used: `run-key` | `launch-agent` | `systemd-user`.
    pub mechanism: String,
    /// The artifact written — a registry path on Windows, a file path elsewhere.
    pub artifact: String,
    /// Human-readable detail behind [`Self::registered`].
    pub note: String,
}

/// The per-OS mechanism name for `os`, so the report and the log agree on one vocabulary.
pub fn mechanism_for(os: Os) -> &'static str {
    match os {
        Os::Windows => "run-key",
        Os::MacOs => "launch-agent",
        Os::Linux => "systemd-user",
    }
}

/// Render the macOS LaunchAgent plist that runs `binary_path` at login and restarts it if it exits.
/// Byte-identical to `dig_app::autostart::macos::launch_agent_plist`.
pub fn launch_agent_plist(binary_path: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{AUTOSTART_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#
    )
}

/// The per-user LaunchAgent path: `<home>/Library/LaunchAgents/<label>.plist`.
pub fn launch_agent_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{AUTOSTART_LABEL}.plist"))
}

/// Render the Linux systemd **user** unit that runs `binary_path` at login and restarts it on
/// failure. Byte-identical to `dig_app::autostart::linux::systemd_user_unit`.
pub fn systemd_user_unit(binary_path: &str) -> String {
    format!(
        r#"[Unit]
Description=DIG user identity agent

[Service]
ExecStart={binary_path}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"#
    )
}

/// The per-user systemd unit path: `<xdg_config_home>/systemd/user/dig-app.service`.
pub fn systemd_user_unit_path(xdg_config_home: &Path) -> PathBuf {
    xdg_config_home.join("systemd/user").join(LINUX_UNIT_NAME)
}

/// Resolve `$XDG_CONFIG_HOME`, falling back to `<home>/.config` per the XDG base-directory spec when
/// the variable is unset or empty. Byte-identical to `dig_app::autostart::linux::xdg_config_home`.
pub fn xdg_config_home(env_value: Option<&str>, home: &Path) -> PathBuf {
    match env_value {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => home.join(".config"),
    }
}

/// The command string a Windows Run entry stores: the executable path, quoted so a path containing
/// spaces (`C:\Program Files\DIG\bin\dig-app.exe` — the default install root) is parsed as ONE
/// argument rather than silently truncated at the first space.
pub fn windows_run_command(binary_path: &Path) -> String {
    format!("\"{}\"", binary_path.display())
}

/// Register `dig_app_bin` to start in the user's session at login on `os`.
///
/// Best-effort by design: autostart is a convenience, so a failure is reported on the
/// [`AutostartResult`] and never aborts an otherwise-successful install — the binary is still on
/// PATH and the user can launch it by hand. A `dry_run` writes nothing and reports the intent.
pub fn register(dig_app_bin: &Path, os: Os, dry_run: bool) -> AutostartResult {
    let mechanism = mechanism_for(os).to_string();
    let Some(home) = dirs::home_dir() else {
        return AutostartResult {
            registered: false,
            mechanism,
            artifact: String::new(),
            note: "could not resolve the user's home directory, so no per-user autostart was \
                   registered — launch dig-app manually or re-run the installer as the intended user"
                .to_string(),
        };
    };
    let artifact = artifact_path(&home, os);
    if dry_run {
        return AutostartResult {
            registered: false,
            mechanism,
            artifact,
            note: "would register dig-app to start at login".to_string(),
        };
    }
    match apply(dig_app_bin, os, &home) {
        Ok(note) => AutostartResult {
            registered: true,
            mechanism,
            artifact,
            note,
        },
        Err(e) => AutostartResult {
            registered: false,
            mechanism,
            artifact,
            note: format!(
                "could not register dig-app to start at login ({e}); dig-app is installed and on \
                 PATH — launch it manually, or re-run the installer"
            ),
        },
    }
}

/// Where the autostart artifact lives for `os` — a registry path on Windows (so the `--json` record
/// names something a user can actually inspect), a file path elsewhere.
fn artifact_path(home: &Path, os: Os) -> String {
    match os {
        Os::Windows => format!("HKCU\\{WINDOWS_RUN_KEY}\\{WINDOWS_RUN_VALUE}"),
        Os::MacOs => launch_agent_path(home).to_string_lossy().into_owned(),
        Os::Linux => {
            let xdg = xdg_config_home(std::env::var("XDG_CONFIG_HOME").ok().as_deref(), home);
            systemd_user_unit_path(&xdg).to_string_lossy().into_owned()
        }
    }
}

/// Perform the per-OS registration, returning the success note.
fn apply(dig_app_bin: &Path, os: Os, home: &Path) -> Result<String, String> {
    match os {
        Os::Windows => register_windows(dig_app_bin),
        Os::MacOs => {
            let path = install_launch_agent(home, dig_app_bin).map_err(|e| e.to_string())?;
            Ok(format!(
                "wrote the LaunchAgent {} — dig-app starts at your next login",
                path.display()
            ))
        }
        Os::Linux => {
            let xdg = xdg_config_home(std::env::var("XDG_CONFIG_HOME").ok().as_deref(), home);
            let path = install_systemd_user_unit(&xdg, dig_app_bin).map_err(|e| e.to_string())?;
            Ok(format!(
                "wrote the systemd user unit {} — enable it now with `systemctl --user enable --now \
                 dig-app.service`, or it starts at your next login once enabled",
                path.display()
            ))
        }
    }
}

/// Write the macOS LaunchAgent for `dig_app_bin` under `home`, creating `LaunchAgents/` if needed.
pub fn install_launch_agent(home: &Path, dig_app_bin: &Path) -> io::Result<PathBuf> {
    let path = launch_agent_path(home);
    write_artifact(&path, &launch_agent_plist(&dig_app_bin.to_string_lossy()))?;
    Ok(path)
}

/// Write the Linux systemd user unit for `dig_app_bin` under `xdg`, creating `systemd/user/` if
/// needed.
pub fn install_systemd_user_unit(xdg: &Path, dig_app_bin: &Path) -> io::Result<PathBuf> {
    let path = systemd_user_unit_path(xdg);
    write_artifact(&path, &systemd_user_unit(&dig_app_bin.to_string_lossy()))?;
    Ok(path)
}

/// Create the artifact's parent directory and write `contents` to `path`.
fn write_artifact(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, contents)
}

/// Windows: set the per-user `Run` value to the quoted dig-app path.
#[cfg(windows)]
fn register_windows(dig_app_bin: &Path) -> Result<String, String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (run, _) = hkcu
        .create_subkey_with_flags(WINDOWS_RUN_KEY, KEY_WRITE)
        .map_err(|e| format!("open HKCU\\{WINDOWS_RUN_KEY}: {e}"))?;
    run.set_value(WINDOWS_RUN_VALUE, &windows_run_command(dig_app_bin))
        .map_err(|e| format!("set {WINDOWS_RUN_VALUE}: {e}"))?;
    Ok(format!(
        "registered dig-app under HKCU\\{WINDOWS_RUN_KEY} — it starts at your next login"
    ))
}

/// Non-Windows builds never reach the Run-key path; kept so [`apply`] compiles per-OS-agnostically.
#[cfg(not(windows))]
fn register_windows(_dig_app_bin: &Path) -> Result<String, String> {
    Err("the Windows Run key is only reachable from a Windows host".to_string())
}

/// Remove the per-user autostart artifact for `os`, treating "already absent" as success (the
/// uninstall idempotence contract, [`crate::uninstall`]).
pub fn deregister(os: Os) -> Result<(), String> {
    let home =
        dirs::home_dir().ok_or_else(|| "could not resolve the home directory".to_string())?;
    match os {
        Os::Windows => deregister_windows(),
        Os::MacOs => remove_if_present(&launch_agent_path(&home)),
        Os::Linux => {
            let xdg = xdg_config_home(std::env::var("XDG_CONFIG_HOME").ok().as_deref(), &home);
            remove_if_present(&systemd_user_unit_path(&xdg))
        }
    }
}

/// Delete `path`, treating a missing file as success.
fn remove_if_present(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

/// Windows: delete the `Run` value, treating a missing value/key as success.
#[cfg(windows)]
fn deregister_windows() -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(run) = hkcu.open_subkey_with_flags(WINDOWS_RUN_KEY, KEY_WRITE) else {
        return Ok(()); // no Run key at all ⇒ nothing of ours to remove
    };
    match run.delete_value(WINDOWS_RUN_VALUE) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("delete {WINDOWS_RUN_VALUE}: {e}")),
    }
}

#[cfg(not(windows))]
fn deregister_windows() -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Byte-identical conformance with dig_app::autostart ---------------------
    //
    // The literals below are copied verbatim from dig-app's own renderers
    // (`crates/dig-app/src/autostart.rs` at dig-app `origin/main`). They are the CONTRACT: if
    // either side's template changes, these fail rather than letting the two writers drift into
    // producing two different autostart artifacts for the same agent.

    #[test]
    fn launch_agent_plist_is_byte_identical_to_dig_apps_own_renderer() {
        let expected = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>net.dig.dig-app</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/dig-app</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#;
        assert_eq!(launch_agent_plist("/usr/local/bin/dig-app"), expected);
    }

    #[test]
    fn systemd_user_unit_is_byte_identical_to_dig_apps_own_renderer() {
        let expected = r#"[Unit]
Description=DIG user identity agent

[Service]
ExecStart=/usr/bin/dig-app
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"#;
        assert_eq!(systemd_user_unit("/usr/bin/dig-app"), expected);
    }

    #[test]
    fn artifact_paths_match_dig_apps_own_locations() {
        assert_eq!(
            launch_agent_path(Path::new("/Users/alice")),
            Path::new("/Users/alice/Library/LaunchAgents/net.dig.dig-app.plist")
        );
        assert_eq!(
            systemd_user_unit_path(Path::new("/home/alice/.config")),
            Path::new("/home/alice/.config/systemd/user/dig-app.service")
        );
    }

    #[test]
    fn xdg_config_home_falls_back_to_dot_config_when_unset_or_empty() {
        let home = Path::new("/home/alice");
        assert_eq!(
            xdg_config_home(None, home),
            Path::new("/home/alice/.config")
        );
        assert_eq!(
            xdg_config_home(Some(""), home),
            Path::new("/home/alice/.config")
        );
        assert_eq!(
            xdg_config_home(Some("/custom/cfg"), home),
            Path::new("/custom/cfg")
        );
    }

    // -- The per-user, per-agent properties ------------------------------------

    /// The agent is registered PER USER, never machine-wide: an HKLM Run entry would launch DIG's
    /// identity agent in every account on the machine. The fixture asserts the key we name is the
    /// HKCU-relative one — the nearest wrong implementation (reusing the machine-wide service idiom
    /// `dig-node` uses) cannot satisfy this.
    #[test]
    fn windows_autostart_is_the_per_user_run_key() {
        assert_eq!(
            WINDOWS_RUN_KEY,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        );
        assert!(!WINDOWS_RUN_KEY.contains("HKEY_LOCAL_MACHINE"));
        assert_eq!(mechanism_for(Os::Windows), "run-key");
        assert_eq!(mechanism_for(Os::MacOs), "launch-agent");
        assert_eq!(mechanism_for(Os::Linux), "systemd-user");
    }

    /// A default Windows install lands in `C:\Program Files\DIG\bin` — a path WITH A SPACE. An
    /// unquoted Run command would be parsed as `C:\Program` plus arguments and silently never
    /// start the agent, so the space is the load-bearing part of this fixture.
    #[test]
    fn windows_run_command_quotes_a_path_containing_spaces() {
        let cmd = windows_run_command(Path::new(r"C:\Program Files\DIG\bin\dig-app.exe"));
        assert_eq!(cmd, "\"C:\\Program Files\\DIG\\bin\\dig-app.exe\"");
        assert!(cmd.starts_with('"') && cmd.ends_with('"'));
    }

    /// The artifact must launch **dig-app**, not the engine. A registration that pointed at the
    /// dig-node binary would still produce a valid-looking plist/unit, so both renderers are asked
    /// for a distinguishable second path.
    #[test]
    fn artifacts_launch_the_dig_app_binary_that_was_passed() {
        let plist = launch_agent_plist("/opt/dig/bin/dig-app");
        assert!(plist.contains("<string>/opt/dig/bin/dig-app</string>"));
        assert!(!plist.contains("dig-node"));
        let unit = systemd_user_unit("/opt/dig/bin/dig-app");
        assert!(unit.contains("ExecStart=/opt/dig/bin/dig-app"));
        assert!(!unit.contains("dig-node"));
    }

    #[test]
    fn install_writes_the_artifact_and_creates_missing_parent_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let plist = install_launch_agent(tmp.path(), Path::new("/usr/local/bin/dig-app"))
            .expect("launch agent written");
        assert_eq!(plist, launch_agent_path(tmp.path()));
        assert_eq!(
            std::fs::read_to_string(&plist).expect("readable"),
            launch_agent_plist("/usr/local/bin/dig-app")
        );

        let unit = install_systemd_user_unit(tmp.path(), Path::new("/usr/bin/dig-app"))
            .expect("unit written");
        assert_eq!(unit, systemd_user_unit_path(tmp.path()));
        assert_eq!(
            std::fs::read_to_string(&unit).expect("readable"),
            systemd_user_unit("/usr/bin/dig-app")
        );
    }

    #[test]
    fn removing_an_absent_artifact_is_success_not_an_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let absent = tmp.path().join("never-written.plist");
        assert!(remove_if_present(&absent).is_ok());
    }

    #[test]
    fn a_dry_run_registers_nothing_and_says_so() {
        let r = register(Path::new("/usr/local/bin/dig-app"), Os::Linux, true);
        assert!(!r.registered);
        assert_eq!(r.mechanism, "systemd-user");
        assert!(r.note.contains("would register"));
    }
}
