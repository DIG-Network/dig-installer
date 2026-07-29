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
    /// The artifact path this mechanism uses — a registry path on Windows, a file path elsewhere.
    ///
    /// Where the artifact GOES, which is not the same as where one was written: it is populated on the
    /// dry-run and failure arms too, so it must be read together with [`Self::registered`]. Named for the
    /// path rather than the act deliberately — a field that claimed a write on a run that made none would
    /// be the planned-vs-effective defect #1748 fixed twice elsewhere in this report.
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

/// Register `dig_app_bin` to start at login, in the session of the [target
/// user](crate::invoker::target_user) — the account that INVOKED the installer, which under `sudo` is
/// NOT the account this process is running as (#1748).
///
/// Best-effort by design: autostart is a convenience, so a failure is reported on the
/// [`AutostartResult`] and never aborts an otherwise-successful install — the binary is still on
/// PATH and the user can launch it by hand. A `dry_run` writes nothing and reports the intent.
///
/// This used to resolve `dirs::home_dir()`, which `sudo` sets to `/root`, so a "per-user" autostart
/// was written to `/root/.config/systemd/user/dig-app.service`: a unit in root's systemd user scope,
/// where the real user cannot see it and root has no session bus to start it. The printed advice
/// (`systemctl --user enable --now dig-app.service`) then failed for both accounts — for the user
/// because no such unit existed, for root because there was no bus.
pub fn register(dig_app_bin: &Path, os: Os, dry_run: bool) -> AutostartResult {
    let user = crate::invoker::target_user();
    register_for(
        dig_app_bin,
        os,
        dry_run,
        user,
        user.acting_for_another_account(crate::invoker::is_root()),
    )
}

/// [`register`] against an explicit target user AND an explicit boundary decision, so the elevated and
/// unelevated paths are both testable.
///
/// `acting_for_another_account` is passed in rather than derived from the ambient uid
/// ([`crate::invoker::TargetUser::acting_for_another_account`]) because a test that reads the real uid
/// can only exercise the arm the runner is in — the mistake that let a defective predicate stay green
/// (#1748).
pub fn register_for(
    dig_app_bin: &Path,
    os: Os,
    dry_run: bool,
    user: &crate::invoker::TargetUser,
    acting_for_another_account: bool,
) -> AutostartResult {
    let mechanism = mechanism_for(os).to_string();
    let artifact = artifact_path(user, os, acting_for_another_account);
    if dry_run {
        return AutostartResult {
            registered: false,
            mechanism,
            artifact,
            note: format!("would register dig-app to start at {}'s login", user.name),
        };
    }
    match apply(dig_app_bin, os, user) {
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

/// `$XDG_CONFIG_HOME` for the TARGET user.
///
/// The environment variable is only consulted when we are running AS that user. Under elevation it
/// describes root (`sudo` may carry root's own `XDG_CONFIG_HOME`, and `su` sets one), so honouring it
/// would put the unit back in root's scope — the #1748 inversion in a second guise. The XDG spec's
/// own default, `<home>/.config`, is the correct answer for another account.
fn target_xdg_config_home(user: &crate::invoker::TargetUser) -> PathBuf {
    // `is_root()`, not the hint: the macOS GUI's root child carries no hint, and honouring root's own
    // `XDG_CONFIG_HOME` there is the #1748 inversion again.
    target_xdg_config_home_when(
        user,
        user.acting_for_another_account(crate::invoker::is_root()),
    )
}

/// [`target_xdg_config_home`] with the boundary decision supplied rather than read from the ambient uid.
///
/// Split out for the same reason the decision itself takes a parameter: a test that depends on the
/// runner's real uid can only ever exercise one arm, and the arm CI reaches is the one the defective
/// predicate also satisfies (#1748).
fn target_xdg_config_home_when(
    user: &crate::invoker::TargetUser,
    acting_for_another_account: bool,
) -> PathBuf {
    let env = if acting_for_another_account {
        None
    } else {
        std::env::var("XDG_CONFIG_HOME").ok()
    };
    xdg_config_home(env.as_deref(), &user.home)
}

/// Where the autostart artifact lives for `os` — a registry path on Windows (so the `--json` record
/// names something a user can actually inspect), a file path elsewhere.
fn artifact_path(
    user: &crate::invoker::TargetUser,
    os: Os,
    acting_for_another_account: bool,
) -> String {
    match os {
        Os::Windows => format!("HKCU\\{WINDOWS_RUN_KEY}\\{WINDOWS_RUN_VALUE}"),
        Os::MacOs => launch_agent_path(&user.home).to_string_lossy().into_owned(),
        Os::Linux => systemd_user_unit_path(&target_xdg_config_home_when(
            user,
            acting_for_another_account,
        ))
        .to_string_lossy()
        .into_owned(),
    }
}

/// Perform the per-OS registration, returning the success note.
///
/// On unix the artifact is written BY the target user ([`crate::userwrite`]), so it is theirs to manage
/// and `systemd --user` will load it — and so a privileged install never follows a symlink planted in
/// the user-writable directories it has to write into (#1748).
fn apply(dig_app_bin: &Path, os: Os, user: &crate::invoker::TargetUser) -> Result<String, String> {
    match os {
        Os::Windows => register_windows(dig_app_bin),
        Os::MacOs => {
            let path = install_launch_agent(&user.home, dig_app_bin, user)?;
            Ok(format!(
                "wrote the LaunchAgent {} — dig-app starts at {}'s next login",
                path.display(),
                user.name
            ))
        }
        Os::Linux => {
            let xdg = target_xdg_config_home(user);
            let path = install_systemd_user_unit(&xdg, dig_app_bin, user)?;
            Ok(format!(
                "wrote the systemd user unit {} — it starts at {}'s next login, or start it now \
                 with: {}",
                path.display(),
                user.name,
                enable_command(user)
            ))
        }
    }
}

/// The command that enables the unit, in a scope where the unit actually EXISTS.
///
/// A root install must not print `systemctl --user enable --now dig-app.service` verbatim: run by
/// root it fails (`Failed to connect to bus` — root has no session bus during a `curl | sudo sh`), and
/// the account that CAN run it is the target user, who has to get into their own session first. So
/// under elevation the printed command names that user explicitly, via `machinectl shell`'s
/// non-privileged stand-in `sudo -u <user> XDG_RUNTIME_DIR=/run/user/<uid> systemctl --user`, which
/// works from the same root shell the installer was launched from.
fn enable_command(user: &crate::invoker::TargetUser) -> String {
    enable_command_when(
        user,
        user.acting_for_another_account(crate::invoker::is_root()),
    )
}

/// [`enable_command`] with the boundary decision supplied rather than read from the ambient uid — see
/// [`target_xdg_config_home_when`] for why.
fn enable_command_when(
    user: &crate::invoker::TargetUser,
    acting_for_another_account: bool,
) -> String {
    const ENABLE: &str = "systemctl --user enable --now dig-app.service";
    match (acting_for_another_account, user.uid) {
        (true, Some(uid)) => format!(
            "sudo -u {} XDG_RUNTIME_DIR=/run/user/{uid} {ENABLE}",
            user.name
        ),
        // Without a uid we cannot name a runtime dir, so tell the user what to do from their own
        // shell rather than printing a command that will fail from this one.
        (true, None) => format!("log in as {} and run: {ENABLE}", user.name),
        (false, _) => ENABLE.to_string(),
    }
}

/// Write the macOS LaunchAgent for `dig_app_bin` under `home`, creating `LaunchAgents/` if needed.
///
/// Written with `user`'s own authority, never root's — see [`crate::userwrite`].
pub fn install_launch_agent(
    home: &Path,
    dig_app_bin: &Path,
    user: &crate::invoker::TargetUser,
) -> Result<PathBuf, String> {
    let path = launch_agent_path(home);
    crate::userwrite::write_as_user(
        &path,
        &launch_agent_plist(&dig_app_bin.to_string_lossy()),
        user,
    )?;
    Ok(path)
}

/// Write the Linux systemd user unit for `dig_app_bin` under `xdg`, creating `systemd/user/` if
/// needed.
///
/// Written with `user`'s own authority, never root's — see [`crate::userwrite`].
pub fn install_systemd_user_unit(
    xdg: &Path,
    dig_app_bin: &Path,
    user: &crate::invoker::TargetUser,
) -> Result<PathBuf, String> {
    let path = systemd_user_unit_path(xdg);
    crate::userwrite::write_as_user(
        &path,
        &systemd_user_unit(&dig_app_bin.to_string_lossy()),
        user,
    )?;
    Ok(path)
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
    // The same target user the install registered for (#1748) — an uninstall run under `sudo` must
    // remove the artifact from the USER's scope, not look for it in root's and declare success.
    let user = crate::invoker::target_user();
    match os {
        Os::Windows => deregister_windows(),
        Os::MacOs => remove_if_present(&launch_agent_path(&user.home)),
        Os::Linux => remove_if_present(&systemd_user_unit_path(&target_xdg_config_home(user))),
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
        // Unelevated: we ARE the user, so the write is direct — the elevated path delegates to the
        // user's own shell instead (`crate::userwrite`), which is what closes the #1748 symlink LPE.
        let me = unelevated_alice();
        let plist = install_launch_agent(tmp.path(), Path::new("/usr/local/bin/dig-app"), &me)
            .expect("launch agent written");
        assert_eq!(plist, launch_agent_path(tmp.path()));
        assert_eq!(
            std::fs::read_to_string(&plist).expect("readable"),
            launch_agent_plist("/usr/local/bin/dig-app")
        );

        let unit = install_systemd_user_unit(tmp.path(), Path::new("/usr/bin/dig-app"), &me)
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

    // -- #1748: a sudo install registers autostart for the INVOKING user --------

    /// The account running the installer itself — no elevation, so no privilege boundary to cross.
    fn unelevated_alice() -> crate::invoker::TargetUser {
        crate::invoker::TargetUser {
            name: "alice".to_string(),
            home: PathBuf::from("/home/alice"),
            uid: None,
            gid: None,
            via_elevation: false,
        }
    }

    /// The account `sudo` was invoked from, described exactly as the installer sees it.
    fn sudoing_ubuntu() -> crate::invoker::TargetUser {
        crate::invoker::TargetUser {
            name: "ubuntu".to_string(),
            home: PathBuf::from("/home/ubuntu"),
            uid: Some(1000),
            gid: Some(1000),
            via_elevation: true,
        }
    }

    /// THE regression: the "per-user" artifact must be written into the INVOKING user's scope, not
    /// root's.
    ///
    /// The fixture is a dry run, which reports the artifact path it WOULD write without touching the
    /// machine — so the assertion is on the path choice itself, which is the defect. A truthful
    /// control follows in `an_unelevated_run_registers_in_its_own_scope`: the same code with
    /// `via_elevation: false` and a different home must produce that home's path, so this test cannot
    /// pass by hardcoding `/home/ubuntu`.
    #[test]
    fn a_sudo_install_writes_the_unit_into_the_invoking_users_scope_not_roots() {
        let r = register_for(
            Path::new("/opt/dig/bin/dig-app"),
            Os::Linux,
            true,
            &sudoing_ubuntu(),
            // Root, acting for ubuntu — stated explicitly so the elevated arm is exercised on an
            // unprivileged CI runner.
            true,
        );
        // Compared as paths, not strings: `join` uses the HOST separator, so a literal
        // forward-slash expectation would fail on a Windows CI runner for a reason that has
        // nothing to do with the property under test.
        assert_eq!(
            Path::new(&r.artifact),
            systemd_user_unit_path(Path::new("/home/ubuntu/.config"))
        );
        assert!(
            !r.artifact.contains("root"),
            "the shipped bug wrote /root/.config/systemd/user/dig-app.service: {}",
            r.artifact
        );
    }

    /// The control for the test above: the same code path with `via_elevation: false` must land under
    /// the TARGET user's home, so the elevated fixture cannot be satisfied by an implementation that
    /// hardcodes `/home/ubuntu` or simply ignores elevation.
    ///
    /// An unelevated run deliberately honours `$XDG_CONFIG_HOME` (SPEC §4.2 — when we ARE the user,
    /// their override is authoritative), so the fixture must remove it to observe the home-derived
    /// default. Without that, the ambient value a CI runner exports (`/home/runner/.config`) is
    /// returned and the assertion fails for a reason unrelated to the property. `nextest` runs each
    /// test in its own process, so mutating the variable cannot leak into a sibling test.
    #[test]
    fn an_unelevated_run_registers_in_its_own_scope() {
        std::env::remove_var("XDG_CONFIG_HOME");

        let alice = crate::invoker::TargetUser {
            name: "alice".to_string(),
            home: PathBuf::from("/home/alice"),
            uid: None,
            gid: None,
            via_elevation: false,
        };
        let r = register_for(
            Path::new("/opt/dig/bin/dig-app"),
            Os::Linux,
            true,
            &alice,
            false,
        );
        assert_eq!(
            Path::new(&r.artifact),
            systemd_user_unit_path(Path::new("/home/alice/.config")),
            "an unelevated run must register under its own home, not the ambient process home"
        );
    }

    /// macOS has the same inversion: the LaunchAgent belongs in the invoking user's `~/Library`.
    #[test]
    fn a_sudo_install_writes_the_launch_agent_into_the_invoking_users_library() {
        let r = register_for(
            Path::new("/opt/dig/bin/dig-app"),
            Os::MacOs,
            true,
            &sudoing_ubuntu(),
            true,
        );
        assert_eq!(
            Path::new(&r.artifact),
            launch_agent_path(Path::new("/home/ubuntu"))
        );
        assert!(!r.artifact.contains("root"));
    }

    /// Under elevation, `$XDG_CONFIG_HOME` describes ROOT (sudo/su set one), so honouring it would put
    /// the unit back in root's scope — the same inversion wearing a different hat.
    ///
    /// The fixture sets the variable to an unmistakable value and asserts it is IGNORED for an
    /// elevated target while being HONOURED for an unelevated one. Asserting only the elevated half
    /// would also pass against an implementation that ignored the variable entirely, which would be a
    /// different bug, so both halves are checked.
    #[test]
    fn xdg_config_home_is_ignored_under_elevation_and_honoured_otherwise() {
        // A value only root could have.
        std::env::set_var("XDG_CONFIG_HOME", "/root/.config");

        let elevated = target_xdg_config_home_when(&sudoing_ubuntu(), true);
        assert_eq!(
            elevated,
            Path::new("/home/ubuntu/.config"),
            "an elevated run must use the XDG default under the TARGET user's home"
        );

        let self_run = crate::invoker::TargetUser {
            name: "root".to_string(),
            home: PathBuf::from("/root"),
            uid: None,
            gid: None,
            via_elevation: false,
        };
        assert_eq!(
            target_xdg_config_home_when(&self_run, false),
            Path::new("/root/.config"),
            "when we ARE the user, their XDG_CONFIG_HOME is authoritative"
        );

        std::env::remove_var("XDG_CONFIG_HOME");
    }

    /// The printed remediation must be runnable in a scope where the unit exists.
    ///
    /// The shipped advice was a bare `systemctl --user enable --now dig-app.service`, which fails for
    /// root (no session bus during `curl | sudo sh`) and for the user (no such unit, because it was
    /// written to root's scope). Under elevation the command must therefore NAME the target user and
    /// their runtime dir.
    #[test]
    fn the_enable_command_names_the_target_user_under_elevation() {
        let cmd = enable_command_when(&sudoing_ubuntu(), true);
        assert!(cmd.contains("-u ubuntu"), "got: {cmd}");
        assert!(
            cmd.contains("XDG_RUNTIME_DIR=/run/user/1000"),
            "systemctl --user needs the target user's runtime dir: {cmd}"
        );
        assert!(cmd.contains("systemctl --user enable --now dig-app.service"));
    }

    /// Run as the user themselves, the plain command IS correct — so the elevated decoration must not
    /// leak into the unelevated case.
    #[test]
    fn the_enable_command_is_plain_when_we_are_the_user() {
        let alice = crate::invoker::TargetUser {
            name: "alice".to_string(),
            home: PathBuf::from("/home/alice"),
            uid: None,
            gid: None,
            via_elevation: false,
        };
        assert_eq!(
            enable_command_when(&alice, false),
            "systemctl --user enable --now dig-app.service"
        );
    }

    /// Elevated but with no resolvable uid: we cannot name a runtime dir, so the advice must tell the
    /// user what to do from their own shell rather than print a command that will fail from this one.
    #[test]
    fn without_a_uid_the_advice_does_not_print_a_command_that_cannot_work() {
        let ghost = crate::invoker::TargetUser {
            name: "ghost".to_string(),
            home: PathBuf::from("/root"),
            uid: None,
            gid: None,
            via_elevation: true,
        };
        let cmd = enable_command_when(&ghost, true);
        assert!(cmd.contains("log in as ghost"), "got: {cmd}");
        assert!(
            !cmd.contains("XDG_RUNTIME_DIR"),
            "no uid means no runtime dir to name: {cmd}"
        );
    }
}
