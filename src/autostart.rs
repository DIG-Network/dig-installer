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
//! * **Linux** — an XDG **autostart desktop entry** under `$XDG_CONFIG_HOME/autostart`.
//!
//! # Why Linux is an XDG desktop entry and NOT a systemd user unit (dig_ecosystem#919)
//!
//! This wrote a systemd **user** unit and then never enabled or started it: a unit file in
//! `~/.config/systemd/user` that is not linked into `default.target.wants` is inert, so Linux
//! autostart had never once worked. The installer could not fix that itself either — `systemctl
//! --user enable` needs the TARGET user's session bus, which a `sudo` install does not have (root
//! has no `--user` bus at all), so the code merely PRINTED a command a human had to run. An install
//! step whose success depends on the user reading a log line is not an install step.
//!
//! An XDG `autostart` desktop entry has neither problem: every desktop session reads
//! `$XDG_CONFIG_HOME/autostart/*.desktop` at login with no `enable`, no session bus and no
//! privilege. The stale systemd unit is REMOVED on upgrade — leaving it behind means a user who ever
//! ran `systemctl --user enable dig-app.service` gets two agents at login.
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

/// The Linux systemd user-unit filename. Retained for REMOVAL only: nothing writes this any more
/// (dig_ecosystem#919), but an upgrade must delete what earlier versions wrote.
const LINUX_UNIT_NAME: &str = "dig-app.service";

/// The Linux XDG autostart desktop-entry filename.
const LINUX_DESKTOP_NAME: &str = "dig-app.desktop";

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
    /// WHY this run did (or did not) register — the machine-readable half of `note`
    /// (dig_ecosystem#919). `SkipHeadless`/`SkipNoTargetUser` mean nothing was written ON PURPOSE,
    /// which a bare `registered: false` could not distinguish from a failure.
    pub disposition: crate::svcscope::AgentDisposition,
}

/// The per-OS mechanism name for `os`, so the report and the log agree on one vocabulary.
pub fn mechanism_for(os: Os) -> &'static str {
    match os {
        Os::Windows => "run-key",
        Os::MacOs => "launch-agent",
        Os::Linux => "xdg-autostart",
    }
}

/// The observable session facts the headless verdict is derived from — gathered by
/// [`SessionFacts::probe`], judged by the pure [`is_headless`].
///
/// Split so the verdict is asserted for all three operating systems from any host: a
/// `#[cfg(unix)]`-only test cannot falsify the Windows arm, and the mutation stays green
/// (dig_ecosystem#1774).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionFacts {
    /// A graphical display is named in the environment (`DISPLAY` / `WAYLAND_DISPLAY`, or
    /// `XDG_SESSION_TYPE` naming x11/wayland). Linux/BSD concept.
    pub display_env: bool,
    /// This host has desktop sessions INSTALLED at all (`/usr/share/xsessions` or
    /// `/usr/share/wayland-sessions` is non-empty) — i.e. somebody could log into a desktop here even
    /// if nobody is right now. A server image has neither directory.
    pub desktop_sessions_installed: bool,
    /// macOS: the Aqua session infrastructure is present (`loginwindow` exists).
    pub aqua_session: bool,
    /// Windows: this process holds an INTERACTIVE window station (`SESSIONNAME` is set — `Console`
    /// or `RDP-Tcp#n`). A service/Session-0 context has none.
    pub interactive_window_station: bool,
}

impl SessionFacts {
    /// Read the facts from this host.
    ///
    /// Deliberately cheap and side-effect-free — no spawn, no `loginctl`: this decides whether to
    /// write one small file, and it runs on every install.
    pub fn probe() -> Self {
        let graphical_session_type = std::env::var("XDG_SESSION_TYPE")
            .map(|t| t == "x11" || t == "wayland")
            .unwrap_or(false);
        let display_env = std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some()
            || graphical_session_type;
        SessionFacts {
            display_env,
            desktop_sessions_installed: ["/usr/share/xsessions", "/usr/share/wayland-sessions"]
                .iter()
                .any(|d| dir_has_entries(Path::new(d))),
            aqua_session: Path::new("/System/Library/CoreServices/loginwindow.app").exists(),
            interactive_window_station: std::env::var("SESSIONNAME")
                .map(|s| !s.is_empty())
                .unwrap_or(false),
        }
    }
}

/// Does `dir` exist and contain at least one entry? An EMPTY `xsessions` directory proves nothing,
/// and some minimal images ship the directory without a session in it.
fn dir_has_entries(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// Is this host HEADLESS — no graphical session for a tray agent to appear in?
///
/// # This verdict errs toward REGISTERING, deliberately
///
/// The two mistakes are not symmetric. Wrongly deciding "headless" denies a desktop user the agent
/// they installed, silently, until they notice; wrongly deciding "graphical" leaves one inert
/// `.desktop` file that no session ever reads. So `true` is returned only on positive evidence:
///
/// * **Linux** — no display in the environment AND no desktop session installed on the box at all. A
///   `sudo` install whose `DISPLAY` was not forwarded still has `/usr/share/xsessions`, so a
///   workstation is never mistaken for a server.
/// * **macOS** — the Aqua session infrastructure is absent, which in practice means a stripped CI
///   image rather than a Mac somebody uses.
/// * **Windows** — this process has no interactive window station, i.e. it is running in a
///   service/Session-0 context where an `HKCU\…\Run` value would belong to nobody who logs in.
pub fn is_headless(os: Os, facts: &SessionFacts) -> bool {
    match os {
        Os::Linux => !facts.display_env && !facts.desktop_sessions_installed,
        Os::MacOs => !facts.aqua_session,
        Os::Windows => !facts.interactive_window_station,
    }
}

/// Render the macOS LaunchAgent plist that runs `binary_path` at login/// Render the macOS LaunchAgent plist that runs `binary_path` at login and restarts it if it exits.
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

/// Render the XDG autostart desktop entry that launches `binary_path` at login.
///
/// `X-GNOME-Autostart-enabled=true` and `Hidden=false` are stated explicitly rather than left to
/// each desktop's default, so an entry a previous version disabled is re-enabled by being rewritten.
/// The spec's `Type=Application` + `Exec=` pair is all a session needs — there is nothing to enable.
pub fn autostart_desktop_entry(binary_path: &str) -> String {
    format!(
        "[Desktop Entry]
Type=Application
Name=DIG App
Comment=DIG user identity agent
Exec={binary_path}
Terminal=false
X-GNOME-Autostart-enabled=true
Hidden=false
"
    )
}

/// The XDG autostart entry path: `<xdg_config_home>/autostart/dig-app.desktop`.
pub fn autostart_desktop_path(xdg_config_home: &Path) -> PathBuf {
    xdg_config_home.join("autostart").join(LINUX_DESKTOP_NAME)
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
        is_headless(os, &SessionFacts::probe()),
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
    headless: bool,
) -> AutostartResult {
    use crate::svcscope::AgentDisposition;

    let mechanism = mechanism_for(os).to_string();
    let artifact = artifact_path(user, os, acting_for_another_account);
    // The target user is KNOWN unless we are acting for another account and could not name it — the
    // macOS `osascript` root child, whose environment carries no hint (SPEC §1.5a).
    let target_user_known = !acting_for_another_account || user.uid.is_some();
    let disposition = crate::svcscope::agent_disposition(os, headless, target_user_known);
    let result = |registered: bool, note: String| AutostartResult {
        registered,
        mechanism: mechanism.clone(),
        artifact: artifact.clone(),
        note,
        disposition,
    };

    match disposition {
        // Nothing is written, and nothing is enabled — in particular NOT `loginctl enable-linger`,
        // which would run a tray agent forever on a server nobody is looking at.
        AgentDisposition::SkipHeadless => {
            return result(
                false,
                "skipped the dig-app login autostart: this host has no graphical session for a \
                 tray agent to appear in. dig-app is installed and on PATH; the DIG node/service \
                 side is unaffected"
                    .to_string(),
            );
        }
        // LOUD, not silent: registering into root's own scope is the #1748 inversion, and an
        // uninstall that then "cleaned" root's scope would leave the real user's autostart behind.
        AgentDisposition::SkipNoTargetUser => {
            return result(
                false,
                "skipped the dig-app login autostart: this run is elevated and could not determine \
                 which account it is acting for, so there is no user scope to register in. Re-run \
                 `dig-installer` as that user (unelevated) to add it"
                    .to_string(),
            );
        }
        AgentDisposition::Register => {}
    }

    if dry_run {
        return result(
            false,
            format!("would register dig-app to start at {}'s login", user.name),
        );
    }
    match apply(dig_app_bin, os, user, acting_for_another_account) {
        Ok(note) => result(true, note),
        Err(e) => result(
            false,
            format!(
                "could not register dig-app to start at login ({e}); dig-app is installed and on \
                 PATH — launch it manually, or re-run the installer"
            ),
        ),
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
        Os::Linux => autostart_desktop_path(&target_xdg_config_home_when(
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
fn apply(
    dig_app_bin: &Path,
    os: Os,
    user: &crate::invoker::TargetUser,
    acting_for_another_account: bool,
) -> Result<String, String> {
    match os {
        Os::Windows => register_windows(dig_app_bin),
        Os::MacOs => {
            let path =
                install_launch_agent(&user.home, dig_app_bin, user, acting_for_another_account)?;
            Ok(format!(
                "wrote the LaunchAgent {} — dig-app starts at {}'s next login",
                path.display(),
                user.name
            ))
        }
        Os::Linux => apply_linux(
            &target_xdg_config_home(user),
            dig_app_bin,
            user,
            acting_for_another_account,
        ),
    }
}

/// The Linux arm of [`apply`], against an EXPLICIT `$XDG_CONFIG_HOME`.
///
/// Split out so the write + the stale-unit removal are asserted against a temp directory rather than
/// whatever `$XDG_CONFIG_HOME` the test runner happens to export — an ambient-env dependency is how a
/// test comes to pass for a reason unrelated to its property.
fn apply_linux(
    xdg: &Path,
    dig_app_bin: &Path,
    user: &crate::invoker::TargetUser,
    acting_for_another_account: bool,
) -> Result<String, String> {
    let path = install_autostart_entry(xdg, dig_app_bin, user, acting_for_another_account)?;
    // Best-effort: a stale unit that cannot be removed is reported, never fatal — the desktop entry
    // this run wrote is what actually starts the agent.
    let stale = remove_stale_systemd_user_unit(xdg);
    Ok(format!(
        "wrote the XDG autostart entry {} — dig-app starts at {}'s next login, with no further          step{stale}",
        path.display(),
        user.name,
    ))
}

/// Remove the systemd **user** unit earlier versions wrote, returning a phrase for the success note
/// (empty when there was nothing to remove).
///
/// Not optional cleanup: the unit and the desktop entry are two independent autostart mechanisms for
/// the same agent, so a user who ever ran `systemctl --user enable dig-app.service` would get TWO
/// dig-app processes at their next login. Removing the file is enough — an enabled unit's
/// `default.target.wants` symlink is dangling once its target is gone, and systemd skips it.
fn remove_stale_systemd_user_unit(xdg: &Path) -> String {
    let unit = systemd_user_unit_path(xdg);
    if !unit.exists() {
        return String::new();
    }
    match std::fs::remove_file(&unit) {
        Ok(()) => format!(
            " (also removed the stale systemd user unit {}, which never actually autostarted)",
            unit.display()
        ),
        Err(e) => format!(
            " (could NOT remove the stale systemd user unit {} ({e}); if you ever ran `systemctl \
             --user enable dig-app.service`, remove it by hand or dig-app may start twice)",
            unit.display()
        ),
    }
}

/// Write the macOS LaunchAgent for `dig_app_bin` under `home`, creating `LaunchAgents/` if needed.
///
/// Written with `user`'s own authority, never root's — see [`crate::userwrite`].
pub fn install_launch_agent(
    home: &Path,
    dig_app_bin: &Path,
    user: &crate::invoker::TargetUser,
    acting_for_another_account: bool,
) -> Result<PathBuf, String> {
    let path = launch_agent_path(home);
    crate::userwrite::write_as_user_when(
        &path,
        &launch_agent_plist(&dig_app_bin.to_string_lossy()),
        user,
        acting_for_another_account,
    )?;
    Ok(path)
}

/// Write the Linux XDG autostart entry for `dig_app_bin` under `xdg`, creating `autostart/` if
/// needed.
///
/// Written with `user`'s own authority, never root's — see [`crate::userwrite`].
pub fn install_autostart_entry(
    xdg: &Path,
    dig_app_bin: &Path,
    user: &crate::invoker::TargetUser,
    acting_for_another_account: bool,
) -> Result<PathBuf, String> {
    let path = autostart_desktop_path(xdg);
    crate::userwrite::write_as_user_when(
        &path,
        &autostart_desktop_entry(&dig_app_bin.to_string_lossy()),
        user,
        acting_for_another_account,
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
        // BOTH mechanisms: an uninstall that removed only the current one would leave a host that
        // was installed by an older version still starting dig-app at every login.
        Os::Linux => {
            let xdg = target_xdg_config_home(user);
            remove_if_present(&autostart_desktop_path(&xdg))
                .and(remove_if_present(&systemd_user_unit_path(&xdg)))
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
        assert_eq!(mechanism_for(Os::Linux), "xdg-autostart");
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
        let entry = autostart_desktop_entry("/opt/dig/bin/dig-app");
        assert!(entry.contains("Exec=/opt/dig/bin/dig-app"));
        assert!(!entry.contains("dig-node"));
    }

    #[test]
    fn install_writes_the_artifact_and_creates_missing_parent_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Unelevated: we ARE the user, so the write is direct — the elevated path delegates to the
        // user's own shell instead (`crate::userwrite`), which is what closes the #1748 symlink LPE.
        let me = unelevated_alice();
        let plist = install_launch_agent(tmp.path(), Path::new("/opt/dig/bin/dig-app"), &me, false)
            .expect("launch agent written");
        assert_eq!(plist, launch_agent_path(tmp.path()));
        assert_eq!(
            std::fs::read_to_string(&plist).expect("readable"),
            launch_agent_plist("/opt/dig/bin/dig-app")
        );

        let entry =
            install_autostart_entry(tmp.path(), Path::new("/opt/dig/bin/dig-app"), &me, false)
                .expect("desktop entry written");
        assert_eq!(entry, autostart_desktop_path(tmp.path()));
        assert_eq!(
            std::fs::read_to_string(&entry).expect("readable"),
            autostart_desktop_entry("/opt/dig/bin/dig-app")
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
        // `register_for` with the session facts as DATA, not `register`: the real probe would read
        // this host, and a Linux target on a Windows box is legitimately headless — which would make
        // the dry-run property untestable here for a reason that has nothing to do with dry runs.
        let r = register_for(
            Path::new("/usr/local/bin/dig-app"),
            Os::Linux,
            true,
            &unelevated_alice(),
            false,
            false,
        );
        assert!(!r.registered);
        assert_eq!(r.mechanism, "xdg-autostart");
        assert!(r.note.contains("would register"), "got: {}", r.note);
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
            // A graphical host, as data: the headless verdict has its own tests, and reading it from
            // the runner here would make this assertion depend on which box CI happens to use.
            false,
        );
        // Compared as paths, not strings: `join` uses the HOST separator, so a literal
        // forward-slash expectation would fail on a Windows CI runner for a reason that has
        // nothing to do with the property under test.
        assert_eq!(
            Path::new(&r.artifact),
            autostart_desktop_path(Path::new("/home/ubuntu/.config"))
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
            false,
        );
        assert_eq!(
            Path::new(&r.artifact),
            autostart_desktop_path(Path::new("/home/alice/.config")),
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
            false,
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

    // -- dig_ecosystem#919: an autostart that actually autostarts, and headless hosts -------------

    /// Linux autostart is an XDG **desktop entry**, not a systemd user unit.
    ///
    /// The shipped code wrote `~/.config/systemd/user/dig-app.service` and never enabled or started
    /// it, so Linux autostart had never worked once. A desktop entry needs no `enable` and no session
    /// bus, which is exactly why the installer can complete the job itself.
    #[test]
    fn the_linux_artifact_is_an_xdg_desktop_entry_that_needs_no_enable_step() {
        let entry = autostart_desktop_entry("/opt/dig/bin/dig-app");
        assert!(entry.starts_with("[Desktop Entry]"), "got: {entry}");
        assert!(entry.contains("Type=Application"));
        assert!(entry.contains("Exec=/opt/dig/bin/dig-app"));
        assert!(entry.contains("X-GNOME-Autostart-enabled=true"));
        assert!(entry.contains("Hidden=false"));
        assert_eq!(
            autostart_desktop_path(Path::new("/home/alice/.config")),
            Path::new("/home/alice/.config/autostart/dig-app.desktop")
        );
    }

    /// An upgrade REMOVES the systemd user unit earlier versions wrote.
    ///
    /// Leaving it is not harmless residue: a user who ever ran `systemctl --user enable
    /// dig-app.service` would get TWO dig-app processes at their next login, one per mechanism.
    #[test]
    fn an_upgrade_removes_the_stale_systemd_user_unit_it_used_to_write() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let unit = systemd_user_unit_path(tmp.path());
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(&unit, systemd_user_unit("/old/path/dig-app")).unwrap();

        let note = apply_linux(
            tmp.path(),
            Path::new("/opt/dig/bin/dig-app"),
            &user_with_config_home(tmp.path()),
            false,
        )
        .expect("the desktop entry is written");

        assert!(
            autostart_desktop_path(tmp.path()).exists(),
            "the entry that actually autostarts must be written"
        );
        assert!(
            !unit.exists(),
            "the stale unit must be removed, or the user gets two agents at login"
        );
        assert!(
            note.contains("removed the stale systemd user unit"),
            "got: {note}"
        );
    }

    /// An uninstall removes BOTH mechanisms — a host installed by an older version must stop
    /// autostarting dig-app too.
    #[test]
    fn removing_the_autostart_removes_both_mechanisms() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let unit = systemd_user_unit_path(tmp.path());
        let entry = autostart_desktop_path(tmp.path());
        for path in [&unit, &entry] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x").unwrap();
        }
        remove_if_present(&entry)
            .and(remove_if_present(&unit))
            .expect("both removed");
        assert!(!entry.exists() && !unit.exists());
    }

    /// A HEADLESS host writes NOTHING and says why — and in particular does not enable linger to
    /// force a tray agent onto a server nobody is looking at.
    ///
    /// The write path is a real temp dir, so a registration that ignored the disposition would leave
    /// an observable file rather than merely a wrong flag.
    #[test]
    fn a_headless_host_registers_nothing_and_reports_the_skip() {
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let r = register_for(
                Path::new("/opt/dig/bin/dig-app"),
                os,
                false, // a REAL run, not a dry run: a dry run cannot prove nothing was written
                &user_with_config_home(tmp.path()),
                false,
                true, // headless
            );
            assert!(!r.registered, "{os:?}");
            assert_eq!(
                r.disposition,
                crate::svcscope::AgentDisposition::SkipHeadless
            );
            assert!(
                r.note.contains("no graphical session"),
                "{os:?} must say why: {}",
                r.note
            );
            assert!(
                !Path::new(&r.artifact).exists(),
                "{os:?}: a headless host must have nothing written at {}",
                r.artifact
            );
            assert!(
                !r.note.contains("linger"),
                "{os:?}: linger must not be enabled to force a GUI onto a headless box"
            );
        }
    }

    /// An elevated unix run that cannot name the account it is acting for skips LOUDLY: registering
    /// into root's own scope is the #1748 inversion, and cleaning root's scope on uninstall would
    /// leave the real user's autostart behind.
    #[test]
    fn an_elevated_run_with_no_resolvable_target_user_skips_loudly() {
        let unknown = crate::invoker::TargetUser {
            name: "root".to_string(),
            home: PathBuf::from("/root"),
            uid: None,
            gid: None,
            via_elevation: false,
        };
        for os in [Os::Linux, Os::MacOs] {
            let r = register_for(
                Path::new("/opt/dig/bin/dig-app"),
                os,
                false,
                &unknown,
                true, // acting for ANOTHER account, but no uid to name it
                false,
            );
            assert!(!r.registered, "{os:?}");
            assert_eq!(
                r.disposition,
                crate::svcscope::AgentDisposition::SkipNoTargetUser,
                "{os:?}"
            );
            assert!(
                r.note.contains("could not determine which account"),
                "{}",
                r.note
            );
        }
        // Windows addresses the running account through HKCU, so the same facts are registrable.
        let r = register_for(
            Path::new("C:/dig/dig-app.exe"),
            Os::Windows,
            true,
            &unknown,
            true,
            false,
        );
        assert_eq!(r.disposition, crate::svcscope::AgentDisposition::Register);
    }

    /// The headless verdict, per OS, from the facts — asserted for all three from any host.
    #[test]
    fn the_headless_verdict_reads_each_os_own_evidence() {
        let graphical = SessionFacts {
            display_env: true,
            desktop_sessions_installed: true,
            aqua_session: true,
            interactive_window_station: true,
        };
        let server = SessionFacts {
            display_env: false,
            desktop_sessions_installed: false,
            aqua_session: false,
            interactive_window_station: false,
        };
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            assert!(!is_headless(os, &graphical), "{os:?}");
            assert!(is_headless(os, &server), "{os:?}");
        }

        // A `sudo` install on a WORKSTATION whose DISPLAY was not forwarded: no display in the
        // environment, but desktop sessions ARE installed. Erring toward "headless" here would
        // silently deny a desktop user the agent they just installed — the asymmetric mistake.
        let sudo_on_a_workstation = SessionFacts {
            display_env: false,
            desktop_sessions_installed: true,
            ..graphical
        };
        assert!(
            !is_headless(Os::Linux, &sudo_on_a_workstation),
            "a workstation must not be mistaken for a server just because DISPLAY was not forwarded"
        );

        // Each OS reads its OWN evidence: Windows must not be swayed by a Linux display variable,
        // and Linux must not be swayed by a Windows window station.
        let only_windows_evidence = SessionFacts {
            interactive_window_station: true,
            ..server
        };
        assert!(is_headless(Os::Linux, &only_windows_evidence));
        assert!(!is_headless(Os::Windows, &only_windows_evidence));
        let only_linux_evidence = SessionFacts {
            display_env: true,
            ..server
        };
        assert!(is_headless(Os::Windows, &only_linux_evidence));
        assert!(!is_headless(Os::Linux, &only_linux_evidence));
    }

    /// A target user whose `$XDG_CONFIG_HOME` is `dir` — so a write test observes a temp directory
    /// rather than the runner's real home.
    fn user_with_config_home(dir: &Path) -> crate::invoker::TargetUser {
        crate::invoker::TargetUser {
            name: "alice".to_string(),
            // `apply` derives `<home>/.config` for another account and honours the env otherwise;
            // this fixture is used with `acting_for_another_account: false` plus an explicit env, or
            // with a home whose `.config` is `dir` — see each call site.
            home: dir.to_path_buf(),
            uid: Some(1000),
            gid: Some(1000),
            via_elevation: false,
        }
    }
}
