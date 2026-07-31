//! Starting dig-app when the install finishes — as the user, never as root (dig_ecosystem#1831).
//!
//! An install used to end with dig-app placed on PATH, an autostart artifact written, and **nothing
//! running**. The tray icon a stranger is looking for did not appear until they logged out and back
//! in, which nobody does, so the visible outcome of a successful install was "it did not work".
//!
//! # Why the launch must be de-elevated, and how
//!
//! The GUI installer declares `requestedExecutionLevel="requireAdministrator"` (#610), so it holds a
//! HIGH-integrity token on Windows and root on unix. dig-app is a **per-user custody surface**: it
//! holds the user's identity key and seals account state under their own account. Started as a child
//! of the installer it would inherit that elevation, and a first run at high integrity seals state
//! that the normal-integrity login autostart then cannot read back — an install that breaks the very
//! autostart it just registered.
//!
//! The measured mechanism (all three probes run from a real HIGH-integrity process, each reporting its
//! OWN token integrity SID):
//!
//! | how the child was started | integrity SID | |
//! |---|---|---|
//! | direct child of the elevated process | `S-1-16-12288` | High — the bug |
//! | `Shell.Application` COM `ShellExecute` | `S-1-16-12288` | **High — does NOT de-elevate** |
//! | `explorer.exe <path>` | `S-1-16-8192` | Medium — correct |
//!
//! The COM route is the one an internet search offers and it is WRONG here: the object is instantiated
//! inside the elevated process, so `ShellExecute` dispatches in that process's context rather than
//! Explorer's. Only handing the path to a **already-running, medium-integrity** `explorer.exe` gets
//! the child Explorer's token. That is why [`windows_launch_program`] names Explorer and the test below
//! pins it — a future "simplification" back to spawning the binary directly reintroduces the defect
//! silently, because from outside the two launches look identical.
//!
//! On unix the same boundary is crossed the way [`crate::userwrite`] already crosses it: the work is
//! delegated to the target user's own shell, so the kernel enforces the identity rather than a `setuid`
//! this module would have to get right.
//!
//! # Starting now and starting at login are the SAME act on unix
//!
//! macOS and Linux both have a per-user service manager, and [`crate::autostart`] has just written it
//! an artifact — which it then only *printed advice* about loading. So the launch here is
//! `launchctl bootstrap` / `systemctl --user enable --now`: one command that starts dig-app **and**
//! makes the artifact live for every future login. That closes the reported "writes a text file and
//! nothing ever starts dig-app" gap at its root rather than starting a process beside an inert file.
//!
//! Windows has no such manager: the `HKCU\…\Run` value is read by the shell at logon and needs no
//! loading, so there the launch is only the launch.
//!
//! # Two consents, two decisions
//!
//! "Start it now" and "start it at every login" are different questions and are answered separately:
//! the completion launch happens **regardless** of the `dig-app-autostart` choice, because the user
//! just chose to install dig-app and expects to see it, while the login registration honours the
//! checkbox. A user who declined autostart therefore gets the app now and no login entry — which is
//! what declining a *login* autostart means. See [`Plan::for_os`].
//!
//! # Idempotence lives in dig-app, not here
//!
//! Finishing an install while dig-app is already running must not produce a second instance. This
//! module does not test for one, deliberately: any check here would be a race between the test and the
//! spawn. dig-app itself takes a per-user OS lock at startup and a duplicate launch exits 0 as a no-op
//! (dig-app `single_instance`), so the exclusion is decided by the kernel in the one process that can
//! decide it. Launching unconditionally is therefore correct AND simpler.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::invoker::TargetUser;
use crate::target::Os;

/// The program a Windows launch hands the path to.
///
/// Explorer, never dig-app itself: see the integrity table in the module docs. Absolute, because
/// resolving `explorer.exe` through `%PATH%` from a privileged process is a search an unprivileged
/// account could influence.
pub const WINDOWS_LAUNCHER: &str = r"C:\Windows\explorer.exe";

/// What the launch did, or would do. Never silent — a stranger who ends up with no tray icon is told
/// why rather than left to discover it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LaunchResult {
    /// Did dig-app actually get started?
    pub launched: bool,
    /// The mechanism used: `explorer` | `launchctl` | `systemd-user` | `user-shell`.
    pub mechanism: String,
    /// Human-readable detail behind [`Self::launched`].
    pub note: String,
}

/// How dig-app is to be started on this host.
///
/// A pure description, separated from the spawning so every platform's decision is unit-tested on every
/// platform — the split [`crate::autostart`] uses for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Windows: hand the path to the running, medium-integrity Explorer.
    ViaExplorer { dig_app_bin: PathBuf },
    /// macOS: load the LaunchAgent into the target user's GUI domain, which starts it now (the plist
    /// carries `RunAtLoad`) and at every subsequent login.
    BootstrapLaunchAgent { uid: u32, plist: PathBuf },
    /// Linux: enable + start the systemd user unit in the target user's own session.
    EnableSystemdUserUnit,
    /// No service manager artifact to load — autostart was declined, or its uid is unknown — so start
    /// the binary directly in the target user's session.
    DirectAsUser { dig_app_bin: PathBuf },
}

impl Plan {
    /// The mechanism name, so the report, the log, and the `--json` record share one vocabulary.
    pub fn mechanism(&self) -> &'static str {
        match self {
            Plan::ViaExplorer { .. } => "explorer",
            Plan::BootstrapLaunchAgent { .. } => "launchctl",
            Plan::EnableSystemdUserUnit => "systemd-user",
            Plan::DirectAsUser { .. } => "user-shell",
        }
    }

    /// The installed binary THIS process causes to execute, if any — what the root-exec guard must vet.
    ///
    /// Only the two plans that name the binary on a command line qualify. The service-manager plans do
    /// not: `launchctl`/`systemd` read the path out of the artifact and start it in the user's own
    /// session, under their uid, so this process never causes a privileged exec of it.
    pub fn binary_this_process_causes_to_run(&self) -> Option<&Path> {
        match self {
            Plan::ViaExplorer { dig_app_bin } | Plan::DirectAsUser { dig_app_bin } => {
                Some(dig_app_bin)
            }
            Plan::BootstrapLaunchAgent { .. } | Plan::EnableSystemdUserUnit => None,
        }
    }

    /// Choose how to start dig-app for `user` on `os`.
    ///
    /// `autostart_registered` says whether [`crate::autostart`] just wrote a service-manager artifact
    /// for this run. When it did, unix loads THAT — starting the app and making the artifact live in
    /// one act. When it did not (the user declined the login autostart), the app is still started, just
    /// without registering anything: the two consents are answered separately.
    pub fn for_os(
        dig_app_bin: &Path,
        os: Os,
        user: &TargetUser,
        autostart_registered: bool,
    ) -> Plan {
        let direct = Plan::DirectAsUser {
            dig_app_bin: dig_app_bin.to_path_buf(),
        };
        match os {
            Os::Windows => Plan::ViaExplorer {
                dig_app_bin: dig_app_bin.to_path_buf(),
            },
            Os::MacOs if autostart_registered => match user.uid {
                // `launchctl bootstrap gui/<uid>` names the GUI domain by uid; without one there is no
                // domain to name, so the binary is started directly instead of guessing.
                Some(uid) => Plan::BootstrapLaunchAgent {
                    uid,
                    plist: crate::autostart::launch_agent_path(&user.home),
                },
                None => direct,
            },
            Os::Linux if autostart_registered => Plan::EnableSystemdUserUnit,
            _ => direct,
        }
    }
}

/// The shell command that carries out `plan` inside the target user's session.
///
/// Returned as a string rather than run, so the exact command every platform would issue is asserted in
/// tests on any host. `None` for the Windows plan, which is a direct spawn of a named program and not a
/// shell command at all.
///
/// Every interpolated path is shell-quoted: a home directory containing a space or a quote must not be
/// able to change the command's structure, let alone one containing `;`.
pub fn user_shell_command(plan: &Plan) -> Option<String> {
    match plan {
        Plan::ViaExplorer { .. } => None,
        Plan::BootstrapLaunchAgent { uid, plist } => Some(format!(
            "launchctl bootstrap gui/{uid} {}",
            crate::userwrite::shell_quote(plist)
        )),
        Plan::EnableSystemdUserUnit => {
            Some("systemctl --user enable --now dig-app.service".to_string())
        }
        // `nohup … &` detaches: the delegating shell exits as soon as the install step is done, and the
        // agent must outlive it rather than dying with its parent. Output is discarded because dig-app
        // writes to its own log; a redirect into the user's terminal would spray the installer's output.
        Plan::DirectAsUser { dig_app_bin } => Some(format!(
            "nohup {} >/dev/null 2>&1 &",
            crate::userwrite::shell_quote(dig_app_bin)
        )),
    }
}

/// The program + argument a Windows launch spawns.
///
/// Split out from the spawn so the "it is Explorer, not dig-app" property is a unit test rather than a
/// comment. Explorer takes the path as a single argument and needs no quoting: it is passed through the
/// argv, not a command line this code builds.
pub fn windows_launch_program(dig_app_bin: &Path) -> (PathBuf, PathBuf) {
    (PathBuf::from(WINDOWS_LAUNCHER), dig_app_bin.to_path_buf())
}

/// Start dig-app for the interactive user, never as this (possibly elevated) process.
///
/// Best-effort by design, exactly like [`crate::autostart::register`]: an install that placed the
/// binary correctly must not be failed because a tray icon did not appear. The [`LaunchResult`] always
/// carries a reason, so the outcome is reported rather than silently absent.
pub fn launch(
    dig_app_bin: &Path,
    os: Os,
    autostart_registered: bool,
    dry_run: bool,
) -> LaunchResult {
    let user = crate::invoker::target_user();
    let plan = Plan::for_os(dig_app_bin, os, user, autostart_registered);
    let mechanism = plan.mechanism().to_string();
    if dry_run {
        return LaunchResult {
            launched: false,
            mechanism,
            note: format!("would start dig-app in {}'s session", user.name),
        };
    }
    match carry_out(&plan, user) {
        Ok(note) => LaunchResult {
            launched: true,
            mechanism,
            note,
        },
        Err(e) => LaunchResult {
            launched: false,
            mechanism,
            note: format!(
                "could not start dig-app now ({e}); it is installed and on PATH — launch it \
                 yourself, or it will start at your next login"
            ),
        },
    }
}

/// Execute `plan`, returning the success note.
///
/// # Why the root-exec guard runs here too
///
/// Every spawn below is of a TRUSTED SYSTEM TOOL — `explorer.exe`, `su`, `sh` — so none of them is the
/// unguarded installed-binary spawn [`crate::guardedcmd`] exists to prevent. But the tool is asked to
/// run dig-app, and there is one arrangement where it does so with root's authority: an install by the
/// root ACCOUNT itself, with no `sudo`/`doas`/`pkexec` hint naming another user. `acting_for_another
/// _account` is then false, so the command runs directly rather than through `su`, and it runs as root.
/// With an explicit `--bin-dir` pointing somewhere unprivileged, that is root executing a binary an
/// unprivileged account can replace — the #1748 escalation, reached through a launch instead of a probe.
///
/// So the same guard the wrapper applies is applied here, to the binary the plan will cause to run. It
/// is a no-op unelevated, which is every ordinary install.
fn carry_out(plan: &Plan, user: &TargetUser) -> Result<String, String> {
    if let Some(bin) = plan.binary_this_process_causes_to_run() {
        crate::secure::root_exec_guard(bin)?;
    }
    match plan {
        Plan::ViaExplorer { dig_app_bin } => spawn_via_explorer(dig_app_bin),
        other => {
            let command = user_shell_command(other).expect("every non-Windows plan is a command");
            run_as_user(&command, user)?;
            Ok(format!("started dig-app in {}'s session", user.name))
        }
    }
}

/// Windows: hand the path to the already-running, medium-integrity Explorer.
///
/// Explorer returns immediately — it dispatches the open and exits — so this waits for THAT process,
/// not for dig-app, which is the point: the agent outlives the installer.
// A trusted SYSTEM tool at a fixed absolute path, not an installed binary, so the crate-wide
// `Command::new` denial (`clippy.toml`, #1748 WU4) is waived here for that stated reason.
#[allow(clippy::disallowed_methods)]
#[cfg(windows)]
fn spawn_via_explorer(dig_app_bin: &Path) -> Result<String, String> {
    use std::process::Command;

    use crate::proc::HideConsole;

    let (program, argument) = windows_launch_program(dig_app_bin);
    if !program.is_file() {
        return Err(format!("{} is not present", program.display()));
    }
    Command::new(&program)
        .arg(&argument)
        .hide_console()
        .status()
        .map_err(|e| format!("spawn {}: {e}", program.display()))?;
    Ok(format!(
        "started dig-app through {} — it runs as you, not elevated",
        program.display()
    ))
}

#[cfg(not(windows))]
fn spawn_via_explorer(_dig_app_bin: &Path) -> Result<String, String> {
    Err("Explorer only exists on Windows".to_string())
}

/// Run `command` in the target user's own session.
///
/// Under elevation this is `su - <user> -c`, the same delegation [`crate::userwrite`] uses to write
/// per-user files: the kernel enforces the identity, so there is no `setuid` dance here to get wrong,
/// and the child cannot inherit root. Unelevated we already ARE that user, so the command runs directly.
// Trusted SYSTEM tools resolved from the fixed directory list (`SPEC.md` §7.6), never an installed
// binary — the stated reason the crate-wide `Command::new` denial is waived here.
#[allow(clippy::disallowed_methods)]
#[cfg(unix)]
fn run_as_user(command: &str, user: &TargetUser) -> Result<(), String> {
    use std::process::Command;

    let elevated = user.acting_for_another_account(crate::invoker::is_root());
    let (tool, args): (&str, Vec<String>) = if elevated {
        (
            "su",
            vec![
                "-".to_string(),
                user.name.clone(),
                "-c".to_string(),
                command.to_string(),
            ],
        )
    } else {
        ("sh", vec!["-c".to_string(), command.to_string()])
    };
    let program = crate::elevation::resolve_system_tool(tool)
        .ok_or_else(|| format!("{tool} not found in any trusted system directory"))?;

    let mut spawn = Command::new(program);
    spawn.args(&args);
    // `systemctl --user` and `launchctl` both need the target user's runtime bus named explicitly:
    // root has none, and without it the command fails with "Failed to connect to bus" — the exact
    // reason the old printed advice did not work either (#1748).
    if let (true, Some(uid)) = (elevated, user.uid) {
        spawn.env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"));
    }
    let status = spawn
        .status()
        .map_err(|e| format!("run as {}: {e}", user.name))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{command}` exited with {status}"))
    }
}

#[cfg(not(unix))]
fn run_as_user(_command: &str, _user: &TargetUser) -> Result<(), String> {
    Err("the user-shell launch path is unix-only".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sudoing_ubuntu() -> TargetUser {
        TargetUser {
            name: "ubuntu".to_string(),
            home: PathBuf::from("/home/ubuntu"),
            uid: Some(1000),
            gid: Some(1000),
            via_elevation: true,
        }
    }

    fn bin() -> PathBuf {
        PathBuf::from("/opt/dig/bin/dig-app")
    }

    /// THE Windows property, and the one that is invisible from outside the process.
    ///
    /// A launch that spawns dig-app directly and a launch that goes through Explorer both end with a
    /// tray icon; only one of them is at medium integrity. Nothing observable about "a process
    /// appeared" separates them, so the discriminator has to be the program named. The measured
    /// integrity SIDs behind this choice are in the module docs.
    #[test]
    fn windows_launches_through_explorer_and_never_the_binary_itself() {
        let (program, argument) =
            windows_launch_program(&PathBuf::from(r"C:\Program Files\DIG\bin\dig-app.exe"));
        assert_eq!(program, PathBuf::from(WINDOWS_LAUNCHER));
        assert!(
            program.ends_with("explorer.exe"),
            "the de-elevation IS Explorer: {}",
            program.display()
        );
        assert_eq!(
            argument,
            PathBuf::from(r"C:\Program Files\DIG\bin\dig-app.exe"),
            "dig-app is Explorer's ARGUMENT, never the program spawned"
        );
        assert!(program.is_absolute(), "never resolved through %PATH%");
    }

    /// On unix, "start it now" and "start it at login" are one command against the artifact autostart
    /// just wrote — which is what closes the reported gap that the artifact was written and never
    /// loaded.
    #[test]
    fn a_registered_autostart_is_loaded_rather_than_left_inert() {
        let mac = Plan::for_os(&bin(), Os::MacOs, &sudoing_ubuntu(), true);
        assert_eq!(
            mac,
            Plan::BootstrapLaunchAgent {
                uid: 1000,
                plist: crate::autostart::launch_agent_path(Path::new("/home/ubuntu")),
            }
        );
        let cmd = user_shell_command(&mac).expect("a shell command");
        assert!(cmd.contains("launchctl bootstrap gui/1000"), "got: {cmd}");
        assert!(cmd.contains("net.dig.dig-app.plist"), "got: {cmd}");

        let linux = Plan::for_os(&bin(), Os::Linux, &sudoing_ubuntu(), true);
        assert_eq!(linux, Plan::EnableSystemdUserUnit);
        assert_eq!(
            user_shell_command(&linux).as_deref(),
            Some("systemctl --user enable --now dig-app.service"),
        );
    }

    /// The two consents are separate: declining the LOGIN autostart must still start the app the user
    /// just installed, and must not register anything.
    ///
    /// The control is the assertion above — the same OS and user with `autostart_registered: true`
    /// produces a service-manager plan — so this cannot pass against an implementation that ignores the
    /// flag and always spawns directly.
    #[test]
    fn declining_the_login_autostart_still_starts_the_app_now_without_registering() {
        for os in [Os::MacOs, Os::Linux] {
            let plan = Plan::for_os(&bin(), os, &sudoing_ubuntu(), false);
            assert_eq!(
                plan,
                Plan::DirectAsUser { dig_app_bin: bin() },
                "{os:?}: a declined login autostart must still start the app now"
            );
            let cmd = user_shell_command(&plan).expect("a shell command");
            assert!(cmd.contains("/opt/dig/bin/dig-app"), "got: {cmd}");
            assert!(
                !cmd.contains("enable") && !cmd.contains("bootstrap"),
                "declining the login autostart must register nothing: {cmd}"
            );
            assert!(
                cmd.contains("nohup") && cmd.trim_end().ends_with('&'),
                "the agent must outlive the shell that started it: {cmd}"
            );
        }
    }

    /// Windows has no per-user service manager to load, so the Run key needs no enabling and the plan
    /// is the same whether or not autostart was registered.
    #[test]
    fn windows_launches_the_same_way_regardless_of_the_autostart_choice() {
        for registered in [true, false] {
            assert_eq!(
                Plan::for_os(&bin(), Os::Windows, &sudoing_ubuntu(), registered),
                Plan::ViaExplorer { dig_app_bin: bin() }
            );
            assert_eq!(
                user_shell_command(&Plan::for_os(
                    &bin(),
                    Os::Windows,
                    &sudoing_ubuntu(),
                    registered
                )),
                None,
                "the Windows launch is a spawn, not a shell command"
            );
        }
    }

    /// `launchctl bootstrap gui/<uid>` cannot be issued without a uid. Rather than guess a domain, fall
    /// back to starting the binary — a running agent with an unloaded plist beats neither running.
    #[test]
    fn macos_without_a_resolvable_uid_starts_the_binary_instead_of_guessing_a_domain() {
        let no_uid = TargetUser {
            name: "ghost".to_string(),
            home: PathBuf::from("/Users/ghost"),
            uid: None,
            gid: None,
            via_elevation: true,
        };
        let plan = Plan::for_os(&bin(), Os::MacOs, &no_uid, true);
        assert_eq!(plan, Plan::DirectAsUser { dig_app_bin: bin() });
        assert!(!user_shell_command(&plan)
            .expect("a shell command")
            .contains("gui/"));
    }

    /// Does `command` contain a `;` that a shell would ACT on — i.e. one outside single quotes?
    ///
    /// A substring search cannot answer this: correctly-quoted output still CONTAINS the attacker's
    /// text, just inertly, so `!contains("; touch …")` fails against a correct implementation and would
    /// have to be weakened into something that proves nothing. Quote parity is the real property, and
    /// it is computed here independently of the code under test rather than by re-calling the quoter,
    /// which would be tautological.
    fn has_an_active_semicolon(command: &str) -> bool {
        let mut chars = command.chars();
        let mut inside = false;
        while let Some(c) = chars.next() {
            match c {
                // Inside single quotes NOTHING is special, not even a backslash — which is exactly why
                // the standard escape for an embedded quote is to CLOSE the quoting first (`'\''`).
                _ if inside => inside = c != '\'',
                // Outside, a backslash makes the next character literal. Missing this rule is what
                // makes a naive parity count misread correct `'\''` output as an escape.
                '\\' => {
                    chars.next();
                }
                '\'' => inside = true,
                ';' => return true,
                _ => {}
            }
        }
        false
    }

    /// A home directory or install path containing shell metacharacters must not be able to change the
    /// command's structure.
    ///
    /// The fixture carries a whole injected command, not merely a space: a space alone is satisfied by
    /// an implementation that wraps in DOUBLE quotes, which still interpolates `$(…)` and backticks and
    /// is the nearest wrong implementation here. The control is the plain path — the same scan must
    /// find no active `;` there either, so a checker that simply always answers "false" is not what is
    /// being observed.
    #[test]
    fn interpolated_paths_are_shell_quoted_against_metacharacters() {
        let nasty = PathBuf::from("/home/a b/'; touch /tmp/pwned; '/dig-app");
        let cmd = user_shell_command(&Plan::DirectAsUser {
            dig_app_bin: nasty.clone(),
        })
        .expect("a shell command");
        assert!(
            !has_an_active_semicolon(&cmd),
            "the injected command escaped its quoting: {cmd}"
        );
        assert!(
            cmd.contains(&crate::userwrite::shell_quote(&nasty)),
            "the path must appear quoted, not raw: {cmd}"
        );

        // The scan must be able to SEE an unquoted separator, or the assertion above is vacuous.
        assert!(has_an_active_semicolon(
            "nohup /bin/dig-app; touch /tmp/pwned"
        ));
    }

    /// Every plan that puts the installed binary on a command line THIS process runs must be vetted by
    /// the root-exec guard, because a root-ACCOUNT install (no `sudo` hint naming another user) takes
    /// the direct branch and would otherwise exec it with root's authority out of a `--bin-dir` the
    /// invoker chose — the #1748 escalation reached through a launch.
    ///
    /// The service-manager plans are the control: they must report NO binary, because `launchctl` and
    /// `systemd --user` read the path from the artifact and start it under the user's own uid. An
    /// implementation that simply answered `Some` for everything would pass a one-sided test and start
    /// refusing legitimate installs, so both arms are asserted.
    #[test]
    fn only_the_plans_this_process_execs_are_offered_to_the_root_exec_guard() {
        assert_eq!(
            Plan::ViaExplorer { dig_app_bin: bin() }.binary_this_process_causes_to_run(),
            Some(bin().as_path())
        );
        assert_eq!(
            Plan::DirectAsUser { dig_app_bin: bin() }.binary_this_process_causes_to_run(),
            Some(bin().as_path())
        );
        assert_eq!(
            Plan::EnableSystemdUserUnit.binary_this_process_causes_to_run(),
            None
        );
        assert_eq!(
            Plan::BootstrapLaunchAgent {
                uid: 1000,
                plist: PathBuf::from("/Users/alice/Library/LaunchAgents/net.dig.dig-app.plist"),
            }
            .binary_this_process_causes_to_run(),
            None
        );
    }

    #[test]
    fn each_plan_reports_a_distinct_mechanism_name() {
        assert_eq!(
            Plan::ViaExplorer { dig_app_bin: bin() }.mechanism(),
            "explorer"
        );
        assert_eq!(
            Plan::BootstrapLaunchAgent {
                uid: 1,
                plist: bin()
            }
            .mechanism(),
            "launchctl"
        );
        assert_eq!(Plan::EnableSystemdUserUnit.mechanism(), "systemd-user");
        assert_eq!(
            Plan::DirectAsUser { dig_app_bin: bin() }.mechanism(),
            "user-shell"
        );
    }
}
