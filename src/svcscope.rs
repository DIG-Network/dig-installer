//! Which SCOPE each DIG component is registered at, and what that means for reboot survival
//! (dig_ecosystem#526/#1863/#919/#1774).
//!
//! # The defect this module exists to make unrepresentable
//!
//! `dig-installer` runs `dig-node install` as root, while `dig-node`'s own `install` preferred a
//! **user-level** systemd unit regardless of privilege. A user-level unit is loaded by
//! `systemd --user`, which only exists inside a login session — so on a headless box the node was
//! registered, reported ready, and then did not come back after a reboot. Worse, under `sudo` there
//! is no `--user` D-Bus bus at all, so the registration could fail outright and still be tolerated.
//!
//! # The model
//!
//! Two kinds of component, and they must never be confused:
//!
//! * an **engine** (`dig-node`, `dig-relay`, `dig-dns`) is a machine daemon — it holds no user
//!   identity, and on an elevated install it belongs in the SYSTEM domain so it survives a reboot
//!   with nobody logged in;
//! * the **agent** (`dig-app`) is per-user — it holds the user's identity, so it must NEVER become a
//!   machine daemon. It starts at LOGIN, in the user's own session, and is therefore login-gated by
//!   design (see [`agent_disposition`]).
//!
//! Reboot survival with NO login session comes from exactly three mechanisms, one per OS:
//! the systemd `multi-user.target.wants` symlink, a launchd **system**-domain plist with
//! `RunAtLoad`, and the Windows SCM's `AUTO_START`. Every per-user mechanism — a systemd `--user`
//! unit, a `gui/<uid>` LaunchAgent, an XDG `autostart` desktop entry, `HKCU\…\Run` — waits for a
//! login. [`survives_reboot_without_login`] is that fact, written down once.
//!
//! # Why every function here is pure
//!
//! Each decision takes its OS, its privilege, and its filesystem facts as PARAMETERS. Nothing here
//! reads `cfg!`, the real uid, or the disk. A `#[cfg(unix)]`-only test makes its guard unfalsifiable
//! on a Windows host — the mutation stays green and the "test" proves nothing (dig_ecosystem#1774).
//! Platform-specific EXECUTION may be `cfg`-gated; the DECISIONS above must not be, and are asserted
//! for all three operating systems from any host.

use std::path::{Path, PathBuf};

use crate::target::Os;

/// The service-manager domain a registration lives in.
///
/// Deliberately two-valued: every OS DIG supports has exactly one machine-wide domain and one
/// per-user domain, and the whole point of this module is that the choice between them is a
/// decision with a stated reason rather than an accident of whichever backend ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceScope {
    /// The machine-wide domain: systemd system units, launchd `LaunchDaemons`, the Windows SCM.
    /// Starts at BOOT, with no login session.
    System,
    /// The per-user domain: `systemd --user`, launchd `gui/<uid>` LaunchAgents. Starts at LOGIN.
    User,
}

impl ServiceScope {
    /// The token passed to a component's `--scope` flag. Byte-identical with `dig-node`'s own
    /// `--scope <auto|system|user>` value set — this string IS the cross-repo contract.
    pub fn as_flag_value(self) -> &'static str {
        match self {
            ServiceScope::System => "system",
            ServiceScope::User => "user",
        }
    }

    /// A short phrase for a human-facing note, so every surface says it the same way.
    pub fn describe(self) -> &'static str {
        match self {
            ServiceScope::System => "machine-wide (system) scope",
            ServiceScope::User => "per-user scope",
        }
    }
}

/// What to do about `dig-app`'s per-user login autostart on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentDisposition {
    /// Register the login autostart for the target user.
    Register,
    /// This host has no graphical session, so a tray agent has nothing to appear in. Skip and SAY
    /// so — never register, and never enable `systemd` linger to force a headless box to run a GUI.
    SkipHeadless,
    /// Running elevated and no target user could be determined, so "per-user" has no referent.
    /// Skip LOUDLY: silently registering into root's scope is the dig_ecosystem#1748 inversion, and
    /// silently cleaning root's scope on uninstall leaves the real user's autostart behind.
    SkipNoTargetUser,
}

/// One registration observed on disk, for the shadow/adoption decisions.
///
/// A record, not a path: relocating an artifact out of a losing directory closes nothing if that
/// directory still WINS resolution, so the decisions below need to know a unit's SCOPE and whether
/// it is the distro-PACKAGED unit, not merely where it sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRecord {
    /// The unit/plist file's absolute path.
    pub path: PathBuf,
    /// Which domain this unit is loaded in.
    pub scope: ServiceScope,
    /// Is this the unit shipped by the distro package (the apt.dig.net `.deb`'s
    /// `net.dignetwork.dig-node.service`), as opposed to one a `dig-node install` wrote?
    pub packaged: bool,
    /// Is it ENABLED (i.e. will it actually be started), not merely present on disk?
    pub enabled: bool,
}

impl UnitRecord {
    /// A record for `path` in `scope`, neither packaged nor enabled — the common case a caller then
    /// adjusts, so a test fixture reads as the one fact it is varying.
    pub fn new(path: impl Into<PathBuf>, scope: ServiceScope) -> Self {
        UnitRecord {
            path: path.into(),
            scope,
            packaged: false,
            enabled: false,
        }
    }
}

/// How this run should obtain the engine's registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineRegistration {
    /// Delegate to the component's own `install` verb at the chosen scope.
    Delegate,
    /// An ENABLED packaged system unit already owns this service — adopt it. Registering a second
    /// enabled unit for the same service is a live port collision, not a belt-and-braces install.
    AdoptPackaged,
}

/// The scope an ENGINE (`dig-node`/`dig-relay`/`dig-dns` — a machine daemon holding no user
/// identity) must be registered at.
///
/// * **Windows** is always [`ServiceScope::System`]: the SCM has no per-user services, and the
///   installer's elevation gate refuses an unelevated Windows service install before this is
///   reached — so there is no second arm to choose.
/// * **Linux/macOS** get the system domain only when BOTH hold: this run is elevated (it can write
///   `/etc/systemd/system` / `/Library/LaunchDaemons`), AND the binary lives in the protected,
///   admin-only root. The second condition is dig_ecosystem#565: a machine-wide daemon pointed at a
///   `--bin-dir` a caller chose is a user→root escalation, so a `--bin-dir` run is FORCED to user
///   scope and told it will not survive a reboot ([`survives_reboot_without_login`]).
pub fn engine_scope(os: Os, elevated: bool, program_in_protected_root: bool) -> ServiceScope {
    match os {
        Os::Windows => ServiceScope::System,
        Os::Linux | Os::MacOs => {
            if elevated && program_in_protected_root {
                ServiceScope::System
            } else {
                ServiceScope::User
            }
        }
    }
}

/// [`engine_scope`] for a binary this run actually PLACED at `program`, judged
/// against the admin-only `protected_root`.
///
/// Takes the root as a parameter rather than reading
/// [`crate::paths::protected_bin_dir`] itself, so the "is it protected?" decision
/// is exercised for both answers from any host — and so a `--bin-dir` run's
/// forced user scope is a test, not a hope.
pub fn engine_scope_for_program(
    os: Os,
    elevated: bool,
    program: &Path,
    protected_root: &Path,
) -> ServiceScope {
    engine_scope(os, elevated, program.starts_with(protected_root))
}

/// The `--scope <value>` argument pair to append to a component's `install`/`uninstall`/`start`/
/// `stop` verb.
///
/// Two elements, `--scope` then the value — never one `--scope=value` token: `dig-node`'s clap
/// parser accepts both, but the split form is what its own docs and the compat probe in
/// [`is_unknown_scope_flag_rejection`] are written against.
pub fn scope_args(scope: ServiceScope) -> Vec<String> {
    vec!["--scope".to_string(), scope.as_flag_value().to_string()]
}

/// Every scope an engine's registration must be removed from on `os`, on EVERY uninstall.
///
/// Always both, unconditionally, on every OS — an uninstall that only visits the scope THIS run
/// would have installed into leaves a registration behind from any earlier run that chose the other
/// one (an unelevated install, an older version that only knew user scope, a `--bin-dir` run). A
/// scope that cannot be reached is a REPORTED failure, never a silent success.
pub fn deregister_scopes(_os: Os) -> Vec<ServiceScope> {
    vec![ServiceScope::System, ServiceScope::User]
}

/// The scope a component that does NOT understand `--scope` will register at — its own default.
///
/// * **Windows** — System, unavoidably: the SCM has no per-user service domain, and `dig-node
///   install` sets `start= auto` there (#301). An older build on Windows is therefore still
///   boot-start, and warning that it "only starts at login" would be false.
/// * **Linux/macOS** — User: dig-node's pre-`--scope` `install` PREFERRED a user-level unit
///   regardless of privilege (its `PREFERS_USER_LEVEL`), which is the whole of dig_ecosystem#526.
///
/// Used to answer honestly what a compat fallback actually achieved
/// ([`survives_reboot_without_login`]) instead of assuming every fallback is a downgrade.
pub fn legacy_default_scope(os: Os) -> ServiceScope {
    match os {
        Os::Windows => ServiceScope::System,
        Os::Linux | Os::MacOs => ServiceScope::User,
    }
}

/// Does a registration at `scope` on `os` start after a reboot with NOBODY logged in?
///
/// Only the machine-wide domain does, on all three operating systems: the systemd
/// `multi-user.target.wants` symlink, a launchd system-domain plist's `RunAtLoad`, and the SCM's
/// `AUTO_START`. Every per-user mechanism waits for a login session to exist — that is what a
/// per-user mechanism IS, so this is a property of the scope, not a per-OS quirk.
pub fn survives_reboot_without_login(_os: Os, scope: ServiceScope) -> bool {
    scope == ServiceScope::System
}

/// What to do about the per-user `dig-app` autostart.
///
/// On Windows the mechanism is `HKCU\…\Run`, which by definition addresses the account this process
/// runs as, so a target user is always known and `target_user_known` has nothing to say. On unix an
/// elevated run must resolve the INVOKING account, and when it cannot, "per-user" has no referent —
/// which is reported ([`AgentDisposition::SkipNoTargetUser`]) rather than quietly aimed at root.
///
/// A headless host is skipped ahead of everything else it might have done: a tray agent has no tray
/// to appear in, and forcing one on with `loginctl enable-linger` would run a GUI process forever on
/// a server nobody is looking at.
pub fn agent_disposition(os: Os, headless: bool, target_user_known: bool) -> AgentDisposition {
    if os != Os::Windows && !target_user_known {
        return AgentDisposition::SkipNoTargetUser;
    }
    if headless {
        return AgentDisposition::SkipHeadless;
    }
    AgentDisposition::Register
}

/// The per-user units that would SHADOW a system-scope engine registration and must be removed.
///
/// After a system-scope register, a leftover per-user unit for the same service is not harmless
/// residue: on Linux `systemd --user` starts it at the next login ALONGSIDE the system unit, and
/// both bind the node's port — one of them loses, non-deterministically. macOS has the same
/// collision between a `gui/<uid>` LaunchAgent and a system LaunchDaemon of the same label. Windows
/// has no per-user service domain, so there is nothing to shadow.
///
/// Only ever removes UNPACKAGED per-user units: the distro package's unit is system-scope and is
/// adopted ([`engine_registration`]), never deleted by this installer.
pub fn shadowing_units_to_remove(
    os: Os,
    scope: ServiceScope,
    existing: &[UnitRecord],
) -> Vec<PathBuf> {
    if os == Os::Windows || scope != ServiceScope::System {
        return Vec::new();
    }
    existing
        .iter()
        .filter(|u| u.scope == ServiceScope::User && !u.packaged)
        .map(|u| u.path.clone())
        .collect()
}

/// How a run ended up with an engine registration in place.
///
/// The three routes look very different in the log and are IDENTICAL in the one way that matters
/// here: none of them removes a per-user unit that was already on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationConclusion {
    /// This run delegated to the component's own `install` and created the registration.
    Registered,
    /// This run adopted an already-enabled packaged system unit ([`EngineRegistration::AdoptPackaged`]).
    AdoptedPackaged,
    /// The component was already up to date, so the existing registration was left untouched.
    LeftAsIs,
}

/// The scope whose registration will actually SERVE this host once the run concludes.
///
/// # Why every conclusion owes the same shadowing sweep
///
/// Adopting a packaged system unit — or leaving an up-to-date one alone — settles on a registration
/// just as firmly as creating one, and NEITHER makes a leftover `~/.config/systemd/user` unit stop
/// existing. `systemd --user` still starts it at the next login, alongside the system unit, and both
/// bind the node's port. Concluding "the right unit is now in place" is not the same as concluding
/// "the right unit WINS": precedence has to be established positionally, by clearing what outranks
/// the settled registration in a user session (dig_ecosystem#526 review, finding 2).
///
/// Adoption only ever happens at system scope ([`engine_registration`]), so that is the scope it
/// settles on regardless of what the run originally requested.
///
/// # Why a LEFT-AS-IS run must answer from the DISK, not from the request
///
/// The requested scope is what this run WOULD have registered. `LeftAsIs` is precisely the arm that
/// registered nothing, so on that path the request is a hypothesis and the only registration in
/// existence is whatever was already on the host. Settling `LeftAsIs` on the REQUEST let an elevated
/// (system-scope) run over an up-to-date binary sweep away a per-user unit that was the host's ONLY
/// registration — and then report `installed: true`, because the sweep is silent and the health check
/// passes against the still-RUNNING service. The loss first becomes visible at the next reboot, when
/// nothing starts. `existing` is therefore consulted: a system registration that will actually be
/// started is what makes clearing the shadowers safe (dig_ecosystem#526 review round 2, finding A1).
pub fn settled_scope(
    requested: ServiceScope,
    conclusion: RegistrationConclusion,
    existing: &[UnitRecord],
) -> ServiceScope {
    match conclusion {
        RegistrationConclusion::AdoptedPackaged => ServiceScope::System,
        RegistrationConclusion::Registered => requested,
        RegistrationConclusion::LeftAsIs => serving_scope(existing),
    }
}

/// Which scope actually serves a host that this run did not register into.
///
/// A system unit only serves if it will be STARTED: a present-but-not-enabled one starts nothing, so
/// it cannot justify deleting the per-user unit that does (the same reasoning
/// [`engine_registration`] applies to a packaged unit). With no such unit, the answer is `User` —
/// which makes [`shadowing_units_to_remove`] propose nothing, because the units it would delete are
/// the registration itself.
fn serving_scope(existing: &[UnitRecord]) -> ServiceScope {
    let system_serves = existing
        .iter()
        .any(|u| u.scope == ServiceScope::System && u.enabled);
    if system_serves {
        ServiceScope::System
    } else {
        ServiceScope::User
    }
}

/// Adopt an already-ENABLED packaged system unit rather than registering a second one.
///
/// apt.dig.net's `.deb` ships `net.dignetwork.dig-node.service` and enables it. Delegating
/// `dig-node install` on top of that produces two enabled units for one service, both binding the
/// node's port — a live collision, and the second one is the one this installer would then report as
/// healthy. A unit that is present but NOT enabled cannot start anything, so it is no reason to skip
/// the registration this run was asked to make.
pub fn engine_registration(
    os: Os,
    scope: ServiceScope,
    existing: &[UnitRecord],
) -> EngineRegistration {
    let adoptable = os != Os::Windows
        && scope == ServiceScope::System
        && existing
            .iter()
            .any(|u| u.packaged && u.enabled && u.scope == ServiceScope::System);
    if adoptable {
        EngineRegistration::AdoptPackaged
    } else {
        EngineRegistration::Delegate
    }
}

/// Does `path` name a per-user systemd unit directory (the shadowing location on Linux)?
///
/// Both the invoking user's `~/.config/systemd/user` and ROOT's `/root/.config/systemd/user` count:
/// a pre-#526 `sudo dig-installer` wrote the unit into root's own user scope, where root has no
/// session bus to load it — invisible to the real user and to `systemctl` alike.
pub fn is_user_unit_dir(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    text.contains("/.config/systemd/user")
}

/// Did a component reject an UNKNOWN `--scope` flag — i.e. is this an older build that predates
/// scope support, rather than a real registration failure?
///
/// clap rejects an unrecognised flag with a non-zero exit BEFORE running any subcommand body, so
/// this failure is side-effect-free and safe to retry without the flag. The retry is gated on the
/// message naming `--scope` specifically: a bare "unexpected argument" from some other cause must
/// not silently downgrade a system-scope install to user scope.
///
/// Matched case-insensitively against every phrasing clap 3/4 has used, so a clap upgrade in
/// `dig-node` does not turn the fallback off silently. No `--help` probing and no version parsing:
/// both add a spawn whose answer this failure already contains.
pub fn is_unknown_scope_flag_rejection(message: &str) -> bool {
    let lower = message.to_lowercase();
    if !lower.contains("--scope") {
        return false;
    }
    const REJECTIONS: &[&str] = &[
        "unexpected argument",
        "wasn't expected",
        "was not expected",
        "unrecognized argument",
        "unrecognised argument",
        "found argument",
        "unknown argument",
        "unexpected flag",
    ];
    REJECTIONS.iter().any(|phrase| lower.contains(phrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every OS, so no assertion below depends on which host runs it (#1774).
    const ALL_OS: [Os; 3] = [Os::Windows, Os::Linux, Os::MacOs];

    // -- engine_scope: the full (3 OS x elevated x in-protected-root) table -------------------

    #[test]
    fn engine_scope_covers_every_os_privilege_and_root_combination() {
        // (os, elevated, in_protected_root) -> scope. Windows is System in every row (the SCM has
        // no user domain); unix needs BOTH elevation and a protected root.
        let table = [
            (Os::Windows, true, true, ServiceScope::System),
            (Os::Windows, true, false, ServiceScope::System),
            (Os::Windows, false, true, ServiceScope::System),
            (Os::Windows, false, false, ServiceScope::System),
            (Os::Linux, true, true, ServiceScope::System),
            (Os::Linux, true, false, ServiceScope::User),
            (Os::Linux, false, true, ServiceScope::User),
            (Os::Linux, false, false, ServiceScope::User),
            (Os::MacOs, true, true, ServiceScope::System),
            (Os::MacOs, true, false, ServiceScope::User),
            (Os::MacOs, false, true, ServiceScope::User),
            (Os::MacOs, false, false, ServiceScope::User),
        ];
        for (os, elevated, in_root, expected) in table {
            assert_eq!(
                engine_scope(os, elevated, in_root),
                expected,
                "os {os:?}, elevated {elevated}, in_protected_root {in_root}"
            );
        }
    }

    #[test]
    fn an_elevated_unix_install_into_a_caller_chosen_bin_dir_is_forced_to_user_scope() {
        // #565: a machine-wide daemon pointed at a `--bin-dir` the caller picked is the escalation
        // itself. Elevation alone must NOT buy system scope — this is the row that distinguishes
        // "gate on privilege" (wrong) from "gate on privilege AND a protected root" (right).
        for os in [Os::Linux, Os::MacOs] {
            assert_eq!(engine_scope(os, true, false), ServiceScope::User);
            assert!(!survives_reboot_without_login(
                os,
                engine_scope(os, true, false)
            ));
        }
    }

    #[test]
    fn the_scope_follows_the_directory_the_binary_was_actually_placed_in() {
        let protected = Path::new("/opt/dig/bin");
        for os in [Os::Linux, Os::MacOs] {
            assert_eq!(
                engine_scope_for_program(os, true, Path::new("/opt/dig/bin/dig-node"), protected),
                ServiceScope::System
            );
            // A `--bin-dir` the caller chose, even while elevated: user scope.
            assert_eq!(
                engine_scope_for_program(
                    os,
                    true,
                    Path::new("/home/alice/.dig/bin/dig-node"),
                    protected
                ),
                ServiceScope::User
            );
            // A sibling directory that merely SHARES a prefix is not the root.
            assert_eq!(
                engine_scope_for_program(
                    os,
                    true,
                    Path::new("/opt/dig/bin-evil/dig-node"),
                    protected
                ),
                ServiceScope::User
            );
        }
        // Windows is System either way — the SCM has no per-user domain.
        assert_eq!(
            engine_scope_for_program(
                Os::Windows,
                true,
                Path::new("C:/Users/a/dig/dig-node.exe"),
                Path::new("C:/Program Files/DIG/bin")
            ),
            ServiceScope::System
        );
    }

    // -- scope_args: the byte-for-byte cross-repo argument surface ----------------------------

    #[test]
    fn scope_args_is_the_two_token_flag_dig_node_parses() {
        assert_eq!(scope_args(ServiceScope::System), vec!["--scope", "system"]);
        assert_eq!(scope_args(ServiceScope::User), vec!["--scope", "user"]);
        // The value tokens are the contract dig-node's `--scope <auto|system|user>` accepts.
        assert_eq!(ServiceScope::System.as_flag_value(), "system");
        assert_eq!(ServiceScope::User.as_flag_value(), "user");
    }

    // -- deregister_scopes: BOTH scopes, every OS ---------------------------------------------

    #[test]
    fn every_os_deregisters_both_scopes() {
        for os in ALL_OS {
            let scopes = deregister_scopes(os);
            assert!(
                scopes.contains(&ServiceScope::System) && scopes.contains(&ServiceScope::User),
                "uninstall on {os:?} must visit both scopes, got {scopes:?}"
            );
            assert_eq!(scopes.len(), 2, "no scope may be visited twice");
        }
    }

    // -- survives_reboot_without_login --------------------------------------------------------

    #[test]
    fn only_system_scope_survives_a_reboot_with_nobody_logged_in() {
        for os in ALL_OS {
            assert!(survives_reboot_without_login(os, ServiceScope::System));
            assert!(!survives_reboot_without_login(os, ServiceScope::User));
        }
    }

    #[test]
    fn a_pre_scope_binary_still_registers_machine_wide_on_windows_but_not_on_unix() {
        // The compat fallback is NOT a downgrade everywhere: the Windows SCM has no per-user domain,
        // so an older `dig-node install` there is still boot-start. Claiming otherwise would print a
        // false warning on every Windows install pinned to an older component — which is exactly what
        // the installer-e2e caught (run 30645063625).
        assert_eq!(legacy_default_scope(Os::Windows), ServiceScope::System);
        assert!(survives_reboot_without_login(
            Os::Windows,
            legacy_default_scope(Os::Windows)
        ));
        for os in [Os::Linux, Os::MacOs] {
            assert_eq!(legacy_default_scope(os), ServiceScope::User, "{os:?}");
            assert!(
                !survives_reboot_without_login(os, legacy_default_scope(os)),
                "{os:?}: a user-level unit is the #526 defect — it waits for a login"
            );
        }
    }

    // -- agent_disposition: the full (3 OS x headless x target-user-known) table --------------

    #[test]
    fn agent_disposition_covers_every_os_headless_and_target_user_combination() {
        let table = [
            (Os::Windows, false, true, AgentDisposition::Register),
            (Os::Windows, true, true, AgentDisposition::SkipHeadless),
            // HKCU addresses the running account, so an unknown target user cannot arise —
            // Windows must not report SkipNoTargetUser for a perfectly registrable host.
            (Os::Windows, false, false, AgentDisposition::Register),
            (Os::Windows, true, false, AgentDisposition::SkipHeadless),
            (Os::Linux, false, true, AgentDisposition::Register),
            (Os::Linux, true, true, AgentDisposition::SkipHeadless),
            (Os::Linux, false, false, AgentDisposition::SkipNoTargetUser),
            (Os::Linux, true, false, AgentDisposition::SkipNoTargetUser),
            (Os::MacOs, false, true, AgentDisposition::Register),
            (Os::MacOs, true, true, AgentDisposition::SkipHeadless),
            (Os::MacOs, false, false, AgentDisposition::SkipNoTargetUser),
            (Os::MacOs, true, false, AgentDisposition::SkipNoTargetUser),
        ];
        for (os, headless, known, expected) in table {
            assert_eq!(
                agent_disposition(os, headless, known),
                expected,
                "os {os:?}, headless {headless}, target_user_known {known}"
            );
        }
    }

    #[test]
    fn the_agent_is_never_registered_on_a_headless_host() {
        // The one property the install path reads: nothing is written when there is no session.
        for os in ALL_OS {
            for known in [true, false] {
                assert_ne!(
                    agent_disposition(os, true, known),
                    AgentDisposition::Register,
                    "os {os:?}, target_user_known {known}"
                );
            }
        }
    }

    // -- shadowing_units_to_remove ------------------------------------------------------------

    /// Two per-user units AND a system unit, so a relocation/filter at the wrong layer is
    /// observable: a rule that returned "every unit but the last" or "only the first" differs from
    /// the correct answer on this fixture. Also carries an ENABLED PACKAGED system unit, which must
    /// never be proposed for deletion.
    fn mixed_units() -> Vec<UnitRecord> {
        vec![
            UnitRecord::new(
                "/home/alice/.config/systemd/user/dignetwork-dig-node.service",
                ServiceScope::User,
            ),
            UnitRecord::new(
                "/root/.config/systemd/user/dignetwork-dig-node.service",
                ServiceScope::User,
            ),
            UnitRecord::new(
                "/etc/systemd/system/dignetwork-dig-node.service",
                ServiceScope::System,
            ),
            UnitRecord {
                path: PathBuf::from("/lib/systemd/system/net.dignetwork.dig-node.service"),
                scope: ServiceScope::System,
                packaged: true,
                enabled: true,
            },
        ]
    }

    #[test]
    fn a_system_scope_register_removes_every_shadowing_user_unit_including_roots() {
        for os in [Os::Linux, Os::MacOs] {
            let removed = shadowing_units_to_remove(os, ServiceScope::System, &mixed_units());
            assert_eq!(
                removed,
                vec![
                    PathBuf::from("/home/alice/.config/systemd/user/dignetwork-dig-node.service"),
                    PathBuf::from("/root/.config/systemd/user/dignetwork-dig-node.service"),
                ],
                "os {os:?}: BOTH user-scope units shadow the system unit — the real user's and \
                 the one a pre-#526 `sudo` install wrote into root's own user scope"
            );
        }
    }

    #[test]
    fn no_system_unit_and_no_packaged_unit_is_ever_proposed_for_removal() {
        let removed = shadowing_units_to_remove(Os::Linux, ServiceScope::System, &mixed_units());
        for path in &removed {
            assert!(
                is_user_unit_dir(path),
                "{} is not a per-user unit and must not be deleted",
                path.display()
            );
        }
    }

    #[test]
    fn a_user_scope_register_removes_nothing_and_windows_has_no_user_domain() {
        // A user-scope run IS the user unit — deleting it would delete what it just wrote.
        assert!(
            shadowing_units_to_remove(Os::Linux, ServiceScope::User, &mixed_units()).is_empty()
        );
        assert!(
            shadowing_units_to_remove(Os::Windows, ServiceScope::System, &mixed_units()).is_empty()
        );
    }

    // -- settled_scope: adopting/skipping still owes the sweep ---------------------------------

    /// Finding 2: the host the reviewer described — the apt.dig.net `.deb`'s ENABLED packaged system
    /// unit PLUS a leftover `~/.config/systemd/user` unit. That is exactly `mixed_units()`, and it is
    /// the fixture that can see the bug: adoption concludes "a system registration is in place" while
    /// two per-user units remain, so `systemd --user` starts a second dig-node at the next login and
    /// both bind the node's port.
    ///
    /// The property under test is that ADOPTING and LEAVING-AS-IS settle on a scope whose shadowers
    /// are still owed a sweep — not merely that some sweep exists somewhere.
    ///
    /// # What this fixture CANNOT see (round 2, finding A1)
    ///
    /// It carries an ENABLED packaged system unit, so a `LeftAsIs` run that settles on System is
    /// sweeping shadowers of a registration that genuinely exists — the deletion is harmless here and
    /// the arm reads correct. On the COMMONEST host there is no packaged unit at all, and the same
    /// code deletes the only registration; that case is
    /// [`leaving_an_up_to_date_registration_as_is_never_sweeps_the_only_registration`].
    #[test]
    fn adopting_or_leaving_a_registration_still_owes_the_shadowing_sweep() {
        let units = mixed_units();
        // Precondition: this fixture really is the adopt case, so the test cannot pass vacuously by
        // exercising the ordinary Delegate path.
        assert_eq!(
            engine_registration(Os::Linux, ServiceScope::System, &units),
            EngineRegistration::AdoptPackaged,
            "fixture must exhibit the adopt case for this test to mean anything"
        );

        for conclusion in [
            RegistrationConclusion::Registered,
            RegistrationConclusion::AdoptedPackaged,
            RegistrationConclusion::LeftAsIs,
        ] {
            let settled = settled_scope(ServiceScope::System, conclusion, &units);
            assert_eq!(settled, ServiceScope::System, "{conclusion:?}");
            assert_eq!(
                shadowing_units_to_remove(Os::Linux, settled, &units),
                vec![
                    PathBuf::from("/home/alice/.config/systemd/user/dignetwork-dig-node.service"),
                    PathBuf::from("/root/.config/systemd/user/dignetwork-dig-node.service"),
                ],
                "{conclusion:?}: a settled system registration does not make a per-user unit stop \
                 winning the user session — it must be cleared positionally"
            );
        }
    }

    /// Adoption is a SYSTEM-scope conclusion even though the run may have asked for something else,
    /// because that is the only scope a packaged unit is ever adopted at. The control keeps the
    /// mapping honest: a plain user-scope registration must NOT be promoted to system, or the sweep
    /// would delete the very unit that run just wrote.
    #[test]
    fn adoption_settles_on_system_while_a_user_registration_stays_user() {
        let units = mixed_units();
        assert_eq!(
            settled_scope(
                ServiceScope::User,
                RegistrationConclusion::AdoptedPackaged,
                &units
            ),
            ServiceScope::System
        );
        for conclusion in [
            RegistrationConclusion::Registered,
            RegistrationConclusion::LeftAsIs,
        ] {
            assert_eq!(
                settled_scope(ServiceScope::User, conclusion, &[]),
                ServiceScope::User,
                "{conclusion:?}"
            );
            assert!(
                shadowing_units_to_remove(
                    Os::Linux,
                    settled_scope(ServiceScope::User, conclusion, &[]),
                    &mixed_units()
                )
                .is_empty(),
                "{conclusion:?}: a user-scope run must never sweep the unit it just wrote"
            );
        }
    }

    /// The host with a pre-#526 registration and NOTHING else: one unpackaged `~/.config/systemd/user`
    /// unit, no packaged unit, no system unit. That is the commonest shape on the machine class #526
    /// is about, and it is the shape the adopt-fixture above cannot exhibit.
    fn only_a_user_unit() -> Vec<UnitRecord> {
        vec![UnitRecord::new(
            "/home/alice/.config/systemd/user/dignetwork-dig-node.service",
            ServiceScope::User,
        )]
    }
    /// Finding A1: an elevated run over an ALREADY-UP-TO-DATE binary registers nothing, so the
    /// per-user unit it would otherwise shadow is the host's only registration — and deleting it
    /// leaves the machine with no service at all while the run still reports success.
    ///
    /// The fixture varies exactly one actor from the adopt fixture: the packaged unit is gone. The
    /// pre-fix implementation (`LeftAsIs` settles on the REQUESTED scope) answers System here and
    /// proposes the only registration for deletion; both the requested scope and the conclusion are
    /// identical to the passing adopt case, so nothing but the disk facts can distinguish them.
    #[test]
    fn leaving_an_up_to_date_registration_as_is_never_sweeps_the_only_registration() {
        let units = only_a_user_unit();
        // Precondition: this really is the no-packaged-unit path, so the test cannot pass by
        // accidentally exercising adoption (whose own arm hard-codes System).
        assert_eq!(
            engine_registration(Os::Linux, ServiceScope::System, &units),
            EngineRegistration::Delegate,
            "fixture must have no adoptable packaged unit for this test to mean anything"
        );
        for os in [Os::Linux, Os::MacOs] {
            let settled = settled_scope(
                ServiceScope::System,
                RegistrationConclusion::LeftAsIs,
                &units,
            );
            assert_eq!(
                settled,
                ServiceScope::User,
                "{os:?}: a run that registered NOTHING is served by what is on the disk, not by the \
                 scope it would have asked for"
            );
            assert!(
                shadowing_units_to_remove(os, settled, &units).is_empty(),
                "{os:?}: the sole registration must never be swept — deleting it reports success \
                 and leaves nothing running after a reboot"
            );
        }
    }

    /// The control that keeps the fix from becoming "never sweep on LeftAsIs": once a system unit is
    /// ENABLED it really will start at boot, so the per-user unit is a genuine collision and is
    /// cleared. A present-but-DISABLED system unit starts nothing and buys no such licence — the row
    /// that separates "a system unit exists" from "a system unit serves".
    #[test]
    fn a_left_as_is_run_sweeps_only_once_a_system_unit_will_actually_start() {
        let user_unit = only_a_user_unit();
        let mut disabled = user_unit.clone();
        disabled.push(UnitRecord::new(
            "/etc/systemd/system/dignetwork-dig-node.service",
            ServiceScope::System,
        ));
        let mut enabled = user_unit.clone();
        enabled.push(UnitRecord {
            path: PathBuf::from("/etc/systemd/system/dignetwork-dig-node.service"),
            scope: ServiceScope::System,
            packaged: false,
            enabled: true,
        });

        let settle = |units: &[UnitRecord]| {
            settled_scope(
                ServiceScope::System,
                RegistrationConclusion::LeftAsIs,
                units,
            )
        };
        assert_eq!(
            settle(&disabled),
            ServiceScope::User,
            "a disabled system unit starts nothing, so it cannot justify the deletion"
        );
        assert!(shadowing_units_to_remove(Os::Linux, settle(&disabled), &disabled).is_empty());
        assert_eq!(settle(&enabled), ServiceScope::System);
        assert_eq!(
            shadowing_units_to_remove(Os::Linux, settle(&enabled), &enabled),
            vec![PathBuf::from(
                "/home/alice/.config/systemd/user/dignetwork-dig-node.service"
            )],
            "an enabled system unit DOES serve, so the per-user unit is a live collision"
        );
    }

    // -- engine_registration: adopt the packaged unit ------------------------------------------

    #[test]
    fn an_enabled_packaged_system_unit_is_adopted_rather_than_double_registered() {
        assert_eq!(
            engine_registration(Os::Linux, ServiceScope::System, &mixed_units()),
            EngineRegistration::AdoptPackaged
        );
    }

    #[test]
    fn a_present_but_disabled_packaged_unit_is_no_reason_to_skip_registration() {
        // Present-but-disabled starts nothing, so skipping would leave the host with NO node.
        let disabled = vec![UnitRecord {
            path: PathBuf::from("/lib/systemd/system/net.dignetwork.dig-node.service"),
            scope: ServiceScope::System,
            packaged: true,
            enabled: false,
        }];
        assert_eq!(
            engine_registration(Os::Linux, ServiceScope::System, &disabled),
            EngineRegistration::Delegate
        );
    }

    #[test]
    fn a_user_scope_run_never_adopts_a_packaged_system_unit() {
        assert_eq!(
            engine_registration(Os::Linux, ServiceScope::User, &mixed_units()),
            EngineRegistration::Delegate
        );
        assert_eq!(
            engine_registration(Os::Windows, ServiceScope::System, &mixed_units()),
            EngineRegistration::Delegate
        );
    }

    // -- is_unknown_scope_flag_rejection: the compat fallback trigger --------------------------

    #[test]
    fn clap_unknown_flag_messages_are_recognised_as_a_pre_scope_binary() {
        // Real clap 4 wording, and the clap 3 wording, both naming --scope.
        for message in [
            "error: unexpected argument '--scope' found\n\nUsage: dig-node install",
            "error: Found argument '--scope' which wasn't expected, or isn't valid in this context",
            "ERROR: UNEXPECTED ARGUMENT \"--SCOPE\"",
        ] {
            assert!(
                is_unknown_scope_flag_rejection(message),
                "must retry without the flag for: {message}"
            );
        }
    }

    #[test]
    fn a_real_registration_failure_never_downgrades_the_scope() {
        // Each of these is a genuine failure that must NOT be retried unflagged — doing so would
        // silently register a user-scope service that does not survive a reboot and report success.
        for message in [
            // Names --scope, but the flag was ACCEPTED and the operation failed.
            "error: --scope system requires root; run with sudo",
            "Failed to connect to bus: No such file or directory",
            // An unknown-argument rejection for some OTHER flag must not trigger a scope retry.
            "error: unexpected argument '--bogus' found",
            "",
        ] {
            assert!(
                !is_unknown_scope_flag_rejection(message),
                "must NOT be treated as a missing-flag compat case: {message}"
            );
        }
    }

    #[test]
    fn scope_describe_and_serialization_are_stable() {
        // `--json` consumers read these; a rename is a breaking change to the report schema.
        assert_eq!(
            serde_json::to_string(&ServiceScope::System).unwrap(),
            "\"system\""
        );
        assert_eq!(
            serde_json::to_string(&ServiceScope::User).unwrap(),
            "\"user\""
        );
        assert_eq!(
            serde_json::to_string(&AgentDisposition::SkipHeadless).unwrap(),
            "\"skip-headless\""
        );
        assert!(ServiceScope::System.describe().contains("system"));
    }
}
