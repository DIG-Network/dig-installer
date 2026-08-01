//! Finding the service-manager units that ALREADY exist for a DIG engine service, so a
//! system-scope registration is not shadowed by one and does not double up on another
//! (dig_ecosystem#526).
//!
//! Two live collisions this closes, both of which end with two units for one service and only one of
//! them able to bind the node's port:
//!
//! * a **per-user leftover** — `~/.config/systemd/user/dignetwork-dig-node.service` from an
//!   unelevated run, or `/root/.config/systemd/user/…` from a pre-#526 `sudo` run — which
//!   `systemd --user` starts at the next login ALONGSIDE the system unit;
//! * the **distro-packaged unit** — `net.dignetwork.dig-node.service` from the apt.dig.net `.deb`,
//!   which is already enabled in the system domain, so delegating `install` on top of it registers a
//!   SECOND enabled unit for the same service.
//!
//! Relocating an artifact out of a directory closes nothing if that directory still WINS resolution,
//! which is why the shadow check is positional (`systemd --user` genuinely starts a user unit
//! regardless of what the system domain holds) rather than a tidy-up.
//!
//! # Layering
//!
//! This module only ENUMERATES what is on disk. Every decision about it — which paths to remove,
//! whether to adopt — is the pure [`crate::svcscope`], tested for all three operating systems from
//! any host.

use std::path::{Path, PathBuf};

use crate::svcscope::{ServiceScope, UnitRecord};
use crate::target::Os;

/// The systemd system-unit directories a packaged unit may live in, most-authoritative first.
///
/// `/etc/systemd/system` holds admin/installer-written units; `/lib` and `/usr/lib` hold PACKAGE
/// units (the `.deb`'s). Both `/lib` and `/usr/lib` are listed because on a usrmerge distribution
/// they are the same directory reached by two names, and on an older one they are not.
const SYSTEM_UNIT_DIRS: [&str; 3] = [
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
];

/// The directories that hold PACKAGE-shipped units — a unit found here is the distro package's, not
/// one this installer or an admin wrote.
const PACKAGED_UNIT_DIRS: [&str; 2] = ["/lib/systemd/system", "/usr/lib/systemd/system"];

/// Enumerate every existing unit/plist for service `id` on `os`.
///
/// `user_config_homes` are the `$XDG_CONFIG_HOME`s (or `~/Library`s on macOS) to search — the target
/// user's AND root's own, because a pre-#526 `sudo` install wrote into root's user scope where root
/// has no session bus to load it, so it is invisible to `systemctl` and to the user alike. They are
/// parameters rather than resolved here so the caller (which already knows the invoking user, #1748)
/// stays the single place that answers "whose scope?".
///
/// Windows returns nothing: the SCM has no per-user services and no unit files to enumerate — the
/// registration IS the service database entry, which [`crate::svc::scope_query`] reads directly.
pub fn existing_units(os: Os, id: &str, user_config_homes: &[PathBuf]) -> Vec<UnitRecord> {
    match os {
        Os::Windows => Vec::new(),
        Os::Linux => linux_units(id, user_config_homes),
        Os::MacOs => macos_units(id, user_config_homes),
    }
}

/// Linux: the derived systemd unit name in each system dir plus each user scope.
///
/// The unit NAME comes from [`crate::svc::linux_unit_name`] — the same derivation every DIG
/// registration goes through — except in the packaged dirs, where the `.deb` names its unit by the
/// FULL reverse-DNS id. Both are checked, because missing the packaged unit is what produces the
/// double registration.
fn linux_units(id: &str, user_config_homes: &[PathBuf]) -> Vec<UnitRecord> {
    let derived = format!("{}.service", crate::svc::linux_unit_name(id));
    let packaged_name = format!("{id}.service");
    let mut units = Vec::new();

    for dir in SYSTEM_UNIT_DIRS {
        let dir = Path::new(dir);
        let is_packaged_dir = PACKAGED_UNIT_DIRS.contains(&dir.to_string_lossy().as_ref());
        for name in [&derived, &packaged_name] {
            let path = dir.join(name);
            if !path.exists() {
                continue;
            }
            units.push(UnitRecord {
                path: path.clone(),
                scope: ServiceScope::System,
                // A unit in a package directory is the package's, whatever it is called.
                packaged: is_packaged_dir,
                enabled: systemd_unit_is_enabled(name),
            });
        }
    }

    for config_home in user_config_homes {
        let path = config_home.join("systemd/user").join(&derived);
        if path.exists() {
            units.push(UnitRecord {
                path,
                scope: ServiceScope::User,
                packaged: false,
                // A user unit's enablement cannot be read without that user's session bus, and it
                // does not matter: an unenabled user unit still shadows nothing, and an enabled one
                // is removed either way, so the safe answer is the one that keeps the record honest.
                enabled: false,
            });
        }
    }
    units
}

/// macOS: the system LaunchDaemon plus each user's LaunchAgent, both named by the FULL label (launchd
/// addresses a service by its label verbatim on every path this crate uses).
fn macos_units(id: &str, user_homes: &[PathBuf]) -> Vec<UnitRecord> {
    let plist = format!("{id}.plist");
    let mut units = Vec::new();
    let daemon = Path::new("/Library/LaunchDaemons").join(&plist);
    if daemon.exists() {
        units.push(UnitRecord {
            path: daemon,
            scope: ServiceScope::System,
            packaged: false,
            enabled: true,
        });
    }
    for home in user_homes {
        let agent = home.join("Library/LaunchAgents").join(&plist);
        if agent.exists() {
            units.push(UnitRecord {
                path: agent,
                scope: ServiceScope::User,
                packaged: false,
                enabled: false,
            });
        }
    }
    units
}

/// Is the systemd system unit `name` ENABLED (linked into a `.wants` directory)?
///
/// Read from the filesystem, not from `systemctl is-enabled`: this decides whether to SKIP delegating
/// an install, and a spawn that fails on a host without systemd would answer "not enabled" for a unit
/// that is. `multi-user.target.wants` is where an enabled boot-start unit is linked — the mechanism
/// that makes a registration survive a reboot with nobody logged in
/// ([`crate::svcscope::survives_reboot_without_login`]).
fn systemd_unit_is_enabled(name: &str) -> bool {
    [
        "/etc/systemd/system/multi-user.target.wants",
        "/etc/systemd/system/default.target.wants",
    ]
    .iter()
    .any(|dir| Path::new(dir).join(name).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_has_no_unit_files_to_enumerate() {
        // The SCM's service database is not a directory of files; `svc::scope_query` reads it.
        assert!(existing_units(
            Os::Windows,
            crate::svc::DIG_NODE_SERVICE_ID,
            &[PathBuf::from("C:/Users/alice/.config")]
        )
        .is_empty());
    }

    #[test]
    fn an_absent_service_enumerates_nothing_on_any_os() {
        // A host with no DIG install: every candidate path is absent, so nothing is reported — and in
        // particular no record is fabricated for a path that does not exist, which would make the
        // shadow removal delete files it never saw.
        let nowhere = PathBuf::from("/definitely/not/a/real/config/home-xyz");
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            assert!(
                existing_units(
                    os,
                    "net.dignetwork.dig-node-not-real-xyz",
                    std::slice::from_ref(&nowhere)
                )
                .is_empty(),
                "{os:?}"
            );
        }
    }

    #[test]
    fn a_user_scope_unit_is_found_under_each_config_home_that_has_one() {
        // Both scopes matter: the real user's AND root's own, which a pre-#526 `sudo` install wrote
        // into. Two config homes with one unit each, so an implementation that only ever looked at
        // the first would differ on this fixture.
        let tmp = tempfile::tempdir().expect("tempdir");
        let id = crate::svc::DIG_NODE_SERVICE_ID;
        let name = format!("{}.service", crate::svc::linux_unit_name(id));
        let mut homes = Vec::new();
        for account in ["alice", "root"] {
            let home = tmp.path().join(account).join(".config");
            std::fs::create_dir_all(home.join("systemd/user")).unwrap();
            std::fs::write(home.join("systemd/user").join(&name), "[Unit]").unwrap();
            homes.push(home);
        }

        let units = existing_units(Os::Linux, id, &homes);
        let user_paths: Vec<&Path> = units
            .iter()
            .filter(|u| u.scope == ServiceScope::User)
            .map(|u| u.path.as_path())
            .collect();
        assert_eq!(
            user_paths.len(),
            2,
            "both accounts' units must be found: {units:?}"
        );
        assert!(units.iter().all(|u| !u.packaged));

        // And the decision built on them removes BOTH when registering system-scope.
        let removals =
            crate::svcscope::shadowing_units_to_remove(Os::Linux, ServiceScope::System, &units);
        assert_eq!(removals.len(), 2, "{removals:?}");
    }

    #[test]
    fn a_macos_launch_agent_under_a_users_library_is_a_user_scope_record() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let id = crate::svc::DIG_NODE_SERVICE_ID;
        let agents = tmp.path().join("Library/LaunchAgents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::write(agents.join(format!("{id}.plist")), "<plist/>").unwrap();

        let units = existing_units(Os::MacOs, id, &[tmp.path().to_path_buf()]);
        assert_eq!(units.len(), 1, "{units:?}");
        assert_eq!(units[0].scope, ServiceScope::User);
        assert!(!units[0].packaged);
    }

    #[test]
    fn the_packaged_unit_directories_are_the_ones_a_deb_installs_into() {
        // A unit in `/etc/systemd/system` was written by an admin or by this installer; one in
        // `/lib`/`/usr/lib` came from the package. Confusing the two would either delete the
        // package's unit or double-register on top of it.
        assert!(PACKAGED_UNIT_DIRS
            .iter()
            .all(|d| SYSTEM_UNIT_DIRS.contains(d)));
        assert!(!PACKAGED_UNIT_DIRS.contains(&"/etc/systemd/system"));
    }
}
