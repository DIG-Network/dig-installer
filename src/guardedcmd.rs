//! The ONE way this crate spawns a binary it installed (#1748).
//!
//! # Why a type, and not a rule
//!
//! Root executing a binary out of a directory an unprivileged account can write is a complete privilege
//! escalation, so every such spawn must first check the directory. Enforcing that has been tried twice:
//!
//! 1. **a written-down list** of the files that spawn — it said four, a fifth existed, and the hardcoded
//!    count made the omission invisible. That fifth was proved to root code execution.
//! 2. **a derived source scan** — better, and it found a guard sitting one frame above its spawn. But it
//!    is a heuristic pretending to be an enumeration: measured at 8 of 17 evasion forms caught, and two of
//!    the misses were ordinary accidents rather than contrivances (a discarded verdict,
//!    `let _ = root_exec_guard(bin);` and a `pub(super) fn` whose body was attributed to a guarded
//!    sibling).
//!
//! A heuristic cannot be the guarantee, because the interesting case is always the one nobody thought of.
//! So the guarantee is moved into the compiler: [`GuardedCommand::for_installed_binary`] is the only
//! constructor, it CANNOT be built without running the guard, and `clippy.toml` forbids
//! `std::process::Command::new` everywhere else in the crate. An unguarded spawn of an installed binary
//! therefore fails the BUILD rather than failing a test that has to think of it first.
//!
//! # What this does not cover
//!
//! Spawning a trusted SYSTEM tool (`su`, `sh`, `id`, `launchctl`) is a different invariant — the path must
//! come from a fixed trusted directory list, never `$PATH` (`SPEC.md` §7.6, [`crate::elevation`]). Those
//! sites are allowed to use `Command::new` directly and are listed in the clippy allow-list by module.

// `Command::new` is denied crate-wide so an unguarded spawn of an INSTALLED binary cannot compile
// (`clippy.toml`, #1748 WU4). The spawns in this module are either trusted SYSTEM tools resolved from a
// fixed directory list (`SPEC.md` §7.6 — a different invariant with its own tests in `elevation`), test
// fixtures, or the guarded wrapper itself.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::process::Command;

/// A [`Command`] for a binary THIS INSTALLER PLACED, which by construction has passed
/// [`crate::secure::root_exec_guard`].
///
/// Holds the command rather than deref-ing to it so the guard cannot be sidestepped by constructing the
/// inner `Command` some other way: the only path to one is [`Self::for_installed_binary`].
pub struct GuardedCommand(Command);

impl GuardedCommand {
    /// Prepare to run `binary` — an installed component — after verifying the directory it lives in.
    ///
    /// `Err` when the guard refuses: the containing directory is group/other-writable, not root-owned, or
    /// its posture could not be established ([`crate::secure::InstallRootSecurity::is_blocking`]).
    /// Inert when unelevated, where executing a binary the user can already write is their own authority.
    ///
    /// The error is the guard's own message, which names the offending level and what to do about it.
    pub fn for_installed_binary(binary: &Path) -> Result<Self, String> {
        crate::secure::root_exec_guard(binary)?;
        Ok(Self(Command::new(binary)))
    }

    /// Add one argument.
    pub fn arg(&mut self, arg: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.0.arg(arg);
        self
    }

    /// Add several arguments.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.0.args(args);
        self
    }

    /// Run to completion, capturing stdout and stderr.
    pub fn output(&mut self) -> std::io::Result<std::process::Output> {
        use crate::proc::HideConsole;
        self.0.hide_console();
        self.0.output()
    }

    /// Run to completion, inheriting stdio, returning the exit status.
    pub fn status(&mut self) -> std::io::Result<std::process::ExitStatus> {
        use crate::proc::HideConsole;
        self.0.hide_console();
        self.0.status()
    }

    /// Consume this and hand back the underlying [`Command`], for a caller that must own it — the bounded
    /// `--version` probe needs a real `Command` to spawn and kill on a deadline.
    ///
    /// Safe to expose: the guard has already run to produce `self`. The invariant is that one cannot be
    /// BUILT without the guard, which the private field and single constructor enforce.
    pub fn into_command(self) -> Command {
        self.0
    }

    /// The underlying command, for the one caller that needs to set environment variables on it.
    ///
    /// The guard has already run by the time this exists, so handing out the inner command cannot bypass
    /// it — what must not be possible is building one WITHOUT the guard, and that is what the private
    /// field and the single constructor prevent.
    pub fn command_mut(&mut self) -> &mut Command {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    // Only the unix guard test constructs a `GuardedCommand`; the source-scan meta-test below reads
    // files and needs nothing from `super`, so on Windows this import would be dead.
    #[cfg(unix)]
    use super::*;

    /// The guard runs at construction, so a refusal means no process was ever spawned.
    ///
    /// The fixture is a WORLD-WRITABLE directory holding a binary — the shape the guard exists to refuse.
    /// Root-gated because the guard is deliberately inert unelevated (running a binary you can already
    /// write is your own authority), and the control asserts exactly that, so neither arm is vacuous.
    #[cfg(unix)]
    #[test]
    fn a_refused_directory_yields_no_command_at_all() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            crate::sources::fixture_root().join(format!("dig-guardedcmd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("dig-dns");
        std::fs::write(
            &bin,
            b"#!/bin/sh
exit 0
",
        )
        .unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let outcome = GuardedCommand::for_installed_binary(&bin);
        if crate::invoker::is_root() {
            assert!(
                outcome.is_err(),
                "root must not obtain a command for a binary in a world-writable directory - the \n                 whole point is that there is no way to spawn without the guard having passed"
            );
            // The control, on the SAME binary: tighten only the directory and the guard permits it, so the
            // refusal is about the posture rather than about refusing everything.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(GuardedCommand::for_installed_binary(&bin).is_ok());
        } else {
            // Their own authority: the guard is inert, and that is the documented contract.
            assert!(outcome.is_ok());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The crate spawns installed binaries ONLY through this type.
    ///
    /// The clippy `disallowed-methods` rule is what enforces this at build time; this test states the same
    /// invariant so it is visible in the suite and so a `clippy.toml` deletion is caught by `cargo test`
    /// as well as by the lint. It checks the CONVERSE of the lint: every file that spawns an
    /// installer-placed binary goes through `GuardedCommand`.
    #[test]
    fn installed_binaries_are_spawned_only_through_the_guarded_type() {
        let allowed_to_spawn_system_tools = [
            // Trusted-system-tool resolution (§7.6) — a different invariant, tested in `elevation`.
            "elevation.rs",
            "secure.rs",
            "proc.rs",
            "daemon_dir.rs",
            "dns/linux.rs",
            "dns/macos.rs",
            "dns/windows.rs",
            "firewall.rs",
            "forcelist/linux.rs",
            "forcelist/macos.rs",
            "forcelist/windows.rs",
            "hosts.rs",
            "scheme.rs",
            "svc.rs",
            "browsers.rs",
            "hardening.rs",
            "migrate.rs",
            "regaudit.rs",
            "beacon.rs",
            "paths.rs",
            "userwrite.rs",
            "pathcheck.rs",
            // Spawns only trusted OS trust-store tools (`certutil`/`security`/`update-ca-*`/`sh -c
            // command -v`) to install + revert the CA trust anchor, resolved absolutely on Windows
            // via `proc::system_tool` (#657). It never executes an INSTALLED binary — the arguments
            // are fixed cert paths + thumbprints, never a DIG binary path (#623/#858).
            "tlsroot.rs",
            // `msiexec.exe` and `taskkill.exe`/`pkill` — trusted system tools resolved absolutely
            // (`proc::system_tool` / `elevation::resolve_system_tool`). Neither ever spawns an
            // INSTALLED binary: msiexec is handed a validated ProductCode (`msi::ProductCode`, which
            // cannot hold a path) and the killers are handed an image NAME, not a path to execute.
            "msi.rs",
            "running.rs",
            // Spawns `explorer.exe` / `su` / `sh` to start dig-app in the USER's session (#1831). The
            // tool is trusted; the binary it goes on to run is put through `secure::root_exec_guard`
            // by `launch::carry_out`, which covers the one arrangement (a root-ACCOUNT install, so no
            // `su` delegation) where the launch would carry root's authority.
            "launch.rs",
            // The wrapper itself.
            "guardedcmd.rs",
        ];
        let mut offenders = Vec::new();
        for (file, src) in crate::sources::all() {
            if allowed_to_spawn_system_tools.contains(&file) {
                continue;
            }
            let production = src.split("\nmod tests {").next().unwrap_or("");
            for (number, line) in production.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains("Command::new(") {
                    offenders.push(format!("{file}:{}: {}", number + 1, line.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these spawn a process without going through GuardedCommand, so nothing forces the \
             root-exec guard to run first (#1748 WU4):\n{}",
            offenders.join("\n")
        );
    }
}
