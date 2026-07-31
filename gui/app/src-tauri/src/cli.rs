//! Command-line intent for the GUI executable.
//!
//! The installed `dig-installer.exe` under the protected bin root IS this Tauri
//! GUI binary: `apply_windows_hardening` persists `std::env::current_exe()`, and
//! on the normal user path the installing process is the GUI, not the CLI
//! thin-shim. The Add/Remove Programs entry it writes therefore points its
//! `UninstallString` at THIS executable with `--uninstall` (#854).
//!
//! Until now this binary ignored its argv entirely, so the OS Uninstall button
//! re-opened the installer window instead of uninstalling — the user-visible
//! bug. Classifying argv here (rather than in `main.rs`, which is a bin target
//! and cannot be unit-tested) keeps the decision falsifiable.

use std::ffi::OsString;

/// The flag the Add/Remove Programs `UninstallString` passes to this binary.
///
/// Byte-identical to the CLI thin-shim's own `--uninstall` and to the string
/// `dig_installer::hardening::arp_entry` bakes into the registry value; a drift
/// between the three silently restores the #854 symptom.
pub const UNINSTALL_ARG: &str = "--uninstall";

/// The optional modifier that plans the teardown without touching the machine.
pub const DRY_RUN_ARG: &str = "--dry-run";

/// What this invocation of the GUI executable is being asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Run the headless whole-stack teardown and exit without starting the
    /// WebView. `dry_run` only plans it.
    Uninstall { dry_run: bool },
    /// Start the normal interactive installer window.
    Gui,
}

/// Classify the process arguments (argv WITHOUT the program name).
///
/// Only an EXACT `--uninstall` selects the teardown. The per-component CLI
/// verbs share that prefix (`--uninstall-dig-node`, `--uninstall-dig-dns`,
/// `--uninstall-dig-updater`, `--uninstall-ext-forcelist`), so a prefix match
/// here would turn a request to remove ONE component into a whole-stack wipe.
pub fn intent_from_args<I>(args: I) -> Intent
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    if !args.iter().any(|a| a == UNINSTALL_ARG) {
        return Intent::Gui;
    }
    Intent::Uninstall {
        dry_run: args.iter().any(|a| a == DRY_RUN_ARG),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    /// The #854 regression, stated as the ARP button's own argv: Windows runs
    /// `"<installer>" --uninstall`, and that MUST NOT open the installer window.
    #[test]
    fn the_add_remove_programs_argv_selects_the_teardown() {
        assert_eq!(
            intent_from_args(args([UNINSTALL_ARG].as_slice())),
            Intent::Uninstall { dry_run: false }
        );
    }

    /// The control, without which "always uninstall" would satisfy the test
    /// above: a bare double-click is still the interactive installer.
    #[test]
    fn a_bare_launch_still_opens_the_gui() {
        assert_eq!(intent_from_args(args(&[])), Intent::Gui);
    }

    /// The distinguishing fixture. A `starts_with("--uninstall")` implementation
    /// passes both tests above while escalating every per-component verb into a
    /// whole-stack wipe — removing dig-node would also tear down dig-dns, the
    /// beacon and every binary. Only an exact match survives this arm.
    #[test]
    fn a_per_component_uninstall_verb_is_not_a_whole_stack_wipe() {
        for verb in [
            "--uninstall-dig-node",
            "--uninstall-dig-dns",
            "--uninstall-dig-updater",
            "--uninstall-ext-forcelist",
        ] {
            assert_eq!(
                intent_from_args(args(&[verb])),
                Intent::Gui,
                "{verb} must not select the whole-stack teardown"
            );
        }
    }

    /// `--dry-run` is only meaningful alongside the teardown, and must survive
    /// argument order.
    #[test]
    fn dry_run_is_carried_in_either_order() {
        assert_eq!(
            intent_from_args(args(&[UNINSTALL_ARG, DRY_RUN_ARG])),
            Intent::Uninstall { dry_run: true }
        );
        assert_eq!(
            intent_from_args(args(&[DRY_RUN_ARG, UNINSTALL_ARG])),
            Intent::Uninstall { dry_run: true }
        );
    }

    /// `--dry-run` on its own must never be mistaken for a teardown request.
    #[test]
    fn dry_run_alone_opens_the_gui() {
        assert_eq!(intent_from_args(args(&[DRY_RUN_ARG])), Intent::Gui);
    }
}
