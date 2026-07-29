//! This crate's own source text, for the invariants that are properties of the CODE rather than of a
//! value it computes.
//!
//! # Why this exists
//!
//! Some security invariants are structural: "every root-side exec calls the guard", "no root-side spawn
//! resolves a bare command name". A behavioural test cannot check those — it can only prove that ONE
//! call site behaves correctly, and the defect is always the site nobody remembered.
//!
//! The obvious way to write such a test is to list the files it should inspect. That was tried, and it
//! failed in the way lists always fail: the list said four files and asserted a count of four, a FIFTH
//! root-side exec existed, and the count made the omission invisible rather than visible. A hardcoded
//! inventory can only ever confirm what its author already believed.
//!
//! So the inventory is DERIVED. `include_str!` needs literal paths, but the compiler resolves them, so
//! the one thing that must stay honest is this list of modules — and [`all`] is checked against the
//! module declarations in `lib.rs` by its own test, which fails when a module is added to the crate and
//! not to this file. That turns "somebody forgot" from a silent gap into a failing build.

/// Every production source file in the crate, as `(display path, contents)`.
///
/// Sorted by path. `main.rs` is excluded: it is the binary's entry point, not part of the library, and
/// the structural invariants here are about library code the GUI also links.
pub fn all() -> Vec<(&'static str, &'static str)> {
    vec![
        ("asset.rs", include_str!("asset.rs")),
        ("autostart.rs", include_str!("autostart.rs")),
        ("beacon.rs", include_str!("beacon.rs")),
        ("browsers.rs", include_str!("browsers.rs")),
        ("daemon_dir.rs", include_str!("daemon_dir.rs")),
        ("dirfd.rs", include_str!("dirfd.rs")),
        ("dns/doctor.rs", include_str!("dns/doctor.rs")),
        ("dns/linux.rs", include_str!("dns/linux.rs")),
        ("dns/macos.rs", include_str!("dns/macos.rs")),
        ("dns/mod.rs", include_str!("dns/mod.rs")),
        ("dns/os_config.rs", include_str!("dns/os_config.rs")),
        ("dns/plan.rs", include_str!("dns/plan.rs")),
        ("dns/windows.rs", include_str!("dns/windows.rs")),
        ("download.rs", include_str!("download.rs")),
        ("elevation.rs", include_str!("elevation.rs")),
        ("error.rs", include_str!("error.rs")),
        ("firewall.rs", include_str!("firewall.rs")),
        ("forcelist/linux.rs", include_str!("forcelist/linux.rs")),
        ("forcelist/macos.rs", include_str!("forcelist/macos.rs")),
        ("forcelist/mod.rs", include_str!("forcelist/mod.rs")),
        ("forcelist/windows.rs", include_str!("forcelist/windows.rs")),
        ("guardedcmd.rs", include_str!("guardedcmd.rs")),
        ("hardening.rs", include_str!("hardening.rs")),
        ("health.rs", include_str!("health.rs")),
        ("hosts.rs", include_str!("hosts.rs")),
        ("invoker.rs", include_str!("invoker.rs")),
        ("lib.rs", include_str!("lib.rs")),
        ("manifest.rs", include_str!("manifest.rs")),
        ("migrate.rs", include_str!("migrate.rs")),
        ("pathcheck.rs", include_str!("pathcheck.rs")),
        ("paths.rs", include_str!("paths.rs")),
        ("proc.rs", include_str!("proc.rs")),
        ("regaudit.rs", include_str!("regaudit.rs")),
        ("release.rs", include_str!("release.rs")),
        ("rootchain.rs", include_str!("rootchain.rs")),
        ("scheme.rs", include_str!("scheme.rs")),
        ("secure.rs", include_str!("secure.rs")),
        ("service.rs", include_str!("service.rs")),
        ("sources.rs", include_str!("sources.rs")),
        ("svc.rs", include_str!("svc.rs")),
        ("target.rs", include_str!("target.rs")),
        ("uninstall.rs", include_str!("uninstall.rs")),
        ("update.rs", include_str!("update.rs")),
        ("userwrite.rs", include_str!("userwrite.rs")),
    ]
}

/// The directory test fixtures build their trees in.
///
/// # Why not `std::env::temp_dir()` (#1748 WU3)
///
/// `/tmp` is mode `1777`, and since the install-root verify walks EVERY level of a path, anything built
/// under it is correctly condemned as sitting beneath a world-writable ancestor. That is the verify being
/// right — but it made 23 lib tests fail when the suite runs AS ROOT, and it meant the one executable proof
/// of the root-exec guard could not pass in the only environment where it runs: skipped unprivileged,
/// failing as root, for a reason that has nothing to do with the property under test.
///
/// So the root gate runs in a container that bakes a purpose-made fixture root — root-owned, `0755`, not
/// sticky — and points `DIG_TEST_FIXTURE_ROOT` at it. Everywhere else this falls back to the system temp
/// directory, which is correct for the unprivileged runs where a writable ancestor is not a finding.
///
/// Fixing the fixture LOCATION rather than relaxing the verify is the whole point: the verify keeps its
/// teeth and the proofs become runnable.
#[cfg(test)]
pub fn fixture_root() -> std::path::PathBuf {
    match std::env::var("DIG_TEST_FIXTURE_ROOT") {
        Ok(dir) if !dir.is_empty() => std::path::PathBuf::from(dir),
        _ => std::env::temp_dir(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`all`] must cover every module the crate declares.
    ///
    /// This is the check that keeps the derived inventory honest: add a module to `lib.rs` without
    /// adding it here and the structural security scans would silently stop covering it, which is the
    /// hardcoded-list failure this module exists to prevent. Comparing against `lib.rs`'s own `pub mod`
    /// declarations means the crate itself is the source of truth.
    #[test]
    fn the_inventory_covers_every_module_the_crate_declares() {
        let lib = include_str!("lib.rs");
        let declared: Vec<&str> = lib
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub mod "))
            .filter_map(|l| l.split(';').next())
            .collect();
        assert!(
            declared.len() > 20,
            "the module-declaration scan found only {declared:?} — it has drifted and would pass \
             vacuously"
        );

        let covered = all();
        for module in declared {
            // `dns` is a directory module: its files are listed individually as `dns/*.rs`.
            let hit = covered.iter().any(|(path, _)| {
                *path == format!("{module}.rs") || path.starts_with(&format!("{module}/"))
            });
            assert!(
                hit,
                "module `{module}` is declared in lib.rs but missing from sources::all(), so every \
                 structural security scan silently skips it"
            );
        }
    }

    /// The contents really are the files, not empty strings — a `include_str!` pointing at the wrong
    /// place would make every scan pass by inspecting nothing.
    #[test]
    fn every_listed_source_has_real_content() {
        for (path, src) in all() {
            assert!(
                src.len() > 100,
                "{path} came back with {} bytes — the scans over it would be vacuous",
                src.len()
            );
        }
    }
}
