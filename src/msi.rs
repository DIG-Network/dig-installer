//! Removing MSI-installed DIG components with `msiexec` (#854).
//!
//! # Why deleting files is not an uninstall
//!
//! Some DIG components ship a Windows Installer package alongside the raw binary — dig-node publishes
//! `dig-node-<ver>-windows-x64.msi`, and [`crate::asset::accepted_extensions`] accepts `.msi` for an
//! installer-kind asset. A product installed that way is registered in the **Windows Installer
//! database**, and that registration outlives its files: delete the binaries and you are left with a
//! ghost Add/Remove-Programs entry, a repair/modify that fails, and a later upgrade that believes an
//! older version is still present. The only correct removal is `msiexec /x`.
//!
//! # The ProductCode is found by UpgradeCode, never by name
//!
//! A ProductCode changes with (almost) every build, so it cannot be hardcoded — but the **UpgradeCode**
//! is stable for the life of the product and is compiled INTO the package
//! (`packaging/windows/dig-node.wxs` → `UpgradeCode="7E9B1C2D-…"`). Windows Installer indexes it at
//! `HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\<packed-upgrade-code>`, whose VALUE NAMES are the
//! packed ProductCodes currently installed for it. So a DIG-owned constant resolves to the exact
//! ProductCode on this machine, with no name matching at all.
//!
//! That matters more than it sounds: matching Add/Remove Programs entries by `DisplayName` is how an
//! uninstaller ends up running `msiexec /x` against somebody else's product. The name scan in
//! [`arp_msi_candidates`] exists only as a fallback for a DIG package whose UpgradeCode index is
//! missing, and it is conjunctive — DIG publisher AND a known DIG product name AND
//! `WindowsInstaller=1` AND a GUID-shaped key.
//!
//! `/x <ProductCode>` is also preferred over `/x <path.msi>` because by uninstall time the original
//! package file is usually long gone.

use serde::Serialize;

/// The `Manufacturer` every DIG MSI package declares (`dig-node.wxs`). Byte-identical with
/// [`crate::hardening::ARP_PUBLISHER`] — a DIG package that disagreed would not be recognised here.
pub const MSI_PUBLISHER: &str = "DIG Network";

/// A DIG MSI package this installer knows how to remove: its human name and the **stable UpgradeCode**
/// compiled into the package. Adding a DIG component that ships an MSI means adding one row here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MsiPackage {
    /// The component stem, matching [`crate::uninstall::COMPONENT_STEMS`].
    pub stem: &'static str,
    /// The `DisplayName` the package registers in Add/Remove Programs.
    pub display_name: &'static str,
    /// The package's stable UpgradeCode, in canonical `{8-4-4-4-12}` form.
    pub upgrade_code: &'static str,
}

/// Every DIG component known to ship a Windows Installer package.
///
/// `dig-node`'s UpgradeCode is the literal from `DIG-Network/dig-node`
/// `packaging/windows/dig-node.wxs`; it is a cross-repo byte-identical contract, so it must never be
/// "tidied" — changing it here silently stops finding installed nodes, and changing it there would
/// break the product's own upgrade path.
pub const MSI_PACKAGES: &[MsiPackage] = &[MsiPackage {
    stem: "dig-node",
    display_name: "DIG NETWORK: NODE",
    upgrade_code: "{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}",
}];

/// A validated Windows Installer ProductCode: canonical `{8-4-4-4-12}` upper-case hex.
///
/// Parsing is the whole point. `msiexec` is spawned with an argv, never a shell string, but the type
/// makes the question moot: a value that could carry a separator, a quote, or a path cannot be
/// constructed, so no call site can pass one — the guard is in the type rather than in a check some
/// future refactor forgets to keep (#1748's lesson applied to argument construction).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ProductCode(String);

impl ProductCode {
    /// The canonical braced form, e.g. `{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProductCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parse `s` as a ProductCode, accepting ONLY a canonical braced GUID (case-insensitively, normalised
/// to upper case). Anything else — an unbraced GUID, a path, a GUID with a command appended — is
/// `None`. Pure.
pub fn parse_product_code(s: &str) -> Option<ProductCode> {
    let t = s.trim();
    let inner = t.strip_prefix('{')?.strip_suffix('}')?;
    let groups: Vec<&str> = inner.split('-').collect();
    let expected = [8usize, 4, 4, 4, 12];
    if groups.len() != expected.len() {
        return None;
    }
    for (g, want) in groups.iter().zip(expected) {
        if g.len() != want || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
    }
    Some(ProductCode(t.to_ascii_uppercase()))
}

/// The `msiexec` argv that removes `code` with no UI and no automatic reboot.
///
/// `/qn` (fully silent) is required — an uninstall driven from Add/Remove Programs, winget, or MDM has
/// no console to answer a prompt on — and `/norestart` keeps the decision to reboot with the caller,
/// which reports it via [`MsiOutcome::RemovedRebootRequired`] instead. Pure.
pub fn uninstall_args(code: &ProductCode) -> Vec<String> {
    vec![
        "/x".to_string(),
        code.as_str().to_string(),
        "/qn".to_string(),
        "/norestart".to_string(),
    ]
}

/// What an `msiexec` exit code means for an uninstall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MsiOutcome {
    /// `ERROR_SUCCESS` — the product was removed.
    Removed,
    /// `ERROR_UNKNOWN_PRODUCT` (1605) — the product is not installed. The DESIRED end state, so the
    /// idempotent second run of an uninstall is a clean no-op, not a failure.
    AlreadyAbsent,
    /// `ERROR_SUCCESS_REBOOT_REQUIRED` (3010) / `ERROR_SUCCESS_REBOOT_INITIATED` (1641) — removed, but
    /// a file was in use; the removal completes at the next reboot. A success that must be REPORTED.
    RemovedRebootRequired,
    /// Anything else: a real failure, carrying the raw code.
    Failed(i32),
}

impl MsiOutcome {
    /// Did the product reach the desired end state (gone, or gone after the pending reboot)?
    pub fn ok(&self) -> bool {
        !matches!(self, MsiOutcome::Failed(_))
    }

    /// Is the product still registered with Windows Installer after this outcome? Only a genuine
    /// failure leaves it registered — a reboot-pending removal has already deregistered the product.
    pub fn still_registered(&self) -> bool {
        matches!(self, MsiOutcome::Failed(_))
    }
}

/// Classify an `msiexec` exit code. Pure — this is the decision the whole step turns on, so it is
/// tested directly rather than inferred from a log line.
pub fn classify_exit(code: i32) -> MsiOutcome {
    match code {
        0 => MsiOutcome::Removed,
        1605 => MsiOutcome::AlreadyAbsent,
        3010 | 1641 => MsiOutcome::RemovedRebootRequired,
        other => MsiOutcome::Failed(other),
    }
}

/// Compress a canonical GUID into the "packed" form Windows Installer uses as a registry key name:
/// the first three fields are reversed whole, and the remaining eight bytes have their two hex digits
/// swapped in place.
///
/// `{01234567-89AB-CDEF-0123-456789ABCDEF}` → `76543210BA98FEDC1032547698BADCFE`.
///
/// Pure, and the reason the UpgradeCode lookup can be exact: without it the DIG-owned UpgradeCode
/// constant cannot be turned into the registry key that names the installed ProductCode.
pub fn pack_guid(code: &ProductCode) -> String {
    let hex: Vec<char> = code
        .as_str()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    debug_assert_eq!(hex.len(), 32, "a validated ProductCode has 32 hex digits");
    let take = |from: usize, len: usize| -> String { hex[from..from + len].iter().rev().collect() };
    let mut out = String::with_capacity(32);
    out.push_str(&take(0, 8));
    out.push_str(&take(8, 4));
    out.push_str(&take(12, 4));
    for pair in hex[16..].chunks(2) {
        out.push(pair[1]);
        out.push(pair[0]);
    }
    out
}

/// Is an Add/Remove-Programs entry a DIG **MSI** product — the fallback identification used only when
/// the UpgradeCode index does not name the product?
///
/// Every clause is required. Publisher alone would fire on a hand-rolled entry; a name substring alone
/// would fire on unrelated products (an "Adobe Digital Editions" is not ours); `windows_installer`
/// alone says nothing about ownership; and a non-GUID key name is not a ProductCode, so `msiexec /x`
/// could not act on it anyway. Pure.
pub fn is_dig_msi_entry(
    key_name: &str,
    display_name: &str,
    publisher: &str,
    windows_installer: bool,
) -> bool {
    windows_installer
        && parse_product_code(key_name).is_some()
        && publisher.trim().eq_ignore_ascii_case(MSI_PUBLISHER)
        && MSI_PACKAGES
            .iter()
            .any(|p| display_name.trim().eq_ignore_ascii_case(p.display_name))
}

/// One MSI product the uninstall found and acted on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MsiRemoval {
    /// The component stem, when the product could be attributed to a known DIG package.
    pub stem: String,
    /// The ProductCode `msiexec /x` was invoked with.
    pub product_code: String,
    /// The outcome of that invocation.
    pub outcome: MsiOutcome,
    /// Human-readable detail.
    pub note: String,
}

/// Summarise the MSI step for the uninstall report: `(ok, note)`, where `ok` means every product
/// reached the desired end state. An empty list is success — no MSI-installed DIG product is present,
/// which is the common case on a raw-binary install. Pure.
pub fn summarise(removals: &[MsiRemoval]) -> (bool, String) {
    if removals.is_empty() {
        return (true, "no MSI-installed DIG product found".to_string());
    }
    let ok = removals.iter().all(|r| r.outcome.ok());
    let notes: Vec<String> = removals.iter().map(|r| r.note.clone()).collect();
    (ok, notes.join("; "))
}

// ---------------------------------------------------------------------------
// Windows I/O: resolve installed ProductCodes, and run msiexec.
// ---------------------------------------------------------------------------

/// The Windows Installer UpgradeCode index, relative to `HKLM`. Its subkeys are packed UpgradeCodes;
/// each subkey's VALUE NAMES are the packed ProductCodes installed for it.
#[cfg(windows)]
const UPGRADE_CODES_KEY: &str = r"SOFTWARE\Classes\Installer\UpgradeCodes";

/// The machine-wide Add/Remove Programs hive, relative to `HKLM`.
#[cfg(windows)]
const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

/// Expand a packed ProductCode back into its canonical braced form — the inverse of [`pack_guid`].
/// Pure, so the round-trip is provable without a registry.
pub fn unpack_guid(packed: &str) -> Option<ProductCode> {
    let hex: Vec<char> = packed.chars().collect();
    if hex.len() != 32 || !hex.iter().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let take = |from: usize, len: usize| -> String { hex[from..from + len].iter().rev().collect() };
    let mut tail = String::new();
    for pair in hex[16..].chunks(2) {
        tail.push(pair[1]);
        tail.push(pair[0]);
    }
    let s = format!(
        "{{{}-{}-{}-{}-{}}}",
        take(0, 8),
        take(8, 4),
        take(12, 4),
        &tail[..4],
        &tail[4..]
    );
    parse_product_code(&s)
}

/// Every installed ProductCode registered against `package`'s UpgradeCode on this machine.
///
/// The exact path: a DIG-owned UpgradeCode constant → the packed registry key → the packed
/// ProductCodes Windows Installer itself recorded. No name matching, so this can never name another
/// vendor's product.
#[cfg(windows)]
fn product_codes_by_upgrade_code(package: &MsiPackage) -> Vec<ProductCode> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let Some(upgrade) = parse_product_code(package.upgrade_code) else {
        return Vec::new();
    };
    let path = format!("{UPGRADE_CODES_KEY}\\{}", pack_guid(&upgrade));
    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(&path, KEY_READ) else {
        return Vec::new();
    };
    key.enum_values()
        .filter_map(|v| v.ok())
        .filter_map(|(name, _)| unpack_guid(&name))
        .collect()
}

/// DIG MSI products found by scanning Add/Remove Programs — the fallback for a package whose
/// UpgradeCode index is missing. Returns `(stem, ProductCode)` pairs.
#[cfg(windows)]
fn arp_msi_candidates() -> Vec<(String, ProductCode)> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let Ok(root) =
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(UNINSTALL_KEY, KEY_READ)
    else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for name in root.enum_keys().filter_map(|k| k.ok()) {
        let Ok(entry) = root.open_subkey_with_flags(&name, KEY_READ) else {
            continue;
        };
        let display: String = entry.get_value("DisplayName").unwrap_or_default();
        let publisher: String = entry.get_value("Publisher").unwrap_or_default();
        let windows_installer = entry.get_value::<u32, _>("WindowsInstaller").unwrap_or(0) == 1;
        if !is_dig_msi_entry(&name, &display, &publisher, windows_installer) {
            continue;
        }
        let Some(code) = parse_product_code(&name) else {
            continue;
        };
        let stem = MSI_PACKAGES
            .iter()
            .find(|p| display.trim().eq_ignore_ascii_case(p.display_name))
            .map(|p| p.stem.to_string())
            .unwrap_or_else(|| display.clone());
        found.push((stem, code));
    }
    found
}

/// Every MSI-installed DIG product currently registered on this machine, as `(stem, ProductCode)`.
/// UpgradeCode-indexed products first, then any Add/Remove-Programs fallback match not already found.
#[cfg(windows)]
pub fn installed_dig_products() -> Vec<(String, ProductCode)> {
    let mut found: Vec<(String, ProductCode)> = Vec::new();
    for package in MSI_PACKAGES {
        for code in product_codes_by_upgrade_code(package) {
            found.push((package.stem.to_string(), code));
        }
    }
    for (stem, code) in arp_msi_candidates() {
        if !found.iter().any(|(_, c)| *c == code) {
            found.push((stem, code));
        }
    }
    found
}

/// No Windows Installer database off Windows, so nothing is ever MSI-installed.
#[cfg(not(windows))]
pub fn installed_dig_products() -> Vec<(String, ProductCode)> {
    Vec::new()
}

/// Run `msiexec /x <code> /qn /norestart` and classify the result.
///
/// `msiexec.exe` is resolved to its absolute `System32` path via [`crate::proc::system_tool`], never
/// looked up on `PATH`: this runs elevated, and Windows searches the current directory before
/// System32 (the #1791/#1748 PATH-hijack class). The arguments are passed as an argv — no shell, and
/// [`ProductCode`] cannot hold anything a shell would care about anyway.
#[cfg(windows)]
pub fn remove_product(code: &ProductCode) -> MsiOutcome {
    use crate::proc::HideConsole;
    use std::process::Command;

    // `msiexec.exe` is a trusted SYSTEM tool resolved to its absolute System32 path by
    // `proc::system_tool` (never `PATH`, never the current directory), so it is not an installed
    // binary and does not go through the `GuardedCommand` exec guard (#1748 WU4 / SPEC.md §7.6).
    #[allow(clippy::disallowed_methods)]
    let out = Command::new(crate::proc::system_tool("msiexec"))
        .args(uninstall_args(code))
        .hide_console()
        .output();
    match out {
        // `msiexec` always terminates with a code; `None` (killed by a signal) is a failure we cannot
        // classify, reported as -1 rather than silently treated as success.
        Ok(o) => classify_exit(o.status.code().unwrap_or(-1)),
        Err(_) => MsiOutcome::Failed(-1),
    }
}

#[cfg(not(windows))]
pub fn remove_product(_code: &ProductCode) -> MsiOutcome {
    MsiOutcome::AlreadyAbsent
}

/// Remove every MSI-installed DIG product, returning one [`MsiRemoval`] per product acted on.
/// An empty result means none were installed — the common case, and a success.
pub fn remove_all_dig_products(dry_run: bool) -> Vec<MsiRemoval> {
    installed_dig_products()
        .into_iter()
        .map(|(stem, code)| {
            if dry_run {
                return MsiRemoval {
                    note: format!("would remove {stem} via msiexec /x {code}"),
                    stem,
                    product_code: code.as_str().to_string(),
                    outcome: MsiOutcome::Removed,
                };
            }
            let outcome = remove_product(&code);
            let note = match outcome {
                MsiOutcome::Removed => format!("{stem}: removed MSI product {code}"),
                MsiOutcome::AlreadyAbsent => format!("{stem}: MSI product {code} already absent"),
                MsiOutcome::RemovedRebootRequired => {
                    format!("{stem}: removed MSI product {code} — a reboot is required to finish")
                }
                MsiOutcome::Failed(c) => {
                    format!("{stem}: msiexec /x {code} failed with exit code {c}")
                }
            };
            MsiRemoval {
                stem,
                product_code: code.as_str().to_string(),
                outcome,
                note,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_canonical_braced_guid_parses_and_normalises_to_upper_case() {
        let c = parse_product_code("{7e9b1c2d-3a4f-4b5c-8d6e-1f2a3b4c5d6e}").expect("valid GUID");
        assert_eq!(c.as_str(), "{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}");
    }

    /// A ProductCode that could carry a second command, a path, or a quote must be UNCONSTRUCTIBLE —
    /// then no call site can pass one to `msiexec`, whatever it does with the value.
    #[test]
    fn nothing_but_a_bare_braced_guid_parses() {
        for bad in [
            "{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E} & calc.exe",
            "7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E",
            "{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6}",
            "{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6EE}",
            "{ZE9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}",
            r"C:\Program Files\DIG\dig-node.msi",
            "",
            "{}",
        ] {
            assert!(
                parse_product_code(bad).is_none(),
                "must not parse as a ProductCode: {bad:?}"
            );
        }
    }

    #[test]
    fn the_uninstall_argv_is_silent_and_never_reboots_by_itself() {
        let c = parse_product_code(MSI_PACKAGES[0].upgrade_code).unwrap();
        assert_eq!(
            uninstall_args(&c),
            vec![
                "/x".to_string(),
                "{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}".to_string(),
                "/qn".to_string(),
                "/norestart".to_string()
            ]
        );
    }

    /// The exit-code contract, from BOTH sides. 1605 ("this product is not installed") is the case an
    /// idempotent uninstall hits every second run: read as a failure it fails the whole run for a
    /// machine that is already in the desired state — and it is distinct from 0, which is why the test
    /// checks the classification and not merely `ok()`.
    #[test]
    fn msiexec_exit_codes_are_classified_by_their_documented_meaning() {
        assert_eq!(classify_exit(0), MsiOutcome::Removed);
        assert_eq!(classify_exit(1605), MsiOutcome::AlreadyAbsent);
        assert!(classify_exit(1605).ok(), "1605 is the desired end state");
        assert!(!classify_exit(1605).still_registered());
        assert_eq!(classify_exit(3010), MsiOutcome::RemovedRebootRequired);
        assert_eq!(classify_exit(1641), MsiOutcome::RemovedRebootRequired);
        assert!(classify_exit(3010).ok());
        // A real failure must NOT be swallowed — 1603 is the everyday "fatal error during
        // installation", and 1618 is "another installation is in progress".
        assert_eq!(classify_exit(1603), MsiOutcome::Failed(1603));
        assert!(!classify_exit(1603).ok());
        assert!(classify_exit(1603).still_registered());
        assert!(!classify_exit(1618).ok());
    }

    /// The documented packed-GUID transformation, on the canonical worked example: the first three
    /// fields reverse whole, the last eight bytes swap their hex digits in place.
    #[test]
    fn packing_a_guid_matches_the_windows_installer_compressed_form() {
        let c = parse_product_code("{01234567-89AB-CDEF-0123-456789ABCDEF}").unwrap();
        assert_eq!(pack_guid(&c), "76543210BA98FEDC1032547698BADCFE");
    }

    /// Packing is only useful if it names the RIGHT key, so prove the transform is a bijection on a
    /// value whose every field differs — a transposition bug that happened to be self-inverse would
    /// survive a round-trip of a palindromic GUID.
    #[test]
    fn packing_round_trips_through_unpacking() {
        for guid in [
            "{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}",
            "{01234567-89AB-CDEF-0123-456789ABCDEF}",
        ] {
            let c = parse_product_code(guid).unwrap();
            assert_eq!(unpack_guid(&pack_guid(&c)).as_ref(), Some(&c));
        }
    }

    #[test]
    fn a_packed_guid_that_is_not_32_hex_digits_is_rejected() {
        assert!(unpack_guid("not-a-packed-guid").is_none());
        assert!(unpack_guid("76543210BA98FEDC1032547698BADCF").is_none());
        assert!(unpack_guid("").is_none());
    }

    /// The dig-node UpgradeCode is a cross-repo contract with `dig-node/packaging/windows/dig-node.wxs`.
    /// A typo here does not fail loudly — it simply never finds the installed node — so it is pinned.
    #[test]
    fn the_dig_node_package_row_matches_its_wxs_contract() {
        let node = MSI_PACKAGES
            .iter()
            .find(|p| p.stem == "dig-node")
            .expect("dig-node ships an MSI");
        assert_eq!(node.upgrade_code, "{7E9B1C2D-3A4F-4B5C-8D6E-1F2A3B4C5D6E}");
        assert_eq!(node.display_name, "DIG NETWORK: NODE");
        assert!(parse_product_code(node.upgrade_code).is_some());
        assert_eq!(MSI_PUBLISHER, crate::hardening::ARP_PUBLISHER);
    }

    /// The fallback name scan is the dangerous one: it is what could point `msiexec /x` at another
    /// vendor's product. Each case below flips exactly ONE clause of the conjunction, so a matcher
    /// that dropped that clause fails here rather than passing on the strength of the others.
    #[test]
    fn the_arp_fallback_matches_only_a_dig_msi_product() {
        let code = "{11111111-2222-3333-4444-555555555555}";
        assert!(is_dig_msi_entry(
            code,
            "DIG NETWORK: NODE",
            "DIG Network",
            true
        ));
        // Someone else's product that merely reads like ours.
        assert!(!is_dig_msi_entry(
            code,
            "Adobe Digital Editions",
            "Adobe Systems",
            true
        ));
        // Our name, another publisher.
        assert!(!is_dig_msi_entry(
            code,
            "DIG NETWORK: NODE",
            "Contoso",
            true
        ));
        // Our publisher, a product we do not ship an MSI for.
        assert!(!is_dig_msi_entry(
            code,
            "DIG Network Relay",
            "DIG Network",
            true
        ));
        // Not a Windows Installer product at all — `msiexec /x` would be wrong.
        assert!(!is_dig_msi_entry(
            code,
            "DIG NETWORK: NODE",
            "DIG Network",
            false
        ));
        // A non-GUID key name is not a ProductCode.
        assert!(!is_dig_msi_entry(
            "DIG_Network",
            "DIG NETWORK: NODE",
            "DIG Network",
            true
        ));
    }

    #[test]
    fn no_msi_product_installed_is_a_success_not_a_gap() {
        let (ok, note) = summarise(&[]);
        assert!(ok);
        assert!(note.contains("no MSI-installed DIG product"));
    }

    /// A reboot-pending removal is a SUCCESS that must still be visible in the note — the caller has
    /// to tell the user, and a step that reported it as a plain failure would fail a clean uninstall.
    #[test]
    fn a_reboot_pending_removal_is_ok_and_reported() {
        let r = MsiRemoval {
            stem: "dig-node".into(),
            product_code: "{11111111-2222-3333-4444-555555555555}".into(),
            outcome: MsiOutcome::RemovedRebootRequired,
            note: "dig-node: removed — a reboot is required to finish".into(),
        };
        let (ok, note) = summarise(std::slice::from_ref(&r));
        assert!(ok);
        assert!(note.contains("reboot"));
    }

    #[test]
    fn a_failed_removal_fails_the_step() {
        let r = MsiRemoval {
            stem: "dig-node".into(),
            product_code: "{11111111-2222-3333-4444-555555555555}".into(),
            outcome: MsiOutcome::Failed(1603),
            note: "dig-node: msiexec failed with 1603".into(),
        };
        assert!(!summarise(&[r]).0);
    }
}
