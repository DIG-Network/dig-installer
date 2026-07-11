//! Robust release-asset selection: pick the right per-OS/arch asset out of a
//! release's *actual* asset list, instead of betting on one guessed filename.
//!
//! Why this exists (thin-shim resilience): the producing repos do not all use
//! the same asset-naming convention, and a convention can change between
//! releases. digstore's CLI release publishes `digstore-<ver>-<os_arch>[.exe]`,
//! while this repo's own GUI installer (migrated from digstore, built by
//! `release.yml`) publishes `DIG-Installer-Setup-<ver>-<os>.{exe,dmg,
//! AppImage}`; the DIG Browser publishes a native installer per OS
//! (`.exe`/`.dmg`/`.AppImage`). Rather than re-encode a single brittle template
//! (which 404s the moment a name varies), the installer fetches the release's
//! asset list from the GitHub API and **matches by OS/arch tokens + an accepted
//! file-extension set**, preferring the canonical templated name when present.
//!
//! This module is pure (no I/O): given the list of asset names and a target it
//! returns the best match, so the selection logic is unit-tested without a
//! network.

use crate::target::{Os, Target};

/// What kind of artifact a component publishes — drives which OS/arch tokens and
/// file extensions count as a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetKind {
    /// A raw executable placed on PATH (digstore CLI, dig-node). Matched by the
    /// `<os>-<arch>` slug and the platform exe extension (`.exe` / none).
    RawBinary,
    /// A native desktop installer (DIG Browser): `.exe` (Windows), `.dmg`
    /// (macOS), `.AppImage` (Linux) — one per OS, arch-agnostic.
    Installer,
}

/// The OS/arch tokens that identify an asset as built for `target`, most- to
/// least-specific. An asset name (lowercased) matching ANY of these tokens is a
/// candidate; the canonical slug is preferred via [`select_asset`]'s ordering.
///
/// The bare-OS tokens (`macos`/`darwin`/`linux`/`windows`) are deliberately last
/// so an arch-less asset (e.g. `...-macos.dmg`) still matches — but only when no
/// *competing* arch token is present (see [`competing_arch_tokens`]).
///
/// For Windows/Linux (single-arch platforms today) the bare arch token (`x64`)
/// is the LAST-resort fallback, lower priority even than the bare-OS token:
/// some producing repos' asset names encode neither the OS name nor a
/// `win`/`linux` prefix at all — e.g. DIG Browser's first release names its
/// Windows installer `ungoogled-chromium_<ver>_installer_x64.exe` (no
/// "win"/"windows" substring anywhere). The accepted-extension check
/// ([`accepted_extensions`]) already pins that asset to a single OS for a given
/// [`AssetKind`] (`.exe`/`.msi` only ever means Windows), so a bare arch token
/// is enough to place it once extension + competing-arch rejection have run —
/// and this stays indifferent to a product-name-prefix rebrand (e.g. to
/// `dig-browser_*`).
pub fn os_arch_tokens(target: &Target) -> Vec<&'static str> {
    match (target.os, target.arch) {
        (Os::Windows, _) => vec![
            "windows-x64",
            "win-x64",
            "win64",
            "x86_64-pc-windows",
            "windows",
            "x64",
        ],
        (Os::Linux, _) => vec![
            "linux-x64",
            "linux-x86_64",
            "x86_64-unknown-linux",
            "linux",
            "x64",
        ],
        (Os::MacOs, crate::target::Arch::Arm64) => {
            vec![
                "macos-arm64",
                "macos-aarch64",
                "darwin-arm64",
                "aarch64-apple-darwin",
                "macos",
                "darwin",
            ]
        }
        (Os::MacOs, crate::target::Arch::X64) => {
            vec![
                "macos-x64",
                "macos-x86_64",
                "darwin-x64",
                "x86_64-apple-darwin",
                "macos",
                "darwin",
            ]
        }
    }
}

/// Arch tokens that, if present in an asset name, mean it was built for a
/// DIFFERENT architecture than `target` — disqualifying it even when a generic
/// OS token also matches. Prevents a bare `macos` token from grabbing an
/// explicitly `macos-x64` asset for an arm64 host (a wrong-arch binary).
fn competing_arch_tokens(target: &Target) -> &'static [&'static str] {
    match (target.os, target.arch) {
        (Os::MacOs, crate::target::Arch::Arm64) => &["x64", "x86_64", "amd64", "intel"],
        (Os::MacOs, crate::target::Arch::X64) => &["arm64", "aarch64"],
        // Windows/Linux ship x64 today; an arm64-tagged asset is the competitor.
        (Os::Windows, _) | (Os::Linux, _) => &["arm64", "aarch64"],
    }
}

/// The file extensions that are valid for an asset of `kind` on `target.os`.
/// An empty entry (`""`) means "no extension" (unix raw binary).
pub fn accepted_extensions(kind: AssetKind, target: &Target) -> Vec<&'static str> {
    match (kind, target.os) {
        (AssetKind::RawBinary, Os::Windows) => vec![".exe"],
        (AssetKind::RawBinary, _) => vec!["", ".bin"],
        (AssetKind::Installer, Os::Windows) => vec![".exe", ".msi"],
        (AssetKind::Installer, Os::MacOs) => vec![".dmg", ".pkg"],
        (AssetKind::Installer, Os::Linux) => vec![".appimage", ".deb"],
    }
}

/// Does `name` end with one of `exts`? `""` matches "no recognised extension"
/// (i.e. a bare unix binary with no dot in its final path segment).
fn has_accepted_ext(name_lc: &str, exts: &[&str]) -> bool {
    for ext in exts {
        if ext.is_empty() {
            // "no extension": the final segment has no dot. (Version dots like
            // `0.6.0` are part of the stem; a true extension is the last dotted
            // suffix that isn't numeric.)
            if !looks_like_it_has_a_file_extension(name_lc) {
                return true;
            }
        } else if name_lc.ends_with(ext) {
            return true;
        }
    }
    false
}

/// Does `haystack` contain `token` delimited by non-alphanumerics (or string
/// ends)? Boundary-aware so `x64` matches in `macos-x64`/`macos_x64.dmg` but not
/// inside an unrelated run of characters. Used for competing-arch rejection.
fn contains_token(haystack: &str, token: &str) -> bool {
    let bytes = haystack.as_bytes();
    let tlen = token.len();
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(token) {
        let i = start + pos;
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let after = i + tlen;
        let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = i + 1;
    }
    false
}

/// Heuristic: does the final dotted suffix look like a file extension (alpha,
/// e.g. `.exe`/`.appimage`) rather than a version component (e.g. `.0`)?
fn looks_like_it_has_a_file_extension(name_lc: &str) -> bool {
    match name_lc.rsplit_once('.') {
        Some((_, suffix)) => !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_alphabetic()),
        None => false,
    }
}

/// Substrings that mark an asset as a GUI/desktop *installer* package, never a
/// raw CLI binary — so the RawBinary matcher never grabs a `DIG-Installer-Setup-*`
/// GUI exe and places it on PATH as the CLI.
const INSTALLER_NAME_MARKERS: &[&str] = &["setup", "installer", "-gui"];

/// Pick the best asset for `target` of `kind` from a release's `asset_names`,
/// where `stem` is the component's canonical binary stem (e.g. `digstore`,
/// `dig-node`, `dig-browser`).
///
/// Strategy (deterministic): among assets whose name contains an OS/arch token
/// AND has an accepted extension, prefer the one whose token appears **earliest**
/// in [`os_arch_tokens`] (most specific first); break ties by preferring a name
/// that starts with the canonical `stem`, then the shortest name.
///
/// For [`AssetKind::RawBinary`] a name matching an [`INSTALLER_NAME_MARKERS`]
/// pattern (e.g. `*-setup-*`) is rejected — a CLI binary and a GUI installer can
/// share the `.exe` extension and OS token, but only the former goes on PATH.
/// Returns `None` if no asset matches — the caller raises `ASSET_NOT_FOUND`.
pub fn select_asset(
    asset_names: &[String],
    target: &Target,
    kind: AssetKind,
    stem: &str,
) -> Option<String> {
    let tokens = os_arch_tokens(target);
    let exts = accepted_extensions(kind, target);
    let competing = competing_arch_tokens(target);
    let stem_lc = stem.to_ascii_lowercase();

    // (token_rank, stem_rank, name_len, name) — lower is better in each slot.
    let mut best: Option<(usize, usize, usize, &String)> = None;
    for name in asset_names {
        let name_lc = name.to_ascii_lowercase();
        if !has_accepted_ext(&name_lc, &exts) {
            continue;
        }
        // Skip detached checksum/signature sidecars — never the binary itself.
        if name_lc.ends_with(".sha256") || name_lc.ends_with(".asc") || name_lc.ends_with(".sig") {
            continue;
        }
        // A raw CLI binary is NOT a GUI installer package, even if both are .exe.
        if kind == AssetKind::RawBinary
            && INSTALLER_NAME_MARKERS.iter().any(|m| name_lc.contains(m))
        {
            continue;
        }
        // Reject an asset that explicitly carries a DIFFERENT arch token —
        // a wrong-arch binary would crash at runtime.
        if competing.iter().any(|t| contains_token(&name_lc, t)) {
            continue;
        }
        let Some(rank) = tokens.iter().position(|t| name_lc.contains(t)) else {
            continue;
        };
        // Prefer the canonical-stem name (rank 0) over an arbitrary match (1).
        let stem_rank = usize::from(!name_lc.starts_with(&stem_lc));
        let cand = (rank, stem_rank, name.len(), name);
        best = match best {
            None => Some(cand),
            Some((br, bs, bl, _)) if (rank, stem_rank, name.len()) < (br, bs, bl) => Some(cand),
            other => other,
        };
    }
    best.map(|(_, _, _, n)| n.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{Arch, Os};

    fn t(os: Os, arch: Arch) -> Target {
        Target { os, arch }
    }

    #[test]
    fn matches_canonical_digstore_cli_asset() {
        let names = vec![
            "digstore-0.6.0-windows-x64.exe".to_string(),
            "digstore-0.6.0-linux-x64".to_string(),
            "digstore-0.6.0-macos-arm64".to_string(),
            "digstore-0.6.0-macos-x64".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            Some("digstore-0.6.0-linux-x64".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            Some("digstore-0.6.0-windows-x64.exe".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::MacOs, Arch::Arm64),
                AssetKind::RawBinary,
                "digstore"
            ),
            Some("digstore-0.6.0-macos-arm64".to_string())
        );
    }

    #[test]
    fn macos_arm64_does_not_match_x64_asset() {
        // The x64 token must NOT satisfy an arm64 request (and vice-versa) — a
        // wrong-arch binary would crash at runtime.
        let names = vec!["digstore-0.6.0-macos-x64".to_string()];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::MacOs, Arch::Arm64),
                AssetKind::RawBinary,
                "digstore"
            ),
            None
        );
    }

    #[test]
    fn raw_binary_on_unix_rejects_installer_extensions() {
        // A `.AppImage`/`.dmg` is NOT a raw CLI binary even if the OS token matches.
        let names = vec![
            "DIG-Installer-Setup-0.6.1-linux-x86_64.AppImage".to_string(),
            "digstore-0.6.0-linux-x64".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            Some("digstore-0.6.0-linux-x64".to_string())
        );
    }

    #[test]
    fn raw_binary_never_picks_a_gui_setup_exe() {
        // Regression: dig-installer's own GUI setup bundle (`DIG-Installer-Setup-
        // *.exe`) is published alongside the raw CLI binary in the same release.
        // The RawBinary matcher must NOT place that GUI exe on PATH as `digstore`
        // — it returns None (→ ASSET_NOT_FOUND) until the real CLI binary is
        // published.
        let names = vec![
            "DIG-Installer-Setup-0.6.1-windows-x64.exe".to_string(),
            "DIG-Installer-Setup-0.6.1-macos.dmg".to_string(),
            "DIG-Installer-Setup-0.6.1-linux-x86_64.AppImage".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            None
        );
        // And once the real CLI binary IS present alongside the GUI, it wins.
        let mut with_cli = names.clone();
        with_cli.push("digstore-0.6.0-windows-x64.exe".to_string());
        assert_eq!(
            select_asset(
                &with_cli,
                &t(Os::Windows, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            Some("digstore-0.6.0-windows-x64.exe".to_string())
        );
    }

    #[test]
    fn installer_matches_per_os_native_package() {
        // DIG Browser-style native installers, one per OS.
        let names = vec![
            "DIG-Browser-1.0.0-windows-x64.exe".to_string(),
            "DIG-Browser-1.0.0-macos.dmg".to_string(),
            "DIG-Browser-1.0.0-linux-x86_64.AppImage".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::Installer,
                "dig-browser"
            ),
            Some("DIG-Browser-1.0.0-windows-x64.exe".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::MacOs, Arch::Arm64),
                AssetKind::Installer,
                "dig-browser"
            ),
            Some("DIG-Browser-1.0.0-macos.dmg".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::Installer,
                "dig-browser"
            ),
            Some("DIG-Browser-1.0.0-linux-x86_64.AppImage".to_string())
        );
    }

    #[test]
    fn installer_accepts_a_gui_setup_package() {
        // The Installer kind (unlike RawBinary) WELCOMES a `*-Setup-*` name — it's
        // exactly what a desktop installer is. `DIG-Installer-Setup-*` is this
        // repo's own GUI bundle naming (release.yml).
        let names = vec!["DIG-Installer-Setup-0.6.1-windows-x64.exe".to_string()];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::Installer,
                "dig-installer"
            ),
            Some("DIG-Installer-Setup-0.6.1-windows-x64.exe".to_string())
        );
    }

    #[test]
    fn installer_falls_back_to_bare_macos_dmg_without_arch() {
        // macOS .dmg often omits the arch ("...-macos.dmg") — the "macos" token
        // (least specific) still matches for both arm64 and x64.
        let names = vec!["DIG-Installer-Setup-0.6.1-macos.dmg".to_string()];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::MacOs, Arch::X64),
                AssetKind::Installer,
                "dig-installer"
            ),
            Some("DIG-Installer-Setup-0.6.1-macos.dmg".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::MacOs, Arch::Arm64),
                AssetKind::Installer,
                "dig-installer"
            ),
            Some("DIG-Installer-Setup-0.6.1-macos.dmg".to_string())
        );
    }

    #[test]
    fn installer_matches_current_dig_browser_alpha_asset_naming() {
        // Regression (#40): DIG Browser's actual first release
        // (149.0.7827.155-1.1-alpha) publishes an installer named
        // `ungoogled-chromium_<ver>_installer_x64.exe` — it carries NEITHER
        // "windows" nor "win" anywhere, only the bare arch token "x64", plus a
        // portable `_windows_x64.zip` sibling that IS os-tokened but is the
        // wrong extension for an Installer (that .zip is the portable build,
        // not the thing we want to run). The matcher must still resolve the
        // installer .exe via the extension (Windows-only for Installer) + the
        // bare "x64" fallback token, and must be indifferent to the
        // `ungoogled-chromium` product-name prefix so the tracked rebrand to
        // `dig-browser_*` (#39) keeps resolving with zero matcher changes.
        let names = vec![
            "ungoogled-chromium_149.0.7827.155-1.1_installer_x64.exe".to_string(),
            "ungoogled-chromium_149.0.7827.155-1.1_windows_x64.zip".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::Installer,
                "DIG-Browser"
            ),
            Some("ungoogled-chromium_149.0.7827.155-1.1_installer_x64.exe".to_string())
        );
    }

    #[test]
    fn bare_x64_fallback_still_rejects_an_arm64_tagged_windows_asset() {
        // The new bare-"x64" fallback token must not defeat the existing
        // competing-arch guard: an asset explicitly tagged arm64 is still
        // rejected for a Windows x64 target even though it has an accepted
        // extension.
        let names = vec!["tool_installer_arm64.exe".to_string()];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::Installer,
                "tool"
            ),
            None
        );
    }

    #[test]
    fn prefers_most_specific_token_then_canonical_stem() {
        // Both a specific and a generic asset match; the specific slug wins.
        let names = vec![
            "tool-macos.dmg".to_string(),       // generic "macos" token
            "tool-macos-arm64.dmg".to_string(), // specific "macos-arm64" token
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::MacOs, Arch::Arm64),
                AssetKind::Installer,
                "tool"
            ),
            Some("tool-macos-arm64.dmg".to_string())
        );
    }

    #[test]
    fn prefers_canonical_stem_on_token_tie() {
        // Two assets share the same (most-specific) token; the one starting with
        // the canonical stem wins over an unrelated sibling.
        let names = vec![
            "extras-linux-x64".to_string(),
            "digstore-linux-x64".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            Some("digstore-linux-x64".to_string())
        );
    }

    #[test]
    fn ignores_checksum_and_signature_sidecars() {
        let names = vec![
            "digstore-0.6.0-linux-x64.sha256".to_string(),
            "digstore-0.6.0-linux-x64.asc".to_string(),
            "digstore-0.6.0-linux-x64".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            Some("digstore-0.6.0-linux-x64".to_string())
        );
    }

    #[test]
    fn returns_none_when_no_asset_matches() {
        let names = vec!["release-notes.txt".to_string(), "source.tar.gz".to_string()];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            None
        );
        assert_eq!(
            select_asset(
                &[],
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            None
        );
    }

    #[test]
    fn windows_request_rejects_an_arm64_tagged_asset() {
        // Windows ships x64; an explicitly arm64 asset must not be chosen.
        let names = vec!["digstore-0.6.0-windows-arm64.exe".to_string()];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            None
        );
    }

    #[test]
    fn contains_token_is_boundary_aware() {
        assert!(contains_token("macos-x64", "x64"));
        assert!(contains_token("macos_x64.dmg", "x64"));
        assert!(contains_token("tool-x64", "x64"));
        // Not a delimited token (would be a false positive):
        assert!(!contains_token("max640", "x64"));
        assert!(!contains_token("linux", "x64"));
    }

    #[test]
    fn version_dots_are_not_mistaken_for_an_extension() {
        // A bare unix binary `digstore-0.6.0-linux-x64` has dots from the version
        // but no real extension — it must match RawBinary's "" extension.
        let names = vec!["digstore-0.6.0-linux-x64".to_string()];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            Some("digstore-0.6.0-linux-x64".to_string())
        );
    }
}
