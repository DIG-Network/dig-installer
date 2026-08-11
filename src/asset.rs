//! Robust release-asset selection: pick the right per-OS/arch asset out of a
//! release's *actual* asset list, instead of betting on one guessed filename.
//!
//! Why this exists (thin-shim resilience): the producing repos do not all use
//! the same asset-naming convention, and a convention can change between
//! releases. dig-store's CLI release publishes `dig-store-<ver>-<os_arch>[.exe]`,
//! while this repo's own GUI installer (migrated from dig-store, built by
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
    /// A raw executable placed on PATH (dig-store CLI, dig-node). Matched by the
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
/// where `stem` is the component's canonical binary stem (e.g. `dig-store`,
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
    matched_candidates(asset_names, target, kind, stem)
        .into_iter()
        .next()
        .map(|c| c.name.clone())
}

/// One release asset that matched `target`/`kind`/`stem`, with the ranking keys
/// [`select_asset`] orders by. Kept as a struct (not a bare tuple) so the
/// variant-aware selector ([`select_loadable_variant`]) can order by
/// [`Self::variant_rank`] AHEAD of these without re-deriving them.
struct Candidate<'a> {
    name: &'a String,
    /// Lowercased once, reused by the variant classifier.
    name_lc: String,
    /// Position in [`os_arch_tokens`] — most-specific first (lower is better).
    token_rank: usize,
    /// `0` when the name starts with the canonical stem, else `1`.
    stem_rank: usize,
}

impl Candidate<'_> {
    /// The base ordering key, most-significant first — the exact tuple
    /// [`select_asset`] historically compared, so single-variant selection is
    /// byte-for-byte unchanged.
    fn base_rank(&self) -> (usize, usize, usize) {
        (self.token_rank, self.stem_rank, self.name.len())
    }

    /// Preference rank among a component's build variants: the default (tray)
    /// build first, the `-headless` build second. A component that ships both a
    /// GTK-linked tray build and a GTK-less `-headless` build publishes two
    /// assets that BOTH carry the same OS/arch slug (e.g. `…-linux-x64` and
    /// `…-linux-x64-headless`), so this is the ONLY key that distinguishes them
    /// — and it is deliberately ordered ahead of the shortest-name tiebreak,
    /// which would otherwise always pick the (shorter) tray name.
    fn variant_rank(&self) -> usize {
        usize::from(self.name_lc.contains("-headless"))
    }

    /// The human-facing variant label surfaced in the install report.
    fn variant_label(&self) -> &'static str {
        if self.variant_rank() == 0 {
            "tray"
        } else {
            "headless"
        }
    }
}

/// Every asset that is a valid build for `target`/`kind`/`stem`, ordered
/// best-first by [`Candidate::base_rank`]. The shared core of [`select_asset`]
/// (which takes the first) and [`select_loadable_variant`] (which re-orders by
/// variant preference and then probes loadability).
fn matched_candidates<'a>(
    asset_names: &'a [String],
    target: &Target,
    kind: AssetKind,
    stem: &str,
) -> Vec<Candidate<'a>> {
    let tokens = os_arch_tokens(target);
    let exts = accepted_extensions(kind, target);
    let competing = competing_arch_tokens(target);
    let stem_lc = stem.to_ascii_lowercase();

    let mut candidates: Vec<Candidate<'a>> = Vec::new();
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
        // A RawBinary asset must BELONG to this component: its name is
        // `{stem}-{version}-{os_arch}[-variant][.ext]`, so it MUST start with
        // `{stem}-`. Anchoring on the base name (not merely the OS/arch token) is
        // what keeps a sibling binary published in the SAME release out of this
        // component's candidate set — e.g. `dign-<ver>-linux-x64` (the dign CLI)
        // ships alongside `dig-app-<ver>-linux-x64` in the dig-app release and
        // matches the same `linux-x64` slug, but it is NOT a dig-app build and
        // must never be installed as one (dig_ecosystem#1774/#1753). The `-`
        // boundary is decisive: `dign-…` does not start with `dig-app-`.
        //
        // Installer assets are deliberately NOT anchored — a native installer
        // legitimately carries a product name unrelated to the stem (DIG Browser
        // ships `ungoogled-chromium_<ver>_installer_x64.exe`), so that kind keeps
        // resolving via the OS/arch token + `stem_rank` preference below.
        if kind == AssetKind::RawBinary && !name_lc.starts_with(&format!("{stem_lc}-")) {
            continue;
        }
        // Reject an asset that explicitly carries a DIFFERENT arch token —
        // a wrong-arch binary would crash at runtime.
        if competing.iter().any(|t| contains_token(&name_lc, t)) {
            continue;
        }
        let Some(token_rank) = tokens.iter().position(|t| name_lc.contains(t)) else {
            continue;
        };
        // Prefer the canonical-stem name (rank 0) over an arbitrary match (1).
        let stem_rank = usize::from(!name_lc.starts_with(&stem_lc));
        candidates.push(Candidate {
            name,
            name_lc,
            token_rank,
            stem_rank,
        });
    }
    candidates.sort_by_key(Candidate::base_rank);
    candidates
}

/// Re-exported from the shared contract so a consumer can spell the oracle's
/// return type without a second dependency line.
pub use dig_release_resolver::loadability::Loadability;

/// The outcome of picking a build among a component's OS/arch-matched variants,
/// with the host's loadability verdict folded in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantOutcome {
    /// A variant was chosen. `loadable` is `true` for a proven-[`Loadability::Loadable`]
    /// pick and `false` for a permissively-chosen [`Loadability::Indeterminate`]
    /// one (a non-ELF artifact, or a host whose library set could not be
    /// established) — never for an `Unloadable` one, which is refused instead.
    Selected {
        asset: String,
        /// `"tray"` or `"headless"`.
        variant: &'static str,
        loadable: bool,
    },
    /// EVERY matched variant is [`Loadability::Unloadable`] on this host — the
    /// installer must NOT place any of them (that is the #1753 regression this
    /// selector exists to prevent). Carries the first refusal, phrased for an
    /// operator.
    Refused { reason: String },
    /// No asset matched this OS/arch at all — the caller raises `ASSET_NOT_FOUND`,
    /// exactly as [`select_asset`] returning `None` does.
    NoCandidate,
}

/// Pick the build a component should install for `target`, among its OS/arch
/// variants, preferring the first that the host can actually LOAD.
///
/// Preference order is tray → headless (via [`Candidate::variant_rank`]), so a
/// desktop host that can load the tray build gets it, and a GTK-less server
/// falls through to the `-headless` build instead of being handed the GTK-linked
/// tray build the shortest-name tiebreak would otherwise steal (#1753/#1774).
///
/// `loadable` is the injected oracle: given an asset NAME it answers that build's
/// [`Loadability`] on this host. It is a parameter — never an execution — so this
/// stays pure and unit-testable on any OS; production wires it to a closure that
/// downloads the candidate and PARSES its ELF via
/// `dig_release_resolver::loadability::inspect_artifact` (the artifact is read,
/// never run — executing a candidate under a root beacon could seal a seed).
///
/// The three-valued verdict is asymmetric (the shared crate's contract): only an
/// `Unloadable` variant is skipped. `Loadable` is taken immediately; an
/// `Indeterminate` variant is taken permissively if no `Loadable` one is found —
/// refusing what cannot be proven harmful would strand a musl host or a
/// non-ELF artifact forever. All variants `Unloadable` → [`VariantOutcome::Refused`].
pub fn select_loadable_variant(
    asset_names: &[String],
    target: &Target,
    kind: AssetKind,
    stem: &str,
    loadable: &dyn Fn(&str) -> Loadability,
) -> VariantOutcome {
    let mut candidates = matched_candidates(asset_names, target, kind, stem);
    if candidates.is_empty() {
        return VariantOutcome::NoCandidate;
    }
    // Variant preference DOMINATES the base rank, so tray is probed before
    // headless even though the (shorter) tray name would win the base tiebreak.
    candidates.sort_by(|a, b| {
        a.variant_rank()
            .cmp(&b.variant_rank())
            .then_with(|| a.base_rank().cmp(&b.base_rank()))
    });

    let mut permissive: Option<(&Candidate, String)> = None;
    let mut first_refusal: Option<String> = None;
    for candidate in &candidates {
        match loadable(candidate.name) {
            Loadability::Loadable => {
                return VariantOutcome::Selected {
                    asset: candidate.name.clone(),
                    variant: candidate.variant_label(),
                    loadable: true,
                };
            }
            indeterminate @ Loadability::Indeterminate { .. } => {
                // Remember the FIRST (highest-preference) indeterminate build as
                // the fallback, but keep looking for a provably loadable one.
                if permissive.is_none() {
                    let why = match &indeterminate {
                        Loadability::Indeterminate { why } => why.clone(),
                        _ => unreachable!("matched the Indeterminate arm"),
                    };
                    permissive = Some((candidate, why));
                }
            }
            refused @ (Loadability::Unloadable { .. } | Loadability::WrongMachine { .. }) => {
                if first_refusal.is_none() {
                    first_refusal = refused.refusal();
                }
            }
        }
    }

    if let Some((candidate, _why)) = permissive {
        return VariantOutcome::Selected {
            asset: candidate.name.clone(),
            variant: candidate.variant_label(),
            loadable: false,
        };
    }
    VariantOutcome::Refused {
        reason: first_refusal
            .unwrap_or_else(|| "every build variant is unloadable on this host".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{Arch, Os};

    fn t(os: Os, arch: Arch) -> Target {
        Target { os, arch }
    }

    #[test]
    fn matches_canonical_dig_store_cli_asset() {
        // Post-#703 the CLI asset stem is `dig-store` (was `digstore`).
        let names = vec![
            "dig-store-0.14.0-windows-x64.exe".to_string(),
            "dig-store-0.14.0-linux-x64".to_string(),
            "dig-store-0.14.0-macos-arm64".to_string(),
            "dig-store-0.14.0-macos-x64".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-store"
            ),
            Some("dig-store-0.14.0-linux-x64".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::RawBinary,
                "dig-store"
            ),
            Some("dig-store-0.14.0-windows-x64.exe".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::MacOs, Arch::Arm64),
                AssetKind::RawBinary,
                "dig-store"
            ),
            Some("dig-store-0.14.0-macos-arm64".to_string())
        );
    }

    #[test]
    fn matches_legacy_digstore_cli_asset_for_the_fallback() {
        // The transitional legacy fallback (epic #703) resolves the pre-rename
        // `digstore-*` stem against a release cut before the asset rename.
        let names = vec![
            "digstore-0.13.0-linux-x64".to_string(),
            "digstore-0.13.0-windows-x64.exe".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "digstore"
            ),
            Some("digstore-0.13.0-linux-x64".to_string())
        );
    }

    #[test]
    fn matches_canonical_digs_cli_asset() {
        // digs (issue #434) is published in the SAME digstore release, alongside
        // digstore, under its own asset stem: digs-<ver>-<os_arch>[.exe]. The
        // RawBinary matcher must resolve it with ZERO new matcher logic — the
        // same `select_asset` parameterized on stem "digs" instead of "digstore".
        //
        // This is a genuine edge case worth locking down: "digs" is a STRING
        // PREFIX of "digstore", so both names satisfy the stem_rank tie
        // ("digstore-...".starts_with("digs") is true too) — the tie is broken
        // by shortest-name, and "digs-<ver>-<slug>" is always exactly 4 bytes
        // shorter than "digstore-<ver>-<slug>", so it deterministically wins
        // when the caller asks for stem "digs".
        let names = vec![
            "digstore-0.6.0-windows-x64.exe".to_string(),
            "digs-0.6.0-windows-x64.exe".to_string(),
            "digstore-0.6.0-linux-x64".to_string(),
            "digs-0.6.0-linux-x64".to_string(),
            "digstore-0.6.0-macos-arm64".to_string(),
            "digs-0.6.0-macos-arm64".to_string(),
            "digstore-0.6.0-macos-x64".to_string(),
            "digs-0.6.0-macos-x64".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "digs"
            ),
            Some("digs-0.6.0-linux-x64".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::RawBinary,
                "digs"
            ),
            Some("digs-0.6.0-windows-x64.exe".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::MacOs, Arch::Arm64),
                AssetKind::RawBinary,
                "digs"
            ),
            Some("digs-0.6.0-macos-arm64".to_string())
        );
        // And resolving stem "digstore" against the SAME name list still gets
        // the digstore binary, never the digs alias (stem_rank prefers the
        // exact-prefix match over the tie-break-by-length path).
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
    fn matches_dig_updater_and_its_worker_sibling_despite_the_stem_prefix_collision() {
        // Issue #514: the beacon `dig-updater` and its unprivileged sibling
        // `dig-updater-worker` publish from the SAME release, and — exactly like
        // digs/digstore above — "dig-updater" is a literal string PREFIX of
        // "dig-updater-worker", so both names satisfy the stem_rank tie for a
        // query of stem "dig-updater". The tie is broken by shortest-name, which
        // always favors the non-worker binary; querying stem "dig-updater-worker"
        // instead wins purely on stem_rank (only the worker name starts with the
        // full "dig-updater-worker" prefix), regardless of length.
        let names = vec![
            "dig-updater-0.6.0-linux-x64".to_string(),
            "dig-updater-worker-0.6.0-linux-x64".to_string(),
            "dig-updater-0.6.0-windows-x64.exe".to_string(),
            "dig-updater-worker-0.6.0-windows-x64.exe".to_string(),
        ];
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-updater"
            ),
            Some("dig-updater-0.6.0-linux-x64".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-updater-worker"
            ),
            Some("dig-updater-worker-0.6.0-linux-x64".to_string())
        );
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Windows, Arch::X64),
                AssetKind::RawBinary,
                "dig-updater"
            ),
            Some("dig-updater-0.6.0-windows-x64.exe".to_string())
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

    // -- variant-aware, loadability-driven selection (#1774) -----------------------------------

    /// dig-app's two Linux builds: the default GTK-linked tray build and the
    /// GTK-less `-headless` build. BOTH match the `linux-x64` slug, so the
    /// shortest-name tiebreak used to hand the (shorter) tray name to every host.
    fn dig_app_linux_variants() -> Vec<String> {
        vec![
            "dig-app-3.1.0-linux-x64".to_string(),
            "dig-app-3.1.0-linux-x64-headless".to_string(),
        ]
    }

    /// A scripted loadability oracle: exact asset name → verdict. Any name not in
    /// the table is [`Loadability::Indeterminate`] (the fail-open default), which
    /// keeps a typo in a fixture from masquerading as a refusal.
    fn oracle(table: Vec<(&'static str, Loadability)>) -> impl Fn(&str) -> Loadability {
        move |name: &str| {
            table
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
                .unwrap_or(Loadability::Indeterminate {
                    why: "not scripted".to_string(),
                })
        }
    }

    fn unloadable(missing: &str) -> Loadability {
        Loadability::Unloadable {
            missing: vec![missing.to_string()],
        }
    }

    #[test]
    fn dig_app_selection_never_picks_the_dign_cli_from_the_same_release() {
        // dig_ecosystem#1774 regression: dig-app's release also ships the `dign`
        // CLI (`dign-<ver>-linux-x64`) — a DIFFERENT binary — under the same
        // linux-x64 slug. Before base-anchoring, `dign-*` was admitted as a
        // dig-app candidate and, being a plain (non-GTK) CLI that loads on a
        // headless box, it was selected as the "tray" build ahead of dig-app's
        // own headless build (which sorts after it by variant_rank). The result
        // on debian:bookworm-slim: `selected_variant: "tray"`, asset
        // `dign-10.1.1-linux-x64` — the installer placed the dign CLI as dig-app.
        //
        // A dig-app candidate must be `dig-app-*`, never `dign-*`. This holds
        // across BOTH the loadability fall-through AND the plain matcher.
        let names = vec![
            "dig-app-10.1.1-linux-x64".to_string(),
            "dig-app-10.1.1-linux-x64-headless".to_string(),
            "dign-10.1.1-linux-x64".to_string(),
        ];
        // On a GTK-less host the tray build is Unloadable; the fall-through must
        // reach dig-app's OWN headless build, NEVER the dign CLI.
        let gtk_less = oracle(vec![
            ("dig-app-10.1.1-linux-x64", unloadable("libgtk-3.so.0")),
            ("dig-app-10.1.1-linux-x64-headless", Loadability::Loadable),
            // dign loads on a headless box — it is the trap this guards against.
            ("dign-10.1.1-linux-x64", Loadability::Loadable),
        ]);
        assert_eq!(
            select_loadable_variant(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-app",
                &gtk_less
            ),
            VariantOutcome::Selected {
                asset: "dig-app-10.1.1-linux-x64-headless".to_string(),
                variant: "headless",
                loadable: true,
            },
            "a GTK-less host must get dig-app's headless build, never the dign CLI"
        );
        // And the plain matcher must never resolve dig-app to the dign CLI either
        // (the pre-existing latent bug: dign is shorter than dig-app, so if
        // dig-app's own build were ever absent, stem_rank could fall through).
        let selected = select_asset(
            &names,
            &t(Os::Linux, Arch::X64),
            AssetKind::RawBinary,
            "dig-app",
        );
        assert_eq!(selected.as_deref(), Some("dig-app-10.1.1-linux-x64"));
        assert!(
            !selected.unwrap().starts_with("dign-"),
            "dig-app must never resolve to the dign CLI"
        );
        // Querying the SAME release for the dign CLI still resolves dign — the
        // base anchor separates the two families, it does not hide either.
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dign"
            ),
            Some("dign-10.1.1-linux-x64".to_string())
        );
    }

    #[test]
    fn desktop_host_gets_the_tray_build_when_it_loads() {
        // Both builds load on a GTK host; tray is preferred, so the desktop user
        // gets the tray agent — not the headless one merely because a probe ran.
        let names = dig_app_linux_variants();
        let both_load = oracle(vec![
            ("dig-app-3.1.0-linux-x64", Loadability::Loadable),
            ("dig-app-3.1.0-linux-x64-headless", Loadability::Loadable),
        ]);
        assert_eq!(
            select_loadable_variant(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-app",
                &both_load
            ),
            VariantOutcome::Selected {
                asset: "dig-app-3.1.0-linux-x64".to_string(),
                variant: "tray",
                loadable: true,
            }
        );
    }

    #[test]
    fn gtk_less_host_falls_through_to_the_headless_build() {
        // THE #1753/#1774 property: on a host that cannot load the GTK tray build,
        // the selector must NOT hand it over on the shortest-name tiebreak — it
        // falls through to the `-headless` build, which loads. Exactly ONE actor
        // varies (the tray build's loadability); the headless build stays a
        // truthful loadable control, so an implementation that refused everything
        // could not pass this.
        let names = dig_app_linux_variants();
        let headless_only = oracle(vec![
            ("dig-app-3.1.0-linux-x64", unloadable("libgtk-3.so.0")),
            ("dig-app-3.1.0-linux-x64-headless", Loadability::Loadable),
        ]);
        assert_eq!(
            select_loadable_variant(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-app",
                &headless_only
            ),
            VariantOutcome::Selected {
                asset: "dig-app-3.1.0-linux-x64-headless".to_string(),
                variant: "headless",
                loadable: true,
            }
        );
    }

    #[test]
    fn every_variant_unloadable_is_refused_not_placed() {
        // Neither build can load (e.g. a broken host libc). The selector must
        // REFUSE rather than place a binary that dies before main.
        let names = dig_app_linux_variants();
        let nothing_loads = oracle(vec![
            ("dig-app-3.1.0-linux-x64", unloadable("libgtk-3.so.0")),
            ("dig-app-3.1.0-linux-x64-headless", unloadable("libc.so.6")),
        ]);
        assert_eq!(
            select_loadable_variant(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-app",
                &nothing_loads
            ),
            VariantOutcome::Refused {
                // The FIRST (tray) refusal is surfaced, and it NAMES the library.
                reason: "needs files this host does not provide (libgtk-3.so.0)".to_string(),
            }
        );
    }

    #[test]
    fn an_indeterminate_variant_is_taken_permissively_when_none_prove_loadable() {
        // A non-ELF artifact, a musl host, a non-Linux host: loadability cannot be
        // established. Refusing would strand the host forever, so the highest-
        // preference indeterminate build is taken with loadable=false. The tray
        // build here is indeterminate and headless is unloadable — tray must win
        // (preference order), proving indeterminate outranks a refusal.
        let names = dig_app_linux_variants();
        let tray_indeterminate = oracle(vec![
            (
                "dig-app-3.1.0-linux-x64",
                Loadability::Indeterminate {
                    why: "not an ELF host".to_string(),
                },
            ),
            ("dig-app-3.1.0-linux-x64-headless", unloadable("libc.so.6")),
        ]);
        assert_eq!(
            select_loadable_variant(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-app",
                &tray_indeterminate
            ),
            VariantOutcome::Selected {
                asset: "dig-app-3.1.0-linux-x64".to_string(),
                variant: "tray",
                loadable: false,
            }
        );
    }

    #[test]
    fn a_loadable_headless_beats_an_indeterminate_tray() {
        // Preference is tray-first, but a PROVEN-loadable build beats a merely-
        // indeterminate higher-preference one: correctness over preference.
        let names = dig_app_linux_variants();
        let table = oracle(vec![
            (
                "dig-app-3.1.0-linux-x64",
                Loadability::Indeterminate {
                    why: "unreadable".to_string(),
                },
            ),
            ("dig-app-3.1.0-linux-x64-headless", Loadability::Loadable),
        ]);
        assert_eq!(
            select_loadable_variant(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-app",
                &table
            ),
            VariantOutcome::Selected {
                asset: "dig-app-3.1.0-linux-x64-headless".to_string(),
                variant: "headless",
                loadable: true,
            }
        );
    }

    #[test]
    fn no_matching_asset_is_no_candidate() {
        // A release with no build for this OS/arch: the oracle is never consulted,
        // and the caller maps this to ASSET_NOT_FOUND exactly as select_asset's
        // None does.
        let names = vec!["dig-app-3.1.0-macos-arm64".to_string()];
        let never = oracle(vec![]);
        assert_eq!(
            select_loadable_variant(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-app",
                &never
            ),
            VariantOutcome::NoCandidate
        );
    }

    #[test]
    fn the_shortest_name_tiebreak_no_longer_steals_the_gtk_build_on_a_gtk_less_host() {
        // Guarding the exact regression: with the OLD select_asset the shorter
        // `…-linux-x64` (the GTK tray build) always won. The variant selector on a
        // GTK-less host must pick the LONGER `-headless` name instead — so the two
        // functions now disagree on this input, which is the whole point.
        let names = dig_app_linux_variants();
        assert_eq!(
            select_asset(
                &names,
                &t(Os::Linux, Arch::X64),
                AssetKind::RawBinary,
                "dig-app"
            ),
            Some("dig-app-3.1.0-linux-x64".to_string()),
            "select_asset still blindly prefers the shortest name"
        );
        let gtk_less = oracle(vec![
            ("dig-app-3.1.0-linux-x64", unloadable("libgtk-3.so.0")),
            ("dig-app-3.1.0-linux-x64-headless", Loadability::Loadable),
        ]);
        match select_loadable_variant(
            &names,
            &t(Os::Linux, Arch::X64),
            AssetKind::RawBinary,
            "dig-app",
            &gtk_less,
        ) {
            VariantOutcome::Selected { asset, .. } => assert_eq!(
                asset, "dig-app-3.1.0-linux-x64-headless",
                "the variant selector must not inherit the GTK-build bug"
            ),
            other => panic!("expected the headless build, got {other:?}"),
        }
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
