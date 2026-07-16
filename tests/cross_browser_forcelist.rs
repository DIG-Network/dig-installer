//! Cross-browser extension force-install + auto-update acceptance — **Tier 1**
//! (issue #645, the last child of the epic #602).
//!
//! The DIG extension is force-installed into every detected Chromium-family
//! browser by writing an `ExtensionInstallForcelist` managed-policy entry that
//! pins the canonical extension id to the self-hosted `update_url`. Each
//! browser's built-in Chromium auto-updater then polls that `update_url` and
//! pulls new CRXs on its own schedule — the SAME mechanism, key, and manifest
//! format for every brand (Chrome, Edge, Brave, Chromium, Vivaldi, Opera).
//!
//! This suite is the **automated, host-independent** half of the #645
//! acceptance: it proves, for EVERY supported browser on EVERY supported OS,
//! that the installer targets the correct per-browser managed-policy location
//! and writes the exact `"<id>;<update_url>"` entry — so the force-install is
//! correctly configured for auto-update on all of them, regardless of the CI
//! runner's own OS or which browsers happen to be installed on it.
//!
//! What each tier proves (see `runbooks/cross-browser-ext-acceptance.md`):
//!
//! * **Tier 1 (here, `cargo test`):** the per-browser × per-OS policy TARGET +
//!   the exact forcelist ENTRY value. Deterministic + pure — runs on any runner.
//! * **The per-writer unit tests** (`src/forcelist/{linux,macos,windows}.rs`)
//!   prove the WRITE MECHANICS at each location kind (registry / plist / JSON
//!   file), including the org-policy-merge + marker-owned-removal invariants.
//! * **Tier 2 (CI, `cross-browser-ext-acceptance.yml`):** the live `update_url`
//!   actually serves a valid Omaha manifest for the id + a fetchable CRX.
//! * **Tier 3 (CI Linux smoke + documented manual):** the SHIPPED binary writes
//!   a real browser's real managed-policy file end-to-end.
//!
//! Together, Tier 1 here + the per-writer unit tests + Tier 2/3 span the full
//! "force-installed and auto-updates on every Chromium browser" claim honestly.

use dig_installer::browsers::{policy_targets_for, PolicyTarget};
use dig_installer::forcelist::{forcelist_entry, is_our_entry, update_url, Channel, EXTENSION_ID};
use dig_installer::target::Os;

/// The complete set of Chromium-family browsers the installer force-installs
/// into — the epic #602 D6 catalogue. Kept here as the acceptance-side source of
/// truth so a browser silently DROPPED from `browsers::CATALOGUE` (and therefore
/// no longer force-installed) fails this suite loudly.
const SUPPORTED_BROWSERS: &[&str] = &["chrome", "edge", "brave", "chromium", "vivaldi", "opera"];

/// Every OS the installer force-installs on.
const SUPPORTED_OSES: &[Os] = &[Os::Windows, Os::MacOs, Os::Linux];

/// The exact managed-policy location the installer must target for one browser
/// on one OS — the registry policy key (Windows), the managed-preferences
/// domain (macOS), or the managed-policy directory (Linux). This is the
/// documented Chromium enterprise-policy surface for each brand; a drift here
/// means that browser's force-install silently writes to the wrong place.
fn expected_location(browser: &str, os: Os) -> &'static str {
    match (browser, os) {
        ("chrome", Os::Windows) => r"SOFTWARE\Policies\Google\Chrome",
        ("chrome", Os::MacOs) => "com.google.Chrome",
        ("chrome", Os::Linux) => "/etc/opt/chrome/policies/managed",

        ("edge", Os::Windows) => r"SOFTWARE\Policies\Microsoft\Edge",
        ("edge", Os::MacOs) => "com.microsoft.Edge",
        ("edge", Os::Linux) => "/etc/opt/edge/policies/managed",

        ("brave", Os::Windows) => r"SOFTWARE\Policies\BraveSoftware\Brave",
        ("brave", Os::MacOs) => "com.brave.Browser",
        ("brave", Os::Linux) => "/etc/brave/policies/managed",

        ("chromium", Os::Windows) => r"SOFTWARE\Policies\Chromium",
        ("chromium", Os::MacOs) => "org.chromium.Chromium",
        ("chromium", Os::Linux) => "/etc/chromium/policies/managed",

        ("vivaldi", Os::Windows) => r"SOFTWARE\Policies\Vivaldi",
        ("vivaldi", Os::MacOs) => "com.vivaldi.Vivaldi",
        ("vivaldi", Os::Linux) => "/etc/opt/vivaldi/policies/managed",

        ("opera", Os::Windows) => r"SOFTWARE\Policies\Opera Software\Opera",
        ("opera", Os::MacOs) => "com.operasoftware.Opera",
        ("opera", Os::Linux) => "/etc/opt/opera/policies/managed",

        other => panic!("no expected policy location catalogued for {other:?}"),
    }
}

/// Read the location string out of a [`PolicyTarget`] regardless of its OS
/// variant, so the matrix assertion can compare it uniformly.
fn location_of(target: &PolicyTarget) -> &str {
    match target {
        PolicyTarget::Windows { policy_key } => policy_key,
        PolicyTarget::Macos { preferences_domain } => preferences_domain,
        PolicyTarget::Linux { managed_policy_dir } => managed_policy_dir,
    }
}

/// The policy-target VARIANT must match the OS it was resolved for — a Windows
/// target on Windows, a plist domain on macOS, a directory on Linux. A mismatch
/// would mean the writer dispatches to the wrong platform mechanism.
fn assert_variant_matches_os(target: &PolicyTarget, os: Os) {
    let ok = matches!(
        (target, os),
        (PolicyTarget::Windows { .. }, Os::Windows)
            | (PolicyTarget::Macos { .. }, Os::MacOs)
            | (PolicyTarget::Linux { .. }, Os::Linux)
    );
    assert!(ok, "policy target {target:?} does not match OS {os:?}");
}

/// The full matrix: every supported browser × every supported OS resolves to
/// the correct managed-policy location and the correct policy-target variant.
/// This is the core Tier-1 acceptance — the force-install lands in the right
/// place for every brand on every platform.
#[test]
fn every_browser_on_every_os_targets_the_correct_policy_location() {
    for &os in SUPPORTED_OSES {
        for &browser in SUPPORTED_BROWSERS {
            let selected = vec![browser.to_string()];
            let targets = policy_targets_for(os, &selected);

            assert_eq!(
                targets.len(),
                1,
                "{browser} on {os:?} must resolve to exactly one policy target"
            );
            let target = &targets[0];
            assert_variant_matches_os(target, os);
            assert_eq!(
                location_of(target),
                expected_location(browser, os),
                "wrong managed-policy location for {browser} on {os:?}"
            );
        }
    }
}

/// The forcelist ENTRY written into every browser's policy is the exact
/// Chromium-documented `"<extension-id>;<update_url>"` force-install form,
/// pinned to the canonical id and the self-hosted per-channel `update_url`.
/// This is the value that arms the auto-update: it is identical for every
/// browser, so proving it once proves it for all of them.
#[test]
fn the_forcelist_entry_is_the_canonical_id_pinned_to_the_self_hosted_update_url() {
    assert_eq!(EXTENSION_ID, "mlibddmbhlgogepnjdienclhnkfpkfah");

    assert_eq!(
        forcelist_entry(Channel::Stable),
        "mlibddmbhlgogepnjdienclhnkfpkfah;https://updates.dig.net/ext/stable/updates.xml"
    );
    assert_eq!(
        forcelist_entry(Channel::Nightly),
        "mlibddmbhlgogepnjdienclhnkfpkfah;https://updates.dig.net/ext/nightly/updates.xml"
    );

    // Both channels' entries are recognized as ours (the marker that scopes
    // removal to only the DIG entry, never an org's).
    assert!(is_our_entry(&forcelist_entry(Channel::Stable)));
    assert!(is_our_entry(&forcelist_entry(Channel::Nightly)));
}

/// The `update_url` is a fixed HTTPS constant on the self-hosted host — the
/// auto-update source every browser polls (#607/#608). It never varies by
/// browser, only by channel.
#[test]
fn the_update_url_is_the_self_hosted_https_endpoint_per_channel() {
    assert_eq!(
        update_url(Channel::Stable),
        "https://updates.dig.net/ext/stable/updates.xml"
    );
    assert_eq!(
        update_url(Channel::Nightly),
        "https://updates.dig.net/ext/nightly/updates.xml"
    );
    for ch in [Channel::Stable, Channel::Nightly] {
        assert!(update_url(ch).starts_with("https://updates.dig.net/ext/"));
    }
}

/// Selecting ALL supported browsers at once resolves to one policy target each,
/// in the caller's order, with no browser silently dropped — the real install
/// flow (#648) force-installs into the full detected set in a single pass.
#[test]
fn selecting_all_browsers_resolves_a_target_for_each_in_order() {
    for &os in SUPPORTED_OSES {
        let selected: Vec<String> = SUPPORTED_BROWSERS.iter().map(|s| s.to_string()).collect();
        let targets = policy_targets_for(os, &selected);

        assert_eq!(
            targets.len(),
            SUPPORTED_BROWSERS.len(),
            "every selected browser must resolve to a target on {os:?}"
        );
        for (browser, target) in SUPPORTED_BROWSERS.iter().zip(&targets) {
            assert_eq!(
                location_of(target),
                expected_location(browser, os),
                "order/identity mismatch for {browser} on {os:?}"
            );
        }
    }
}

/// A foreign / stale browser id can never widen the force-install set — it is
/// silently ignored rather than resolving to some default target. Guards the
/// "regardless of brand" claim from the opposite side: only KNOWN brands are
/// ever written to.
#[test]
fn an_unknown_browser_id_resolves_to_no_target() {
    for &os in SUPPORTED_OSES {
        let selected = vec!["not-a-browser".to_string(), "safari".to_string()];
        assert!(
            policy_targets_for(os, &selected).is_empty(),
            "unknown ids must not resolve to any policy target on {os:?}"
        );
    }
}
