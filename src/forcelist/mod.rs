//! `ExtensionInstallForcelist` managed-policy writer/remover (issue #612, WU-3).
//!
//! Force-installs the DIG Chromium extension into each user-selected
//! Chromium-family browser by writing an `ExtensionInstallForcelist` entry into
//! that browser's per-OS **enterprise managed-policy** surface — the same policy
//! mechanism the DoH writer (`crate::dns`) uses, mirrored here rather than
//! reinvented.
//!
//! The single entry written is the canonical `"<id>;<update_url>"` pair for the
//! tracked channel (see [`forcelist_entry`]); the extension id and the
//! `update_url` are compiled-in constants (§canonical) — **no user or
//! environment input ever flows into the value**, so there is no injection
//! surface (#565).
//!
//! # Security invariants (the ones the merge-gate refutation lenses attack)
//!
//! * **Never clobber a pre-existing org forcelist.** `ExtensionInstallForcelist`
//!   is a *list*. On Windows/macOS we MERGE our single entry alongside whatever
//!   an enterprise already set, and on removal delete ONLY our entry; on Linux we
//!   drop a uniquely-named dig-owned policy file the OS policy-union merges, so
//!   there is nothing to clobber.
//! * **Marker-owned.** Every artifact is self-identifying so `remove` deletes
//!   ONLY what this installer wrote: on Windows/macOS the entry's own value *is*
//!   the marker (it begins with the canonical [`EXTENSION_ID`], which no other
//!   tool emits — [`is_our_entry`]); on Linux the marker is the dedicated
//!   [`LINUX_POLICY_FILENAME`] this installer solely owns.
//! * **Idempotent + no half-write.** Re-running never duplicates an entry, a
//!   removal is complete, and a channel switch is a clean per-browser reinstall
//!   ([`reinstall`]) — never a naive rewrite, because a nightly build outranks
//!   the matching stable and Chromium will not auto-downgrade across channels.
//! * **Privileged-only.** Every target location (`HKLM`, `/etc`,
//!   `/Library/Managed Preferences`) is admin-owned; the caller performs these
//!   writes only inside the already-gated elevated context (#565) — this module
//!   never elevates on its own and reads no user-writable input.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use crate::browsers::PolicyTarget;

/// The canonical DIG Chromium extension id, pinned in the `canonical` skill and
/// derived from the extension signing key's SPKI. It is BOTH the thing we
/// force-install AND — because it is unique to DIG — the marker by which
/// [`remove`] recognizes exactly our forcelist entry. It MUST NOT drift (a
/// rotation is a new id that breaks every installed force-install).
pub const EXTENSION_ID: &str = "mlibddmbhlgogepnjdienclhnkfpkfah";

/// The dedicated, dig-owned policy filename dropped into each browser's Linux
/// managed-policy directory. Uniquely named so the OS policy union merges it
/// beside any org policy file and `remove` deletes only this file — never an
/// admin's own policy JSON.
#[cfg(any(target_os = "linux", test))]
pub const LINUX_POLICY_FILENAME: &str = "dig-extension-forcelist.json";

/// The release channel the force-installed extension tracks. Mirrors the beacon
/// channel model (#604): each channel is an independent signed feed served under
/// its own `update_url` path. **Defaults to [`Channel::Stable`].**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Channel {
    /// The rolling nightly pre-release channel.
    Nightly,
    /// The stable release channel — the default an installer tracks.
    #[default]
    Stable,
}

impl Channel {
    /// The channel's canonical slug — the `<channel>` path segment in the
    /// `update_url` and the CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Nightly => "nightly",
            Channel::Stable => "stable",
        }
    }

    /// Parse the CLI spelling (`nightly` / `stable`, case-insensitive). Returns
    /// `None` for any other token so the caller can reject it explicitly rather
    /// than silently defaulting.
    pub fn parse(s: &str) -> Option<Channel> {
        match s.trim().to_ascii_lowercase().as_str() {
            "nightly" => Some(Channel::Nightly),
            "stable" => Some(Channel::Stable),
            _ => None,
        }
    }
}

/// The extension auto-update manifest URL for `channel` — a fixed, compiled-in
/// HTTPS constant (§canonical, #608). No caller input is interpolated.
pub fn update_url(channel: Channel) -> String {
    format!(
        "https://updates.dig.net/ext/{}/updates.xml",
        channel.as_str()
    )
}

/// The exact `ExtensionInstallForcelist` entry value for `channel`:
/// `"<extension-id>;<update-url>"`, the Chromium-documented force-install form.
pub fn forcelist_entry(channel: Channel) -> String {
    format!("{EXTENSION_ID};{}", update_url(channel))
}

/// Is `value` an `ExtensionInstallForcelist` entry THIS installer wrote? True
/// iff it is the DIG extension id optionally followed by `;<update_url>` — the
/// marker that lets [`remove`] delete only our entry and never an org's. The id
/// is unique to DIG, so a prefix match is a reliable, channel-independent marker
/// (a nightly and a stable entry are both ours).
pub fn is_our_entry(value: &str) -> bool {
    value == EXTENSION_ID || value.starts_with(&format!("{EXTENSION_ID};"))
}

/// What happened to one browser's forcelist policy in an [`apply`]/[`remove`]
/// pass. Machine-consumable (§6.2) so the install report + tests can assert the
/// exact outcome per browser without parsing prose.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ForcelistOutcome {
    /// The policy location acted on (the registry key, plist path, or JSON
    /// file), for the install log + audit trail.
    pub location: String,
    /// The action taken.
    pub action: ForcelistAction,
    /// A human-readable note (honest caveats — e.g. the macOS MDM caveat).
    pub note: String,
}

/// The action an [`apply`]/[`remove`] pass took for one browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForcelistAction {
    /// Our forcelist entry was written (a fresh add).
    Wrote,
    /// Our entry was already present + current — nothing changed (idempotent).
    AlreadyPresent,
    /// Our entry was updated in place (e.g. a channel switch).
    Updated,
    /// Our entry was removed (uninstall/unconfigure).
    Removed,
    /// Nothing was present to remove.
    NothingToRemove,
    /// Skipped without writing — e.g. a pre-existing non-DIG managed policy on
    /// macOS that MUST NOT be clobbered (see [`ForcelistOutcome::note`]).
    Skipped,
    /// The write/remove failed (see the note); a partial failure never leaves a
    /// half-registered policy.
    Failed,
}

/// Force-install the DIG extension into every `target`, MERGING our single entry
/// beside any pre-existing org forcelist and never touching another admin's
/// entries. Idempotent: a second pass with the same channel is a no-op.
///
/// This is the INSTALL path (a fresh add / ensure-present at `channel`). A
/// CHANNEL SWITCH on an already-force-installed browser must instead go through
/// [`reinstall`] — a naive value rewrite would not downgrade a higher-versioned
/// nightly to stable.
///
/// Each `PolicyTarget` carries a per-OS location (#609); a target whose OS is
/// not the host OS is skipped (its platform writer is compiled out). Callers
/// pass only the targets for browsers the user selected (#611).
pub fn apply(targets: &[PolicyTarget], channel: Channel) -> Vec<ForcelistOutcome> {
    targets.iter().map(|t| apply_one(t, channel)).collect()
}

/// Remove ONLY the DIG forcelist entry from every `target`, leaving any
/// pre-existing org forcelist untouched. Idempotent + complete (zero residue).
pub fn remove(targets: &[PolicyTarget]) -> Vec<ForcelistOutcome> {
    targets.iter().map(remove_one).collect()
}

/// Switch every `target` to `channel` as a **clean reinstall** — remove our
/// current forcelist entry, then add the new channel's entry.
///
/// A channel switch CANNOT be a naive value rewrite. The extension id is the
/// same for both channels (only the `update_url` differs), and a nightly build
/// (`X.Y.Z.N`) numerically OUTRANKS the matching stable `X.Y.Z`. So repointing a
/// nightly-installed browser at the stable `update_url` is a downgrade Chromium
/// refuses to auto-apply — it keeps the higher-versioned nightly. Dropping our
/// forcelist entry first makes the browser UNINSTALL the extension; re-adding it
/// at the new channel then triggers a clean fresh install of that channel.
///
/// This is the per-browser primitive the beacon-follow job (#613) drives; #613
/// owns staging the remove and the re-add across policy-refresh cycles so the
/// browser actually observes the uninstall before the reinstall.
///
/// A FAILED re-add is never masked as success. If the remove succeeded but the
/// re-add failed, the browser is left in the dangerous "extension removed, not
/// restored" state — this MUST surface as [`ForcelistAction::Failed`] so the
/// exit-code / `ok` contract ([`crate::forcelist_json`], the CLI verb) reports
/// the failure. Only a genuinely successful re-add is relabelled `Updated`.
pub fn reinstall(targets: &[PolicyTarget], channel: Channel) -> Vec<ForcelistOutcome> {
    targets.iter().map(|t| reinstall_one(t, channel)).collect()
}

fn reinstall_one(target: &PolicyTarget, channel: Channel) -> ForcelistOutcome {
    let removed = remove_one(target);
    let applied = apply_one(target, channel);
    combine_reinstall(&removed, applied, channel)
}

/// Fold a reinstall's `removed` + `applied` outcomes into the reported result,
/// never masking a failed re-add. PURE — separated from the OS-dispatching
/// [`reinstall_one`] so the "remove succeeded but re-add failed" path (which is
/// hard to provoke through real registry/plist I/O) is directly unit-tested.
fn combine_reinstall(
    removed: &ForcelistOutcome,
    mut applied: ForcelistOutcome,
    channel: Channel,
) -> ForcelistOutcome {
    let re_add_ok = matches!(
        applied.action,
        ForcelistAction::Wrote | ForcelistAction::AlreadyPresent
    );

    if re_add_ok {
        // Successful transition — report it as an in-place channel update.
        applied.action = ForcelistAction::Updated;
        applied.note = format!(
            "channel reinstall (removed then re-added at {}): {}",
            channel.as_str(),
            applied.note
        );
    } else if removed.action == ForcelistAction::Removed {
        // The dangerous state: our entry was removed (the browser will
        // uninstall the extension) but the re-add did not succeed. Surface it
        // as a hard failure, never a silent success.
        applied.action = ForcelistAction::Failed;
        applied.note = format!(
            "channel reinstall LEFT THE EXTENSION REMOVED (re-add did not succeed at {}): {}",
            channel.as_str(),
            applied.note
        );
    } else {
        // Nothing was removed AND the re-add did not write (e.g. macOS Skipped
        // on a pre-existing org plist). Preserve apply_one's own action
        // verbatim — no masking either way.
        applied.note = format!(
            "channel reinstall no-op/skip at {}: {}",
            channel.as_str(),
            applied.note
        );
    }
    applied
}

fn apply_one(target: &PolicyTarget, channel: Channel) -> ForcelistOutcome {
    match target {
        #[cfg(windows)]
        PolicyTarget::Windows { policy_key } => windows::apply(policy_key, channel),
        #[cfg(target_os = "macos")]
        PolicyTarget::Macos { preferences_domain } => macos::apply(preferences_domain, channel),
        #[cfg(target_os = "linux")]
        PolicyTarget::Linux { managed_policy_dir } => linux::apply(managed_policy_dir, channel),
        other => skipped_off_os(other),
    }
}

fn remove_one(target: &PolicyTarget) -> ForcelistOutcome {
    match target {
        #[cfg(windows)]
        PolicyTarget::Windows { policy_key } => windows::remove(policy_key),
        #[cfg(target_os = "macos")]
        PolicyTarget::Macos { preferences_domain } => macos::remove(preferences_domain),
        #[cfg(target_os = "linux")]
        PolicyTarget::Linux { managed_policy_dir } => linux::remove(managed_policy_dir),
        other => skipped_off_os(other),
    }
}

/// A target for a DIFFERENT OS than the host — never written to (its platform
/// writer is compiled out). Reported as [`ForcelistAction::Skipped`] rather than
/// silently dropped so the outcome is explicit.
fn skipped_off_os(target: &PolicyTarget) -> ForcelistOutcome {
    let location = match target {
        PolicyTarget::Windows { policy_key } => policy_key.clone(),
        PolicyTarget::Macos { preferences_domain } => preferences_domain.clone(),
        PolicyTarget::Linux { managed_policy_dir } => managed_policy_dir.clone(),
    };
    ForcelistOutcome {
        location,
        action: ForcelistAction::Skipped,
        note: "policy target is for a different operating system than the host".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_defaults_to_stable() {
        assert_eq!(Channel::default(), Channel::Stable);
        assert_eq!(Channel::default().as_str(), "stable");
    }

    #[test]
    fn channel_parse_is_case_insensitive_and_rejects_junk() {
        assert_eq!(Channel::parse("stable"), Some(Channel::Stable));
        assert_eq!(Channel::parse("NIGHTLY"), Some(Channel::Nightly));
        assert_eq!(Channel::parse("  Stable "), Some(Channel::Stable));
        assert_eq!(Channel::parse("beta"), None);
        assert_eq!(Channel::parse(""), None);
    }

    #[test]
    fn update_url_pins_the_canonical_host_and_channel_path() {
        assert_eq!(
            update_url(Channel::Stable),
            "https://updates.dig.net/ext/stable/updates.xml"
        );
        assert_eq!(
            update_url(Channel::Nightly),
            "https://updates.dig.net/ext/nightly/updates.xml"
        );
    }

    #[test]
    fn forcelist_entry_is_id_semicolon_update_url() {
        assert_eq!(
            forcelist_entry(Channel::Stable),
            "mlibddmbhlgogepnjdienclhnkfpkfah;https://updates.dig.net/ext/stable/updates.xml"
        );
        // The entry always begins with the canonical id (the marker).
        assert!(forcelist_entry(Channel::Nightly).starts_with(EXTENSION_ID));
    }

    #[test]
    fn is_our_entry_matches_only_the_dig_id_prefix() {
        assert!(is_our_entry(&forcelist_entry(Channel::Stable)));
        assert!(is_our_entry(&forcelist_entry(Channel::Nightly)));
        assert!(is_our_entry(EXTENSION_ID));
        // A different vendor's forcelist entry is NOT ours — never removed.
        assert!(!is_our_entry(
            "aapbdbdomjkkjkaonfhkkikfgjllcleb;https://clients2.google.com/service/update2/crx"
        ));
        // A superstring of the id (not id-then-semicolon) is not ours.
        assert!(!is_our_entry("mlibddmbhlgogepnjdienclhnkfpkfahEXTRA"));
    }

    fn outcome(action: ForcelistAction) -> ForcelistOutcome {
        ForcelistOutcome {
            location: "loc".to_string(),
            action,
            note: "n".to_string(),
        }
    }

    #[test]
    fn reinstall_reports_failure_when_remove_succeeds_but_re_add_fails() {
        // The dangerous state #613's exit-code contract must catch: the entry
        // was removed (browser uninstalls the extension) but the re-add failed
        // — MUST surface as Failed, never a masked Updated/success.
        let removed = outcome(ForcelistAction::Removed);
        let applied = outcome(ForcelistAction::Failed);
        let out = combine_reinstall(&removed, applied, Channel::Stable);
        assert_eq!(out.action, ForcelistAction::Failed);
        assert!(out.note.contains("LEFT THE EXTENSION REMOVED"));

        // And the success gates report the failure.
        let json = crate::forcelist_json(std::slice::from_ref(&out));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["ok"], false, "forcelist_json must report not-ok");
    }

    #[test]
    fn reinstall_relabels_a_successful_re_add_as_updated() {
        let out = combine_reinstall(
            &outcome(ForcelistAction::Removed),
            outcome(ForcelistAction::Wrote),
            Channel::Nightly,
        );
        assert_eq!(out.action, ForcelistAction::Updated);
        let out2 = combine_reinstall(
            &outcome(ForcelistAction::NothingToRemove),
            outcome(ForcelistAction::AlreadyPresent),
            Channel::Stable,
        );
        assert_eq!(out2.action, ForcelistAction::Updated);
    }

    #[test]
    fn reinstall_preserves_a_skip_when_nothing_was_removed() {
        // macOS non-DIG plist: nothing removed, apply Skipped → stays Skipped,
        // not masked as Updated and not escalated to Failed.
        let out = combine_reinstall(
            &outcome(ForcelistAction::NothingToRemove),
            outcome(ForcelistAction::Skipped),
            Channel::Stable,
        );
        assert_eq!(out.action, ForcelistAction::Skipped);
    }

    #[test]
    fn off_os_targets_are_skipped_never_written() {
        // Construct a target for an OS we are (almost certainly) not building
        // for and assert it is reported skipped, not acted on.
        #[cfg(not(windows))]
        let foreign = PolicyTarget::Windows {
            policy_key: r"SOFTWARE\Policies\Google\Chrome".to_string(),
        };
        #[cfg(windows)]
        let foreign = PolicyTarget::Linux {
            managed_policy_dir: "/etc/opt/chrome/policies/managed".to_string(),
        };
        let out = apply(std::slice::from_ref(&foreign), Channel::Stable);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].action, ForcelistAction::Skipped);
    }
}
