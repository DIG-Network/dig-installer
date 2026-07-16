//! macOS `ExtensionInstallForcelist` writer (issue #612) — best-effort, honest
//! about MDM.
//!
//! On macOS, enterprise Chromium policy is a **managed-preferences** plist per
//! bundle id under `/Library/Managed Preferences/<domain>.plist`, and those
//! plists are normally provisioned by an MDM. macOS does NOT union multiple
//! plists for one domain, so we cannot safely drop a second file the way Linux
//! allows.
//!
//! Therefore this writer is deliberately conservative and self-honest:
//!
//! * if NO managed plist exists for the domain, we write a dig-owned one holding
//!   just our `ExtensionInstallForcelist` entry, tagged with [`MARKER`];
//! * if a plist exists and is OURS (carries [`MARKER`]), we rewrite it in place
//!   (idempotent / channel switch);
//! * if a plist exists and is NOT ours (an MDM/org policy), we SKIP it — never
//!   clobbering an enterprise forcelist — and the note recommends MDM for a
//!   managed fleet.
//!
//! Removal deletes the plist only when it is ours (marker present).

use std::path::{Path, PathBuf};

use super::{forcelist_entry, Channel, ForcelistAction, ForcelistOutcome};

/// The real per-machine managed-preferences directory.
const MANAGED_PREFS_DIR: &str = "/Library/Managed Preferences";

/// The dig ownership marker embedded as an XML comment in a plist we wrote, so
/// `remove` (and the pre-write guard) can tell our plist from an MDM one.
const MARKER: &str = "managed by dig-installer (extension force-install, #612)";

/// Force-install the extension for `channel` into the browser identified by
/// `preferences_domain` (e.g. `com.google.Chrome`).
pub fn apply(preferences_domain: &str, channel: Channel) -> ForcelistOutcome {
    apply_in(Path::new(MANAGED_PREFS_DIR), preferences_domain, channel)
}

/// Remove the DIG-owned managed plist for `preferences_domain` (only if ours).
pub fn remove(preferences_domain: &str) -> ForcelistOutcome {
    remove_in(Path::new(MANAGED_PREFS_DIR), preferences_domain)
}

fn plist_path(dir: &Path, domain: &str) -> PathBuf {
    dir.join(format!("{domain}.plist"))
}

/// Build the managed-preferences plist body: a single-key dictionary with our
/// `ExtensionInstallForcelist` array, prefixed by the dig [`MARKER`] comment.
fn plist_body(channel: Channel) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!-- {MARKER} -->\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>ExtensionInstallForcelist</key>\n\
         \t<array>\n\
         \t\t<string>{}</string>\n\
         \t</array>\n\
         </dict>\n\
         </plist>\n",
        forcelist_entry(channel)
    )
}

fn is_ours(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|c| c.contains(MARKER))
        .unwrap_or(false)
}

/// Testable core of [`apply`], parametrized on the managed-prefs directory.
fn apply_in(dir: &Path, domain: &str, channel: Channel) -> ForcelistOutcome {
    let path = plist_path(dir, domain);
    let location = path.display().to_string();
    let desired = plist_body(channel);

    if path.exists() && !is_ours(&path) {
        return outcome(
            location,
            ForcelistAction::Skipped,
            "a non-DIG managed policy already exists — not overwritten; deploy the DIG \
             extension via MDM on a managed fleet",
        );
    }
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if existing == desired {
            return outcome(
                location,
                ForcelistAction::AlreadyPresent,
                "dig plist already current",
            );
        }
    }
    if let Err(e) = std::fs::create_dir_all(dir) {
        return failed(location, &format!("create dir: {e}"));
    }
    match std::fs::write(&path, &desired) {
        Ok(()) => outcome(
            location,
            ForcelistAction::Wrote,
            "wrote dig-owned managed plist (best-effort; MDM is authoritative on macOS)",
        ),
        Err(e) => failed(location, &format!("write: {e}")),
    }
}

/// Testable core of [`remove`], parametrized on the managed-prefs directory.
fn remove_in(dir: &Path, domain: &str) -> ForcelistOutcome {
    let path = plist_path(dir, domain);
    let location = path.display().to_string();
    if !path.exists() {
        return outcome(location, ForcelistAction::NothingToRemove, "no dig plist");
    }
    if !is_ours(&path) {
        return outcome(
            location,
            ForcelistAction::Skipped,
            "existing managed plist is not ours — left untouched",
        );
    }
    match std::fs::remove_file(&path) {
        Ok(()) => outcome(
            location,
            ForcelistAction::Removed,
            "removed dig-owned managed plist",
        ),
        Err(e) => failed(location, &format!("remove: {e}")),
    }
}

fn outcome(location: String, action: ForcelistAction, note: &str) -> ForcelistOutcome {
    ForcelistOutcome {
        location,
        action,
        note: note.to_string(),
    }
}

fn failed(location: String, note: &str) -> ForcelistOutcome {
    outcome(location, ForcelistAction::Failed, note)
}

#[cfg(test)]
mod tests {
    use super::super::{is_our_entry, EXTENSION_ID};
    use super::*;
    use tempfile::tempdir;

    const DOMAIN: &str = "com.google.Chrome";

    #[test]
    fn apply_writes_a_marked_plist_with_our_entry() {
        let dir = tempdir().unwrap();
        let out = apply_in(dir.path(), DOMAIN, Channel::Stable);
        assert_eq!(out.action, ForcelistAction::Wrote);

        let body = std::fs::read_to_string(plist_path(dir.path(), DOMAIN)).unwrap();
        assert!(body.contains(MARKER), "carries dig marker");
        assert!(body.contains(EXTENSION_ID));
        assert!(body.contains("stable"));
    }

    #[test]
    fn apply_is_idempotent() {
        let dir = tempdir().unwrap();
        apply_in(dir.path(), DOMAIN, Channel::Stable);
        assert_eq!(
            apply_in(dir.path(), DOMAIN, Channel::Stable).action,
            ForcelistAction::AlreadyPresent
        );
    }

    #[test]
    fn apply_switches_channel_in_place() {
        let dir = tempdir().unwrap();
        apply_in(dir.path(), DOMAIN, Channel::Stable);
        let out = apply_in(dir.path(), DOMAIN, Channel::Nightly);
        assert_eq!(out.action, ForcelistAction::Wrote);
        let body = std::fs::read_to_string(plist_path(dir.path(), DOMAIN)).unwrap();
        assert!(body.contains("nightly"));
        assert_eq!(body.matches("<string>").count(), 1, "still one entry");
    }

    #[test]
    fn apply_never_clobbers_a_non_dig_managed_plist() {
        let dir = tempdir().unwrap();
        let org =
            "<?xml version=\"1.0\"?><plist><dict><key>SomeOrgPolicy</key><true/></dict></plist>";
        std::fs::write(plist_path(dir.path(), DOMAIN), org).unwrap();

        let out = apply_in(dir.path(), DOMAIN, Channel::Stable);
        assert_eq!(out.action, ForcelistAction::Skipped);
        assert_eq!(
            std::fs::read_to_string(plist_path(dir.path(), DOMAIN)).unwrap(),
            org,
            "org plist untouched"
        );
    }

    #[test]
    fn remove_deletes_only_our_plist() {
        let dir = tempdir().unwrap();
        apply_in(dir.path(), DOMAIN, Channel::Stable);
        let out = remove_in(dir.path(), DOMAIN);
        assert_eq!(out.action, ForcelistAction::Removed);
        assert!(!plist_path(dir.path(), DOMAIN).exists());
    }

    #[test]
    fn remove_leaves_a_non_dig_plist_untouched() {
        let dir = tempdir().unwrap();
        let org = "<?xml version=\"1.0\"?><plist><dict/></plist>";
        std::fs::write(plist_path(dir.path(), DOMAIN), org).unwrap();
        let out = remove_in(dir.path(), DOMAIN);
        assert_eq!(out.action, ForcelistAction::Skipped);
        assert!(plist_path(dir.path(), DOMAIN).exists());
    }

    #[test]
    fn remove_is_a_noop_when_absent() {
        let dir = tempdir().unwrap();
        assert_eq!(
            remove_in(dir.path(), DOMAIN).action,
            ForcelistAction::NothingToRemove
        );
    }

    #[test]
    fn written_entry_is_ours() {
        let dir = tempdir().unwrap();
        apply_in(dir.path(), DOMAIN, Channel::Stable);
        assert!(is_our_entry(&forcelist_entry(Channel::Stable)));
    }
}
