//! Linux `ExtensionInstallForcelist` writer (issue #612).
//!
//! Chromium on Linux reads *every* JSON file in a browser's
//! `.../policies/managed/` directory and takes the POLICY UNION. So we never
//! edit an admin's policy file: we drop a single, uniquely-named,
//! installer-owned file ([`super::LINUX_POLICY_FILENAME`]) containing only our
//! `ExtensionInstallForcelist` array. The union merges it beside any org policy,
//! and removal is a clean delete of exactly that one file — a pre-existing org
//! forcelist is untouched by construction.

use std::path::{Path, PathBuf};

use super::{forcelist_entry, Channel, ForcelistAction, ForcelistOutcome, LINUX_POLICY_FILENAME};

/// Write our dig-owned forcelist policy file into `managed_policy_dir`,
/// force-installing the extension for `channel`. Idempotent: an unchanged file
/// is left as-is; a channel switch rewrites it.
pub fn apply(managed_policy_dir: &str, channel: Channel) -> ForcelistOutcome {
    apply_in(Path::new(managed_policy_dir), channel)
}

/// Remove our dig-owned forcelist policy file from `managed_policy_dir`. Only
/// our uniquely-named file is deleted — never an admin's policy JSON.
pub fn remove(managed_policy_dir: &str) -> ForcelistOutcome {
    remove_in(Path::new(managed_policy_dir))
}

/// The JSON body of our managed-policy file: a single-element
/// `ExtensionInstallForcelist` array. Chromium unions this with every other file
/// in the directory, so we deliberately carry ONLY our key.
fn policy_json(channel: Channel) -> String {
    serde_json::json!({ "ExtensionInstallForcelist": [forcelist_entry(channel)] }).to_string()
}

fn policy_path(dir: &Path) -> PathBuf {
    dir.join(LINUX_POLICY_FILENAME)
}

/// Testable core of [`apply`], parametrized on the directory so unit tests write
/// into a temp dir instead of `/etc`.
fn apply_in(dir: &Path, channel: Channel) -> ForcelistOutcome {
    let path = policy_path(dir);
    let location = path.display().to_string();
    let desired = policy_json(channel);

    if let Ok(existing) = std::fs::read_to_string(&path) {
        if existing == desired {
            return outcome(location, ForcelistAction::AlreadyPresent, "already current");
        }
    }
    if let Err(e) = std::fs::create_dir_all(dir) {
        return outcome(
            location,
            ForcelistAction::Failed,
            &format!("create dir: {e}"),
        );
    }
    // A single atomic-ish write: on failure nothing partial is force-installed
    // (the file either has the full policy or does not exist).
    match std::fs::write(&path, &desired) {
        Ok(()) => outcome(
            location,
            ForcelistAction::Wrote,
            "wrote dig-owned managed-policy file (merged by the Chromium policy union)",
        ),
        Err(e) => outcome(location, ForcelistAction::Failed, &format!("write: {e}")),
    }
}

/// Testable core of [`remove`], parametrized on the directory.
fn remove_in(dir: &Path) -> ForcelistOutcome {
    let path = policy_path(dir);
    let location = path.display().to_string();
    if !path.exists() {
        return outcome(
            location,
            ForcelistAction::NothingToRemove,
            "no dig policy file",
        );
    }
    match std::fs::remove_file(&path) {
        Ok(()) => outcome(
            location,
            ForcelistAction::Removed,
            "removed dig-owned policy file",
        ),
        Err(e) => outcome(location, ForcelistAction::Failed, &format!("remove: {e}")),
    }
}

fn outcome(location: String, action: ForcelistAction, note: &str) -> ForcelistOutcome {
    ForcelistOutcome {
        location,
        action,
        note: note.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{is_our_entry, EXTENSION_ID};
    use super::*;
    use tempfile::tempdir;

    fn read_forcelist(dir: &Path) -> Vec<String> {
        let raw = std::fs::read_to_string(policy_path(dir)).expect("policy file exists");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        v["ExtensionInstallForcelist"]
            .as_array()
            .expect("array")
            .iter()
            .map(|e| e.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn apply_writes_a_dig_owned_file_with_our_entry() {
        let dir = tempdir().unwrap();
        let out = apply_in(dir.path(), Channel::Stable);
        assert_eq!(out.action, ForcelistAction::Wrote);

        let list = read_forcelist(dir.path());
        assert_eq!(list.len(), 1);
        assert!(is_our_entry(&list[0]));
        assert!(list[0].contains("stable"));
    }

    #[test]
    fn apply_creates_missing_managed_dir() {
        let root = tempdir().unwrap();
        let nested = root.path().join("etc/opt/chrome/policies/managed");
        let out = apply_in(&nested, Channel::Stable);
        assert_eq!(out.action, ForcelistAction::Wrote);
        assert!(policy_path(&nested).exists());
    }

    #[test]
    fn apply_is_idempotent() {
        let dir = tempdir().unwrap();
        assert_eq!(
            apply_in(dir.path(), Channel::Stable).action,
            ForcelistAction::Wrote
        );
        // A second identical pass writes nothing new.
        assert_eq!(
            apply_in(dir.path(), Channel::Stable).action,
            ForcelistAction::AlreadyPresent
        );
        assert_eq!(read_forcelist(dir.path()).len(), 1, "no duplicate entry");
    }

    #[test]
    fn apply_switches_channel_in_place() {
        let dir = tempdir().unwrap();
        apply_in(dir.path(), Channel::Stable);
        let out = apply_in(dir.path(), Channel::Nightly);
        assert_eq!(out.action, ForcelistAction::Wrote);
        let list = read_forcelist(dir.path());
        assert_eq!(list.len(), 1, "still exactly one dig entry");
        assert!(list[0].contains("nightly"));
    }

    #[test]
    fn remove_deletes_only_our_file_and_leaves_org_policy() {
        let dir = tempdir().unwrap();
        // An admin's own policy file, in the same managed directory.
        let org = dir.path().join("org-policy.json");
        std::fs::write(
            &org,
            r#"{"ExtensionInstallForcelist":["someorgext;https://x"]}"#,
        )
        .unwrap();

        apply_in(dir.path(), Channel::Stable);
        let out = remove_in(dir.path());
        assert_eq!(out.action, ForcelistAction::Removed);

        assert!(!policy_path(dir.path()).exists(), "dig file gone");
        assert!(org.exists(), "org policy file untouched");
    }

    #[test]
    fn remove_is_a_noop_when_absent() {
        let dir = tempdir().unwrap();
        assert_eq!(
            remove_in(dir.path()).action,
            ForcelistAction::NothingToRemove
        );
    }

    #[test]
    fn our_file_never_contains_a_foreign_id() {
        let dir = tempdir().unwrap();
        apply_in(dir.path(), Channel::Stable);
        let list = read_forcelist(dir.path());
        assert!(list.iter().all(|e| e.starts_with(EXTENSION_ID)));
    }
}
