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
    // Symlink-safe atomic write (#650): as root into a compiled-in `/etc/**`
    // path, write a fresh O_NOFOLLOW temp file and atomically rename it over the
    // target. `rename` replaces the final path component itself (never following
    // a symlink AT it), so a redirecting symlink cannot divert the write, and the
    // policy file is only ever seen fully-written or absent — never partial.
    match write_atomic_nofollow(&path, desired.as_bytes()) {
        Ok(()) => outcome(
            location,
            ForcelistAction::Wrote,
            "wrote dig-owned managed-policy file (merged by the Chromium policy union)",
        ),
        Err(e) => outcome(location, ForcelistAction::Failed, &format!("write: {e}")),
    }
}

/// Write `contents` to `path` symlink-safely and atomically (#650): stage a
/// fresh temp file in the SAME directory, opened `O_NOFOLLOW | O_EXCL` so a
/// pre-seeded symlink at the temp name is refused rather than followed, then
/// `rename` it over `path`. The rename is atomic and operates on `path`'s final
/// component directly — replacing a redirecting symlink there with our regular
/// file instead of writing through it. The hardened pattern for a root writer
/// into a directory an attacker might race.
fn write_atomic_nofollow(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "policy path has no parent",
        )
    })?;
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "policy path has no file name",
        )
    })?;
    // A unique, hidden temp name in the same dir so the final rename is atomic
    // (same filesystem). The PID + a nanosecond stamp avoid colliding with a
    // concurrent run or a pre-planted name; O_EXCL is the real guarantee.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{file_name}.dig-tmp-{}-{stamp}",
        std::process::id()
    ));

    let write_tmp = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: refuse any pre-existing object (symlink included)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()
    };
    if let Err(e) = write_tmp() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
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

    /// #650 regression: a symlink pre-planted AT the policy path must NOT be
    /// followed — the atomic rename replaces the symlink itself with our regular
    /// file, leaving the symlink's target untouched (no write-through).
    #[test]
    fn apply_does_not_follow_a_symlink_at_the_policy_path() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        // The file a hostile symlink would try to redirect our root write into.
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, "original-victim-content").unwrap();
        // Plant a symlink where our policy file goes, pointing at the victim.
        symlink(&victim, policy_path(dir.path())).unwrap();

        let out = apply_in(dir.path(), Channel::Stable);
        assert_eq!(out.action, ForcelistAction::Wrote);

        // The victim was NOT overwritten through the symlink …
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "original-victim-content",
            "the write must never follow the symlink into the victim file"
        );
        // … and the policy path is now a real file with our policy (symlink gone).
        let meta = std::fs::symlink_metadata(policy_path(dir.path())).unwrap();
        assert!(
            meta.file_type().is_file(),
            "the policy path must be a regular file after the atomic replace"
        );
        assert!(is_our_entry(&read_forcelist(dir.path())[0]));
    }

    /// The atomic write leaves no stray temp files behind on success.
    #[test]
    fn apply_leaves_no_temp_file_behind() {
        let dir = tempdir().unwrap();
        apply_in(dir.path(), Channel::Stable);
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("dig-tmp"))
            .collect();
        assert!(strays.is_empty(), "no .dig-tmp-* file must remain");
    }

    #[test]
    fn our_file_never_contains_a_foreign_id() {
        let dir = tempdir().unwrap();
        apply_in(dir.path(), Channel::Stable);
        let list = read_forcelist(dir.path());
        assert!(list.iter().all(|e| e.starts_with(EXTENSION_ID)));
    }
}
