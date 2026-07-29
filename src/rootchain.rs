//! The privileged install root is a CHAIN, not a directory (#1748).
//!
//! # The defect this module removes
//!
//! Pinning the mode of `/opt/dig/bin` and verifying only that leaf leaves its PARENT untouched.
//! `create_dir_all` creates intermediate levels at the process umask, so `/opt/dig` was created `0755`,
//! `0775` or — under `umask 000` — `0777`, and nothing ever checked or repaired it. Every one of those
//! installs reported `✓ DIG is ready.`
//!
//! A world-writable `/opt/dig` is a complete escalation on its own, with no race and no password:
//!
//! ```text
//! mv /opt/dig/bin /opt/dig/bin.orig     # rename needs write on the PARENT, not on bin
//! mkdir /opt/dig/bin                    # now attacker-owned
//! cp evil /opt/dig/bin/dig-store        # root runs it via the /usr/local/bin symlink
//! ```
//!
//! and every service `ExecStart=/opt/dig/bin/…` plus the root-run beacon resolve to the attacker's
//! binaries at the next start. Naming the target directly does not help when the target's parent can be
//! swapped. Mode bits on a leaf mean nothing without its ancestry.
//!
//! # The shape
//!
//! * **Every DIG-owned level is created and owned explicitly** — the unix mirror of
//!   [`crate::secure::windows_created_root_levels`], which already does exactly this on Windows.
//! * **The mode is REPAIRED, not only set at creation.** A box that installed an earlier version under
//!   `umask 000` already has a `0777` `/opt/dig`; an install that merely refrained from making it worse
//!   would leave the escalation in place and still print a tick. So each level is re-moded on every run.
//! * **Every level is verified through an `O_NOFOLLOW` DESCRIPTOR**, from `/` down, including the
//!   ancestors DIG does not own (`/`, `/opt`) — a writable ancestor means the level below it can be
//!   replaced wholesale. `fstat` on the descriptor describes the inode that was opened, so a path
//!   cannot be re-resolved to another inode in between, and a planted symlink fails to open at all
//!   rather than redirecting the check.

#![cfg(unix)]

use std::path::{Component, Path, PathBuf};

use crate::dirfd::{self, DirFd, ROOT_UID};

/// The mode every DIG-owned level of the privileged root is pinned to: owner (root) writes, everybody
/// else reads and traverses. Group and other write are exactly what must never be set — that is what
/// lets a non-root account replace a binary root executes.
pub const PRIVILEGED_DIR_MODE: u32 = 0o755;

/// The permission bits that make a directory unsafe to hold a root-executed binary: group write or
/// other write.
const GROUP_OR_OTHER_WRITE: u32 = 0o022;

/// The levels of `root` that DIG itself introduces, outermost first — the ones this installer created
/// and is therefore entitled to own and re-mode.
///
/// `/opt/dig/bin` yields `[/opt/dig, /opt/dig/bin]`: `/opt` is the distribution's, and re-moding it
/// would be overreach. The Windows counterpart makes the same distinction —
/// [`crate::secure::windows_created_root_levels`] owns the `DIG` and `bin` levels under Program Files
/// and never touches Program Files itself.
///
/// A directory with no recognised DIG prefix (a `--bin-dir` the operator chose) yields nothing: it is
/// not ours to re-mode. It is still VERIFIED — see [`verify`] — because root writing into it is only
/// safe if no non-root account can reach it.
pub fn dig_owned_levels(root: &Path) -> Vec<PathBuf> {
    // `/opt/dig` is the prefix this installer owns; the DIG-owned levels are it and everything below.
    let owned_prefix = Path::new("/opt/dig");
    let Ok(below) = root.strip_prefix(owned_prefix) else {
        return Vec::new();
    };
    let mut levels = vec![owned_prefix.to_path_buf()];
    let mut walked = owned_prefix.to_path_buf();
    for component in below.components() {
        walked.push(component);
        levels.push(walked.clone());
    }
    levels
}

/// Create every DIG-owned level of `root` and pin each to [`PRIVILEGED_DIR_MODE`], root-owned.
///
/// Idempotent and REPAIRING: a level that already exists has its mode and ownership re-asserted rather
/// than being accepted as-is, because the mode `create_dir_all` left behind on an earlier run (or that
/// somebody else chose) is exactly the defect. Each level is opened `O_NOFOLLOW` and modified through
/// that descriptor, so a symlink planted at a level is refused instead of followed.
///
/// A directory with no DIG-owned levels (an operator's `--bin-dir`) is created if absent and otherwise
/// left entirely alone — its posture is reported by [`verify`], not rewritten.
///
/// Ownership is repaired only when this process is root, since only root can give a directory away;
/// otherwise a wrong owner is left for [`verify`] to report. The MODE is always repaired, because that
/// is within the authority of whoever owns the level.
pub fn ensure(root: &Path) -> Result<(), String> {
    let levels = dig_owned_levels(root);
    if levels.is_empty() {
        if !root.is_dir() {
            std::fs::create_dir_all(root).map_err(|e| format!("create {}: {e}", root.display()))?;
        }
        return Ok(());
    }
    ensure_levels(&levels)
}

/// [`ensure`] over an explicit level list, outermost first, so the create-and-repair behaviour is
/// exercisable against a temporary tree instead of the real `/opt/dig`.
fn ensure_levels(levels: &[PathBuf]) -> Result<(), String> {
    for level in levels {
        if !level.is_dir() {
            // `create_dir` (not `_all`) so each level is created by this loop and none is created
            // implicitly at the umask by a deeper call.
            match std::fs::create_dir(level) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("create {}: {e}", level.display())),
            }
        }
        let fd = dirfd::open_dir_nofollow(None, level)?
            .ok_or_else(|| format!("{} vanished while being created", level.display()))?;
        // Through the descriptor, so the inode re-moded is the one just opened. The mode is asserted
        // unconditionally: this is the repair path for a level an earlier run left group/world-writable.
        dirfd::fchmod(&fd, PRIVILEGED_DIR_MODE, level)?;
        // Ownership can only be GIVEN by root, so it is repaired when we have the authority to do so
        // and merely VERIFIED otherwise. An unprivileged run that finds a non-root level does not fail
        // here — it fails at `verify`, whose ownership arm reports it and which readiness treats as
        // fatal under elevation. Attempting the `fchown` regardless turned "this level has the wrong
        // owner" into "chown: operation not permitted", which is a worse message for the same fact.
        let (owner, _) = dirfd::stat_of(&fd, level)?;
        if owner != ROOT_UID && crate::invoker::is_root() {
            dirfd::fchown(&fd, ROOT_UID, ROOT_UID, level)?;
        }
    }
    Ok(())
}

/// The verdict for `root`: is every level of its path, from `/` down, safe from modification by a
/// non-root account?
///
/// Reports the FIRST unsafe level, so the message names the directory an operator must repair rather
/// than the leaf that merely sits beneath it. `Err` describes a level that could not be inspected at
/// all — a symlink, a non-directory, or an unreadable one — which is a refusal, never a pass.
///
/// # Why every ancestor, and why by descriptor
///
/// Write permission on a directory is permission to REPLACE its children: a `0777` `/opt/dig` lets any
/// account rename `/opt/dig/bin` aside and substitute its own, whatever `bin`'s own mode says. So the
/// leaf's mode is meaningless without its ancestry, and the walk covers levels DIG does not own
/// (`/`, `/opt`) as well as those it does.
///
/// Each component is opened `O_NOFOLLOW|O_DIRECTORY` and `fstat`ed. A path-based `std::fs::metadata`
/// FOLLOWS symlinks, which let `--bin-dir /home/alice/bin` — where `~/bin` is a symlink to `/etc` —
/// report "root-owned with no group/other write (mode 755)" while describing `/etc`, and root then
/// created files there.
pub fn verify(root: &Path) -> Result<Option<Unsafe>, String> {
    verify_within(Path::new("/"), root)
}

/// [`verify`] for the levels strictly BELOW `base`.
///
/// `base` itself is not judged. In production it is `/`, whose permissions are the kernel's business and
/// on which a write grant means the machine is already lost by any measure. In tests it is a temporary
/// directory, which lives under a `1777` `/tmp` that would otherwise be reported as the first unsafe
/// level and mask what the test is actually about.
fn verify_within(base: &Path, root: &Path) -> Result<Option<Unsafe>, String> {
    let Ok(below) = root.strip_prefix(base) else {
        return Err(format!(
            "{} is not below {} — refusing to verify a chain that was not asked about",
            root.display(),
            base.display()
        ));
    };
    let mut walked = base.to_path_buf();
    let mut fd: DirFd = dirfd::open_dir_nofollow(None, base)?
        .ok_or_else(|| format!("{} could not be opened", base.display()))?;
    for component in below.components() {
        // `CurDir`/`ParentDir` cannot appear in the absolute, normalised paths this is called with, and
        // are skipped rather than guessed at.
        let Component::Normal(name) = component else {
            continue;
        };
        walked.push(name);
        let Some(next) = dirfd::open_dir_nofollow(Some(&fd), Path::new(name))? else {
            // Absent: nothing beneath it can be unsafe, and `ensure` is what creates it.
            return Ok(None);
        };
        fd = next;
        if let Some(bad) = level_verdict(&fd, &walked)? {
            return Ok(Some(bad));
        }
    }
    Ok(None)
}

/// A level of the install root that a non-root account can modify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsafe {
    /// The offending level, which may be an ANCESTOR of the directory asked about.
    pub level: PathBuf,
    /// Why it is unsafe, phrased for an operator who has to repair it.
    pub reason: String,
}

/// Is this one already-open level safe? `None` means yes.
fn level_verdict(fd: &DirFd, path: &Path) -> Result<Option<Unsafe>, String> {
    let (owner, mode) = dirfd::stat_of(fd, path)?;
    if mode & GROUP_OR_OTHER_WRITE != 0 {
        // Sticky directories (`/tmp`, mode 1777) are deliberately NOT special-cased: the sticky bit
        // stops a non-owner deleting a SIBLING's entry, and DIG's levels are created by root, so a
        // privileged root under a sticky directory is still a directory a stranger can add entries to.
        return Ok(Some(Unsafe {
            level: path.to_path_buf(),
            reason: format!(
                "mode {:o} allows group or other to write, so a non-root account can replace what it \
                 contains",
                mode & 0o7777
            ),
        }));
    }
    if owner != ROOT_UID {
        return Ok(Some(Unsafe {
            level: path.to_path_buf(),
            reason: format!(
                "it is owned by uid {owner}, not root, so its owner can replace what it contains"
            ),
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dig_owned_levels_are_the_prefix_and_below_never_the_distributions_own() {
        assert_eq!(
            dig_owned_levels(Path::new("/opt/dig/bin")),
            vec![PathBuf::from("/opt/dig"), PathBuf::from("/opt/dig/bin")],
            "/opt/dig must be owned explicitly — leaving it at the umask is the escalation (#1748)"
        );
        // `/opt` belongs to the distribution. Re-moding it would be overreach, and the Windows
        // counterpart makes the same distinction about Program Files.
        assert!(!dig_owned_levels(Path::new("/opt/dig/bin")).contains(&PathBuf::from("/opt")));
        // A directory the operator nominated is not ours to re-mode.
        assert!(dig_owned_levels(Path::new("/home/alice/bin")).is_empty());
    }

    /// THE F1 escalation, as a test: a world-writable PARENT must make the verdict unsafe even when the
    /// leaf itself is a perfect `0755` root-owned directory.
    ///
    /// The fixture is deliberately the exploit's exact shape — the leaf is beyond reproach, so a check
    /// that looks only at the leaf (which is what shipped) passes it. Write permission on the parent is
    /// permission to rename the leaf aside and substitute an attacker-owned directory of the same name.
    #[test]
    fn a_writable_ancestor_is_unsafe_even_when_the_leaf_is_perfect() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("dig");
        let leaf = parent.join("bin");
        std::fs::create_dir_all(&leaf).unwrap();
        set_mode(&leaf, 0o755);
        set_mode(&parent, 0o777);

        let bad = verify_within(tmp.path(), &leaf)
            .expect("the walk must complete")
            .expect("a world-writable ancestor must be reported");
        assert_eq!(
            bad.level, parent,
            "the FIRST unsafe level must be named, so an operator repairs the parent and not the leaf"
        );
        assert!(bad.reason.contains("write"), "got: {}", bad.reason);

        // The control, and it is load-bearing: with ONLY the parent repaired, the same leaf must now
        // verify clean. A `verify` that reported unsafe unconditionally would satisfy the assertion
        // above, and one that ignored ownership would satisfy this one — so ownership is asserted
        // separately below.
        set_mode(&parent, 0o755);
        if running_as_root(&parent) {
            assert!(
                verify_within(tmp.path(), &leaf).unwrap().is_none(),
                "a root-owned 0755 chain must verify clean"
            );
        } else {
            // Unprivileged the levels are owned by the test user, so the OWNERSHIP arm fires instead —
            // which is itself the assertion that a non-root-owned level is refused.
            let bad = verify_within(tmp.path(), &leaf)
                .unwrap()
                .expect("not root-owned");
            assert!(bad.reason.contains("not root"), "got: {}", bad.reason);
        }
    }

    /// Group write is as fatal as other write: `0775` under `umask 002` is the common real-world case,
    /// and every member of the group can replace a binary root executes.
    #[test]
    fn group_write_on_a_level_is_unsafe() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dig");
        std::fs::create_dir(&dir).unwrap();
        set_mode(&dir, 0o775);
        let bad = verify_within(tmp.path(), &dir)
            .unwrap()
            .expect("0775 must be reported");
        assert_eq!(bad.level, dir);
        assert!(bad.reason.contains("write"), "got: {}", bad.reason);
    }

    /// A symlink standing in for a level is REFUSED, never followed — the F2 shape. A path-based
    /// `metadata` would have described the target and reported it secure.
    #[test]
    fn a_symlinked_level_is_refused_rather_than_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        set_mode(&real, 0o755);
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = verify_within(tmp.path(), &link).expect_err("a symlinked level must be refused");
        assert!(err.contains("symlink"), "got: {err}");
    }

    /// `ensure` REPAIRS an existing level rather than accepting it. A box that installed an earlier
    /// version under `umask 000` already has a `0777` level, so an install that only got new
    /// directories right would leave the escalation in place and still print a tick.
    ///
    /// Both levels start wrong, so a fix that repaired only the leaf — which is what shipped — fails.
    #[test]
    fn ensure_repairs_an_existing_chain_it_did_not_create() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("dig");
        let leaf = parent.join("bin");
        std::fs::create_dir_all(&leaf).unwrap();
        set_mode(&parent, 0o777);
        set_mode(&leaf, 0o777);

        ensure_levels(&[parent.clone(), leaf.clone()]).expect("the repair must succeed");

        for level in [&parent, &leaf] {
            assert_eq!(
                mode_of(level),
                0o755,
                "{} was left writable — the repair path is part of the fix, not optional",
                level.display()
            );
        }
    }

    fn set_mode(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// A temp dir is owned by the test user, not root, so the "verifies clean" control can only be
    /// asserted where the chain really is root-owned.
    fn running_as_root(p: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).map(|m| m.uid() == 0).unwrap_or(false)
    }
}
