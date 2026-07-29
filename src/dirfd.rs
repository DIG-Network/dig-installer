//! Directory operations performed on an OPEN DESCRIPTOR rather than on a path.
//!
//! # Why a path is not good enough
//!
//! Every path-based filesystem call resolves the whole path again, following symlinks, at the moment it
//! runs. For an installer running as root that is two separate defects:
//!
//! * **it follows a link somebody else planted.** `std::fs::metadata` follows symlinks, so a directory
//!   check can describe `/etc` while the caller believes it described `~/bin`. Root then creates files
//!   there and the verdict still reads "secure".
//! * **it re-resolves between the check and the act.** A `metadata` + `set_permissions` pair on the same
//!   path is a TOCTOU window: the inode inspected and the inode modified need not be the same one. Won
//!   in practice — 9 hijacks in 6000 iterations — turning a root-owned `0600` file into `0755`.
//!
//! So this module opens each component with `O_NOFOLLOW|O_DIRECTORY` and then asks and acts through the
//! resulting descriptor (`fstat`, `fchown`, `fchmod`). A descriptor names one inode for its whole
//! lifetime: what was inspected is necessarily what is modified, and a symlink cannot be traversed
//! because opening it fails outright.
//!
//! unix only. On Windows the equivalent guarantees come from the ACL model and are handled in
//! [`crate::secure`].

#![cfg(unix)]

use std::path::Path;

/// uid 0 — root.
pub const ROOT_UID: u32 = 0;

/// An open directory descriptor, closed on drop.
pub struct DirFd(std::os::fd::OwnedFd);

impl DirFd {
    fn raw(&self) -> libc::c_int {
        use std::os::fd::AsRawFd;
        self.0.as_raw_fd()
    }
}

/// `openat` `name` beneath `parent` (or open `name` absolutely when `parent` is `None`) as a
/// directory, refusing to traverse a symlink.
///
/// `Ok(None)` distinguishes "does not exist yet" — an ordinary case for most callers — from an error. A
/// symlink surfaces as `ELOOP` and is reported as the ancestor attack it is.
pub fn open_dir_nofollow(parent: Option<&DirFd>, name: &Path) -> Result<Option<DirFd>, String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let c_name = std::ffi::CString::new(name.as_os_str().as_bytes())
        .map_err(|_| format!("{} contains an interior NUL byte", name.display()))?;
    // O_NOFOLLOW: a symlink at this component fails rather than being followed. O_DIRECTORY: a
    // non-directory fails rather than being opened. O_CLOEXEC: never leaked into a child process.
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let raw = match parent {
        // SAFETY: `c_name` is a valid NUL-terminated string; `parent`'s descriptor is owned and open
        // for the duration of the call; the return value is checked before being adopted.
        Some(p) => unsafe { libc::openat(p.raw(), c_name.as_ptr(), flags) },
        // SAFETY: as above, with an absolute path and no directory descriptor.
        None => unsafe { libc::open(c_name.as_ptr(), flags) },
    };
    if raw >= 0 {
        // SAFETY: `raw` is a fresh, valid descriptor this call owns and nothing else holds.
        return Ok(Some(DirFd(unsafe {
            std::os::fd::OwnedFd::from_raw_fd(raw)
        })));
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOENT) => Ok(None),
        // ELOOP is O_NOFOLLOW's report that the component IS a symlink; ENOTDIR means it is a
        // non-directory standing where a directory must be. Both are refusals, never repairs.
        Some(libc::ELOOP) | Some(libc::ENOTDIR) => Err(format!(
            "{} is a symlink or not a directory — refusing to treat it as a directory, because a \
             planted link is how a root-side operation is redirected somewhere it must never reach",
            name.display()
        )),
        _ => Err(format!("could not open {}: {err}", name.display())),
    }
}

/// The owning uid and permission bits of the already-open directory `fd`, read via `fstat` so they
/// describe the inode the descriptor holds rather than whatever `path` may resolve to by now (`path` is
/// for the message only).
pub fn stat_of(fd: &DirFd, path: &Path) -> Result<(u32, u32), String> {
    // SAFETY: `stat` is a plain C struct that is fully written by a successful `fstat`; the descriptor
    // is owned and open, and the result is checked before any field is read.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd.raw(), &mut st) };
    if rc != 0 {
        return Err(format!(
            "could not read the ownership of {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok((st.st_uid as u32, u32::from(st.st_mode) & 0o7777))
}

/// The owning uid of the already-open directory `fd`.
pub fn owner_of(fd: &DirFd, path: &Path) -> Result<u32, String> {
    stat_of(fd, path).map(|(uid, _)| uid)
}

/// `fchown` the open directory to `uid`:`gid`, through the descriptor — never by path.
pub fn fchown(fd: &DirFd, uid: u32, gid: u32, path: &Path) -> Result<(), String> {
    // SAFETY: the descriptor is owned and open; `fchown` takes it by value and touches no memory.
    let rc = unsafe { libc::fchown(fd.raw(), uid as libc::uid_t, gid as libc::gid_t) };
    if rc != 0 {
        return Err(format!(
            "{} was created by root and could not be handed back to uid {uid}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `fchmod` the open directory to `mode`, through the descriptor — never by path.
pub fn fchmod(fd: &DirFd, mode: u32, path: &Path) -> Result<(), String> {
    // SAFETY: the descriptor is owned and open; `fchmod` takes it by value and touches no memory.
    let rc = unsafe { libc::fchmod(fd.raw(), mode as libc::mode_t) };
    if rc != 0 {
        return Err(format!(
            "could not set the permissions of {} to {mode:o}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `fchmod` an open FILE to `mode`, through the descriptor.
///
/// The file counterpart of [`fchmod`], for the one caller that already holds the `File` it just
/// created and must not re-resolve its path to make it executable.
pub fn fchmod_file(file: &std::fs::File, mode: u32, path: &Path) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    // SAFETY: the descriptor is owned by `file` and open for the duration of the call.
    let rc = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
    if rc != 0 {
        return Err(format!(
            "could not set the permissions of {} to {mode:o}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal that the whole module exists for: a symlink standing where a directory is expected
    /// is REFUSED, not followed. `std::fs::metadata` would have described the target instead.
    #[test]
    fn a_symlink_where_a_directory_is_expected_is_refused_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-dir");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link-to-real");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err =
            open_dir_nofollow(None, &link).expect_err("a symlink must be refused, never traversed");
        assert!(err.contains("symlink"), "got: {err}");

        // The control: the real directory opens fine, so the refusal is about the LINK and not about
        // the call failing for everything.
        assert!(open_dir_nofollow(None, &real).unwrap().is_some());
    }

    /// A missing component is `Ok(None)`, distinct from an error — callers create it.
    #[test]
    fn a_missing_directory_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(open_dir_nofollow(None, &tmp.path().join("absent"))
            .unwrap()
            .is_none());
    }

    /// A non-directory is refused as firmly as a symlink: `O_DIRECTORY` is what stops a planted regular
    /// file from being treated as a level of the install root.
    #[test]
    fn a_regular_file_standing_in_for_a_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        assert!(open_dir_nofollow(None, &file).is_err());
    }

    /// `fchmod` acts on the inode the descriptor holds, and `stat_of` reads it back from the same
    /// descriptor — the pair that replaces a `metadata`/`set_permissions` path race.
    #[test]
    fn fchmod_and_stat_go_through_the_descriptor() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("level");
        std::fs::create_dir(&dir).unwrap();
        let fd = open_dir_nofollow(None, &dir).unwrap().unwrap();

        fchmod(&fd, 0o755, &dir).unwrap();
        let (_, mode) = stat_of(&fd, &dir).unwrap();
        assert_eq!(mode & 0o777, 0o755);

        fchmod(&fd, 0o700, &dir).unwrap();
        assert_eq!(stat_of(&fd, &dir).unwrap().1 & 0o777, 0o700);
    }

    /// `fchmod_file` makes a file executable through the descriptor that created it, which is what
    /// removes the chmod-by-path hijack from the download write.
    #[test]
    fn fchmod_file_sets_the_mode_of_the_open_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("binary");
        let file = std::fs::File::create(&path).unwrap();
        fchmod_file(&file, 0o755, &path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
