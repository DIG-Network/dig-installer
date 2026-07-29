//! Writing a per-user file from a privileged installer — with the USER's authority, never root's.
//!
//! # Why this module exists
//!
//! An elevated install has to place per-user artifacts (a systemd user unit, a LaunchAgent, a
//! `.desktop` handler) inside the invoking user's home. Doing that the obvious way — root calls
//! `create_dir_all` + `write`, then `chown`s the result back — is a local privilege escalation, not a
//! style problem:
//!
//! * every path component is a directory the TARGET USER fully controls, and the leaf names are
//!   deterministic and published in `SPEC.md`;
//! * so unprivileged code running as that user (a malicious `npm`/`pip` postinstall, a browser
//!   payload, a compromised dotfiles repo — no password needed) can plant a symlink and wait for the
//!   next `curl -fsSL https://dig.net/install.sh | sudo sh`;
//! * root then follows it. A dangling symlink makes root CREATE the target — `/etc/ld.so.preload` —
//!   and hand it to the attacker; a symlink onto a root-owned `0600` file transfers that file
//!   outright; and a `chown -R` reaches through a symlinked ANCESTOR, so `~/.config` → `/etc` on any
//!   systemd box gives away `/etc/systemd`, including `dig-node.service`, whose `ExecStart` the
//!   attacker then rewrites.
//!
//! Patching each call site with `O_NOFOLLOW` and `chown -h` is possible but fragile, and `-h` alone
//! does not even fix the ancestor variant (`chown` dereferences by default; `chown -R` on a symlink
//! ARGUMENT does not traverse, which is exactly why the ancestor case works).
//!
//! # The approach: remove the primitive
//!
//! So the root-side write is REMOVED rather than hardened. Under elevation the file is written by the
//! target user's own shell, so the kernel enforces the boundary for us and there is no ownership to
//! hand back afterwards:
//!
//! * a planted symlink pointing anywhere the user cannot already write simply FAILS — it is their uid
//!   doing the write, so `/etc/ld.so.preload` is `EACCES`, not a takeover;
//! * a symlink pointing somewhere they CAN write is entirely within the authority they already had,
//!   which is not an escalation;
//! * the artifact is created owned by the user, so no `chown` — and therefore no `chown -R` ancestor
//!   amplifier — exists at all.
//!
//! When we are NOT elevated we already ARE that user, so there is no boundary to cross and the write
//! is direct.
//!
//! Fail-closed: if the write cannot be performed as the user, it is reported as a failure and NOT
//! retried as root. Every caller here is best-effort convenience (autostart, scheme handlers) — a
//! missing artifact is a note in the install log, whereas a root-authored one is a root shell.

use crate::invoker::TargetUser;
use std::path::Path;

/// Create `path`'s parent directory and write `contents` to `path`, using `user`'s authority.
///
/// Under elevation the work is delegated to the user's own shell (see the module docs); otherwise it
/// is a direct write, because we are already that user.
pub fn write_as_user(path: &Path, contents: &str, user: &TargetUser) -> Result<(), String> {
    write_bytes_as_user(path, contents.as_bytes(), user)
}

/// [`write_as_user`] for a binary artifact (an icon, a cache) — same authority rules.
pub fn write_bytes_as_user(path: &Path, contents: &[u8], user: &TargetUser) -> Result<(), String> {
    if !user.via_elevation {
        return write_directly(path, contents);
    }
    #[cfg(unix)]
    {
        write_via_user_shell(path, contents, user)
    }
    // Windows never reaches here: its per-user registrations are HKCU registry values written by the
    // user's own session, not files root places in a user-writable directory.
    #[cfg(not(unix))]
    {
        write_directly(path, contents)
    }
}

/// Hand back to `user` any directory on the way to `dir` that ROOT created, so their own shell can
/// write there — refusing, loudly, anything that cannot be done safely.
///
/// # Why this is needed at all
///
/// Delegating the write to the user (above) is only sufficient while every directory on the way to the
/// artifact is one the user can write. An earlier PRIVILEGED component in the same install can leave a
/// root-owned level behind: then `mkdir -p` succeeds (the directory already exists, so it is a no-op)
/// and only the redirect fails, which is exactly the observed regression —
/// `-bash: line 1: /home/runner/.config/systemd/user/dig-app.service: Permission denied`. It is
/// silent, because autostart is best-effort, so the install still reports ready while dig-app will
/// never start at login.
///
/// # Why the descriptor walk, and not `chown`
///
/// The obvious remedy — `lstat` the chain, then `chown` the offending path — is NOT safe here, and the
/// unsafety is the very attack this module exists to close. The adversary is the TARGET USER, who owns
/// every directory being inspected, so they can swap a component between the check and the `chown`:
/// point `~/.config/systemd` at `/etc/systemd` after the `lstat`, and root hands them
/// `/etc/systemd/system`, where a unit file runs as root. `lchown` does not help — it declines to
/// follow only the FINAL component, while an intermediate symlink is still traversed.
///
/// So the chain is walked with `openat(O_NOFOLLOW | O_DIRECTORY)` from the user's home downwards and
/// each level is `fchown`ed through the DESCRIPTOR that was `fstat`ed. A descriptor is bound to an
/// inode, so there is no second path resolution for an attacker to race, and `O_NOFOLLOW` at every
/// step means a planted symlink is refused rather than traversed.
///
/// # What it refuses rather than repairs (fail loudly, never widen)
///
/// * any component that is a **symlink** — the ancestor attack;
/// * a home directory **not owned by the target user** — we are then not in their tree at all;
/// * a level owned by a **third party** (neither root nor the target user) — taking someone else's
///   directory is not ours to do;
/// * it never changes a **mode**, only ownership, and only on levels root itself owns. A level root
///   left mode `0555` is therefore reported, not force-widened.
///
/// Handing a root-created level to the user grants them nothing they did not have: the walk cannot
/// leave the home directory it verified they own, and the artifacts here (`~/.config/systemd/user`,
/// `~/.local/share/applications`, `~/Library/LaunchAgents`) are consumed by USER-scope facilities that
/// already execute as that user.
#[cfg(unix)]
fn ensure_user_can_write_dir(dir: &Path, user: &TargetUser) -> Result<(), String> {
    let (Some(uid), Some(gid)) = (user.uid, user.gid.or(user.uid)) else {
        // No uid means we are already the user, so there is no boundary and nothing to reclaim.
        return Ok(());
    };
    // Only ever act INSIDE the target user's own home. Anything else is out of scope by construction:
    // we neither inspect nor modify it, and let the write itself succeed or fail on its own merits.
    let Ok(relative) = dir.strip_prefix(&user.home) else {
        return Ok(());
    };

    let home = open_dir_nofollow(None, &user.home)?.ok_or_else(|| {
        format!(
            "{} does not exist, so {}'s per-user artifacts have nowhere to live",
            user.home.display(),
            user.name
        )
    })?;
    let home_owner = owner_of(&home, &user.home)?;
    if home_owner != uid {
        return Err(format!(
            "{} is owned by uid {home_owner}, not by {} (uid {uid}) — refusing to touch it, because \
             a home directory that is not the user's own is not a tree this installer may hand over",
            user.home.display(),
            user.name
        ));
    }

    let mut parent = home;
    let mut walked = user.home.to_path_buf();
    for component in relative.components() {
        walked.push(component);
        let Some(level) = open_dir_nofollow(Some(&parent), Path::new(component.as_os_str()))?
        else {
            // Absent from here down: the user's own `mkdir -p` creates these, owned by them.
            return Ok(());
        };
        let owner = owner_of(&level, &walked)?;
        if owner != uid && owner == ROOT_UID {
            // The level this installer (or an earlier privileged component) created as root. Hand it
            // over through the descriptor just inspected — no path is resolved a second time.
            fchown(&level, uid, gid, &walked)?;
        } else if owner != uid {
            return Err(format!(
                "{} is owned by uid {owner} — neither root nor {} (uid {uid}) — so it is not this \
                 installer's to hand over; give it to {} yourself, or remove it, and re-run",
                walked.display(),
                user.name,
                user.name
            ));
        }
        parent = level;
    }
    Ok(())
}

/// The descriptor-based directory primitives this walk is built on live in [`crate::dirfd`], shared with
/// [`crate::rootchain`] so there is ONE implementation of "open this level without following a symlink,
/// then act through the descriptor".
#[cfg(unix)]
use crate::dirfd::{fchown, open_dir_nofollow, owner_of, ROOT_UID};

/// The unelevated write: we are the user, so there is no privilege boundary to respect.
fn write_directly(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    std::fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Write `path` by running `mkdir` + `cat` as `user`, feeding `contents` on stdin.
///
/// `cat > file` rather than a here-doc so `contents` is never interpreted by the shell — no quoting,
/// expansion or command-substitution hazard, whatever the artifact body contains.
///
/// `su` is resolved from the trusted system directories, never `$PATH`
/// ([`crate::elevation::resolve_system_tool`]): this runs as root, and macOS's stock sudoers sets no
/// `secure_path`, so a `$PATH` beginning with a user-writable Homebrew prefix would otherwise let the
/// attacker supply `su` itself.
#[cfg(unix)]
fn write_via_user_shell(path: &Path, contents: &[u8], user: &TargetUser) -> Result<(), String> {
    use crate::proc::HideConsole;
    use std::io::Write;
    use std::process::{Command, Stdio};

    let su = crate::elevation::resolve_system_tool("su")
        .ok_or_else(|| "su not found in any trusted system directory".to_string())?;
    let dir = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    // Delegating the write is not enough on its own: an earlier privileged component can have left a
    // root-owned directory on the way, and then `mkdir -p` is a silent no-op and only the redirect
    // fails. Hand back what root created, or refuse loudly (#1748).
    ensure_user_can_write_dir(dir, user)?;
    let script = format!(
        "mkdir -p {} && cat > {}",
        shell_quote(dir),
        shell_quote(path)
    );

    let mut child = Command::new(su)
        .arg("-")
        .arg(&user.name)
        .arg("-c")
        .arg(&script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .hide_console()
        .spawn()
        .map_err(|e| format!("could not run the write as {}: {e}", user.name))?;

    child
        .stdin
        .take()
        .ok_or_else(|| "the write's stdin was unavailable".to_string())?
        .write_all(contents)
        .map_err(|e| format!("could not send {} to {}: {e}", path.display(), user.name))?;

    let out = child
        .wait_with_output()
        .map_err(|e| format!("could not wait for the write as {}: {e}", user.name))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let detail = if stderr.is_empty() {
        format!("exit {}", out.status.code().unwrap_or(-1))
    } else {
        stderr
    };
    Err(format!(
        "{} could not be written as {}: {detail}",
        path.display(),
        user.name
    ))
}

/// Single-quote for a POSIX shell, escaping embedded single quotes, so a path containing spaces or
/// shell metacharacters reaches `su -c` as exactly one word.
#[cfg(unix)]
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn user(name: &str, elevated: bool) -> TargetUser {
        TargetUser {
            name: name.to_string(),
            home: PathBuf::from(format!("/home/{name}")),
            uid: if elevated { Some(1000) } else { None },
            gid: if elevated { Some(1000) } else { None },
            via_elevation: elevated,
        }
    }

    /// Unelevated we ARE the user, so the write is direct and must simply work, parents included.
    #[test]
    fn an_unelevated_write_creates_the_file_and_its_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a").join("b").join("unit.service");
        write_as_user(&path, "BODY", &user("alice", false)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "BODY");
    }

    /// THE #1748 privilege-escalation regression: under elevation this process must NEVER perform the
    /// write itself, because every component of the path is user-controlled and a planted symlink
    /// would redirect a root-authored write anywhere on the filesystem.
    ///
    /// The fixture plants exactly the attack: a symlink at the artifact's name pointing at a file the
    /// installer must not touch. The elevated write is delegated to `su - <user>`, and the user here
    /// does not exist, so the write MUST fail with the victim untouched. The previous implementation
    /// (`std::fs::write` as ourselves, then `chown`) would have followed the link and overwritten it —
    /// which is what this test goes red on. Runs unprivileged: the point is precisely that the
    /// installer's OWN process does not do the write.
    #[cfg(unix)]
    #[test]
    fn an_elevated_write_never_follows_a_planted_symlink_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim-root-owned");
        std::fs::write(&victim, "SECRET").unwrap();

        let planted = tmp.path().join("dig-app.service");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        let result = write_as_user(
            &planted,
            "PAYLOAD",
            &user("definitely-not-a-real-account-xyz", true),
        );

        // Content first: it names the actual escalation, so a regression reports the LPE rather than
        // an unwrap panic on the returned Result.
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "SECRET",
            "an elevated install wrote THROUGH a user-planted symlink — this is the #1748 LPE"
        );
        assert!(
            result.is_err(),
            "the write must be reported as failed, never silently skipped"
        );
    }

    // -- #1748: a root-owned ancestor left by an EARLIER privileged component ----
    //
    // Observed in the e2e (run 30402180957, diagnostic): before the install `~/.config` is the user's
    // and `~/.config/systemd` does not exist; after it, BOTH `~/.config/systemd` and
    // `~/.config/systemd/user` are `root:root 0755`, because `sudo -E` leaks
    // `XDG_CONFIG_HOME=/home/runner/.config` into the root process and a `systemctl --user` run as root
    // creates them there. `mkdir -p` is then a silent no-op and only the redirect fails:
    //     -bash: line 1: /home/runner/.config/systemd/user/dig-app.service: Permission denied
    // The creator is a third-party binary, so this layer must cope with it rather than prevent it.

    /// A directory tree rooted at a temp dir, described as the target user's home.
    #[cfg(unix)]
    fn home_of(name: &str, uid: u32, home: &Path) -> TargetUser {
        TargetUser {
            name: name.to_string(),
            home: home.to_path_buf(),
            uid: Some(uid),
            gid: Some(uid),
            via_elevation: true,
        }
    }

    #[cfg(unix)]
    fn my_uid() -> u32 {
        // SAFETY: `getuid` takes no arguments, touches no memory, and cannot fail.
        unsafe { libc::getuid() as u32 }
    }

    #[cfg(unix)]
    fn owner_uid(p: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).unwrap().uid()
    }

    /// THE REGRESSION. Drives the real ordering: a root-owned `~/.config/systemd/user` left behind by
    /// an earlier privileged component, THEN the dig-app autostart write. Both levels must be handed
    /// back to the user, so their own shell can write the unit.
    ///
    /// Needs root, because only root can create a root-owned directory and only root can `fchown` it
    /// away — the branch under test does not exist unprivileged. The unprivileged half of this fix (the
    /// refusals) is covered by the tests below, which DO run in CI, and the full delegated write is
    /// gated end-to-end by the e2e's `autostart.registered` assertion.
    #[cfg(unix)]
    #[test]
    fn a_root_owned_ancestor_left_by_an_earlier_component_is_handed_back() {
        if my_uid() != 0 {
            eprintln!("skipped: needs root to create a root-owned ancestor (see the e2e gate)");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home-of-alice");
        let user_uid = 1000;

        // The user's own home and `.config` — theirs, exactly as the runner's are.
        std::fs::create_dir_all(home.join(".config")).unwrap();
        fchown_path(&home, user_uid);
        fchown_path(&home.join(".config"), user_uid);
        // The two levels an earlier privileged component left behind, root-owned 0755.
        let unit_dir = home.join(".config").join("systemd").join("user");
        std::fs::create_dir_all(&unit_dir).unwrap();
        assert_eq!(owner_uid(&unit_dir), 0, "fixture must start root-owned");

        let user = home_of("alice", user_uid, &home);
        ensure_user_can_write_dir(&unit_dir, &user)
            .expect("a root-created level must be handed back");

        assert_eq!(
            owner_uid(&home.join(".config").join("systemd")),
            user_uid,
            "the intermediate level root created must be handed back too — otherwise `mkdir -p` \
             cannot even reach the leaf"
        );
        assert_eq!(owner_uid(&unit_dir), user_uid);
        // The levels that were ALREADY the user's are untouched, and nothing was widened.
        assert_eq!(owner_uid(&home.join(".config")), user_uid);
        assert_eq!(owner_uid(&home), user_uid);
    }

    /// The reclaim must never take a directory belonging to a THIRD party — only one root itself owns.
    /// Root-gated for the same reason: it needs a home owned by the target user.
    #[cfg(unix)]
    #[test]
    fn a_level_owned_by_a_third_party_is_refused_not_taken() {
        if my_uid() != 0 {
            eprintln!("skipped: needs root");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home-of-alice");
        let (alice, mallory) = (1000, 1001);
        let dir = home.join(".config").join("systemd");
        std::fs::create_dir_all(&dir).unwrap();
        fchown_path(&home, alice);
        fchown_path(&home.join(".config"), alice);
        fchown_path(&dir, mallory);

        let err = ensure_user_can_write_dir(&dir, &home_of("alice", alice, &home)).unwrap_err();
        assert!(
            err.contains(&format!("owned by uid {mallory}")),
            "the refusal must name the owner it declined to take: {err}"
        );
        assert_eq!(
            owner_uid(&dir),
            mallory,
            "a third party's directory must be left exactly as it was"
        );
    }

    #[cfg(unix)]
    fn fchown_path(p: &Path, uid: u32) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; `lchown` touches no other memory. Test-only fixture
        // setup, so a plain path-based call is fine — the PRODUCTION path never does this (see
        // `ensure_user_can_write_dir`'s doc on why it walks descriptors instead).
        let rc = unsafe { libc::lchown(c.as_ptr(), uid as libc::uid_t, uid as libc::gid_t) };
        assert_eq!(rc, 0, "fixture chown of {} failed", p.display());
    }

    /// THE ancestor-symlink attack, and the one security-critical branch that DOES run unprivileged: a
    /// symlink standing where a directory must be is REFUSED, never traversed. Without `O_NOFOLLOW` the
    /// walk would descend into the target and, as root, hand it to the user — `~/.config` → `/etc` is
    /// how `/etc/systemd` gets given away.
    ///
    /// The fixture points the link at a REAL directory the walk would otherwise happily accept, so the
    /// refusal cannot be passing merely because the target does not exist.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_ancestor_is_refused_and_never_traversed() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(home.join("real-config")).unwrap();
        std::fs::create_dir_all(elsewhere.join("systemd").join("user")).unwrap();
        // `~/.config` is a symlink out of the home, with the rest of the chain real beneath it.
        std::os::unix::fs::symlink(&elsewhere, home.join(".config")).unwrap();

        let target = home.join(".config").join("systemd").join("user");
        let err =
            ensure_user_can_write_dir(&target, &home_of("alice", my_uid(), &home)).unwrap_err();
        assert!(
            err.contains("symlink or not a directory"),
            "the ancestor symlink must be reported as the refusal it is: {err}"
        );
        // The truthful control: the same walk over a REAL directory of the same shape succeeds, so the
        // assertion above is about the symlink and not about the walk rejecting everything.
        let real = home.join("real-config");
        assert!(ensure_user_can_write_dir(&real, &home_of("alice", my_uid(), &home)).is_ok());
    }

    /// A home directory that is not the target user's is refused outright — we are not in their tree,
    /// so nothing inside it is ours to hand over. Runs unprivileged by asking about a uid we are not.
    #[cfg(unix)]
    #[test]
    fn a_home_not_owned_by_the_target_user_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(home.join(".config")).unwrap();
        let not_us = my_uid() + 4242;

        let err =
            ensure_user_can_write_dir(&home.join(".config"), &home_of("alice", not_us, &home))
                .unwrap_err();
        assert!(
            err.contains("not by alice"),
            "the refusal must say whose home it expected: {err}"
        );
    }

    /// The ordinary case must stay cheap and silent: a level that does not exist yet is left for the
    /// user's own `mkdir -p`, which creates it owned by them. Asserted so the walk cannot "fix" the
    /// common path by creating directories as root — the very thing this module removed.
    #[cfg(unix)]
    #[test]
    fn an_absent_level_is_left_for_the_user_to_create() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let deep = home.join(".config").join("systemd").join("user");

        assert!(ensure_user_can_write_dir(&deep, &home_of("alice", my_uid(), &home)).is_ok());
        assert!(
            !home.join(".config").exists(),
            "the walk must not create anything as root — the user's own mkdir does that"
        );
    }

    /// A target outside the user's home is out of scope by construction: neither inspected nor changed.
    #[cfg(unix)]
    #[test]
    fn a_target_outside_the_home_is_left_entirely_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let outside = tmp.path().join("etc");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        assert!(ensure_user_can_write_dir(&outside, &home_of("alice", my_uid(), &home)).is_ok());
        assert_eq!(owner_uid(&outside), my_uid());
    }

    /// The elevated path must also not CREATE a dangling symlink's target — the `/etc/ld.so.preload`
    /// variant, where root brings the file into existence and hands it over.
    #[cfg(unix)]
    #[test]
    fn an_elevated_write_does_not_create_a_dangling_symlinks_target() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("ld.so.preload");
        let planted = tmp.path().join("dig-app.service");
        std::os::unix::fs::symlink(&absent, &planted).unwrap();

        let _ = write_as_user(
            &planted,
            "PAYLOAD",
            &user("definitely-not-a-real-account-xyz", true),
        );

        assert!(
            !absent.exists(),
            "an elevated install CREATED a dangling symlink's target — root would then hand it to \
             the attacker (#1748)"
        );
    }
}
