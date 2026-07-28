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
