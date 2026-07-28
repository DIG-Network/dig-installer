//! Who is this install FOR? — resolving the invoking human under `sudo` (#1748).
//!
//! An installer run as `curl … | sudo sh` executes as root, and root's environment is NOT the
//! environment the person who typed the command lives in. `sudo` sets `HOME=/root`, so every
//! `dirs::home_dir()` call in an elevated process answers `/root` — which is how a whole DIG
//! install came to land in `/root/.dig/bin`, invisible to the actual user's PATH, with no
//! `/etc/profile.d` entry and no per-user autostart in the account that would ever log in.
//!
//! This module resolves the **target user**: the account whose per-user artifacts (home-scoped bin
//! dir, shell profiles, autostart unit) an install must be written for and owned by. Under
//! elevation that is the *invoking* account, named by the escalation tool:
//!
//! * `sudo` — `SUDO_USER` / `SUDO_UID` / `SUDO_GID`
//! * `doas` — `DOAS_USER`
//! * `pkexec` — `PKEXEC_UID` (a uid only, so it is resolved back to a name via the passwd database)
//!
//! # Why the resolution is pure
//!
//! Every decision here is a pure function over an environment lookup and the *contents* of the
//! passwd database ([`resolve`], [`elevation_hint`], [`passwd_lookup`]). The live wrappers
//! ([`target_user`]) supply the real `geteuid()` and `/etc/passwd`. That split is what lets a test
//! assert the `HOME=/root` inversion directly — construct the exact env `sudo` produces and assert
//! the resolved home is the *user's*, not root's — on any host, including a non-root Windows CI
//! runner where the bug is unreproducible in situ.

use std::path::{Path, PathBuf};

/// The account an install writes its per-user artifacts for, and the ownership those artifacts
/// must carry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TargetUser {
    /// The account name (`ubuntu`, `alice`, …).
    pub name: String,
    /// The account's home directory — the one per-user artifacts belong under.
    pub home: PathBuf,
    /// The account's numeric uid, when known. `Some` under elevation (so the account can be named
    /// precisely — e.g. its `XDG_RUNTIME_DIR`); `None` when we are already running as that user.
    /// Per-user artifacts are written BY the user ([`crate::userwrite`]), so this is never used to
    /// `chown` a root-authored file back — that shape was the #1748 privilege escalation.
    pub uid: Option<u32>,
    /// The account's numeric gid, when known.
    pub gid: Option<u32>,
    /// Are we root acting on behalf of a DIFFERENT account (a `sudo`/`doas`/`pkexec` install)?
    ///
    /// This is the flag every per-user decision must consult: when `true`, `dirs::home_dir()` and
    /// `std::env::var("PATH")` describe root, not the user, and must not be trusted.
    pub via_elevation: bool,
}

impl TargetUser {
    /// The `~/.dig/bin` directory for this user (the non-elevated CLI install root).
    pub fn dig_bin_dir(&self) -> PathBuf {
        self.home.join(".dig").join("bin")
    }
}

/// One parsed passwd-database record — the fields this module needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    /// Account name (field 1).
    pub name: String,
    /// Numeric uid (field 3).
    pub uid: u32,
    /// Numeric gid (field 4).
    pub gid: u32,
    /// Home directory (field 6).
    pub home: PathBuf,
}

/// What an escalation tool told us about the human who invoked it. Any field may be absent: `doas`
/// supplies only a name, `pkexec` only a uid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElevationHint {
    /// The invoking account name, if the tool named one.
    pub name: Option<String>,
    /// The invoking account's uid, if the tool supplied one.
    pub uid: Option<u32>,
    /// The invoking account's gid, if the tool supplied one.
    pub gid: Option<u32>,
}

impl ElevationHint {
    /// Did the tool identify anybody at all?
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.uid.is_none()
    }
}

/// Environment variables naming the invoking account, in precedence order (`sudo` first — it is the
/// documented install path).
const NAME_VARS: [&str; 2] = ["SUDO_USER", "DOAS_USER"];

/// Environment variables carrying the invoking account's uid, in precedence order.
const UID_VARS: [&str; 2] = ["SUDO_UID", "PKEXEC_UID"];

/// Read the escalation hint out of the environment.
///
/// Returns an empty hint when `euid != 0`: if we are not root there is nothing to redirect — the
/// process already IS the target user, and a stale `SUDO_USER` inherited from an unrelated ancestor
/// shell must not hijack the install. A hint naming `root` itself is also ignored, since
/// `sudo -u root` is not the inversion this module exists to correct.
pub fn elevation_hint(euid: u32, get: impl Fn(&str) -> Option<String>) -> ElevationHint {
    if euid != 0 {
        return ElevationHint::default();
    }
    let named = NAME_VARS
        .iter()
        .filter_map(|v| get(v))
        .map(|v| v.trim().to_string())
        .find(|v| !v.is_empty() && v != "root");
    let uid = UID_VARS
        .iter()
        .filter_map(|v| get(v))
        .filter_map(|v| v.trim().parse::<u32>().ok())
        .find(|&u| u != 0);
    let gid = get("SUDO_GID")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|&g| g != 0);
    ElevationHint {
        name: named,
        uid,
        gid,
    }
}

/// Parse a passwd database (the contents of `/etc/passwd`, or `getent passwd` output).
///
/// Malformed and comment lines are skipped rather than failing the parse: a single unparseable
/// record in a machine's passwd file must not cost the install its user resolution.
pub fn parse_passwd(contents: &str) -> Vec<PasswdEntry> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let f: Vec<&str> = line.split(':').collect();
            // name:passwd:uid:gid:gecos:home:shell — home is field 6, so 6 fields is the minimum.
            if f.len() < 6 {
                return None;
            }
            Some(PasswdEntry {
                name: f[0].to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                home: PathBuf::from(f[5]),
            })
        })
        .collect()
}

/// Find the passwd record matching `hint` — by name when the tool named one, else by uid.
///
/// Name takes precedence over uid because a name is what the user typed into `sudo`, and because
/// two records can legitimately share a uid (an alias account), in which case the name disambiguates.
pub fn passwd_lookup<'a>(
    entries: &'a [PasswdEntry],
    hint: &ElevationHint,
) -> Option<&'a PasswdEntry> {
    if let Some(name) = &hint.name {
        if let Some(e) = entries.iter().find(|e| &e.name == name) {
            return Some(e);
        }
    }
    hint.uid
        .and_then(|uid| entries.iter().find(|e| e.uid == uid))
}

/// Resolve the account this install is for.
///
/// * Not root, or root with no escalation hint (a genuine root login) → the current process's own
///   account, described by `self_name` / `self_home`. Nothing is redirected.
/// * Root with a hint → the invoking account, with its home read from the passwd database, NEVER
///   from `$HOME` (which `sudo` has already overwritten with `/root`).
///
/// When a hint names an account the passwd database does not contain, the hint's own uid/gid are
/// still carried so ownership can be fixed, but the home falls back to `self_home` and
/// [`TargetUser::via_elevation`] stays `true` — the caller can then see that a per-user location is
/// not trustworthy and prefer a machine-wide one.
pub fn resolve(
    euid: u32,
    get: impl Fn(&str) -> Option<String>,
    passwd: &[PasswdEntry],
    self_name: &str,
    self_home: &Path,
) -> TargetUser {
    let hint = elevation_hint(euid, get);
    if hint.is_empty() {
        return TargetUser {
            name: self_name.to_string(),
            home: self_home.to_path_buf(),
            uid: None,
            gid: None,
            via_elevation: false,
        };
    }
    match passwd_lookup(passwd, &hint) {
        Some(e) => TargetUser {
            name: e.name.clone(),
            home: e.home.clone(),
            uid: Some(e.uid),
            gid: Some(e.gid),
            via_elevation: true,
        },
        None => TargetUser {
            name: hint.name.clone().unwrap_or_else(|| self_name.to_string()),
            home: self_home.to_path_buf(),
            uid: hint.uid,
            gid: hint.gid,
            via_elevation: true,
        },
    }
}

/// Is this process running with root's effective uid? Always `false` on Windows, where elevation is
/// a token privilege rather than a uid (see [`crate::elevation`] for the Windows check).
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` reads the calling process's effective uid; it takes no arguments,
        // touches no caller memory, and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The live [`TargetUser`], resolved once per process.
///
/// Cached because [`crate::paths::default_bin_dir`] consults it and is called from dozens of places:
/// the answer cannot change during a run (neither our euid nor the invoking account moves), so
/// re-reading the passwd database each time would be pure waste.
static LIVE: std::sync::OnceLock<TargetUser> = std::sync::OnceLock::new();

/// The account this process is installing for. See [`resolve`] for the rules.
pub fn target_user() -> &'static TargetUser {
    LIVE.get_or_init(resolve_live)
}

/// Resolve the [`TargetUser`] for the live process — the real `geteuid()`, the real environment, and
/// the real passwd database.
fn resolve_live() -> TargetUser {
    let self_home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
    let self_name = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string());
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments, touches no memory, and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let contents = read_passwd_file();
        let mut entries = parse_passwd(&contents);
        // The flat file is the fast, common answer. When it cannot name the invoking account — a
        // directory-backed box, or macOS, whose stock `/etc/passwd` lists no ordinary user at all — ask
        // the OS resolver for that ONE account and append it, so `resolve` can apply its normal
        // precedence to a complete list. Done here rather than inside `resolve` to keep that function
        // pure and exhaustively unit-testable (#1748 F2).
        let hint = elevation_hint(euid, |k| std::env::var(k).ok());
        if !hint.is_empty() && passwd_lookup(&entries, &hint).is_none() {
            if let Some(entry) = directory_lookup(&hint) {
                entries.push(entry);
            }
        }
        resolve(
            euid,
            |k| std::env::var(k).ok(),
            &entries,
            &self_name,
            &self_home,
        )
    }
    #[cfg(not(unix))]
    {
        resolve(1, |_| None, &[], &self_name, &self_home)
    }
}

/// The flat `/etc/passwd`, as text. The authoritative answer for a directory-backed account comes from
/// [`directory_lookup`] instead — see there for why this is no longer a `getent` spawn.
#[cfg(unix)]
fn read_passwd_file() -> String {
    std::fs::read_to_string("/etc/passwd").unwrap_or_default()
}

/// Ask the OS itself for ONE account, through libc's own resolver — `getpwnam_r`/`getpwuid_r`.
///
/// # Why not `getent passwd` (#1748 F2)
///
/// This used to spawn `getent`, resolved from a fixed list of trusted directories. That list included
/// `/usr/local/bin`, which Homebrew on an Intel Mac leaves `<user>:admin 0775` — so the "trusted" list
/// itself contained a user-writable directory, and the hole was in the list rather than in `$PATH`. Two
/// things made that acute rather than theoretical on macOS: stock `/etc/passwd` there has no account
/// with uid >= 1000, so the fallback branch was UNCONDITIONAL; and macOS ships no `getent` at all under
/// `/usr/bin` or `/bin`. The only way that spawn could ever SUCCEED on a Mac was if someone had planted
/// a binary at `/usr/local/bin/getent` — which root would then run, and whose stdout was parsed as the
/// passwd database, letting the attacker also choose the account the rest of the install trusts.
///
/// `getpwnam_r` closes it by construction: it is an in-process libc call, so there is no tool to plant,
/// no directory to trust, and no child to spawn or bound. It also consults the platform's real name
/// service — nsswitch (LDAP/SSSD) on Linux, Open Directory on macOS — so it answers for
/// directory-backed accounts that the flat file omits, which is the reason the fallback existed.
///
/// It also fixes a CORRECTNESS bug, not only the exposure: with no `getent` on macOS the lookup always
/// failed, [`resolve`] fell to its `None` arm, and that returns OUR home — `/root` under `sudo`. So
/// #1748's home inversion was never actually fixed on macOS. This is what fixes it.
#[cfg(unix)]
fn directory_lookup(hint: &ElevationHint) -> Option<PasswdEntry> {
    // A generous first buffer, grown on ERANGE: a record with many long fields (a directory-served
    // account with a long gecos) can exceed a small one, and a truncated read must never silently
    // become a wrong home directory.
    let mut capacity = 4096;
    loop {
        let mut buf = vec![0 as libc::c_char; capacity];
        // SAFETY: `pwd` is a plain C struct fully written by a successful lookup; `buf` outlives the
        // call and is sized by `capacity`; `found` is only dereferenced after a zero return AND a
        // non-null check, which is exactly the contract `getpw*_r` documents.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            match (&hint.name, hint.uid) {
                (Some(name), _) => {
                    let Ok(c_name) = std::ffi::CString::new(name.as_bytes()) else {
                        return None;
                    };
                    libc::getpwnam_r(
                        c_name.as_ptr(),
                        &mut pwd,
                        buf.as_mut_ptr(),
                        capacity,
                        &mut found,
                    )
                }
                (None, Some(uid)) => libc::getpwuid_r(
                    uid as libc::uid_t,
                    &mut pwd,
                    buf.as_mut_ptr(),
                    capacity,
                    &mut found,
                ),
                (None, None) => return None,
            }
        };
        if rc == libc::ERANGE && capacity < 1 << 20 {
            capacity *= 4;
            continue;
        }
        if rc != 0 || found.is_null() {
            // Not found, or the resolver failed. Fail-closed: the caller keeps whatever the flat file
            // said, and `resolve` applies its own precedence to that.
            return None;
        }
        // SAFETY: `found` is non-null and `rc == 0`, so libc has fully populated `pwd`, and its
        // `pw_name`/`pw_dir` point into `buf`, which is still alive here.
        return unsafe { entry_from_passwd(&pwd) };
    }
}

/// Copy a libc `passwd` record into an owned [`PasswdEntry`].
///
/// # Safety
///
/// `pwd` must be a record libc populated successfully, with `pw_name`/`pw_dir` pointing at NUL-
/// terminated strings whose backing buffer is still alive.
#[cfg(unix)]
unsafe fn entry_from_passwd(pwd: &libc::passwd) -> Option<PasswdEntry> {
    if pwd.pw_name.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    let name = std::ffi::CStr::from_ptr(pwd.pw_name)
        .to_string_lossy()
        .into_owned();
    let home = std::ffi::CStr::from_ptr(pwd.pw_dir)
        .to_string_lossy()
        .into_owned();
    if name.is_empty() || home.is_empty() {
        return None;
    }
    Some(PasswdEntry {
        name,
        uid: pwd.pw_uid as u32,
        gid: pwd.pw_gid as u32,
        home: PathBuf::from(home),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- #1748 F2: the account lookup no longer spawns a plantable tool ----------

    /// The OS resolver must actually answer for a real account, because it REPLACED the `getent` spawn
    /// as the fallback for an account the flat file does not list. If it answered nothing, `resolve`
    /// would fall to its `None` arm and return OUR home — `/root` under `sudo` — which IS #1748.
    ///
    /// Asked about the account this test process runs as, so there is a real record to find on any host
    /// and the assertion is about the resolver rather than about a fixture.
    #[cfg(unix)]
    #[test]
    fn the_os_resolver_answers_for_a_real_account() {
        // SAFETY: `getuid` takes no arguments, touches no memory, and cannot fail.
        let me = unsafe { libc::getuid() } as u32;
        let by_uid = directory_lookup(&ElevationHint {
            name: None,
            uid: Some(me),
            gid: None,
        })
        .expect("the OS must resolve the uid this process is running as");
        assert_eq!(by_uid.uid, me);
        assert!(
            by_uid.home.is_absolute(),
            "a home directory must be absolute, or the artifact paths built from it are nonsense: {}",
            by_uid.home.display()
        );
        assert!(!by_uid.name.is_empty());

        // And by NAME, which is the form `SUDO_USER` supplies — the path that matters most.
        let by_name = directory_lookup(&ElevationHint {
            name: Some(by_uid.name.clone()),
            uid: None,
            gid: None,
        })
        .expect("the OS must resolve the account by name too");
        assert_eq!(
            by_name.home, by_uid.home,
            "the same account must resolve to the same home by name and by uid"
        );
    }

    /// Fail-closed: an account that does not exist yields `None` rather than a partially-filled record
    /// (which would become a bogus home directory the installer then wrote into).
    #[cfg(unix)]
    #[test]
    fn the_os_resolver_declines_an_account_that_does_not_exist() {
        assert_eq!(
            directory_lookup(&ElevationHint {
                name: Some("definitely-not-a-real-account-xyz-1748".to_string()),
                uid: None,
                gid: None,
            }),
            None
        );
        assert_eq!(
            directory_lookup(&ElevationHint {
                name: None,
                uid: Some(4_000_000_000),
                gid: None,
            }),
            None
        );
    }

    /// The macOS shape of the bug, as a unit: stock `/etc/passwd` there lists no ordinary user, so the
    /// flat file cannot answer `SUDO_USER` — and with the old `getent` fallback dead on that platform
    /// (macOS ships none), `resolve` returned ROOT's home while claiming `via_elevation`. Every per-user
    /// artifact then went to `/root`, which is #1748 itself.
    ///
    /// Both arms are asserted on the same hint so the contrast is the test: absent from the passwd list
    /// → the inversion; present (which is what the OS resolver now supplies) → the user's own home.
    #[test]
    fn an_account_the_flat_file_cannot_name_must_not_resolve_to_our_own_home() {
        let hint_only = resolve(0, sudo_env, &[], "root", Path::new("/root"));
        assert_eq!(
            hint_only.home,
            Path::new("/root"),
            "with NO passwd record this is the documented fallback — and exactly why the OS resolver \
             must supply one on macOS, where the flat file never can"
        );

        // With the record the OS resolver now contributes, the same hint resolves correctly.
        let found = resolve(
            0,
            sudo_env,
            &[PasswdEntry {
                name: "ubuntu".to_string(),
                uid: 1000,
                gid: 1000,
                home: PathBuf::from("/home/ubuntu"),
            }],
            "root",
            Path::new("/root"),
        );
        assert_eq!(found.home, Path::new("/home/ubuntu"));
        assert_eq!(found.uid, Some(1000));
        assert!(found.via_elevation);
    }

    /// The exact environment `curl … | sudo sh` produces on Ubuntu: root's euid, root's `HOME`, and
    /// `SUDO_USER`/`SUDO_UID`/`SUDO_GID` naming the human. This is the #1748 fixture.
    fn sudo_env(k: &str) -> Option<String> {
        match k {
            "SUDO_USER" => Some("ubuntu".to_string()),
            "SUDO_UID" => Some("1000".to_string()),
            "SUDO_GID" => Some("1000".to_string()),
            "HOME" => Some("/root".to_string()),
            _ => None,
        }
    }

    fn ubuntu_passwd() -> Vec<PasswdEntry> {
        parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
        )
    }

    // -- #1748: the HOME=/root inversion --------------------------------------

    /// THE regression. Under `sudo`, the resolved home MUST be the invoking user's, never root's.
    ///
    /// The fixture deliberately supplies `HOME=/root` — the value `sudo` really sets and the value
    /// `dirs::home_dir()` really returned when this shipped — so an implementation that consults
    /// the environment's `HOME` instead of the passwd database fails here rather than passing on a
    /// fixture that never contained the wrong answer in the first place.
    #[test]
    fn sudo_install_resolves_the_invoking_user_not_root() {
        let t = resolve(0, sudo_env, &ubuntu_passwd(), "root", Path::new("/root"));
        assert_eq!(t.name, "ubuntu");
        assert_eq!(t.home, Path::new("/home/ubuntu"));
        assert_eq!(t.uid, Some(1000));
        assert_eq!(t.gid, Some(1000));
        assert!(t.via_elevation, "a sudo install is acting for another user");
        // The shipped bug in one assertion: per-user artifacts must not land under /root.
        assert!(
            !t.dig_bin_dir().starts_with("/root"),
            "per-user bin dir must not be under root's home: {}",
            t.dig_bin_dir().display()
        );
        assert_eq!(t.dig_bin_dir(), Path::new("/home/ubuntu/.dig/bin"));
    }

    /// A non-root process is already the target user, so nothing is redirected — and a `SUDO_USER`
    /// left over in an ancestor environment must NOT hijack the resolution. The fixture keeps a
    /// truthful control: the same hostile-looking env, only euid differs.
    #[test]
    fn unelevated_run_targets_itself_and_ignores_a_stale_sudo_user() {
        let t = resolve(
            1000,
            sudo_env,
            &ubuntu_passwd(),
            "alice",
            Path::new("/home/alice"),
        );
        assert_eq!(t.name, "alice");
        assert_eq!(t.home, Path::new("/home/alice"));
        assert!(!t.via_elevation);
        assert_eq!(t.uid, None, "no chown needed when we already are the user");
    }

    /// A genuine root login (root's own shell, no escalation) legitimately targets root.
    #[test]
    fn genuine_root_login_targets_root() {
        let t = resolve(0, |_| None, &ubuntu_passwd(), "root", Path::new("/root"));
        assert_eq!(t.name, "root");
        assert_eq!(t.home, Path::new("/root"));
        assert!(!t.via_elevation);
    }

    /// `sudo -u root` is root acting as root — not the inversion this module corrects.
    #[test]
    fn sudo_to_root_is_not_treated_as_acting_for_another_user() {
        let get = |k: &str| match k {
            "SUDO_USER" => Some("root".to_string()),
            "SUDO_UID" => Some("0".to_string()),
            _ => None,
        };
        let t = resolve(0, get, &ubuntu_passwd(), "root", Path::new("/root"));
        assert!(!t.via_elevation);
        assert_eq!(t.home, Path::new("/root"));
    }

    /// `doas` names the user but supplies no uid; `pkexec` supplies a uid but no name. Both must
    /// resolve, which is what forces name-OR-uid lookup rather than name-only.
    #[test]
    fn doas_and_pkexec_both_resolve() {
        let doas = resolve(
            0,
            |k| (k == "DOAS_USER").then(|| "ubuntu".to_string()),
            &ubuntu_passwd(),
            "root",
            Path::new("/root"),
        );
        assert_eq!(doas.home, Path::new("/home/ubuntu"));
        assert_eq!(doas.uid, Some(1000), "uid comes from the passwd record");

        let pkexec = resolve(
            0,
            |k| (k == "PKEXEC_UID").then(|| "1000".to_string()),
            &ubuntu_passwd(),
            "root",
            Path::new("/root"),
        );
        assert_eq!(
            pkexec.name, "ubuntu",
            "a uid-only hint resolves back to a name"
        );
        assert_eq!(pkexec.home, Path::new("/home/ubuntu"));
    }

    /// `sudo` wins over a stale `DOAS_USER`, and the *named* account wins over a uid that points
    /// somewhere else. A double that could only carry one field could not express this conflict, so
    /// the fixture makes the two disagree.
    #[test]
    fn the_named_account_wins_over_a_conflicting_uid() {
        let get = |k: &str| match k {
            "SUDO_USER" => Some("ubuntu".to_string()),
            "DOAS_USER" => Some("bob".to_string()),
            // A uid pointing at a DIFFERENT account than SUDO_USER names.
            "SUDO_UID" => Some("1001".to_string()),
            _ => None,
        };
        let mut pw = ubuntu_passwd();
        pw.push(PasswdEntry {
            name: "bob".to_string(),
            uid: 1001,
            gid: 1001,
            home: PathBuf::from("/home/bob"),
        });
        let t = resolve(0, get, &pw, "root", Path::new("/root"));
        assert_eq!(t.name, "ubuntu", "SUDO_USER outranks DOAS_USER");
        assert_eq!(t.home, Path::new("/home/ubuntu"));
        assert_eq!(
            t.uid,
            Some(1000),
            "uid comes from the NAMED record, not SUDO_UID"
        );
    }

    /// An account the passwd database does not know still reports `via_elevation`, so a caller can
    /// tell that the per-user home it was handed is a fallback and prefer a machine-wide location.
    #[test]
    fn an_unknown_account_keeps_the_elevation_flag_set() {
        let get = |k: &str| match k {
            "SUDO_USER" => Some("ghost".to_string()),
            "SUDO_UID" => Some("4242".to_string()),
            _ => None,
        };
        let t = resolve(0, get, &ubuntu_passwd(), "root", Path::new("/root"));
        assert!(t.via_elevation, "we are still root acting for someone else");
        assert_eq!(t.name, "ghost");
        assert_eq!(
            t.uid,
            Some(4242),
            "the hint's uid is kept so chown can still work"
        );
    }

    // -- passwd parsing --------------------------------------------------------

    #[test]
    fn parse_passwd_reads_name_uid_gid_and_home() {
        let e = parse_passwd("ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "ubuntu");
        assert_eq!(e[0].uid, 1000);
        assert_eq!(e[0].gid, 1000);
        assert_eq!(e[0].home, Path::new("/home/ubuntu"));
    }

    /// One malformed record must not cost the whole database — the good record either side of it
    /// still parses. The fixture puts the damage in the MIDDLE so a parser that aborts on first
    /// error is distinguishable from one that skips.
    #[test]
    fn parse_passwd_skips_junk_and_keeps_the_rest() {
        let e = parse_passwd(
            "# a comment\n\
             root:x:0:0:root:/root:/bin/bash\n\
             truncated:x:1000\n\
             notanumber:x:abc:def:x:/home/n:/bin/sh\n\
             \n\
             ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
        );
        assert_eq!(
            e.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["root", "ubuntu"]
        );
    }

    /// A home containing no `:` but plenty of other punctuation must survive field splitting.
    #[test]
    fn parse_passwd_handles_a_gecos_field_with_commas() {
        let e = parse_passwd("alice:x:1001:1001:Alice A,,,:/home/alice:/bin/zsh\n");
        assert_eq!(e[0].home, Path::new("/home/alice"));
        assert_eq!(e[0].uid, 1001);
    }

    // -- hint extraction ------------------------------------------------------

    #[test]
    fn an_empty_sudo_user_is_not_a_hint() {
        let get = |k: &str| (k == "SUDO_USER").then(|| "   ".to_string());
        assert!(elevation_hint(0, get).is_empty());
    }

    #[test]
    fn a_non_numeric_uid_is_ignored_rather_than_panicking() {
        let get = |k: &str| (k == "SUDO_UID").then(|| "not-a-uid".to_string());
        assert!(elevation_hint(0, get).is_empty());
    }
}
