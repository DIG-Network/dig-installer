//! Machine-wide daemon state directory creation + ACL (#501 support, #499).
//!
//! The dig-node and dig-dns daemons resolve their control/auth state (the
//! control-token the operator CLI reads for `dig-node pair approve …`) from a
//! machine-wide, identity-independent directory — so the state is the SAME
//! whether the daemon runs as a boot service (LocalSystem) or is queried by the
//! interactive user's shell. The installer CREATES those directories and sets a
//! TIGHT ACL at install time:
//!   * Windows `%PROGRAMDATA%\DigNode` / `%PROGRAMDATA%\DigDns`
//!   * Linux `/var/lib/dig-node` / `/var/lib/dig-dns`
//!   * macOS `/Library/Application Support/DigNode` / `…/DigDns`
//!
//! ACL contract (Windows): inheritance removed, then **SYSTEM + Administrators
//! = full**, the **installing interactive user = READ** (so the operator CLI
//! reads the control-token WITHOUT being SYSTEM). It is deliberately NOT
//! world/`Users`-readable — a loose ACL on a control-token dir is a local
//! privilege-escalation vector. On Unix: owned by root, mode `0750`, plus a
//! best-effort read ACL for the invoking (`SUDO_USER`) account.
//!
//! Layering: the directory-path derivation + the `icacls` argv builder are pure
//! and unit-tested; the create + ACL calls are the thin I/O layer.

use std::path::PathBuf;

use crate::target::Os;

/// One daemon's machine-wide state dir: the daemon id + its resolved path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonDir {
    /// The daemon id (`dig-node` / `dig-dns`).
    pub daemon: &'static str,
    /// The machine-wide state directory for it on this OS.
    pub path: PathBuf,
}

/// The result of ensuring one daemon dir exists + is ACL'd. Never silent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DaemonDirResult {
    pub daemon: String,
    pub path: String,
    /// The directory now exists (created or already present).
    pub created: bool,
    /// The tight ACL was applied (SYSTEM+Admins full, installing user read).
    pub acl_applied: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// The Windows machine-wide data root (`%PROGRAMDATA%`, default
/// `C:\ProgramData`).
fn program_data() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

/// The two daemon state directories for `os` (dig-node then dig-dns). Pure
/// given `os` + the `%PROGRAMDATA%` env, so the path contract is unit-tested.
pub fn daemon_dirs(os: Os) -> Vec<DaemonDir> {
    match os {
        Os::Windows => {
            let base = program_data();
            vec![
                DaemonDir {
                    daemon: "dig-node",
                    path: base.join("DigNode"),
                },
                DaemonDir {
                    daemon: "dig-dns",
                    path: base.join("DigDns"),
                },
            ]
        }
        Os::Linux => vec![
            DaemonDir {
                daemon: "dig-node",
                path: PathBuf::from("/var/lib/dig-node"),
            },
            DaemonDir {
                daemon: "dig-dns",
                path: PathBuf::from("/var/lib/dig-dns"),
            },
        ],
        Os::MacOs => {
            let base = PathBuf::from("/Library/Application Support");
            vec![
                DaemonDir {
                    daemon: "dig-node",
                    path: base.join("DigNode"),
                },
                DaemonDir {
                    daemon: "dig-dns",
                    path: base.join("DigDns"),
                },
            ]
        }
    }
}

/// The current interactive user, for the READ grant. On Windows, `DOMAIN\USER`
/// from the environment (when elevated via UAC of the same user, these are the
/// interactive user — NOT SYSTEM, which is guarded against in `elevation`).
#[cfg(windows)]
fn interactive_user() -> Option<String> {
    let user = std::env::var("USERNAME").ok().filter(|u| !u.is_empty())?;
    match std::env::var("USERDOMAIN") {
        Ok(dom) if !dom.is_empty() => Some(format!("{dom}\\{user}")),
        _ => Some(user),
    }
}

/// The `icacls` argv (after the `icacls` program) that locks a daemon dir down:
/// reset inheritance, then grant SYSTEM + Administrators full and the
/// interactive `user` READ — inheritable to child files (the control-token).
/// Pure so the exact ACL is unit-tested without touching the filesystem.
pub fn windows_icacls_args(dir: &str, user: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        "SYSTEM:(OI)(CI)F".to_string(),
        "/grant:r".to_string(),
        "*S-1-5-32-544:(OI)(CI)F".to_string(), // BUILTIN\Administrators, locale-independent
        "/grant:r".to_string(),
        format!("{user}:(OI)(CI)R"),
    ]
}

/// Create the machine-wide daemon state directories + apply the tight ACL
/// (#501). `dry_run` reports intent only. Best-effort per dir: a failure is
/// recorded, never aborts (the rest of the install proceeds).
pub fn ensure(os: Os, dry_run: bool, log: &mut dyn FnMut(&str)) -> Vec<DaemonDirResult> {
    let mut out = Vec::new();
    for d in daemon_dirs(os) {
        let path_str = d.path.to_string_lossy().into_owned();
        if dry_run {
            log(&format!(
                "    (would create {} and ACL it: SYSTEM+Administrators full, the installing user read)",
                path_str
            ));
            out.push(DaemonDirResult {
                daemon: d.daemon.to_string(),
                path: path_str,
                created: false,
                acl_applied: false,
                note: "dry run".to_string(),
            });
            continue;
        }
        out.push(ensure_one(os, &d, &path_str, log));
    }
    out
}

fn ensure_one(
    os: Os,
    d: &DaemonDir,
    path_str: &str,
    log: &mut dyn FnMut(&str),
) -> DaemonDirResult {
    let mut result = DaemonDirResult {
        daemon: d.daemon.to_string(),
        path: path_str.to_string(),
        created: false,
        acl_applied: false,
        note: String::new(),
    };
    if let Err(e) = std::fs::create_dir_all(&d.path) {
        result.note = format!("could not create {path_str}: {e}");
        log(&format!("    ! {}", result.note));
        return result;
    }
    result.created = true;

    #[cfg(windows)]
    {
        let _ = os;
        match interactive_user() {
            Some(user) => {
                let args = windows_icacls_args(path_str, &user);
                match std::process::Command::new("icacls").args(&args).output() {
                    Ok(o) if o.status.success() => {
                        result.acl_applied = true;
                        result.note =
                            format!("created + ACL'd (SYSTEM+Administrators full, {user} read)");
                    }
                    Ok(o) => {
                        result.note = format!(
                            "created but icacls failed: {}",
                            String::from_utf8_lossy(&o.stderr).trim()
                        );
                    }
                    Err(e) => result.note = format!("created but icacls did not run: {e}"),
                }
            }
            None => {
                result.note =
                    "created but could not determine the interactive user for the read ACL"
                        .to_string();
            }
        }
    }
    #[cfg(unix)]
    {
        result.acl_applied = apply_unix_acl(os, &d.path, &mut result.note);
        if result.note.is_empty() {
            result.note = "created + locked down (root:root 0750 + invoking-user read)".to_string();
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = os;
        result.note = "created (no ACL support on this OS)".to_string();
    }

    if result.acl_applied {
        log(&format!("    ✓ {} — {}", path_str, result.note));
    } else {
        log(&format!("    ! {} — {}", path_str, result.note));
    }
    result
}

/// Unix: `chmod 0750` + owned by root; best-effort read ACL for the invoking
/// (`SUDO_USER`) account via `setfacl` so the operator CLI can read the
/// control-token without being root. Returns whether the tight perms were set.
#[cfg(unix)]
fn apply_unix_acl(_os: Os, path: &std::path::Path, note: &mut String) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // Not world/group readable beyond the ACL: owner rwx, group r-x, other none.
    let mode_ok = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o750)).is_ok();
    // Best-effort: grant the invoking (sudo) user read+execute via setfacl.
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() {
            let _ = std::process::Command::new("setfacl")
                .args(["-m", &format!("u:{user}:rx"), &path.to_string_lossy()])
                .status();
        }
    }
    if !mode_ok {
        *note = "created but could not set 0750 permissions".to_string();
    }
    mode_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_dirs_are_under_program_data() {
        let dirs = daemon_dirs(Os::Windows);
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0].daemon, "dig-node");
        assert!(dirs[0].path.ends_with("DigNode"));
        assert_eq!(dirs[1].daemon, "dig-dns");
        assert!(dirs[1].path.ends_with("DigDns"));
    }

    #[test]
    fn linux_dirs_are_under_var_lib() {
        let dirs = daemon_dirs(Os::Linux);
        assert_eq!(dirs[0].path, PathBuf::from("/var/lib/dig-node"));
        assert_eq!(dirs[1].path, PathBuf::from("/var/lib/dig-dns"));
    }

    #[test]
    fn macos_dirs_are_under_application_support() {
        let dirs = daemon_dirs(Os::MacOs);
        assert!(dirs[0]
            .path
            .ends_with("Library/Application Support/DigNode"));
        assert!(dirs[1]
            .path
            .ends_with("Library/Application Support/DigDns"));
    }

    #[test]
    fn icacls_args_lock_down_the_dir() {
        let args = windows_icacls_args(r"C:\ProgramData\DigNode", r"MYPC\alice");
        // Inheritance is reset (NOT left world/Users-readable).
        assert!(args.contains(&"/inheritance:r".to_string()));
        // SYSTEM + Administrators (well-known SID, locale-independent) get full.
        assert!(args.iter().any(|a| a == "SYSTEM:(OI)(CI)F"));
        assert!(args.iter().any(|a| a == "*S-1-5-32-544:(OI)(CI)F"));
        // The interactive user gets READ only — never full, never world.
        assert!(args.iter().any(|a| a == r"MYPC\alice:(OI)(CI)R"));
        assert!(
            !args.iter().any(|a| a.contains("Everyone") || a.contains("Users:")),
            "must NOT grant Everyone/Users (loose ACL = priv-esc): {args:?}"
        );
    }

    #[test]
    fn dry_run_reports_intent_without_creating() {
        let mut lines = Vec::new();
        let out = ensure(Os::Windows, true, &mut |l| lines.push(l.to_string()));
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| !r.created && !r.acl_applied));
        assert!(lines.iter().any(|l| l.contains("would create")));
    }

    #[test]
    fn daemon_dir_result_serializes_with_stable_fields() {
        let r = DaemonDirResult {
            daemon: "dig-node".into(),
            path: r"C:\ProgramData\DigNode".into(),
            created: true,
            acl_applied: true,
            note: "ok".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["daemon"], "dig-node");
        assert_eq!(v["created"], true);
        assert_eq!(v["acl_applied"], true);
    }
}
