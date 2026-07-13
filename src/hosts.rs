//! `dig.local` hosts-file registration (installer side of task #91).
//!
//! When the dig-node service is installed, the installer best-effort registers a
//! loopback hosts entry **`127.0.0.2   dig.local`** so consumers (the DIG
//! Browser, the extension) can address the local node port-free at
//! `http://dig.local` (with `localhost` as the fallback). `127.0.0.2` — rather
//! than `127.0.0.1` — keeps `dig.local` on its own loopback IP so it never
//! collides with whatever else the user runs on `localhost`.
//!
//! Scope (installer side ONLY): this module writes/removes the hosts entry. The
//! dig-node *dual-listener* (`127.0.0.2:80` + `localhost:<port>` + Host
//! allowlist) that makes the entry actually resolve to the node is a SEPARATE
//! dig-node task and is NOT done here.
//!
//! Contract:
//! * **Idempotent** — [`with_dig_local_entry`] is a no-op (returns `None`) if the
//!   exact entry is already present, so re-running the installer never duplicates.
//! * **Reversible** — [`without_dig_local_entry`] removes only the lines this
//!   installer added (tagged with [`MARKER`]), for a clean uninstall.
//! * **Best-effort** — the actual file write needs elevation; a failure is
//!   surfaced but **never aborts the install** (the caller keeps `localhost`).
//!
//! The pure edit logic here is unit-tested; the elevated file I/O is in
//! [`write_dig_local`] / [`remove_dig_local`].

use std::net::ToSocketAddrs;
use std::path::PathBuf;

/// The loopback IP `dig.local` resolves to. Distinct from `127.0.0.1` so the
/// DIG local node owns its own address (see module docs).
pub const DIG_LOCAL_IP: &str = "127.0.0.2";

/// The hostname the local DIG node is reachable at, port-free.
pub const DIG_LOCAL_HOST: &str = "dig.local";

/// Trailing tag on the line we add, so an uninstall can find + remove exactly
/// the installer's own entry without touching anything the user wrote.
pub const MARKER: &str = "# added by dig-installer (dig.local → local DIG node)";

/// The canonical hosts line this installer writes.
pub fn dig_local_line() -> String {
    format!("{DIG_LOCAL_IP}\t{DIG_LOCAL_HOST}\t{MARKER}")
}

/// Platform hosts-file path: `%SystemRoot%\System32\drivers\etc\hosts` on
/// Windows (honouring `%SystemRoot%`), `/etc/hosts` elsewhere.
pub fn hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        PathBuf::from(root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// Is an active (non-commented) `dig.local` mapping already present in `contents`?
///
/// "Active" = a line that, with comments stripped, maps some IP to the
/// `dig.local` host. We treat ANY existing active mapping as "present" so we
/// don't fight a user who pointed `dig.local` somewhere deliberately.
pub fn has_dig_local(contents: &str) -> bool {
    contents.lines().any(line_maps_dig_local)
}

/// Does a single hosts line actively map `dig.local`? (Ignores comment-only and
/// blank lines; a trailing `# ...` comment after the mapping is fine.)
fn line_maps_dig_local(line: &str) -> bool {
    let code = match line.split_once('#') {
        // Keep the part before the FIRST '#', unless the whole line is a comment.
        Some((before, _)) => before,
        None => line,
    };
    let mut fields = code.split_whitespace();
    // First field is the IP; the rest are hostnames/aliases.
    let _ip = match fields.next() {
        Some(ip) => ip,
        None => return false,
    };
    fields.any(|host| host.eq_ignore_ascii_case(DIG_LOCAL_HOST))
}

/// Compute the new hosts-file contents with the `dig.local` entry **appended**,
/// or `None` if an active mapping already exists (idempotent no-op).
///
/// Pure: no I/O. Preserves the existing content verbatim and appends one line,
/// ensuring exactly one trailing newline before it.
pub fn with_dig_local_entry(contents: &str) -> Option<String> {
    if has_dig_local(contents) {
        return None;
    }
    let mut out = String::from(contents);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&dig_local_line());
    out.push('\n');
    Some(out)
}

/// Does a hosts `line` actively map `dig.local` to EXACTLY `ip`?
fn line_maps_dig_local_to(line: &str, ip: &str) -> bool {
    let code = match line.split_once('#') {
        Some((before, _)) => before,
        None => line,
    };
    let mut fields = code.split_whitespace();
    match fields.next() {
        Some(line_ip) if line_ip == ip => {
            fields.any(|host| host.eq_ignore_ascii_case(DIG_LOCAL_HOST))
        }
        _ => false,
    }
}

/// Is `dig.local` already mapped to the CORRECT [`DIG_LOCAL_IP`] (127.0.0.2)?
pub fn has_correct_dig_local(contents: &str) -> bool {
    contents
        .lines()
        .any(|l| line_maps_dig_local_to(l, DIG_LOCAL_IP))
}

/// Remove the `dig.local` alias from a mapping line (used to correct a
/// wrong-IP entry, #499). Returns the rewritten line, or `None` if the line
/// mapped ONLY `dig.local` (so the whole line should be dropped).
fn strip_dig_local_from_line(line: &str) -> Option<String> {
    let (code, comment) = match line.split_once('#') {
        Some((before, after)) => (before, Some(after)),
        None => (line, None),
    };
    let mut fields = code.split_whitespace();
    let ip = fields.next()?;
    let hosts: Vec<&str> = fields
        .filter(|h| !h.eq_ignore_ascii_case(DIG_LOCAL_HOST))
        .collect();
    if hosts.is_empty() {
        return None; // the line ONLY mapped dig.local (to a wrong IP) — drop it.
    }
    let mut rewritten = format!("{ip}\t{}", hosts.join(" "));
    if let Some(c) = comment {
        rewritten.push_str(&format!(" #{c}"));
    }
    Some(rewritten)
}

/// Compute corrected hosts contents that ENSURE `dig.local` maps to
/// [`DIG_LOCAL_IP`] (127.0.0.2) — the node's dedicated loopback IP (#499).
///
/// * `None` if a correct `127.0.0.2 → dig.local` active mapping already exists
///   (idempotent no-op).
/// * Otherwise `Some(updated)`: any active `dig.local` mapping to a DIFFERENT
///   IP (e.g. a stale `127.0.0.1 dig.local` from an older install — the bug
///   that made the post-install resolve check warn 127.0.0.1) is corrected —
///   the `dig.local` alias is stripped from that line (the line dropped if it
///   then maps nothing) — and the canonical marked line is appended. Pure.
pub fn ensure_dig_local_entry(contents: &str) -> Option<String> {
    if has_correct_dig_local(contents) {
        return None;
    }
    let mut kept: Vec<String> = Vec::new();
    for line in contents.lines() {
        if line_maps_dig_local(line) {
            if let Some(rewritten) = strip_dig_local_from_line(line) {
                kept.push(rewritten);
            }
            // else: drop a line that only mapped dig.local to the wrong IP.
        } else {
            kept.push(line.to_string());
        }
    }
    let mut out = kept.join("\n");
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&dig_local_line());
    out.push('\n');
    Some(out)
}

/// Compute the new hosts-file contents with the installer's `dig.local` line(s)
/// **removed**, or `None` if there is nothing tagged to remove.
///
/// Only removes lines carrying our [`MARKER`] — a hand-written `dig.local` entry
/// the user added is left untouched. Pure: no I/O.
pub fn without_dig_local_entry(contents: &str) -> Option<String> {
    if !contents.contains(MARKER) {
        return None;
    }
    let kept: Vec<&str> = contents
        .lines()
        .filter(|line| !line.contains(MARKER))
        .collect();
    let mut out = kept.join("\n");
    // Preserve a trailing newline if the original had one.
    if contents.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    Some(out)
}

/// Best-effort: ensure `127.0.0.2 dig.local` is in the system hosts file.
///
/// Returns:
/// * `Ok(Some(note))` — the entry was added (note describes it),
/// * `Ok(None)`       — already present (idempotent no-op),
/// * `Err(reason)`    — could not write (e.g. needs elevation). The CALLER must
///   treat this as best-effort and continue (keep `localhost`).
pub fn write_dig_local() -> Result<Option<String>, String> {
    write_dig_local_at(&hosts_path())
}

/// [`write_dig_local`] against an explicit hosts-file `path`. The real call uses
/// [`hosts_path`]; tests point this at a temp file so the read→compute→write
/// roundtrip is exercised without touching the system hosts file.
pub(crate) fn write_dig_local_at(path: &std::path::Path) -> Result<Option<String>, String> {
    let current = std::fs::read_to_string(path).unwrap_or_default();
    // #499: CORRECT a stale/wrong-IP dig.local mapping (e.g. an old
    // `127.0.0.1 dig.local`) to the canonical 127.0.0.2, not just append when
    // absent — otherwise a stale entry silently wins and the resolve check
    // warns 127.0.0.1.
    match ensure_dig_local_entry(&current) {
        None => Ok(None),
        Some(updated) => {
            std::fs::write(path, updated).map_err(|e| format!("write {}: {e}", path.display()))?;
            Ok(Some(format!(
                "{DIG_LOCAL_IP} {DIG_LOCAL_HOST} → {}",
                path.display()
            )))
        }
    }
}

/// Best-effort: remove the installer's `dig.local` entry from the hosts file
/// (for uninstall). Same result contract as [`write_dig_local`].
pub fn remove_dig_local() -> Result<Option<String>, String> {
    remove_dig_local_at(&hosts_path())
}

/// [`remove_dig_local`] against an explicit hosts-file `path` (see
/// [`write_dig_local_at`]). A missing file is a no-op (`Ok(None)`).
pub(crate) fn remove_dig_local_at(path: &std::path::Path) -> Result<Option<String>, String> {
    let current = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    match without_dig_local_entry(&current) {
        None => Ok(None),
        Some(updated) => {
            std::fs::write(path, updated).map_err(|e| format!("write {}: {e}", path.display()))?;
            Ok(Some(format!(
                "removed {DIG_LOCAL_HOST} from {}",
                path.display()
            )))
        }
    }
}

/// The result of the post-install verification that `dig.local` actually
/// resolves to [`DIG_LOCAL_IP`] (task #140) — distinct from a successful hosts
/// *write* (see [`write_dig_local`]): it proves the OS resolver picked up the
/// change, catching drift a raw file write can't (a stale Windows DNS-client
/// cache, an `nsswitch.conf` ordering that skips `files`, a hosts write that
/// silently landed in the wrong file, …).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ResolveResult {
    /// `true` iff resolving [`DIG_LOCAL_HOST`] returned [`DIG_LOCAL_IP`] among
    /// its addresses.
    pub resolves: bool,
    /// Human-readable detail: what resolved (or the error), for the CLI/JSON
    /// output — never silent (task #140's "failures surface a clear message").
    pub note: String,
}

/// Best-effort, real post-install check: does the OS resolver actually map
/// `dig.local` → `127.0.0.2` right now? Uses [`std::net::ToSocketAddrs`],
/// which resolves a hostname the same way the rest of the OS does
/// (`getaddrinfo`/the Windows equivalent — reads the hosts file the installer
/// wrote, honouring `nsswitch.conf` ordering on Unix), so this is a genuine
/// resolution probe, not a re-parse of our own write.
pub fn resolve_dig_local() -> ResolveResult {
    resolve_host(DIG_LOCAL_HOST)
}

/// [`resolve_dig_local`] against an arbitrary `host` string — the pure/
/// testable core. Accepts either a hostname (real OS resolution, needs the
/// system hosts file / DNS) or a bare IP literal (parsed directly, no I/O —
/// what the unit tests below drive to stay deterministic and environment-
/// independent).
pub(crate) fn resolve_host(host: &str) -> ResolveResult {
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            if ips.iter().any(|ip| ip == DIG_LOCAL_IP) {
                ResolveResult {
                    resolves: true,
                    note: format!("{host} → {DIG_LOCAL_IP}"),
                }
            } else {
                ResolveResult {
                    resolves: false,
                    note: format!(
                        "{host} resolved but not to {DIG_LOCAL_IP} (got {})",
                        if ips.is_empty() {
                            "no addresses".to_string()
                        } else {
                            ips.join(", ")
                        }
                    ),
                }
            }
        }
        Err(e) => ResolveResult {
            resolves: false,
            note: format!("{host} did not resolve: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_when_absent() {
        let before = "127.0.0.1\tlocalhost\n::1\tlocalhost\n";
        let after = with_dig_local_entry(before).expect("should append");
        assert!(after.starts_with(before));
        assert!(after.contains("127.0.0.2\tdig.local"));
        assert!(after.contains(MARKER));
        assert!(after.ends_with('\n'));
    }

    #[test]
    fn idempotent_when_our_entry_present() {
        let before = format!("127.0.0.1 localhost\n{}\n", dig_local_line());
        assert_eq!(with_dig_local_entry(&before), None);
    }

    // -- #499: ensure_dig_local_entry corrects a stale/wrong-IP mapping --------

    #[test]
    fn ensure_is_noop_when_already_127_0_0_2() {
        let before = format!("127.0.0.1 localhost\n{}\n", dig_local_line());
        assert!(has_correct_dig_local(&before));
        assert_eq!(ensure_dig_local_entry(&before), None);
    }

    #[test]
    fn ensure_corrects_a_stale_127_0_0_1_dig_local_line() {
        // The exact bug: an old install left `127.0.0.1 dig.local`, so the
        // resolve check warned 127.0.0.1. ensure must DROP the stale line and
        // add the canonical 127.0.0.2 entry.
        let before = "127.0.0.1\tdig.local\n::1\tlocalhost\n";
        let after = ensure_dig_local_entry(before).expect("must correct the stale entry");
        assert!(
            !after.lines().any(|l| l.starts_with("127.0.0.1") && l.contains("dig.local")),
            "stale 127.0.0.1 dig.local must be gone:\n{after}"
        );
        assert!(after.contains("127.0.0.2\tdig.local"));
        assert!(after.contains(MARKER));
        assert!(after.contains("::1\tlocalhost"), "other entries preserved");
        // And the corrected file now has a valid entry.
        assert!(has_correct_dig_local(&after));
    }

    #[test]
    fn ensure_strips_dig_local_from_a_shared_wrong_ip_line_keeping_other_hosts() {
        // A shared line `127.0.0.1 localhost dig.local` must keep localhost but
        // lose dig.local (which moves to its own 127.0.0.2 line).
        let before = "127.0.0.1 localhost dig.local\n";
        let after = ensure_dig_local_entry(before).expect("must correct");
        assert!(
            after.lines().any(|l| l.contains("localhost") && !l.contains("dig.local")),
            "localhost must remain on 127.0.0.1 without dig.local:\n{after}"
        );
        assert!(after.contains("127.0.0.2\tdig.local"));
        assert!(has_correct_dig_local(&after));
    }

    #[test]
    fn ensure_appends_when_absent() {
        let before = "127.0.0.1\tlocalhost\n";
        let after = ensure_dig_local_entry(before).expect("append");
        assert!(after.contains("127.0.0.2\tdig.local"));
        assert!(after.contains("127.0.0.1\tlocalhost"));
    }

    #[test]
    fn idempotent_when_user_added_dig_local() {
        // A user-written mapping (no marker, even different IP) counts as present —
        // we never fight a deliberate override.
        let before = "127.0.0.1 localhost\n10.0.0.5   dig.local\n";
        assert_eq!(with_dig_local_entry(before), None);
        assert!(has_dig_local(before));
    }

    #[test]
    fn commented_dig_local_is_not_active() {
        let before = "127.0.0.1 localhost\n# 127.0.0.2 dig.local (disabled)\n";
        assert!(!has_dig_local(before));
        let after = with_dig_local_entry(before).expect("should append");
        assert!(after.contains(&dig_local_line()));
    }

    #[test]
    fn adds_newline_before_entry_when_file_lacks_trailing_newline() {
        let before = "127.0.0.1 localhost"; // no trailing newline
        let after = with_dig_local_entry(before).expect("should append");
        assert_eq!(
            after,
            format!("127.0.0.1 localhost\n{}\n", dig_local_line())
        );
    }

    #[test]
    fn appends_to_empty_file() {
        let after = with_dig_local_entry("").expect("should append");
        assert_eq!(after, format!("{}\n", dig_local_line()));
    }

    #[test]
    fn removes_only_our_marked_line() {
        let before = format!(
            "127.0.0.1 localhost\n{}\n10.0.0.9   dig.local\n",
            dig_local_line()
        );
        let after = without_dig_local_entry(&before).expect("should remove");
        assert!(!after.contains(MARKER));
        // The user's own dig.local override survives.
        assert!(after.contains("10.0.0.9   dig.local"));
        assert!(after.contains("127.0.0.1 localhost"));
    }

    #[test]
    fn remove_is_noop_when_marker_absent() {
        let before = "127.0.0.1 localhost\n10.0.0.9 dig.local\n";
        assert_eq!(without_dig_local_entry(before), None);
    }

    #[test]
    fn write_then_remove_roundtrips_to_original() {
        let original = "127.0.0.1\tlocalhost\n::1\tlocalhost\n";
        let added = with_dig_local_entry(original).unwrap();
        let removed = without_dig_local_entry(&added).unwrap();
        assert_eq!(removed, original);
    }

    #[test]
    fn host_match_is_case_insensitive() {
        assert!(line_maps_dig_local("127.0.0.2   DIG.LOCAL"));
        assert!(line_maps_dig_local("127.0.0.2 dig.local # note"));
        assert!(!line_maps_dig_local("127.0.0.2 notdig.local"));
        assert!(!line_maps_dig_local("# 127.0.0.2 dig.local"));
        assert!(!line_maps_dig_local(""));
    }

    #[test]
    fn dig_local_line_carries_ip_host_and_marker() {
        let line = dig_local_line();
        assert!(line.contains(DIG_LOCAL_IP));
        assert!(line.contains(DIG_LOCAL_HOST));
        assert!(line.contains(MARKER));
    }

    #[test]
    fn hosts_path_is_platform_correct() {
        let p = hosts_path().to_string_lossy().to_string();
        #[cfg(windows)]
        assert!(p.to_lowercase().ends_with("drivers\\etc\\hosts"), "got {p}");
        #[cfg(not(windows))]
        assert_eq!(p, "/etc/hosts");
    }

    // -- File-I/O wrapper tests against a TEMP hosts file (never the real one). --

    fn tmp_hosts(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("dig-installer-hosts-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("hosts")
    }

    #[test]
    fn write_dig_local_at_adds_then_is_idempotent() {
        let path = tmp_hosts("write");
        std::fs::write(&path, "127.0.0.1\tlocalhost\n").unwrap();

        let note = write_dig_local_at(&path).expect("write ok").expect("added");
        assert!(note.contains("dig.local"));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains(&dig_local_line()));

        // Second write is a no-op (entry already present).
        assert_eq!(write_dig_local_at(&path).expect("ok"), None);
    }

    #[test]
    fn write_then_remove_at_roundtrips_the_file() {
        let path = tmp_hosts("roundtrip");
        let original = "127.0.0.1\tlocalhost\n::1\tlocalhost\n";
        std::fs::write(&path, original).unwrap();

        write_dig_local_at(&path).expect("ok").expect("added");
        let removed = remove_dig_local_at(&path)
            .expect("remove ok")
            .expect("removed something");
        assert!(removed.contains("removed dig.local"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn remove_dig_local_at_is_noop_when_marker_absent() {
        let path = tmp_hosts("noop");
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();
        assert_eq!(remove_dig_local_at(&path).expect("ok"), None);
    }

    #[test]
    fn remove_dig_local_at_missing_file_is_ok_none() {
        let path = std::env::temp_dir().join("dig-installer-hosts-does-not-exist-xyz/hosts");
        assert_eq!(remove_dig_local_at(&path).expect("missing file ok"), None);
    }

    // -- Post-install resolve check (task #140) ------------------------------
    //
    // `resolve_host` is exercised against IP LITERALS (no DNS/hosts-file I/O —
    // `ToSocketAddrs` parses a literal directly) so these stay deterministic
    // and environment-independent, unlike the real `resolve_dig_local()`
    // (which depends on the live system hosts file and is only exercisable as
    // a manual/integration check post-install).

    #[test]
    fn resolve_host_reports_success_when_ip_matches() {
        // A bare IP literal equal to DIG_LOCAL_IP "resolves" to itself (no I/O).
        let r = resolve_host(DIG_LOCAL_IP);
        assert!(r.resolves, "note: {}", r.note);
        assert!(r.note.contains(DIG_LOCAL_IP));
    }

    #[test]
    fn resolve_host_reports_failure_when_resolved_to_a_different_ip() {
        // 127.0.0.1 resolves (it's a valid literal) but not to DIG_LOCAL_IP —
        // the mismatch must be reported, not swallowed as success.
        let r = resolve_host("127.0.0.1");
        assert!(!r.resolves);
        assert!(r.note.contains("127.0.0.1"), "got: {}", r.note);
        assert!(r.note.contains(DIG_LOCAL_IP), "got: {}", r.note);
    }

    #[test]
    fn resolve_host_reports_failure_when_host_does_not_resolve() {
        // `.invalid` is a reserved TLD (RFC 2606) guaranteed to never resolve —
        // exercises the "did not resolve" branch deterministically, no network.
        let r = resolve_host("definitely-not-a-real-host.invalid");
        assert!(!r.resolves);
        assert!(r.note.contains("did not resolve"), "got: {}", r.note);
    }

    #[test]
    fn resolve_result_serializes_with_resolves_and_note() {
        let r = resolve_host(DIG_LOCAL_IP);
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["resolves"], true);
        assert!(v["note"].is_string());
    }
}
