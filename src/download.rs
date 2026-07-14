//! Network fetching: latest-release discovery + binary download with an
//! optional SHA-256 integrity check.
//!
//! All HTTP goes through `ureq` (rustls, no system OpenSSL). The pure helpers
//! (`tag_name_from_release_json`, `sha256_hex`) are unit-tested; the functions
//! that actually hit the network are thin and only used at install time.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::release::Repo;

/// GitHub requires a User-Agent on API requests.
const USER_AGENT: &str = concat!("dig-installer/", env!("CARGO_PKG_VERSION"));

/// A GitHub release reduced to what the installer needs: the tag and the names
/// of every uploaded asset (so the OS/arch matcher in [`crate::asset`] can pick
/// the right one, instead of betting on a single guessed filename).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag_name: String,
    pub asset_names: Vec<String>,
}

/// Parse the `tag_name` out of a GitHub release JSON payload.
/// Pure — takes the raw body, returns the tag (e.g. `v0.6.0`).
pub fn tag_name_from_release_json(body: &str) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parse release JSON: {e}"))?;
    v.get("tag_name")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "release JSON had no tag_name".to_string())
}

/// Extract a [`Release`] (tag + asset names) from a single release JSON object
/// (`serde_json::Value`). Shared by [`release_from_json`] (a single-release API
/// response) and [`release_from_list_json`] (one entry of a releases-list
/// response) so both parse identically.
fn release_from_value(v: &serde_json::Value) -> Result<Release, String> {
    let tag_name = v
        .get("tag_name")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "release JSON had no tag_name".to_string())?;
    let asset_names = v
        .get("assets")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(Release {
        tag_name,
        asset_names,
    })
}

/// Parse a GitHub release JSON payload into a [`Release`] (tag + asset names).
/// Pure — the heart of the thin-shim asset resolution, unit-tested without a
/// network.
pub fn release_from_json(body: &str) -> Result<Release, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parse release JSON: {e}"))?;
    release_from_value(&v)
}

/// Parse a GitHub *releases list* JSON payload (an array, newest first) into
/// the newest [`Release`], regardless of its prerelease/draft flags.
///
/// This is the fallback for [`latest_release`] when `/releases/latest` 404s:
/// that endpoint excludes prereleases AND drafts, so a repo whose newest (or
/// only) release is prerelease-flagged — e.g. DIG Browser's alpha channel —
/// never appears there even though a real, asset-bearing release exists. The
/// list endpoint has no such filter, so its first entry is the newest release
/// GitHub knows about.
pub fn release_from_list_json(body: &str) -> Result<Release, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parse releases list JSON: {e}"))?;
    let arr = v
        .as_array()
        .ok_or_else(|| "releases list JSON was not an array".to_string())?;
    let first = arr
        .first()
        .ok_or_else(|| "no releases published".to_string())?;
    release_from_value(first)
}

/// True when a release-lookup error indicates "no such release" (HTTP 404) —
/// the signal that `/releases/latest` found nothing published, so the caller
/// should fall back to the full releases list ([`release_from_list_json`])
/// rather than treating it as a transport failure.
fn is_release_not_found(err: &str) -> bool {
    err.contains("404") || err.contains("Not Found")
}

/// Discover the latest published tag for a repo via the GitHub API.
pub fn latest_tag(repo: &Repo) -> Result<String, String> {
    Ok(latest_release(repo)?.tag_name)
}

/// Fetch the latest release (tag + asset list) for a repo via the GitHub API.
///
/// Tries `/releases/latest` first; that endpoint excludes prereleases and
/// drafts, so it 404s for a repo whose newest release is prerelease-only
/// (DIG Browser's alpha channel). On a 404, fall back to the full releases
/// list ([`release_from_list_json`]) and take the newest entry regardless of
/// prerelease status. Repos that always ship a non-prerelease "latest" (the
/// common case) never hit the fallback.
pub fn latest_release(repo: &Repo) -> Result<Release, String> {
    let url = repo.latest_release_api();
    match get_text(&url) {
        Ok(body) => release_from_json(&body),
        Err(e) if is_release_not_found(&e) => {
            let body = get_text(&repo.releases_list_api())?;
            release_from_list_json(&body)
        }
        Err(e) => Err(e),
    }
}

/// Fetch a specific release by tag (tag + asset list) via the GitHub API.
pub fn release_by_tag(repo: &Repo, tag: &str) -> Result<Release, String> {
    let url = repo.release_by_tag_api(tag);
    let body = get_text(&url)?;
    release_from_json(&body)
}

/// GET a URL as text with the GitHub API headers, optionally authenticated via
/// [`GITHUB_TOKEN_ENV`] (see [`get_text_with_token`]). Internal helper — the
/// production entry point every `latest_release`/`release_by_tag` call goes
/// through.
fn get_text(url: &str) -> Result<String, String> {
    get_text_with_token(url, std::env::var(GITHUB_TOKEN_ENV).ok().as_deref())
}

/// The environment variable an optional GitHub token is read from (task
/// #502/#524: unauthenticated `api.github.com` calls are capped at 60/hour
/// per source IP, a limit CI runners — which share a huge, heavily-used IP
/// pool — hit routinely; a token raises it to 5,000/hour). Matches the name
/// GitHub Actions already exposes as `secrets.GITHUB_TOKEN` and the `gh` CLI
/// convention, so CI needs no new secret — just `env: GITHUB_TOKEN:
/// ${{ secrets.GITHUB_TOKEN }}` on the step. Entirely optional: every call
/// works unauthenticated exactly as before when it is unset.
const GITHUB_TOKEN_ENV: &str = "GITHUB_TOKEN";

/// [`get_text`] with an injectable token — the pure-ish core so the
/// Authorization-header decision is unit-tested (against a real local
/// socket) without mutating the process environment. `token: None` sends the
/// SAME anonymous request as before this option existed.
fn get_text_with_token(url: &str, token: Option<&str>) -> Result<String, String> {
    let mut req = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json");
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let resp = req.call().map_err(|e| format!("GET {url}: {e}"))?;
    resp.into_string().map_err(|e| format!("read {url}: {e}"))
}

/// Hex SHA-256 of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Download `url` into memory. Returns the bytes (binaries are tens of MB —
/// fine to hold in RAM, and it lets us checksum before writing anything).
pub fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body {url}: {e}"))?;
    if buf.is_empty() {
        return Err(format!("downloaded 0 bytes from {url}"));
    }
    Ok(buf)
}

/// The result of writing a component binary to its destination.
///
/// Distinguishes the ordinary in-place write from the locked-destination
/// fallback (#544), so the caller can LOUDLY tell the user when a restart is
/// required before the new binary takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The bytes were written to the destination — the new binary is live now.
    Replaced,
    /// The destination was still locked by a running service/process (on
    /// Windows a running executable cannot be opened for writing → a sharing
    /// violation, "os error 32"), so the new binary was STAGED beside it and an
    /// atomic replace was scheduled for the next reboot
    /// (`MoveFileEx … MOVEFILE_DELAY_UNTIL_REBOOT`). The old binary keeps
    /// running until then; the destination is NEVER left half-written. The
    /// caller must tell the user a restart is required to finish the update.
    ScheduledForReboot,
}

/// Download a binary to `dest`, making it executable on unix. If
/// `expected_sha256` is `Some`, the download is verified before writing and a
/// mismatch is a hard error (nothing is written).
pub fn download_binary(
    url: &str,
    dest: &Path,
    expected_sha256: Option<&str>,
) -> Result<WriteOutcome, String> {
    let bytes = fetch_bytes(url)?;
    verify_and_write(&bytes, dest, expected_sha256).map_err(|e| e.replace("the artifact", url))
}

/// Verify `bytes` against `expected_sha256` (if given) and write them to `dest`,
/// creating the parent dir. Split out from [`download_binary`] (which adds the
/// network fetch) so the checksum + write logic is unit-tested WITHOUT a
/// network. On a checksum mismatch nothing is written. The write itself goes
/// through [`replace_binary`], which is resilient to a locked destination.
fn verify_and_write(
    bytes: &[u8],
    dest: &Path,
    expected_sha256: Option<&str>,
) -> Result<WriteOutcome, String> {
    if let Some(expected) = expected_sha256 {
        let got = sha256_hex(bytes);
        if !got.eq_ignore_ascii_case(expected.trim()) {
            return Err(format!(
                "checksum mismatch for the artifact: expected {expected}, got {got}"
            ));
        }
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    replace_binary(dest, bytes)
}

/// Write `bytes` to `dest`, resilient to `dest` being held open by a running
/// service/process (#544).
///
/// On Windows a running executable is locked against being opened for writing,
/// so a plain in-place write fails with a sharing violation ("os error 32") —
/// the exact failure a running `dig-dns` service produced when an upgrade tried
/// to overwrite `dig-dns.exe`. When that happens the new binary is staged beside
/// `dest` and an atomic replace is scheduled for the next reboot, rather than
/// aborting with a half-written or missing binary. On unix, replacing a busy
/// binary in place is permitted, so the write always applies immediately.
pub fn replace_binary(dest: &Path, bytes: &[u8]) -> Result<WriteOutcome, String> {
    replace_binary_with(dest, bytes, schedule_replace_on_reboot)
}

/// [`replace_binary`] with an injectable "schedule the delayed replace" action
/// — production passes [`schedule_replace_on_reboot`] (the real
/// `MoveFileEx`-until-reboot staging); tests inject a recorder so the
/// locked-destination fallback is exercised without touching the system's
/// pending-rename registry or needing a real reboot.
fn replace_binary_with(
    dest: &Path,
    bytes: &[u8],
    schedule_on_reboot: impl Fn(&Path, &[u8]) -> Result<(), String>,
) -> Result<WriteOutcome, String> {
    match std::fs::write(dest, bytes) {
        Ok(()) => {
            set_executable(dest);
            Ok(WriteOutcome::Replaced)
        }
        Err(e) if is_sharing_violation(&e) => {
            schedule_on_reboot(dest, bytes)?;
            Ok(WriteOutcome::ScheduledForReboot)
        }
        Err(e) => Err(format!("write {}: {e}", dest.display())),
    }
}

/// Does this write error mean the destination is locked by another process?
/// `ERROR_SHARING_VIOLATION` (32) is exactly the "the process cannot access the
/// file because it is being used by another process" a running Windows service
/// produces; `ERROR_LOCK_VIOLATION` (33) is its byte-range sibling. Never true
/// on non-Windows, where a busy binary can be replaced in place.
fn is_sharing_violation(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        matches!(e.raw_os_error(), Some(32) | Some(33))
    }
    #[cfg(not(windows))]
    {
        let _ = e;
        false
    }
}

/// Mark `dest` executable (owner/group/other) on unix; a no-op on Windows,
/// where executability is by extension, not a permission bit.
fn set_executable(dest: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(dest) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(dest, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dest;
    }
}

/// The sibling path new bytes are staged to before a delayed replace — a
/// hidden, pid-tagged neighbour of `dest` so concurrent runs never collide and
/// a stale stage is recognizable. Windows-only: the delayed-replace fallback it
/// serves ([`schedule_replace_on_reboot`]) never runs on other platforms.
#[cfg(windows)]
fn staging_path(dest: &Path) -> std::path::PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "binary".to_string());
    dest.with_file_name(format!(".{name}.pending-{}", std::process::id()))
}

/// Stage `bytes` beside `dest` and schedule an atomic replace of `dest` on the
/// next reboot. Windows: write the staging file, then `MoveFileExW(staging,
/// dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT)` so the OS
/// swaps in the new binary before any process can re-open the still-running old
/// one. Requires the elevation the install already holds (it records the rename
/// under `HKLM\SYSTEM\…\PendingFileRenameOperations`).
#[cfg(windows)]
fn schedule_replace_on_reboot(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING,
    };

    let staging = staging_path(dest);
    std::fs::write(&staging, bytes).map_err(|e| format!("stage {}: {e}", staging.display()))?;

    let wide = |p: &Path| -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let existing = wide(&staging);
    let target = wide(dest);
    // SAFETY: both pointers are NUL-terminated UTF-16 buffers kept alive across
    // the call; the flags are the documented reboot-replace pair.
    let ok = unsafe {
        MoveFileExW(
            existing.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        let _ = std::fs::remove_file(&staging);
        return Err(format!(
            "could not schedule the reboot-time replace of {} (Win32 error {code})",
            dest.display()
        ));
    }
    Ok(())
}

/// Non-Windows never reaches the delayed-replace fallback ([`is_sharing_violation`]
/// is always `false` off Windows, since a busy binary is replaceable in place),
/// so this exists only to satisfy the injection seam's signature.
#[cfg(not(windows))]
fn schedule_replace_on_reboot(dest: &Path, _bytes: &[u8]) -> Result<(), String> {
    Err(format!(
        "unexpected locked destination replacing {} on a non-Windows host",
        dest.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_tag_name() {
        let body = r#"{"tag_name":"v0.6.0","name":"digstore v0.6.0","draft":false}"#;
        assert_eq!(tag_name_from_release_json(body).unwrap(), "v0.6.0");
    }

    #[test]
    fn errors_without_tag_name() {
        assert!(tag_name_from_release_json(r#"{"name":"x"}"#).is_err());
        assert!(tag_name_from_release_json("not json").is_err());
    }

    #[test]
    fn release_from_json_extracts_tag_and_asset_names() {
        let body = r#"{
            "tag_name": "v0.6.0",
            "assets": [
                {"name": "digstore-0.6.0-linux-x64", "size": 123},
                {"name": "digstore-0.6.0-windows-x64.exe"},
                {"name": "digstore-0.6.0-macos-arm64"}
            ]
        }"#;
        let r = release_from_json(body).unwrap();
        assert_eq!(r.tag_name, "v0.6.0");
        assert_eq!(
            r.asset_names,
            vec![
                "digstore-0.6.0-linux-x64".to_string(),
                "digstore-0.6.0-windows-x64.exe".to_string(),
                "digstore-0.6.0-macos-arm64".to_string(),
            ]
        );
    }

    #[test]
    fn release_from_json_tolerates_no_assets() {
        let r = release_from_json(r#"{"tag_name":"v1.0.0"}"#).unwrap();
        assert_eq!(r.tag_name, "v1.0.0");
        assert!(r.asset_names.is_empty());
    }

    #[test]
    fn release_from_json_errors_without_tag() {
        assert!(release_from_json(r#"{"assets":[]}"#).is_err());
        assert!(release_from_json("not json").is_err());
    }

    #[test]
    fn sha256_is_lowercase_hex() {
        // SHA-256 of the empty input.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn release_from_json_skips_assets_without_a_name() {
        // An asset entry missing `name` is filtered out (not a crash, not an empty
        // string) — only well-formed asset names survive.
        let body = r#"{
            "tag_name": "v1.2.3",
            "assets": [
                {"size": 10},
                {"name": "good-1.2.3-linux-x64"},
                {"name": 42}
            ]
        }"#;
        let r = release_from_json(body).unwrap();
        assert_eq!(r.tag_name, "v1.2.3");
        assert_eq!(r.asset_names, vec!["good-1.2.3-linux-x64".to_string()]);
    }

    #[test]
    fn release_from_json_treats_non_array_assets_as_empty() {
        // `assets` present but not an array → no asset names (no panic).
        let r = release_from_json(r#"{"tag_name":"v1.0.0","assets":"oops"}"#).unwrap();
        assert!(r.asset_names.is_empty());
    }

    #[test]
    fn is_release_not_found_detects_404_variants() {
        // ureq's Status Display is "{url}: status code {code}"; get_text wraps it
        // as "GET {url}: {ureq display}" — both forms must be recognised, plus
        // the plain-English "Not Found" the rest of the codebase also checks for
        // (see lib.rs::classify_release_error, same convention).
        assert!(is_release_not_found(
            "GET https://api.github.com/x: https://api.github.com/x: status code 404"
        ));
        assert!(is_release_not_found(
            "GET https://api.github.com/x: 404 Not Found"
        ));
        assert!(!is_release_not_found(
            "GET https://api.github.com/x: status code 500"
        ));
        assert!(!is_release_not_found(
            "GET https://api.github.com/x: timed out"
        ));
    }

    #[test]
    fn release_from_list_json_takes_the_newest_entry_regardless_of_prerelease() {
        // Regression (#40): DIG Browser's only release
        // (149.0.7827.155-1.1-alpha) is prerelease-flagged, so GitHub's
        // `/releases/latest` (which excludes prereleases/drafts) 404s even
        // though a real release exists. The fallback list-parse must pick the
        // newest (first) entry regardless of its prerelease flag.
        let body = r#"[
            {
                "tag_name": "149.0.7827.155-1.1-alpha",
                "prerelease": true,
                "draft": false,
                "assets": [
                    {"name": "ungoogled-chromium_149.0.7827.155-1.1_installer_x64.exe"},
                    {"name": "ungoogled-chromium_149.0.7827.155-1.1_windows_x64.zip"}
                ]
            },
            {
                "tag_name": "148.0.0.0-1.0-alpha",
                "prerelease": true,
                "draft": false,
                "assets": []
            }
        ]"#;
        let r = release_from_list_json(body).unwrap();
        assert_eq!(r.tag_name, "149.0.7827.155-1.1-alpha");
        assert_eq!(
            r.asset_names,
            vec![
                "ungoogled-chromium_149.0.7827.155-1.1_installer_x64.exe".to_string(),
                "ungoogled-chromium_149.0.7827.155-1.1_windows_x64.zip".to_string(),
            ]
        );
    }

    #[test]
    fn release_from_list_json_errors_on_empty_list() {
        let err = release_from_list_json("[]").unwrap_err();
        assert!(err.contains("no releases"), "got: {err}");
    }

    #[test]
    fn release_from_list_json_errors_on_non_array() {
        assert!(release_from_list_json(r#"{"tag_name":"v1.0.0"}"#).is_err());
        assert!(release_from_list_json("not json").is_err());
    }

    #[test]
    fn verify_and_write_writes_bytes_when_no_checksum_given() {
        let dir = std::env::temp_dir().join(format!("dig-dl-nohash-{}", std::process::id()));
        let dest = dir.join("nested").join("artifact.bin");
        let outcome = verify_and_write(b"hello dig", &dest, None).expect("write ok");
        assert_eq!(outcome, WriteOutcome::Replaced);
        // The nested parent dir was created and the bytes round-trip.
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello dig");
    }

    #[test]
    fn verify_and_write_accepts_a_matching_checksum() {
        let dir = std::env::temp_dir().join(format!("dig-dl-ok-{}", std::process::id()));
        let dest = dir.join("artifact.bin");
        let data = b"verified payload";
        let sum = sha256_hex(data);
        // Upper-cased + padded to prove the compare is case-insensitive + trimmed.
        let expected = format!("  {}  ", sum.to_uppercase());
        verify_and_write(data, &dest, Some(&expected)).expect("matching checksum ok");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[test]
    fn verify_and_write_rejects_a_mismatched_checksum_and_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("dig-dl-bad-{}", std::process::id()));
        let dest = dir.join("artifact.bin");
        let err = verify_and_write(b"payload", &dest, Some("deadbeef")).unwrap_err();
        assert!(err.contains("checksum mismatch"), "got: {err}");
        // Nothing is written on a mismatch.
        assert!(!dest.exists());
    }

    #[cfg(unix)]
    #[test]
    fn verify_and_write_marks_the_file_executable_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dig-dl-exec-{}", std::process::id()));
        let dest = dir.join("tool");
        verify_and_write(b"#!/bin/sh\n", &dest, None).expect("ok");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "owner/group/other exec bits set");
    }

    // -- get_text_with_token: the optional GitHub-auth header (#502/#524) ----
    //
    // Drives the REAL `ureq` request against a one-shot local server that
    // echoes back whatever `Authorization` header it received (or `NONE`),
    // so the assertion is on the actual wire request `get_text_with_token`
    // sends — not a re-statement of its own `if let` branch. Uses an
    // injected `token: Option<&str>` (never a real env var), so these run
    // safely under Rust's parallel test harness with no shared mutable state.

    /// A one-shot HTTP/1.1 server that reads the request line + headers,
    /// replies 200 with the received `Authorization` header value (or `NONE`)
    /// as the body, then exits. Mirrors `health.rs`'s `one_shot_json_server`.
    fn one_shot_echo_auth_server() -> u16 {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                    .ok();
                let mut buf = [0u8; 4096];
                let mut request = Vec::new();
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let auth = text
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    .map(|l| l.split_once(':').map_or("", |(_, v)| v).trim().to_string())
                    .unwrap_or_else(|| "NONE".to_string());
                let body = format!("{{\"tag_name\":\"v0.0.0\",\"__auth\":\"{auth}\"}}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
        port
    }

    #[test]
    fn get_text_with_token_sends_no_authorization_header_when_token_is_none() {
        let port = one_shot_echo_auth_server();
        let body = get_text_with_token(&format!("http://127.0.0.1:{port}/"), None).unwrap();
        assert!(body.contains(r#""__auth":"NONE""#), "got: {body}");
    }

    #[test]
    fn get_text_with_token_sends_no_authorization_header_when_token_is_empty() {
        // An empty string is treated the same as absent — never sends a
        // hollow `Authorization: Bearer` header.
        let port = one_shot_echo_auth_server();
        let body = get_text_with_token(&format!("http://127.0.0.1:{port}/"), Some("")).unwrap();
        assert!(body.contains(r#""__auth":"NONE""#), "got: {body}");
    }

    #[test]
    fn get_text_with_token_sends_a_bearer_authorization_header_when_present() {
        let port = one_shot_echo_auth_server();
        let body =
            get_text_with_token(&format!("http://127.0.0.1:{port}/"), Some("ghp_test123")).unwrap();
        assert!(
            body.contains(r#""__auth":"Bearer ghp_test123""#),
            "got: {body}"
        );
    }

    #[test]
    fn get_text_reads_the_real_github_token_env_var() {
        // get_text (the production entry point) reads GITHUB_TOKEN_ENV itself;
        // this only proves the constant names the variable CI already
        // exposes (`secrets.GITHUB_TOKEN`) — the header-sending behavior
        // itself is covered token-injected above, never via a real env
        // mutation (parallel-test-safe).
        assert_eq!(GITHUB_TOKEN_ENV, "GITHUB_TOKEN");
    }

    // -- #544: replacing a binary whose file is locked by a running service ----
    //
    // The reported P1: an upgrade over a RUNNING dig-dns held `dig-dns.exe`
    // open, so overwriting it in place failed with "os error 32" (a Windows
    // sharing violation). `replace_binary` must convert that into a safe,
    // staged, reboot-time replace instead of a hard error — and never leave a
    // half-written binary.

    #[test]
    fn replace_binary_writes_in_place_when_the_destination_is_free() {
        let dir = std::env::temp_dir().join(format!("dig-dl-free-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dig-dns-free.bin");
        let outcome = replace_binary(&dest, b"NEW").expect("an unlocked write applies in place");
        assert_eq!(outcome, WriteOutcome::Replaced);
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_sharing_violation_only_flags_the_lock_error_on_windows() {
        // A plain not-found error is never a sharing violation on any OS.
        let not_found = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(!is_sharing_violation(&not_found));
    }

    /// The exact user-reported failure, reproduced end-to-end: a running
    /// service holds its exe open (a handle that shares READ but not WRITE —
    /// how Windows keeps a running image locked), a naive in-place write hits
    /// `os error 32`, and `replace_binary_with` instead stages the new bytes +
    /// reports a reboot is required, leaving the old binary intact. Once the
    /// holder releases (the service stopped), the in-place write applies.
    #[cfg(windows)]
    #[test]
    fn replace_binary_falls_back_to_a_scheduled_replace_when_the_destination_is_locked() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        let dir = std::env::temp_dir().join(format!("dig-dl-locked-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dig-dns.exe");
        std::fs::write(&dest, b"OLD BINARY").unwrap();

        // Simulate the running service's lock: a handle sharing only READ, so a
        // second open requesting WRITE is refused with a sharing violation.
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&dest)
            .expect("open the locked holder handle");

        // The reported bug: a naive in-place write hits ERROR_SHARING_VIOLATION (32).
        let naive = std::fs::write(&dest, b"NEW BINARY");
        assert_eq!(
            naive.unwrap_err().raw_os_error(),
            Some(32),
            "must reproduce the exact os error 32 the user reported"
        );
        assert!(
            is_sharing_violation(&std::fs::write(&dest, b"x").unwrap_err()),
            "the classifier must recognise a real sharing violation"
        );

        // The fix: stage + schedule instead of erroring, never half-writing dest.
        let scheduled = std::cell::Cell::new(false);
        let outcome = replace_binary_with(&dest, b"NEW BINARY", |_dest, _bytes| {
            scheduled.set(true);
            Ok(())
        })
        .expect("resilient replace must not error on a locked destination");
        assert_eq!(outcome, WriteOutcome::ScheduledForReboot);
        assert!(
            scheduled.get(),
            "the delayed replace must have been scheduled"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"OLD BINARY",
            "the destination must be left intact (never half-written) while locked"
        );

        // Stopping the service releases the handle → the fast in-place path applies.
        drop(holder);
        let outcome = replace_binary(&dest, b"NEW BINARY").expect("write succeeds once unlocked");
        assert_eq!(outcome, WriteOutcome::Replaced);
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW BINARY");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
