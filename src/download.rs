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

/// Parse a GitHub release JSON payload into a [`Release`] (tag + asset names).
/// Pure — the heart of the thin-shim asset resolution, unit-tested without a
/// network.
pub fn release_from_json(body: &str) -> Result<Release, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parse release JSON: {e}"))?;
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

/// Discover the latest published tag for a repo via the GitHub API.
pub fn latest_tag(repo: &Repo) -> Result<String, String> {
    Ok(latest_release(repo)?.tag_name)
}

/// Fetch the latest release (tag + asset list) for a repo via the GitHub API.
pub fn latest_release(repo: &Repo) -> Result<Release, String> {
    let url = repo.latest_release_api();
    let body = get_text(&url)?;
    release_from_json(&body)
}

/// Fetch a specific release by tag (tag + asset list) via the GitHub API.
pub fn release_by_tag(repo: &Repo, tag: &str) -> Result<Release, String> {
    let url = repo.release_by_tag_api(tag);
    let body = get_text(&url)?;
    release_from_json(&body)
}

/// GET a URL as text with the GitHub API headers. Internal helper.
fn get_text(url: &str) -> Result<String, String> {
    let resp = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
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

/// Download a binary to `dest`, making it executable on unix. If
/// `expected_sha256` is `Some`, the download is verified before writing and a
/// mismatch is a hard error (nothing is written).
pub fn download_binary(
    url: &str,
    dest: &Path,
    expected_sha256: Option<&str>,
) -> Result<(), String> {
    let bytes = fetch_bytes(url)?;
    verify_and_write(&bytes, dest, expected_sha256).map_err(|e| e.replace("the artifact", url))
}

/// Verify `bytes` against `expected_sha256` (if given) and write them to `dest`,
/// creating the parent dir and marking the file executable on unix. Split out
/// from [`download_binary`] (which adds the network fetch) so the checksum +
/// write + perms logic is unit-tested WITHOUT a network. On a checksum mismatch
/// nothing is written.
fn verify_and_write(
    bytes: &[u8],
    dest: &Path,
    expected_sha256: Option<&str>,
) -> Result<(), String> {
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
    std::fs::write(dest, bytes).map_err(|e| format!("write {}: {e}", dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dest)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(dest, perms);
    }
    Ok(())
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
    fn verify_and_write_writes_bytes_when_no_checksum_given() {
        let dir = std::env::temp_dir().join(format!("dig-dl-nohash-{}", std::process::id()));
        let dest = dir.join("nested").join("artifact.bin");
        verify_and_write(b"hello dig", &dest, None).expect("write ok");
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
}
