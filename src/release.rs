//! GitHub release coordinates and download-URL construction.
//!
//! Pure URL/identity logic (no network): a [`Repo`] names a tool's GitHub repo
//! and binary stem; from it and a resolved [`Target`](crate::target::Target)
//! we build the **download URL** for a specific tag, or the **latest-release
//! API URL** to discover the newest tag. Network fetching lives in
//! [`crate::download`]; this module stays unit-testable.

use crate::target::Target;

/// A tool's GitHub release source: `owner/name` plus the binary stem used in
/// asset filenames (e.g. repo `DIG-Network/digstore`, stem `digstore`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub owner: String,
    pub name: String,
    /// The binary/asset stem (e.g. `digstore`, `dig-node`).
    pub stem: String,
}

impl Repo {
    pub fn new(owner: &str, name: &str, stem: &str) -> Repo {
        Repo {
            owner: owner.to_string(),
            name: name.to_string(),
            stem: stem.to_string(),
        }
    }

    /// The canonical digstore CLI release source.
    pub fn digstore() -> Repo {
        Repo::new("DIG-Network", "digstore", "digstore")
    }

    /// The canonical dig-node release source.
    ///
    /// Note: the binary is published as `dig-node-*` once the dig-companion →
    /// dig-node rename lands; the repo `DIG-Network/dig-node` is its home. While
    /// the rename is pending the artifacts may still carry the `dig-companion`
    /// stem — see [`Repo::dig_node_legacy`] for that fallback.
    pub fn dig_node() -> Repo {
        Repo::new("DIG-Network", "dig-node", "dig-node")
    }

    /// Pre-rename dig-node source (`DIG-Network/dig-companion`, stem
    /// `dig-companion`). Used as a fallback so the installer keeps working
    /// across the rename.
    pub fn dig_node_legacy() -> Repo {
        Repo::new("DIG-Network", "dig-companion", "dig-companion")
    }

    /// The DIG Browser release source (`DIG-Network/DIG_Browser`). Publishes a
    /// native installer per OS (`.exe` / `.dmg` / `.AppImage`), so it is matched
    /// as an [`AssetKind::Installer`](crate::asset::AssetKind::Installer), not a
    /// raw PATH binary.
    pub fn dig_browser() -> Repo {
        Repo::new("DIG-Network", "DIG_Browser", "DIG-Browser")
    }

    /// The DIG Relay release source (`DIG-Network/dig-relay`). Publishes a raw
    /// per-OS/arch binary `dig-relay-<ver>-<os_arch>[.exe]` (matched as a
    /// [`AssetKind::RawBinary`](crate::asset::AssetKind::RawBinary)); the
    /// run-your-own-relay component registers it as an OS service via the binary's
    /// own `install`/`start` subcommands (like dig-node).
    pub fn dig_relay() -> Repo {
        Repo::new("DIG-Network", "dig-relay", "dig-relay")
    }

    /// GitHub API URL for the latest release of this repo (returns JSON with a
    /// `tag_name` and an `assets` array).
    pub fn latest_release_api(&self) -> String {
        format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            self.owner, self.name
        )
    }

    /// GitHub API URL for a specific release by tag (returns the same shape as
    /// [`latest_release_api`](Self::latest_release_api)).
    pub fn release_by_tag_api(&self, tag: &str) -> String {
        format!(
            "https://api.github.com/repos/{}/{}/releases/tags/{}",
            self.owner, self.name, tag
        )
    }

    /// Browser download URL for a named asset at a given tag.
    ///
    /// `tag` is the git tag exactly as published (e.g. `v0.6.0`).
    pub fn asset_download_url(&self, tag: &str, asset: &str) -> String {
        format!(
            "https://github.com/{}/{}/releases/download/{}/{}",
            self.owner, self.name, tag, asset
        )
    }

    /// Convenience: the download URL for THIS tool's binary asset at a tag, for
    /// a target. `version` is the bare semver (tag without the leading `v`).
    pub fn binary_url(&self, tag: &str, version: &str, target: &Target) -> String {
        let asset = target.asset_name(&self.stem, version);
        self.asset_download_url(tag, &asset)
    }
}

/// Normalize a git tag (`v0.6.0`) to a bare semver version (`0.6.0`).
pub fn version_from_tag(tag: &str) -> String {
    tag.strip_prefix('v').unwrap_or(tag).to_string()
}

/// Normalize a user-supplied version/tag to a git tag form (`v0.6.0`).
/// Accepts both `0.6.0` and `v0.6.0`; the empty string and the literal
/// `latest` are returned unchanged so callers can branch on them.
pub fn tag_from_input(input: &str) -> String {
    if input.is_empty() || input == "latest" {
        return input.to_string();
    }
    if input.starts_with('v') {
        input.to_string()
    } else {
        format!("v{input}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{Arch, Os};

    fn lin() -> Target {
        Target {
            os: Os::Linux,
            arch: Arch::X64,
        }
    }
    fn win() -> Target {
        Target {
            os: Os::Windows,
            arch: Arch::X64,
        }
    }

    #[test]
    fn canonical_repos() {
        assert_eq!(
            Repo::digstore(),
            Repo::new("DIG-Network", "digstore", "digstore")
        );
        assert_eq!(
            Repo::dig_node(),
            Repo::new("DIG-Network", "dig-node", "dig-node")
        );
        assert_eq!(
            Repo::dig_node_legacy(),
            Repo::new("DIG-Network", "dig-companion", "dig-companion")
        );
        assert_eq!(
            Repo::dig_browser(),
            Repo::new("DIG-Network", "DIG_Browser", "DIG-Browser")
        );
        assert_eq!(
            Repo::dig_relay(),
            Repo::new("DIG-Network", "dig-relay", "dig-relay")
        );
    }

    #[test]
    fn dig_relay_binary_url_matches_published_asset_naming() {
        // The release workflow names assets dig-relay-<ver>-<os_arch>[.exe]; the installer must
        // build the SAME URL so it resolves the binary.
        assert_eq!(
            Repo::dig_relay().binary_url("v0.1.0", "0.1.0", &lin()),
            "https://github.com/DIG-Network/dig-relay/releases/download/v0.1.0/dig-relay-0.1.0-linux-x64"
        );
        assert_eq!(
            Repo::dig_relay().binary_url("v0.1.0", "0.1.0", &win()),
            "https://github.com/DIG-Network/dig-relay/releases/download/v0.1.0/dig-relay-0.1.0-windows-x64.exe"
        );
    }

    #[test]
    fn dig_browser_latest_release_api_url() {
        assert_eq!(
            Repo::dig_browser().latest_release_api(),
            "https://api.github.com/repos/DIG-Network/DIG_Browser/releases/latest"
        );
    }

    #[test]
    fn latest_release_api_url() {
        assert_eq!(
            Repo::digstore().latest_release_api(),
            "https://api.github.com/repos/DIG-Network/digstore/releases/latest"
        );
    }

    #[test]
    fn release_by_tag_api_url() {
        assert_eq!(
            Repo::digstore().release_by_tag_api("v0.6.0"),
            "https://api.github.com/repos/DIG-Network/digstore/releases/tags/v0.6.0"
        );
    }

    #[test]
    fn asset_download_url_uses_tag_verbatim() {
        assert_eq!(
            Repo::digstore().asset_download_url("v0.6.0", "digstore-0.6.0-linux-x64"),
            "https://github.com/DIG-Network/digstore/releases/download/v0.6.0/digstore-0.6.0-linux-x64"
        );
    }

    #[test]
    fn binary_url_composes_tag_and_target_asset() {
        assert_eq!(
            Repo::digstore().binary_url("v0.6.0", "0.6.0", &lin()),
            "https://github.com/DIG-Network/digstore/releases/download/v0.6.0/digstore-0.6.0-linux-x64"
        );
        assert_eq!(
            Repo::digstore().binary_url("v0.6.0", "0.6.0", &win()),
            "https://github.com/DIG-Network/digstore/releases/download/v0.6.0/digstore-0.6.0-windows-x64.exe"
        );
    }

    #[test]
    fn version_tag_roundtrip() {
        assert_eq!(version_from_tag("v0.6.0"), "0.6.0");
        assert_eq!(version_from_tag("0.6.0"), "0.6.0");
        assert_eq!(tag_from_input("0.6.0"), "v0.6.0");
        assert_eq!(tag_from_input("v0.6.0"), "v0.6.0");
        assert_eq!(tag_from_input("latest"), "latest");
        assert_eq!(tag_from_input(""), "");
    }
}
