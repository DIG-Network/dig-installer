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

    /// The canonical dig-store CLI release source.
    ///
    /// The repo was renamed `digstore` → `dig-store` (epic #703) and its release
    /// assets now carry the `dig-store-*` stem. The GitHub repo redirect keeps the
    /// old `DIG-Network/digstore` URL working, but the ASSET STEM changed, so a
    /// release that only has the pre-rename `digstore-*` assets is resolved via
    /// [`Repo::dig_store_legacy`] instead — mirroring [`Repo::dig_node`] /
    /// [`Repo::dig_node_legacy`].
    pub fn dig_store() -> Repo {
        Repo::new("DIG-Network", "dig-store", "dig-store")
    }

    /// Pre-rename dig-store source: the new repo name (its redirect also covers
    /// the old `digstore` URL) but the OLD asset stem `digstore`. Used as a
    /// fallback so the installer keeps resolving a release that was cut before the
    /// asset rename landed.
    pub fn dig_store_legacy() -> Repo {
        Repo::new("DIG-Network", "dig-store", "digstore")
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

    /// The dig-dns release source (`DIG-Network/dig-dns`). Publishes a raw
    /// per-OS/arch binary `dig-dns-<ver>-<os_arch>[.exe]` (matched as a
    /// [`AssetKind::RawBinary`](crate::asset::AssetKind::RawBinary)) — the local
    /// `*.dig` name resolver (DNS responder + HTTP gateway + `doctor`). Unlike
    /// dig-node/dig-relay, dig-dns ships NO `install`/`start` subcommands of its
    /// own, so this installer registers it as an OS service directly (see
    /// [`crate::dns`]) rather than delegating.
    pub fn dig_dns() -> Repo {
        Repo::new("DIG-Network", "dig-dns", "dig-dns")
    }

    /// The DIG auto-update beacon's release source (`DIG-Network/dig-updater`,
    /// issue #514). Publishes a raw per-OS/arch binary
    /// `dig-updater-<ver>-<os_arch>[.exe]` (matched as an
    /// [`AssetKind::RawBinary`](crate::asset::AssetKind::RawBinary)) — a
    /// privileged broker that registers itself as a daily OS-scheduled task/
    /// timer/LaunchDaemon (see [`crate::beacon`]) checking for + installing new
    /// signed DIG releases. Its unprivileged fetch/verify sibling is published
    /// in the SAME release under its own stem — see [`Repo::dig_updater_worker`].
    pub fn dig_updater() -> Repo {
        Repo::new("DIG-Network", "dig-updater", "dig-updater")
    }

    /// The beacon's unprivileged fetch/verify worker (issue #514): the
    /// privileged broker (`dig-updater`) spawns this sibling process to do all
    /// network fetching + signature/checksum verification with NO install
    /// privilege. Published in the **SAME** `DIG-Network/dig-updater` release as
    /// [`Repo::dig_updater`], under its own asset stem
    /// (`dig-updater-worker-<ver>-<os_arch>[.exe]`) — resolved via the identical
    /// asset matcher, parameterized on stem `"dig-updater-worker"` instead of
    /// `"dig-updater"` (mirrors [`Repo::digs`]'s alongside-the-primary pattern).
    pub fn dig_updater_worker() -> Repo {
        Repo::new("DIG-Network", "dig-updater", "dig-updater-worker")
    }

    /// The `digs` alias binary's release source (issue #434): `digs <args>`
    /// behaves IDENTICALLY to `dig-store <args>` (same entrypoint, dig-store's
    /// `SPEC.md` § "CLI binaries") and is published in the **SAME**
    /// `DIG-Network/dig-store` release as the `dig-store` CLI, under its own
    /// asset stem (`digs-<ver>-<os_arch>[.exe]` — byte-for-byte the same shape
    /// as `dig-store-<ver>-<os_arch>[.exe]`). Same owner/repo as
    /// [`Repo::dig_store`], only the stem differs, so it resolves via the SAME
    /// [`crate::asset::select_asset`] matcher with zero new matcher logic. The
    /// `digs` stem is unchanged by the #703 rename, so it needs no legacy fallback.
    pub fn digs() -> Repo {
        Repo::new("DIG-Network", "dig-store", "digs")
    }

    /// The `dign` alias binary's release source (issue #548): `dign <args>`
    /// behaves IDENTICALLY to `dig-node <args>` and is published in the
    /// **SAME** `DIG-Network/dig-node` release as `dig-node`, under its own
    /// asset stem (`dign-<ver>-<os_arch>[.exe]` — byte-for-byte the same shape
    /// as `dig-node-<ver>-<os_arch>[.exe]`). Same owner/repo as
    /// [`Repo::dig_node`], only the stem differs, so it resolves via the SAME
    /// [`crate::asset::select_asset`] matcher, mirroring [`Repo::digs`].
    pub fn dign() -> Repo {
        Repo::new("DIG-Network", "dig-node", "dign")
    }

    /// The `digd` alias binary's release source (issue #548): `digd <args>`
    /// behaves IDENTICALLY to `dig-dns <args>` and is published in the
    /// **SAME** `DIG-Network/dig-dns` release as `dig-dns`, under its own
    /// asset stem (`digd-<ver>-<os_arch>[.exe]` — byte-for-byte the same shape
    /// as `dig-dns-<ver>-<os_arch>[.exe]`). Same owner/repo as
    /// [`Repo::dig_dns`], only the stem differs, so it resolves via the SAME
    /// [`crate::asset::select_asset`] matcher, mirroring [`Repo::digs`].
    pub fn digd() -> Repo {
        Repo::new("DIG-Network", "dig-dns", "digd")
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

    /// GitHub API URL for the FULL releases list (returns a JSON array, newest
    /// first, with NO prerelease/draft filtering). The fallback source when
    /// [`latest_release_api`](Self::latest_release_api) 404s because the
    /// newest release is prerelease-only (e.g. DIG Browser's alpha channel) —
    /// see [`crate::download::latest_release`].
    pub fn releases_list_api(&self) -> String {
        format!(
            "https://api.github.com/repos/{}/{}/releases",
            self.owner, self.name
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
            Repo::dig_store(),
            Repo::new("DIG-Network", "dig-store", "dig-store")
        );
        assert_eq!(
            Repo::dig_store_legacy(),
            Repo::new("DIG-Network", "dig-store", "digstore")
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
        assert_eq!(
            Repo::dig_dns(),
            Repo::new("DIG-Network", "dig-dns", "dig-dns")
        );
        assert_eq!(Repo::digs(), Repo::new("DIG-Network", "dig-store", "digs"));
        assert_eq!(Repo::dign(), Repo::new("DIG-Network", "dig-node", "dign"));
        assert_eq!(Repo::digd(), Repo::new("DIG-Network", "dig-dns", "digd"));
        assert_eq!(
            Repo::dig_updater(),
            Repo::new("DIG-Network", "dig-updater", "dig-updater")
        );
        assert_eq!(
            Repo::dig_updater_worker(),
            Repo::new("DIG-Network", "dig-updater", "dig-updater-worker")
        );
    }

    #[test]
    fn dig_updater_worker_shares_the_dig_updater_repo_with_its_own_stem() {
        // The worker (issue #514) is published in the SAME dig-updater release,
        // just under a different asset stem — same owner/name as Repo::dig_updater().
        let worker = Repo::dig_updater_worker();
        let broker = Repo::dig_updater();
        assert_eq!(worker.owner, broker.owner);
        assert_eq!(worker.name, broker.name);
        assert_eq!(worker.stem, "dig-updater-worker");
    }

    #[test]
    fn dig_updater_binary_url_matches_published_asset_naming() {
        assert_eq!(
            Repo::dig_updater().binary_url("v0.6.0", "0.6.0", &lin()),
            "https://github.com/DIG-Network/dig-updater/releases/download/v0.6.0/dig-updater-0.6.0-linux-x64"
        );
        assert_eq!(
            Repo::dig_updater().binary_url("v0.6.0", "0.6.0", &win()),
            "https://github.com/DIG-Network/dig-updater/releases/download/v0.6.0/dig-updater-0.6.0-windows-x64.exe"
        );
        assert_eq!(
            Repo::dig_updater_worker().binary_url("v0.6.0", "0.6.0", &lin()),
            "https://github.com/DIG-Network/dig-updater/releases/download/v0.6.0/dig-updater-worker-0.6.0-linux-x64"
        );
    }

    #[test]
    fn digs_shares_the_dig_store_repo_with_its_own_stem() {
        // digs (issue #434) is published in the SAME dig-store release, just under
        // a different asset stem — same owner/name as Repo::dig_store().
        let digs = Repo::digs();
        let dig_store = Repo::dig_store();
        assert_eq!(digs.owner, dig_store.owner);
        assert_eq!(digs.name, dig_store.name);
        assert_eq!(digs.stem, "digs");
    }

    #[test]
    fn digs_binary_url_matches_published_asset_naming() {
        // dig-store's release.yml publishes digs-<ver>-<os_arch>[.exe] alongside
        // dig-store-<ver>-<os_arch>[.exe] in the SAME release — the installer must
        // build the same URL shape, against the dig-store repo, to resolve it.
        assert_eq!(
            Repo::digs().binary_url("v0.6.0", "0.6.0", &lin()),
            "https://github.com/DIG-Network/dig-store/releases/download/v0.6.0/digs-0.6.0-linux-x64"
        );
        assert_eq!(
            Repo::digs().binary_url("v0.6.0", "0.6.0", &win()),
            "https://github.com/DIG-Network/dig-store/releases/download/v0.6.0/digs-0.6.0-windows-x64.exe"
        );
    }

    #[test]
    fn dig_store_resolves_the_renamed_asset_stem() {
        // Post-#703 the CLI asset is dig-store-<ver>-<os_arch>[.exe].
        assert_eq!(
            Repo::dig_store().binary_url("v0.14.0", "0.14.0", &lin()),
            "https://github.com/DIG-Network/dig-store/releases/download/v0.14.0/dig-store-0.14.0-linux-x64"
        );
    }

    #[test]
    fn dig_store_legacy_resolves_the_pre_rename_asset_stem() {
        // The transitional fallback keeps the old digstore-<ver> asset resolvable
        // via the (redirecting) repo, so a release cut before the asset rename
        // still installs.
        assert_eq!(
            Repo::dig_store_legacy().binary_url("v0.13.0", "0.13.0", &win()),
            "https://github.com/DIG-Network/dig-store/releases/download/v0.13.0/digstore-0.13.0-windows-x64.exe"
        );
    }

    #[test]
    fn dign_shares_the_dig_node_repo_with_its_own_stem() {
        // dign (issue #548) is published in the SAME dig-node release, just under
        // a different asset stem — same owner/name as Repo::dig_node().
        let dign = Repo::dign();
        let dig_node = Repo::dig_node();
        assert_eq!(dign.owner, dig_node.owner);
        assert_eq!(dign.name, dig_node.name);
        assert_eq!(dign.stem, "dign");
    }

    #[test]
    fn dign_binary_url_matches_published_asset_naming() {
        // dig-node's release.yml publishes dign-<ver>-<os_arch>[.exe] alongside
        // dig-node-<ver>-<os_arch>[.exe] in the SAME release — the installer must
        // build the same URL shape, against the dig-node repo, to resolve it.
        assert_eq!(
            Repo::dign().binary_url("v0.31.0", "0.31.0", &lin()),
            "https://github.com/DIG-Network/dig-node/releases/download/v0.31.0/dign-0.31.0-linux-x64"
        );
        assert_eq!(
            Repo::dign().binary_url("v0.31.0", "0.31.0", &win()),
            "https://github.com/DIG-Network/dig-node/releases/download/v0.31.0/dign-0.31.0-windows-x64.exe"
        );
    }

    #[test]
    fn digd_shares_the_dig_dns_repo_with_its_own_stem() {
        // digd (issue #548) is published in the SAME dig-dns release, just under
        // a different asset stem — same owner/name as Repo::dig_dns().
        let digd = Repo::digd();
        let dig_dns = Repo::dig_dns();
        assert_eq!(digd.owner, dig_dns.owner);
        assert_eq!(digd.name, dig_dns.name);
        assert_eq!(digd.stem, "digd");
    }

    #[test]
    fn digd_binary_url_matches_published_asset_naming() {
        // dig-dns's release.yml publishes digd-<ver>-<os_arch>[.exe] alongside
        // dig-dns-<ver>-<os_arch>[.exe] in the SAME release — the installer must
        // build the same URL shape, against the dig-dns repo, to resolve it.
        assert_eq!(
            Repo::digd().binary_url("v0.12.0", "0.12.0", &lin()),
            "https://github.com/DIG-Network/dig-dns/releases/download/v0.12.0/digd-0.12.0-linux-x64"
        );
        assert_eq!(
            Repo::digd().binary_url("v0.12.0", "0.12.0", &win()),
            "https://github.com/DIG-Network/dig-dns/releases/download/v0.12.0/digd-0.12.0-windows-x64.exe"
        );
    }

    #[test]
    fn dig_dns_binary_url_matches_published_asset_naming() {
        assert_eq!(
            Repo::dig_dns().binary_url("v0.6.0", "0.6.0", &lin()),
            "https://github.com/DIG-Network/dig-dns/releases/download/v0.6.0/dig-dns-0.6.0-linux-x64"
        );
        assert_eq!(
            Repo::dig_dns().binary_url("v0.6.0", "0.6.0", &win()),
            "https://github.com/DIG-Network/dig-dns/releases/download/v0.6.0/dig-dns-0.6.0-windows-x64.exe"
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
            Repo::dig_store().latest_release_api(),
            "https://api.github.com/repos/DIG-Network/dig-store/releases/latest"
        );
    }

    #[test]
    fn releases_list_api_url() {
        assert_eq!(
            Repo::dig_browser().releases_list_api(),
            "https://api.github.com/repos/DIG-Network/DIG_Browser/releases"
        );
    }

    #[test]
    fn release_by_tag_api_url() {
        assert_eq!(
            Repo::dig_store().release_by_tag_api("v0.6.0"),
            "https://api.github.com/repos/DIG-Network/dig-store/releases/tags/v0.6.0"
        );
    }

    #[test]
    fn asset_download_url_uses_tag_verbatim() {
        assert_eq!(
            Repo::dig_store().asset_download_url("v0.6.0", "dig-store-0.6.0-linux-x64"),
            "https://github.com/DIG-Network/dig-store/releases/download/v0.6.0/dig-store-0.6.0-linux-x64"
        );
    }

    #[test]
    fn binary_url_composes_tag_and_target_asset() {
        assert_eq!(
            Repo::dig_store().binary_url("v0.6.0", "0.6.0", &lin()),
            "https://github.com/DIG-Network/dig-store/releases/download/v0.6.0/dig-store-0.6.0-linux-x64"
        );
        assert_eq!(
            Repo::dig_store().binary_url("v0.6.0", "0.6.0", &win()),
            "https://github.com/DIG-Network/dig-store/releases/download/v0.6.0/dig-store-0.6.0-windows-x64.exe"
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
