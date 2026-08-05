//! Provision the privileged TLS root so `dig-node` serves HTTPS on `https://dig.local`
//! instead of plaintext (#623 core, folded into #858).
//!
//! `dig-node` resolves its TLS material from [`dig_cert::TlsPaths::machine()`] and REFUSES to
//! serve HTTPS unless the root passes its own `security::dir_is_privileged` gate — every path
//! component owned by a privileged principal (SYSTEM / Administrators / TrustedInstaller on
//! Windows; uid 0 on unix) and not group/world-writable, non-reparse/non-symlink. Until the root
//! exists under that owner, the node serves plaintext only. This module is what creates it, so the
//! node can turn HTTPS on:
//!
//!   * Windows `%ProgramData%\DIG\tls` — `C:\ProgramData` already qualifies (TrustedInstaller);
//!     this owns + locks the `DIG` and `tls` levels to `{SYSTEM:F, Administrators:F}`, exactly the
//!     hardened, fail-closed, read-back-verified pattern [`crate::daemon_dir`] proved for the
//!     control-token dir (#501/#715). No interactive-user ACE: the node service reads the material
//!     as SYSTEM/Administrator, so the CA private key is never exposed to a normal account.
//!   * Linux + macOS `/etc/dig/tls` — created by root under root-owned `/etc`, `tls` mode `0700`,
//!     `/etc/dig` `0755`, symlink-rejected, fail-closed on any chmod failure.
//!
//! Inside the root it mints a per-machine, name-constrained CA + a 90-day leaf via [`dig_cert`]
//! (never re-implemented here), writes `ca.{key,crt}` + `leaf.{key,crt}` with owner-only key modes,
//! and installs `ca.crt` as an OS trust anchor (Windows `certutil -addstore Root`, macOS
//! `security add-trusted-cert`, Linux `update-ca-certificates` with a `update-ca-trust` fallback)
//! so a browser on the machine trusts `https://dig.local`. Every installed anchor is recorded in a
//! trust-manifest ledger at [`dig_cert::TlsPaths::trust_manifest`] so [`crate::uninstall`] can
//! revert exactly the DIG-owned entries and nothing else.
//!
//! ## Idempotent + fail-closed
//!
//! A run that finds a valid CA + leaf already on disk SKIPS the mint — never clobbering a working
//! CA (which would orphan the trust anchor already installed against it). A root that cannot be
//! created + hardened yields `created: false`, which [`crate::evaluate_readiness`] folds into a
//! NOT-ready verdict rather than letting the node fall back to plaintext silently.
//!
//! Layering mirrors `daemon_dir`: the argv builders, the PEM→DER + SHA-1 thumbprint, the manifest
//! round-trip, and the skip-mint decision are PURE and unit-tested cross-platform; the create +
//! mint + trust-store calls are the thin per-OS I/O layer.

// `Command::new` is denied crate-wide (`clippy.toml`, #1748) so an unguarded spawn of an INSTALLED
// binary cannot compile. Every spawn here is a trusted OS trust-store tool resolved absolutely on
// Windows ([`crate::proc::system_tool`]) or a fixed unix system utility, mirroring `daemon_dir`.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::proc::HideConsole;
use crate::target::Os;

/// The hostname the local CA + leaf certify — the canonical local-node name every client resolves
/// (`https://dig.local`). Byte-identical to what dig-node expects (SYSTEM.md TLS-root contract).
pub const TLS_HOSTNAME: &str = "dig.local";

/// The macOS system keychain the CA trust anchor is added to / deleted from.
pub const MACOS_SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// The Debian/Ubuntu trust-anchor drop path consumed by `update-ca-certificates`.
pub const LINUX_ANCHOR_PATH_DEB: &str = "/usr/local/share/ca-certificates/dig-local-ca.crt";

/// The RHEL/Fedora trust-anchor drop path consumed by `update-ca-trust` (the fallback distro).
pub const LINUX_ANCHOR_PATH_RHEL: &str = "/etc/pki/ca-trust/source/anchors/dig-local-ca.crt";

/// The mode of the parent `/etc/dig` directory: a normal world-readable `0755` container (the
/// secret material lives one level down under the owner-only `0700` `tls` root).
#[cfg(unix)]
const PARENT_DIR_MODE: u32 = 0o755;

/// Stable per-OS trust-store identifiers recorded in the manifest, so uninstall knows which tool to
/// drive to revert each entry — never inferred from the ambient OS (an uninstall must revert an
/// entry a prior install recorded, on the same machine).
pub const STORE_WINDOWS_ROOT: &str = "windows-root";
pub const STORE_MACOS_SYSTEM_KEYCHAIN: &str = "macos-system-keychain";
pub const STORE_LINUX_TRUST_ANCHORS: &str = "linux-trust-anchors";

/// The result of provisioning the TLS root — never silent, folded into the install report and the
/// readiness verdict. Mirrors [`crate::daemon_dir::DaemonDirResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsRootResult {
    /// The resolved TLS root (`%ProgramData%\DIG\tls` / `/etc/dig/tls`).
    pub root: String,
    /// The root now exists AND is privileged-owned AND holds a `ca`+`leaf` pair — i.e. dig-node's
    /// own gate will pass and it can serve HTTPS. `false` makes the install NOT ready.
    pub created: bool,
    /// A fresh CA + leaf were minted this run (`false` = a valid pair already existed and was kept).
    pub ca_minted: bool,
    /// `ca.crt` was installed into the OS trust store (browsers on the machine trust `dig.local`).
    /// Reported but NOT a readiness gate: the node serves HTTPS regardless; the anchor only makes
    /// local clients trust it, and a headless host may lack the trust tool.
    pub trust_installed: bool,
    /// Human-readable detail — never silent.
    pub note: String,
}

impl TlsRootResult {
    fn failed(root: &Path, note: impl Into<String>) -> Self {
        Self {
            root: root.to_string_lossy().into_owned(),
            created: false,
            ca_minted: false,
            trust_installed: false,
            note: note.into(),
        }
    }
}

/// One installed trust-store anchor, recorded so uninstall can revert exactly it — the DIG-owned
/// scope, never wider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEntry {
    /// Which OS trust store the anchor lives in (one of the `STORE_*` ids).
    pub store: String,
    /// The CA certificate's SHA-1 thumbprint (uppercase hex, no separators) — the identity
    /// `certutil -delstore Root <fp>` and `security delete-certificate -Z <fp>` both accept.
    pub fingerprint: String,
    /// The on-disk anchor file to remove on Linux (`None` on Windows/macOS, where the store is a
    /// database keyed by thumbprint, not a file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// The trust-manifest ledger written at [`dig_cert::TlsPaths::trust_manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrustManifest {
    /// Every trust anchor this install placed.
    pub entries: Vec<TrustEntry>,
}

impl TrustManifest {
    /// Serialize to the on-disk JSON form (pretty, trailing newline) — the exact bytes written to
    /// the ledger and parsed back by uninstall.
    pub fn to_json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string());
        s.push('\n');
        s
    }

    /// Parse a ledger back. A malformed/empty ledger yields an empty manifest rather than an error:
    /// uninstall then simply has nothing recorded to revert (idempotent), never aborting teardown.
    pub fn from_json(text: &str) -> Self {
        serde_json::from_str(text).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Pure helpers — argv builders, PEM→DER, thumbprint, skip-mint (unit-tested
// cross-platform; the I/O layer below is the only OS-specific part).
// ---------------------------------------------------------------------------

/// `certutil -addstore -f Root <cert>` — add the CA to the machine Root store (idempotent; `-f`
/// overwrites a same-thumbprint entry rather than prompting). Pure argv.
pub fn certutil_addstore_args(cert_path: &str) -> Vec<String> {
    vec![
        "-addstore".to_string(),
        "-f".to_string(),
        "Root".to_string(),
        cert_path.to_string(),
    ]
}

/// `certutil -delstore Root <thumbprint>` — remove the CA from the machine Root store by its SHA-1
/// thumbprint (DIG-owned scope: the exact anchor this install placed). Pure argv.
pub fn certutil_delstore_args(fingerprint: &str) -> Vec<String> {
    vec![
        "-delstore".to_string(),
        "Root".to_string(),
        fingerprint.to_string(),
    ]
}

/// `security add-trusted-cert -d -r trustRoot -k <system-keychain> <cert>` — add the CA to the
/// macOS system keychain as a trusted root (`-d` = admin/system domain). Pure argv.
pub fn security_add_trusted_cert_args(cert_path: &str) -> Vec<String> {
    vec![
        "add-trusted-cert".to_string(),
        "-d".to_string(),
        "-r".to_string(),
        "trustRoot".to_string(),
        "-k".to_string(),
        MACOS_SYSTEM_KEYCHAIN.to_string(),
        cert_path.to_string(),
    ]
}

/// `security delete-certificate -Z <thumbprint> <system-keychain>` — remove the CA from the macOS
/// system keychain by its SHA-1 hash (`-Z`). Pure argv.
pub fn security_delete_certificate_args(fingerprint: &str) -> Vec<String> {
    vec![
        "delete-certificate".to_string(),
        "-Z".to_string(),
        fingerprint.to_string(),
        MACOS_SYSTEM_KEYCHAIN.to_string(),
    ]
}

/// `update-ca-certificates [--fresh]` — refresh the Debian/Ubuntu trust bundle after dropping /
/// removing the anchor file. `--fresh` (used on uninstall) rebuilds the bundle from scratch so a
/// just-removed anchor is dropped. Pure argv.
pub fn update_ca_certificates_args(fresh: bool) -> Vec<String> {
    if fresh {
        vec!["--fresh".to_string()]
    } else {
        Vec::new()
    }
}

/// The RHEL/Fedora fallback: `update-ca-trust extract` rebuilds the consolidated trust store from
/// the anchors in `/etc/pki/ca-trust/source/anchors`. Pure argv.
pub fn update_ca_trust_args() -> Vec<String> {
    vec!["extract".to_string()]
}

/// Should the mint be SKIPPED because a valid CA + leaf already exist (idempotent reinstall)?
///
/// TRUE only when all four material files are present AND the on-disk CA parses (`ca_parses`). A
/// partial set (a leftover `ca.crt` with no key, a `ca` with no `leaf`) or an unparseable CA is
/// re-minted, so a half-provisioned root self-heals. Keeping a working CA is the safe default: it
/// still backs the trust anchor a prior install placed, so clobbering it would orphan that anchor.
/// Pure.
pub fn should_skip_mint(
    ca_cert_present: bool,
    ca_key_present: bool,
    leaf_cert_present: bool,
    leaf_key_present: bool,
    ca_parses: bool,
) -> bool {
    ca_cert_present && ca_key_present && leaf_cert_present && leaf_key_present && ca_parses
}

/// The SHA-1 thumbprint (uppercase hex, no separators) of a PEM certificate's DER body — the
/// identity both `certutil -delstore` and `security -Z` address a trust entry by. `None` when the
/// PEM carries no certificate block. Pure.
pub fn certificate_sha1_thumbprint(cert_pem: &str) -> Option<String> {
    use sha1::{Digest, Sha1};
    let der = pem_first_certificate_der(cert_pem)?;
    let digest = Sha1::digest(&der);
    Some(hex::encode_upper(digest))
}

/// Extract the DER bytes of the FIRST `CERTIFICATE` block in a PEM document (base64 between the
/// BEGIN/END markers, decoded). `None` when there is no certificate block or the base64 is
/// malformed. Pure — so the thumbprint is unit-tested against a known vector.
pub fn pem_first_certificate_der(pem: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN)? + BEGIN.len();
    let rest = &pem[start..];
    let end = rest.find(END)?;
    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64_decode(&body)
}

/// Decode standard-alphabet base64 (RFC 4648, with `=` padding) into bytes. Pure, dependency-free
/// (the crate carries no base64 crate), and unit-tested — used only to turn a PEM certificate body
/// into DER for the thumbprint. `None` on any invalid character or length.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        // Padding may appear only as the final one or two characters.
        if pad > 2 || (pad > 0 && chunk[3] != b'=') || (pad == 2 && chunk[2] != b'=') {
            return None;
        }
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let six = if c == b'=' { 0 } else { val(c)? };
            acc |= (six as u32) << (18 - 6 * i);
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Provisioning entrypoint.
// ---------------------------------------------------------------------------

/// Provision the machine TLS root so dig-node can serve HTTPS. Resolves
/// [`dig_cert::TlsPaths::machine()`] and delegates to [`provision_at`]. `dry_run` reports intent
/// only (no writes). Called from the install orchestration gated on `plan.with_dig_node`.
pub fn provision(dry_run: bool, log: &mut dyn FnMut(&str)) -> TlsRootResult {
    let paths = match dig_cert::TlsPaths::machine() {
        Ok(p) => p,
        Err(e) => {
            let note = format!("could not resolve the machine TLS root: {e}");
            log(&format!("    ! {note}"));
            return TlsRootResult::failed(Path::new("<unresolved>"), note);
        }
    };
    provision_at(
        &paths,
        current_os(),
        dry_run,
        OffsetDateTime::now_utc(),
        log,
    )
}

/// The provisioning body, parameterised on the resolved `paths` + `os` + issuance `now` so it is
/// testable against a tempdir root. Order: harden the root (fail closed) → mint-or-skip the CA/leaf
/// → install the trust anchor → write the ledger.
pub fn provision_at(
    paths: &dig_cert::TlsPaths,
    os: Os,
    dry_run: bool,
    now: OffsetDateTime,
    log: &mut dyn FnMut(&str),
) -> TlsRootResult {
    let root = paths.root.clone();
    let root_str = root.to_string_lossy().into_owned();

    if dry_run {
        log(&format!(
            "    (would provision the privileged TLS root {root_str}: mint a name-constrained CA + \
             leaf for {TLS_HOSTNAME}, lock it privileged-owned, and install the CA as a trusted root)"
        ));
        return TlsRootResult {
            root: root_str,
            created: false,
            ca_minted: false,
            trust_installed: false,
            note: "dry run".to_string(),
        };
    }

    // 1. Harden the root — fail CLOSED (no root ⇒ dig-node stays on plaintext, reported NOT ready).
    if let Err(e) = harden_root(os, &root) {
        let note = format!("could not create + harden the TLS root: {e}");
        log(&format!("    ! {root_str} — {note}"));
        return TlsRootResult::failed(&root, note);
    }

    // 2. Mint the CA + leaf, or keep a valid existing pair (idempotent).
    let ca_minted = match ensure_ca_and_leaf(paths, os, now) {
        Ok(minted) => minted,
        Err(e) => {
            let note = format!("could not write the CA/leaf material: {e}");
            log(&format!("    ! {root_str} — {note}"));
            return TlsRootResult::failed(&root, note);
        }
    };

    // 3. Install the CA as an OS trust anchor + record the ledger (non-fatal — see field doc).
    let (trust_installed, trust_note) = match install_trust_anchor(paths, os) {
        Ok((installed, note)) => (installed, note),
        Err(e) => (false, format!("trust anchor NOT installed: {e}")),
    };

    let note = format!(
        "TLS root ready ({}); {trust_note}",
        if ca_minted {
            "minted a fresh CA + leaf"
        } else {
            "kept the existing valid CA + leaf"
        }
    );
    log(&format!("    ✓ {root_str} — {note}"));
    TlsRootResult {
        root: root_str,
        created: true,
        ca_minted,
        trust_installed,
        note,
    }
}

/// This build's OS as a [`Os`], for the production [`provision`] path.
fn current_os() -> Os {
    #[cfg(target_os = "windows")]
    {
        Os::Windows
    }
    #[cfg(target_os = "macos")]
    {
        Os::MacOs
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Os::Linux
    }
}

// ---------------------------------------------------------------------------
// CA / leaf material (dig-cert owns the crypto — never re-implemented here).
// ---------------------------------------------------------------------------

/// Ensure `ca.{key,crt}` + `leaf.{key,crt}` exist under `paths`, minting a fresh pair unless a
/// valid one already exists ([`should_skip_mint`]). Returns whether a mint happened.
fn ensure_ca_and_leaf(
    paths: &dig_cert::TlsPaths,
    os: Os,
    now: OffsetDateTime,
) -> Result<bool, String> {
    let ca_valid = existing_ca_parses(paths);
    let skip = should_skip_mint(
        paths.ca_cert().exists(),
        paths.ca_key().exists(),
        paths.leaf_cert().exists(),
        paths.leaf_key().exists(),
        ca_valid,
    );
    if skip {
        return Ok(false);
    }

    let ca = dig_cert::generate_ca(TLS_HOSTNAME, now).map_err(|e| format!("generate CA: {e}"))?;
    // Key first, then cert: a reader that sees the cert can assume the key is already present.
    write_material(&paths.ca_key(), ca.key_pem.as_bytes(), os, true)?;
    write_material(&paths.ca_cert(), ca.cert_pem.as_bytes(), os, false)?;

    let parsed = dig_cert::ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem)
        .map_err(|e| format!("reload freshly minted CA: {e}"))?;
    let leaf = dig_cert::issue_leaf(&parsed, now).map_err(|e| format!("issue leaf: {e}"))?;
    write_material(&paths.leaf_key(), leaf.key_pem.as_bytes(), os, true)?;
    write_material(&paths.leaf_cert(), leaf.cert_pem.as_bytes(), os, false)?;
    Ok(true)
}

/// Does the CA material already on disk parse as a usable issuer? Fail-safe `false` on any read /
/// parse error, so a corrupt or partial pair is re-minted rather than trusted.
fn existing_ca_parses(paths: &dig_cert::TlsPaths) -> bool {
    let (Ok(cert), Ok(key)) = (
        std::fs::read_to_string(paths.ca_cert()),
        std::fs::read_to_string(paths.ca_key()),
    ) else {
        return false;
    };
    dig_cert::ParsedCa::from_pem(&cert, &key).is_ok()
}

/// Write one material file with the intended perms. On unix a key gets `0600`, a cert `0644`
/// ([`dig_cert::KEY_FILE_MODE`]/[`dig_cert::CERT_FILE_MODE`]); on Windows it inherits the root's
/// locked `{SYSTEM:F, Administrators:F}` DACL (no per-file ACL needed).
fn write_material(path: &Path, bytes: &[u8], _os: Os, is_key: bool) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_key {
            dig_cert::KEY_FILE_MODE
        } else {
            dig_cert::CERT_FILE_MODE
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {:o} {}: {e}", mode, path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = is_key;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Root hardening (per OS).
// ---------------------------------------------------------------------------

/// Create + harden the TLS root so dig-node's `dir_is_privileged` gate passes, fail-closed.
fn harden_root(os: Os, root: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _ = os;
        harden_root_windows(root)
    }
    #[cfg(unix)]
    {
        let _ = os;
        harden_root_unix(root)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (os, root);
        Err("no privileged-directory support on this OS".to_string())
    }
}

/// Unix: create `/etc/dig` (`0755`) + `/etc/dig/tls` (`0700`) under root-owned `/etc` (not
/// squattable, exactly [`crate::daemon_dir`]'s `/var/lib` model), reject a symlinked `tls`, and
/// fail closed if the tight `0700` mode cannot be set (a world-readable TLS root would expose the
/// CA private key).
#[cfg(unix)]
fn harden_root_unix(root: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let parent = root
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", root.display()))?;
    std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    // `/etc/dig` is a normal, world-readable directory (`0755`) — it holds no secret itself; the
    // owner-only `0700` restriction belongs to the `tls` leaf that holds the CA private key.
    let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(PARENT_DIR_MODE));

    // Reject a pre-existing symlink at the leaf BEFORE creating/writing through it — a symlinked
    // root would redirect the CA key write out of the root-owned tree.
    if let Ok(md) = std::fs::symlink_metadata(root) {
        if md.file_type().is_symlink() {
            return Err(format!(
                "{} is a symlink — refusing to write TLS material through a redirected path (fail closed)",
                root.display()
            ));
        }
    }
    std::fs::create_dir_all(root).map_err(|e| format!("create {}: {e}", root.display()))?;
    if std::fs::set_permissions(root, std::fs::Permissions::from_mode(dig_cert::DIR_MODE)).is_err()
    {
        // Fail closed: a TLS root we cannot restrict to owner-only must not be left holding a key.
        let _ = std::fs::remove_dir_all(root);
        return Err(format!(
            "could not set {:o} on {} (fail closed)",
            dig_cert::DIR_MODE,
            root.display()
        ));
    }
    Ok(())
}

/// Windows: own + lock `%ProgramData%\DIG` then `%ProgramData%\DIG\tls` NON-recursively to a
/// protected `{SYSTEM:F, Administrators:F}` DACL, read-back-verified — the exact fail-closed
/// pattern [`crate::daemon_dir::ensure_webview_data_dir_in`] proved (#715). `C:\ProgramData` already
/// qualifies (TrustedInstaller-owned), so only the two DIG-owned levels are hardened. No
/// interactive-user ACE: the node reads the CA key as SYSTEM/Administrator.
#[cfg(windows)]
fn harden_root_windows(root: &Path) -> Result<(), String> {
    // The two DIG-owned levels, shallowest first: `…\DIG`, `…\DIG\tls`.
    let tls = root.to_path_buf();
    let dig = tls
        .parent()
        .ok_or_else(|| format!("{} has no parent", tls.display()))?
        .to_path_buf();
    let levels = [dig, tls];

    let purge = |from: &Path| {
        let _ = std::fs::remove_dir_all(from);
    };

    // Reject a reparse point anywhere on the path BEFORE writing through it.
    if any_component_is_reparse_point(&levels[1]) {
        return Err(format!(
            "{} (or an ancestor) is a reparse point — refusing (fail closed)",
            levels[1].display()
        ));
    }

    // Purge the shallowest DIG-owned level that pre-exists with an untrusted owner (a squat), so a
    // single removal clears the whole subtree, then recreate + lock each level.
    for level in &levels {
        if level.exists() {
            let trusted = matches!(
                crate::daemon_dir::dir_owner_sid(level).as_deref(),
                Some("S-1-5-18") | Some("S-1-5-32-544")
            );
            if !trusted {
                let _ = crate::daemon_dir::run_icacls(&crate::daemon_dir::setowner_system_args(
                    &level.to_string_lossy(),
                ));
                std::fs::remove_dir_all(level).map_err(|e| {
                    format!(
                        "{} pre-existed with an untrusted owner and could not be purged ({e}); fail closed",
                        level.display()
                    )
                })?;
                break;
            }
        }
    }

    for level in &levels {
        if let Err(e) = create_dir_if_absent(level) {
            purge(&levels[0]);
            return Err(format!("create {} ({e}); fail closed", level.display()));
        }
        if let Err(e) = lock_and_verify_here(level) {
            purge(&levels[0]);
            return Err(format!(
                "ACL lockdown/verify FAILED on {} ({e}); removed the DIG subtree (fail closed)",
                level.display()
            ));
        }
    }

    if any_component_is_reparse_point(&levels[1]) {
        purge(&levels[0]);
        return Err(format!(
            "{} became a reparse point during hardening; fail closed",
            levels[1].display()
        ));
    }
    Ok(())
}

/// Own→SYSTEM + purge own explicit ACEs + protected `{SYSTEM:F, Administrators:F}` DACL +
/// read-back verify, all NON-recursively — reusing [`crate::daemon_dir`]'s proven, tested argv +
/// verification (`webview_lockdown_grant_args`/`parse_webview_acl_verify`).
#[cfg(windows)]
fn lock_and_verify_here(dir: &Path) -> Result<(), String> {
    use crate::daemon_dir::{
        acl_verify_ps_command, parse_webview_acl_verify, reset_dacl_args_here, run_icacls,
        setowner_system_args_here, webview_lockdown_grant_args,
    };
    let s = dir.to_string_lossy().into_owned();
    run_icacls(&setowner_system_args_here(&s))
        .and_then(|_| run_icacls(&reset_dacl_args_here(&s)))
        .and_then(|_| run_icacls(&webview_lockdown_grant_args(&s)))?;
    let out = crate::proc::powershell(&acl_verify_ps_command(&s))
        .output()
        .map_err(|e| format!("Get-Acl read-back failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Get-Acl read-back exited non-zero: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_webview_acl_verify(&String::from_utf8_lossy(&out.stdout))
}

/// `create_dir` (NON-recursive) treating already-exists as success — each level is created only
/// after its parent is locked, so a planted intermediate junction is never followed.
#[cfg(windows)]
fn create_dir_if_absent(dir: &Path) -> std::io::Result<()> {
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Is ANY existing component of `path` a reparse point (junction/symlink/mount)? Walks every
/// ancestor so a junction planted on `…\DIG` is caught, not just the leaf.
#[cfg(windows)]
fn any_component_is_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let mut cur = std::path::PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        if std::fs::symlink_metadata(&cur)
            .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Trust-store install + the ledger.
// ---------------------------------------------------------------------------

/// Install `ca.crt` as an OS trust anchor and write the manifest ledger. Returns
/// `(installed, note)`. A failure to install the anchor is returned as `Err` and treated as
/// non-fatal by the caller (the node still serves HTTPS; only client trust is affected).
fn install_trust_anchor(paths: &dig_cert::TlsPaths, os: Os) -> Result<(bool, String), String> {
    let ca_cert = paths.ca_cert();
    let cert_pem = std::fs::read_to_string(&ca_cert)
        .map_err(|e| format!("read {}: {e}", ca_cert.display()))?;
    let fingerprint = certificate_sha1_thumbprint(&cert_pem)
        .ok_or_else(|| "ca.crt has no certificate block".to_string())?;
    let ca_cert_str = ca_cert.to_string_lossy().into_owned();

    let (entry, note) = match os {
        Os::Windows => {
            run_trust_tool(
                "certutil",
                &certutil_addstore_args(&ca_cert_str),
                windows_trust_uses_certutil(),
            )?;
            (
                TrustEntry {
                    store: STORE_WINDOWS_ROOT.to_string(),
                    fingerprint: fingerprint.clone(),
                    path: None,
                },
                "installed the CA into the machine Root store".to_string(),
            )
        }
        Os::MacOs => {
            run_trust_tool(
                "security",
                &security_add_trusted_cert_args(&ca_cert_str),
                true,
            )?;
            (
                TrustEntry {
                    store: STORE_MACOS_SYSTEM_KEYCHAIN.to_string(),
                    fingerprint: fingerprint.clone(),
                    path: None,
                },
                "installed the CA into the system keychain".to_string(),
            )
        }
        Os::Linux => install_trust_anchor_linux(&ca_cert, fingerprint.clone())?,
    };

    let manifest = TrustManifest {
        entries: vec![entry],
    };
    let manifest_path = paths.trust_manifest();
    std::fs::write(&manifest_path, manifest.to_json())
        .map_err(|e| format!("write trust manifest {}: {e}", manifest_path.display()))?;
    Ok((true, note))
}

/// Linux: drop `ca.crt` into the distro trust-anchor dir and refresh the bundle. Prefers the
/// Debian/Ubuntu `update-ca-certificates`; falls back to the RHEL/Fedora
/// anchors + `update-ca-trust` when that tool is absent.
#[cfg(unix)]
fn install_trust_anchor_linux(
    ca_cert: &Path,
    fingerprint: String,
) -> Result<(TrustEntry, String), String> {
    // Debian/Ubuntu path first.
    if command_exists("update-ca-certificates") {
        let anchor = Path::new(LINUX_ANCHOR_PATH_DEB);
        copy_anchor(ca_cert, anchor)?;
        run_trust_tool(
            "update-ca-certificates",
            &update_ca_certificates_args(false),
            true,
        )?;
        return Ok((
            TrustEntry {
                store: STORE_LINUX_TRUST_ANCHORS.to_string(),
                fingerprint,
                path: Some(anchor.to_string_lossy().into_owned()),
            },
            "installed the CA into the system trust anchors (update-ca-certificates)".to_string(),
        ));
    }
    // RHEL/Fedora fallback.
    if command_exists("update-ca-trust") {
        let anchor = Path::new(LINUX_ANCHOR_PATH_RHEL);
        copy_anchor(ca_cert, anchor)?;
        run_trust_tool("update-ca-trust", &update_ca_trust_args(), true)?;
        return Ok((
            TrustEntry {
                store: STORE_LINUX_TRUST_ANCHORS.to_string(),
                fingerprint,
                path: Some(anchor.to_string_lossy().into_owned()),
            },
            "installed the CA into the system trust anchors (update-ca-trust)".to_string(),
        ));
    }
    Err("no system trust-anchor tool (update-ca-certificates / update-ca-trust) found".to_string())
}

#[cfg(not(unix))]
fn install_trust_anchor_linux(
    _ca_cert: &Path,
    _fingerprint: String,
) -> Result<(TrustEntry, String), String> {
    Err("linux trust install is unix-only".to_string())
}

/// Copy the CA certificate to a distro anchor path, creating the anchor dir if absent.
#[cfg(unix)]
fn copy_anchor(ca_cert: &Path, anchor: &Path) -> Result<(), String> {
    if let Some(dir) = anchor.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    std::fs::copy(ca_cert, anchor)
        .map(|_| ())
        .map_err(|e| format!("copy CA to {}: {e}", anchor.display()))
}

/// Is a bare command resolvable on `PATH` (a `which`-style probe)? Used only to pick between the
/// Debian and RHEL trust tools. Unix-only.
#[cfg(unix)]
fn command_exists(name: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .hide_console()
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether Windows trust install goes through `certutil` — always true on Windows; a distinct
/// helper so the (rare) build without it stays a no-op-friendly seam.
#[cfg(windows)]
fn windows_trust_uses_certutil() -> bool {
    true
}
#[cfg(not(windows))]
fn windows_trust_uses_certutil() -> bool {
    false
}

/// Spawn one OS trust-store tool with `args` through the crate's guarded, console-hidden wrapper
/// ([`crate::proc`]). On Windows the tool is resolved to its absolute System32 path
/// ([`crate::proc::system_tool`], #657); on unix it is the bare system utility. `Ok(())` iff the
/// tool exits 0.
fn run_trust_tool(tool: &str, args: &[String], enabled: bool) -> Result<(), String> {
    if !enabled {
        return Err(format!("{tool} is not available on this platform"));
    }
    let program = crate::proc::system_tool(tool);
    let out = std::process::Command::new(&program)
        .args(args)
        .hide_console()
        .output()
        .map_err(|e| format!("{tool} failed to run: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{tool} exited with {}: {}",
            out.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string()),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

// ---------------------------------------------------------------------------
// Uninstall: revert the trust anchors recorded in the ledger, then remove the root.
// ---------------------------------------------------------------------------

/// Revert every trust anchor recorded in the manifest at [`dig_cert::TlsPaths::trust_manifest`],
/// then remove the TLS root. Strictly DIG-owned scope (only the recorded entries) and idempotent
/// (an already-absent anchor / root is success). Returns `(ok, note)`.
pub fn remove_trust_and_root(dry_run: bool) -> (bool, String) {
    let paths = match dig_cert::TlsPaths::machine() {
        Ok(p) => p,
        Err(e) => return (false, format!("could not resolve the TLS root: {e}")),
    };
    if dry_run {
        return (
            true,
            format!(
                "would revert the recorded DIG trust anchors and remove {}",
                paths.root.display()
            ),
        );
    }
    remove_trust_and_root_at(&paths, current_os())
}

/// The teardown body, parameterised for testing. Reads the ledger (absent ⇒ nothing recorded to
/// revert), reverts each entry, then removes the root.
pub fn remove_trust_and_root_at(paths: &dig_cert::TlsPaths, os: Os) -> (bool, String) {
    let mut ok = true;
    let mut notes = Vec::new();

    let manifest = std::fs::read_to_string(paths.trust_manifest())
        .map(|t| TrustManifest::from_json(&t))
        .unwrap_or_default();
    if manifest.entries.is_empty() {
        notes.push("no trust manifest recorded — nothing to revert".to_string());
    }
    for entry in &manifest.entries {
        match revert_trust_entry(entry, os) {
            Ok(n) => notes.push(n),
            Err(e) => {
                ok = false;
                notes.push(format!("trust revert failed: {e}"));
            }
        }
    }

    match std::fs::remove_dir_all(&paths.root) {
        Ok(()) => notes.push(format!("removed {}", paths.root.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            notes.push(format!("{}: already absent", paths.root.display()))
        }
        Err(e) => {
            ok = false;
            notes.push(format!("could not remove {}: {e}", paths.root.display()));
        }
    }
    (ok, notes.join("; "))
}

/// Revert ONE recorded trust anchor via the tool matching its store id. Idempotent — a
/// delstore/delete of an already-absent entry is success (the tools exit non-zero for "not found",
/// which is the desired end state), and a Linux anchor file already gone is success.
fn revert_trust_entry(entry: &TrustEntry, os: Os) -> Result<String, String> {
    match entry.store.as_str() {
        STORE_WINDOWS_ROOT => {
            let _ = run_trust_tool(
                "certutil",
                &certutil_delstore_args(&entry.fingerprint),
                windows_trust_uses_certutil(),
            );
            Ok(format!(
                "removed the CA {} from the machine Root store",
                entry.fingerprint
            ))
        }
        STORE_MACOS_SYSTEM_KEYCHAIN => {
            let _ = run_trust_tool(
                "security",
                &security_delete_certificate_args(&entry.fingerprint),
                matches!(os, Os::MacOs),
            );
            Ok(format!(
                "removed the CA {} from the system keychain",
                entry.fingerprint
            ))
        }
        STORE_LINUX_TRUST_ANCHORS => revert_linux_anchor(entry),
        other => Err(format!("unknown trust store id '{other}'")),
    }
}

/// Linux: remove the recorded anchor file (already-absent = success), then refresh the bundle.
#[cfg(unix)]
fn revert_linux_anchor(entry: &TrustEntry) -> Result<String, String> {
    if let Some(path) = &entry.path {
        match std::fs::remove_file(path) {
            Ok(()) | Err(_) => {}
        }
    }
    if command_exists("update-ca-certificates") {
        let _ = run_trust_tool(
            "update-ca-certificates",
            &update_ca_certificates_args(true),
            true,
        );
    } else if command_exists("update-ca-trust") {
        let _ = run_trust_tool("update-ca-trust", &update_ca_trust_args(), true);
    }
    Ok(format!(
        "removed the CA trust anchor {}",
        entry.path.as_deref().unwrap_or("(no path)")
    ))
}

#[cfg(not(unix))]
fn revert_linux_anchor(_entry: &TrustEntry) -> Result<String, String> {
    Ok("linux anchor revert is a no-op off unix".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- argv builders --------------------------------------------------------

    #[test]
    fn certutil_addstore_targets_the_root_store_and_forces_overwrite() {
        let a = certutil_addstore_args(r"C:\ProgramData\DIG\tls\ca.crt");
        assert_eq!(
            a,
            vec!["-addstore", "-f", "Root", r"C:\ProgramData\DIG\tls\ca.crt"]
        );
    }

    #[test]
    fn certutil_delstore_addresses_the_root_store_by_thumbprint() {
        let a = certutil_delstore_args("ABCD1234");
        assert_eq!(a, vec!["-delstore", "Root", "ABCD1234"]);
    }

    #[test]
    fn security_add_trusted_cert_targets_the_system_keychain_as_trust_root() {
        let a = security_add_trusted_cert_args("/etc/dig/tls/ca.crt");
        assert_eq!(
            a,
            vec![
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                MACOS_SYSTEM_KEYCHAIN,
                "/etc/dig/tls/ca.crt",
            ]
        );
    }

    #[test]
    fn security_delete_certificate_addresses_the_keychain_by_sha1_hash() {
        let a = security_delete_certificate_args("DEADBEEF");
        assert_eq!(
            a,
            vec![
                "delete-certificate",
                "-Z",
                "DEADBEEF",
                MACOS_SYSTEM_KEYCHAIN
            ]
        );
    }

    #[test]
    fn update_ca_certificates_uses_fresh_only_on_uninstall() {
        assert!(update_ca_certificates_args(false).is_empty());
        assert_eq!(update_ca_certificates_args(true), vec!["--fresh"]);
    }

    // -- skip-mint decision ---------------------------------------------------

    #[test]
    fn skip_mint_only_when_a_complete_valid_pair_exists() {
        // The whole point of idempotency: a complete + parseable pair is kept.
        assert!(should_skip_mint(true, true, true, true, true));
    }

    #[test]
    fn a_partial_or_unparseable_pair_is_reminted() {
        // Every distinguishing case: each missing file, and a present-but-unparseable CA, must
        // re-mint — a single all-true control above proves the skip path is reachable, so these
        // pin that the guard is load-bearing rather than always-false.
        assert!(!should_skip_mint(false, true, true, true, true)); // no ca.crt
        assert!(!should_skip_mint(true, false, true, true, true)); // no ca.key
        assert!(!should_skip_mint(true, true, false, true, true)); // no leaf.crt
        assert!(!should_skip_mint(true, true, true, false, true)); // no leaf.key
        assert!(!should_skip_mint(true, true, true, true, false)); // CA does not parse
    }

    // -- manifest round-trip --------------------------------------------------

    #[test]
    fn trust_manifest_round_trips_through_json() {
        let m = TrustManifest {
            entries: vec![
                TrustEntry {
                    store: STORE_WINDOWS_ROOT.to_string(),
                    fingerprint: "AABBCC".to_string(),
                    path: None,
                },
                TrustEntry {
                    store: STORE_LINUX_TRUST_ANCHORS.to_string(),
                    fingerprint: "DDEEFF".to_string(),
                    path: Some(LINUX_ANCHOR_PATH_DEB.to_string()),
                },
            ],
        };
        let parsed = TrustManifest::from_json(&m.to_json());
        assert_eq!(parsed, m);
    }

    #[test]
    fn a_malformed_manifest_parses_to_empty_so_uninstall_never_aborts() {
        assert_eq!(
            TrustManifest::from_json("not json"),
            TrustManifest::default()
        );
        assert!(TrustManifest::from_json("").entries.is_empty());
    }

    // -- base64 / DER / thumbprint --------------------------------------------

    #[test]
    fn base64_decodes_known_vectors_including_padding() {
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
        assert!(base64_decode("A").is_none()); // not a multiple of 4
        assert!(base64_decode("****").is_none()); // invalid alphabet
    }

    #[test]
    fn thumbprint_is_the_sha1_of_the_der_not_the_pem_text() {
        // DER = base64-decode of the PEM body; SHA-1 over the DER, uppercase hex. A single-byte
        // DER (`M`) has a known SHA-1, proving the pipeline decodes then hashes rather than hashing
        // the PEM text or the base64.
        let pem = "-----BEGIN CERTIFICATE-----\nTQ==\n-----END CERTIFICATE-----\n";
        let fp = certificate_sha1_thumbprint(pem).unwrap();
        // SHA-1(0x4D "M") = c63ae6dd… (verified independently: `printf M | sha1sum`), uppercased.
        assert_eq!(fp, "C63AE6DD4FC9F9DDA66970E827D13F7C73FE841C");
        assert_eq!(fp, fp.to_uppercase(), "thumbprint must be uppercase hex");
    }

    #[test]
    fn pem_without_a_certificate_block_has_no_thumbprint() {
        assert!(certificate_sha1_thumbprint("no pem here").is_none());
    }

    // -- CA + leaf material + idempotency (real dig-cert, tempdir root) --------

    fn fixed_now() -> OffsetDateTime {
        // A pinned issuance instant — never wall-clock — so the fixture is deterministic and the
        // CA/leaf validity window is explicit rather than "whenever the test ran".
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn provision_at_mints_material_hardens_the_root_and_records_the_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("dig").join("tls");
        let paths = dig_cert::TlsPaths::under(&root);
        let mut logs = Vec::new();
        // Linux path with no trust tool present in the sandbox → trust install is a non-fatal miss,
        // but the ROOT + material (the readiness-bearing part) must still be created.
        let r = provision_at(&paths, Os::Linux, false, fixed_now(), &mut |m| {
            logs.push(m.to_string())
        });
        assert!(
            r.created,
            "the TLS root + material must be provisioned: {r:?}"
        );
        assert!(r.ca_minted, "a fresh CA must be minted on an empty root");
        assert!(paths.ca_key().exists() && paths.ca_cert().exists());
        assert!(paths.leaf_key().exists() && paths.leaf_cert().exists());
        // The minted CA must reload as a usable issuer (proves we wrote real dig-cert material).
        let cert = std::fs::read_to_string(paths.ca_cert()).unwrap();
        let key = std::fs::read_to_string(paths.ca_key()).unwrap();
        assert!(dig_cert::ParsedCa::from_pem(&cert, &key).is_ok());

        // Key files are owner-only (0600); the CA private key must never be group/world readable.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(paths.ca_key())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, dig_cert::KEY_FILE_MODE, "ca.key must be 0600");
        let dir_mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, dig_cert::DIR_MODE, "the TLS root must be 0700");
    }

    #[cfg(unix)]
    #[test]
    fn a_second_provision_keeps_the_existing_ca_and_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("dig").join("tls");
        let paths = dig_cert::TlsPaths::under(&root);
        let mut sink = |_: &str| {};
        let first = provision_at(&paths, Os::Linux, false, fixed_now(), &mut sink);
        assert!(first.ca_minted);
        let ca_before = std::fs::read(paths.ca_cert()).unwrap();

        // Second run over the same root: the valid pair is kept, never clobbered (which would
        // orphan the installed trust anchor). This is a placement/decision property — a second run
        // that re-minted would produce DIFFERENT bytes, so comparing the bytes is load-bearing.
        let second = provision_at(&paths, Os::Linux, false, fixed_now(), &mut sink);
        assert!(second.created);
        assert!(
            !second.ca_minted,
            "a valid existing CA must be kept, not re-minted"
        );
        assert_eq!(std::fs::read(paths.ca_cert()).unwrap(), ca_before);
    }

    #[test]
    fn dry_run_provisions_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("dig").join("tls");
        let paths = dig_cert::TlsPaths::under(&root);
        let r = provision_at(&paths, Os::Linux, true, fixed_now(), &mut |_| {});
        assert!(!r.created && !r.ca_minted && !r.trust_installed);
        assert!(!root.exists(), "dry-run must not create the root");
    }
}
