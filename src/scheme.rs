//! OS URL-scheme handler registration for `chia://` (and best-effort `urn:`)
//! that ENFORCES routing a clicked link through the local DIG node (#389).
//!
//! Clicking a `chia://<store>/<path>` link anywhere on the OS invokes the
//! handler this installer registers → the handler resolves the target against
//! the local dig-node (the §5.3 ladder: `dig.local` → `localhost` →
//! `rpc.dig.net`) and opens the resolved DIG content in the browser. The
//! handler is THIS installer's own persisted binary run with the hidden
//! `handle-url <uri>` subcommand (the same self-host pattern the dig-dns
//! Windows service uses) — so no separate shim binary is shipped.
//!
//! Per-OS registration (all per-user — NO elevation needed, unlike service
//! install):
//!   * **Windows:** `HKCU\Software\Classes\chia` (`URL Protocol`) →
//!     `"<bin>" handle-url "%1"`.
//!   * **Linux:** a `~/.local/share/applications/*.desktop` with
//!     `MimeType=x-scheme-handler/chia;` + `xdg-mime default`.
//!   * **macOS:** LaunchServices scheme binding needs a real `.app`; a
//!     CLI-only install cannot own the scheme, so registration is a documented
//!     best-effort no-op (reported honestly, never a silent fake success).
//!
//! `urn:` is registered only where the OS permits a generic `urn:` handler
//! (Windows: yes, HKCU; Linux: `x-scheme-handler/urn`); the installer's CLAIM
//! is scoped to `urn:dig:chia:` semantics even where the OS handler is the
//! broad `urn:`.
//!
//! Layering: the URI parse + local-URL build + per-OS registration-content
//! builders are pure and unit-tested; the registry/file writes + browser-open
//! are the thin I/O layer.

use std::path::Path;

/// The schemes this installer registers. `chia` is the primary; `urn` is
/// best-effort (registered where the OS allows a generic handler).
pub const PRIMARY_SCHEME: &str = "chia";
pub const URN_SCHEME: &str = "urn";

/// A parsed DIG scheme target: the store id + the in-store path (may be empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeTarget {
    /// The store id / host portion (e.g. the store hash or a named store).
    pub store: String,
    /// The path within the store, WITHOUT a leading slash (may be empty).
    pub path: String,
}

/// Parse a `chia://<store>/<path>` or `urn:dig:chia:<store>[/<path>]` URI into
/// its store + path. Pure. Returns `None` for anything that is not a DIG
/// scheme target this installer routes.
///
/// Accepted forms:
/// * `chia://STORE` / `chia://STORE/a/b` (host = store, rest = path)
/// * `urn:dig:chia:STORE` / `urn:dig:chia:STORE/a/b`
pub fn parse_target(uri: &str) -> Option<SchemeTarget> {
    let uri = uri.trim();
    if let Some(rest) = uri.strip_prefix("chia://") {
        let rest = rest.trim_end_matches('/');
        if rest.is_empty() {
            return None;
        }
        let (store, path) = match rest.split_once('/') {
            Some((s, p)) => (s, p),
            None => (rest, ""),
        };
        if store.is_empty() {
            return None;
        }
        return Some(SchemeTarget {
            store: store.to_string(),
            path: path.trim_start_matches('/').to_string(),
        });
    }
    // urn:dig:chia:<store>[/<path>] — case-insensitive scheme + NID prefix.
    let lower = uri.to_ascii_lowercase();
    if let Some(idx) = lower.find("urn:dig:chia:") {
        let after = &uri[idx + "urn:dig:chia:".len()..];
        let after = after.trim().trim_end_matches('/');
        if after.is_empty() {
            return None;
        }
        let (store, path) = match after.split_once('/') {
            Some((s, p)) => (s, p),
            None => (after, ""),
        };
        if store.is_empty() {
            return None;
        }
        return Some(SchemeTarget {
            store: store.to_string(),
            path: path.trim_start_matches('/').to_string(),
        });
    }
    None
}

/// The three §5.3 base endpoints a clicked link is routed to, in order. The
/// handler tries each and opens the first reachable one; `dig.local` is
/// **port-free** (the installer's hosts entry maps it to the node's loopback
/// so it serves on port 80), matching the "reach it port-free" contract.
pub const LADDER_BASES: &[&str] = &[
    "http://dig.local",
    "http://localhost:9778",
    "https://rpc.dig.net",
];

/// Build the local-node serve URL for a target against a chosen base
/// (`base` has no trailing slash). The node serves a store root-scoped at
/// `/s/<store>/<path>` (§289 dig-node local web server). Pure.
pub fn serve_url(base: &str, target: &SchemeTarget) -> String {
    let base = base.trim_end_matches('/');
    if target.path.is_empty() {
        format!("{base}/s/{}/", target.store)
    } else {
        format!("{base}/s/{}/{}", target.store, target.path)
    }
}

/// The argv (after the program path) the OS handler invokes on this installer's
/// own binary to route a clicked URI: `handle-url <uri>`. Pure — the hidden
/// subcommand token is a stable contract with [`matches_handle_url_invocation`].
pub const HANDLE_URL_SUBCOMMAND: &str = "handle-url";

/// If `argv` (the full process args, argv[0] included) is the hidden
/// `handle-url <uri>` invocation, return the URI. Sniffed before clap (like the
/// dig-dns service host) since it carries no public `--help` surface.
pub fn matches_handle_url_invocation(argv: &[String]) -> Option<String> {
    // argv[0] = program, argv[1] = "handle-url", argv[2] = the URI.
    if argv.len() >= 3 && argv[1] == HANDLE_URL_SUBCOMMAND {
        return Some(argv[2].clone());
    }
    None
}

/// The Windows handler command string written to
/// `HKCU\Software\Classes\<scheme>\shell\open\command`: the installer binary +
/// the hidden subcommand + the `%1` URI placeholder. Pure.
pub fn windows_handler_command(bin: &Path) -> String {
    format!("\"{}\" {HANDLE_URL_SUBCOMMAND} \"%1\"", bin.display())
}

/// The `.desktop` file body registering this installer's binary as the handler
/// for the given scheme(s) on Linux. Pure (unit-tested); the file write +
/// `xdg-mime`/`update-desktop-database` calls are the I/O layer.
pub fn linux_desktop_contents(bin: &Path, schemes: &[&str]) -> String {
    let mime: String = schemes
        .iter()
        .map(|s| format!("x-scheme-handler/{s};"))
        .collect();
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=DIG Network Link Handler\n\
         Comment=Open chia:// links through the local DIG node\n\
         Exec=\"{}\" {HANDLE_URL_SUBCOMMAND} %u\n\
         Terminal=false\n\
         NoDisplay=true\n\
         MimeType={mime}\n",
        bin.display()
    )
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// The outcome of registering (or, on dry-run, planning to register) the URL
/// scheme handler. Never silent — `note` always explains the state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SchemeResult {
    /// The handler was registered (or, on dry-run, would be).
    pub registered: bool,
    /// The schemes actually registered (e.g. `["chia", "urn"]`).
    pub schemes: Vec<String>,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// Register the `chia://` (+ best-effort `urn:`) URL-scheme handler pointing at
/// `bin` (this installer's persisted binary) run as `handle-url %1`. Per-user,
/// no elevation. `dry_run` reports the intent without touching the OS.
pub fn register(bin: &Path, with_urn: bool, dry_run: bool) -> SchemeResult {
    let mut schemes = vec![PRIMARY_SCHEME.to_string()];
    if with_urn {
        schemes.push(URN_SCHEME.to_string());
    }
    if dry_run {
        return SchemeResult {
            registered: false,
            schemes: schemes.clone(),
            note: format!(
                "would register the {} URL-scheme handler(s) → this installer's `handle-url` \
                 (clicked links resolve through the local dig-node, then open in the browser)",
                schemes.join(", ")
            ),
        };
    }
    #[cfg(windows)]
    {
        register_windows(bin, &schemes)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        register_linux(bin, &schemes)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = bin;
        macos_unsupported(schemes)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = bin;
        SchemeResult {
            registered: false,
            schemes,
            note: "URL-scheme registration is not supported on this OS".to_string(),
        }
    }
}

/// Unregister the scheme handler this installer created (idempotent — absent is
/// a clean no-op). Per-user, no elevation.
pub fn unregister(dry_run: bool) -> SchemeResult {
    let schemes = vec![PRIMARY_SCHEME.to_string(), URN_SCHEME.to_string()];
    if dry_run {
        return SchemeResult {
            registered: false,
            schemes,
            note: "would unregister the chia:// / urn: URL-scheme handler".to_string(),
        };
    }
    #[cfg(windows)]
    {
        unregister_windows(&schemes)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        unregister_linux(&schemes)
    }
    #[cfg(target_os = "macos")]
    {
        macos_unsupported(schemes)
    }
    #[cfg(not(any(windows, unix)))]
    {
        SchemeResult {
            registered: false,
            schemes,
            note: "not supported on this OS".to_string(),
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_unsupported(schemes: Vec<String>) -> SchemeResult {
    // LaunchServices binds a scheme to a bundle (`.app`), not a bare CLI. A
    // CLI-only install cannot own `chia://`; the DIG Browser (a real .app)
    // registers it via its own `CFBundleURLTypes` when installed. Reported
    // honestly — never a silent fake success.
    SchemeResult {
        registered: false,
        schemes,
        note: "chia:// handler registration on macOS requires a .app bundle (the DIG Browser \
               registers it when installed); skipped for this CLI install"
            .to_string(),
    }
}

#[cfg(windows)]
fn register_windows(bin: &Path, schemes: &[String]) -> SchemeResult {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let cmd = windows_handler_command(bin);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for scheme in schemes {
        let base = format!("Software\\Classes\\{scheme}");
        let write = || -> Result<(), String> {
            let (key, _) = hkcu
                .create_subkey_with_flags(&base, KEY_WRITE)
                .map_err(|e| format!("create {base}: {e}"))?;
            key.set_value("", &format!("URL:{scheme} (DIG Network)"))
                .map_err(|e| e.to_string())?;
            // The "URL Protocol" empty value marks the key as a URL scheme.
            key.set_value("URL Protocol", &"")
                .map_err(|e| e.to_string())?;
            let (cmd_key, _) = hkcu
                .create_subkey_with_flags(format!("{base}\\shell\\open\\command"), KEY_WRITE)
                .map_err(|e| format!("create {base}\\shell\\open\\command: {e}"))?;
            cmd_key.set_value("", &cmd).map_err(|e| e.to_string())?;
            Ok(())
        };
        if let Err(e) = write() {
            return SchemeResult {
                registered: false,
                schemes: schemes.to_vec(),
                note: format!("could not register the {scheme}:// handler: {e}"),
            };
        }
    }
    SchemeResult {
        registered: true,
        schemes: schemes.to_vec(),
        note: format!(
            "registered the {} URL-scheme handler(s) under HKCU\\Software\\Classes",
            schemes.join(", ")
        ),
    }
}

#[cfg(windows)]
fn unregister_windows(schemes: &[String]) -> SchemeResult {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let mut removed = Vec::new();
    for scheme in schemes {
        let base = format!("Software\\Classes\\{scheme}");
        // Only delete if it's OUR handler (the command points at handle-url) —
        // never clobber a pre-existing/foreign registration.
        let ours = hkcu
            .open_subkey(format!("{base}\\shell\\open\\command"))
            .ok()
            .and_then(|k| k.get_value::<String, _>("").ok())
            .map(|v| v.contains(HANDLE_URL_SUBCOMMAND))
            .unwrap_or(false);
        if ours {
            let _ = hkcu.delete_subkey_all(&base);
            removed.push(scheme.clone());
        }
    }
    SchemeResult {
        registered: false,
        schemes: removed.clone(),
        note: if removed.is_empty() {
            "no DIG-owned scheme handler to remove".to_string()
        } else {
            format!("unregistered: {}", removed.join(", "))
        },
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn desktop_file_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| {
        h.join(".local")
            .join("share")
            .join("applications")
            .join("dig-network-url-handler.desktop")
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn register_linux(bin: &Path, schemes: &[String]) -> SchemeResult {
    use std::process::Command;
    let refs: Vec<&str> = schemes.iter().map(String::as_str).collect();
    let body = linux_desktop_contents(bin, &refs);
    let path = match desktop_file_path() {
        Some(p) => p,
        None => {
            return SchemeResult {
                registered: false,
                schemes: schemes.to_vec(),
                note: "no home directory to write the .desktop handler".to_string(),
            }
        }
    };
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return SchemeResult {
                registered: false,
                schemes: schemes.to_vec(),
                note: format!("create {}: {e}", parent.display()),
            };
        }
    }
    if let Err(e) = std::fs::write(&path, body) {
        return SchemeResult {
            registered: false,
            schemes: schemes.to_vec(),
            note: format!("write {}: {e}", path.display()),
        };
    }
    let desktop_name = path.file_name().unwrap().to_string_lossy().into_owned();
    // Best-effort: refresh the desktop DB + set as default for each scheme.
    if let Some(dir) = path.parent() {
        let _ = Command::new("update-desktop-database").arg(dir).status();
    }
    for scheme in schemes {
        let _ = Command::new("xdg-mime")
            .args([
                "default",
                &desktop_name,
                &format!("x-scheme-handler/{scheme}"),
            ])
            .status();
    }
    SchemeResult {
        registered: true,
        schemes: schemes.to_vec(),
        note: format!("registered {} via {}", schemes.join(", "), path.display()),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unregister_linux(schemes: &[String]) -> SchemeResult {
    let path = desktop_file_path();
    let removed = match &path {
        Some(p) if p.exists() => std::fs::remove_file(p).is_ok(),
        _ => false,
    };
    SchemeResult {
        registered: false,
        schemes: if removed {
            schemes.to_vec()
        } else {
            Vec::new()
        },
        note: if removed {
            "removed the DIG .desktop scheme handler".to_string()
        } else {
            "no DIG .desktop scheme handler to remove".to_string()
        },
    }
}

/// Handle a clicked `chia://` / `urn:` URI (the hidden `handle-url` subcommand):
/// parse it, pick the first reachable §5.3 base, build the node serve URL, and
/// open it in the default browser (which routes through dig-dns/dig-node).
/// Returns the URL opened. `probe` decides base reachability (injected for
/// tests); `open` opens a URL (injected for tests).
pub fn handle_url(uri: &str) -> Result<String, String> {
    handle_url_with(uri, &base_reachable, &open_in_browser)
}

fn handle_url_with(
    uri: &str,
    probe: &dyn Fn(&str) -> bool,
    open: &dyn Fn(&str) -> Result<(), String>,
) -> Result<String, String> {
    let target = parse_target(uri)
        .ok_or_else(|| format!("not a DIG chia:// / urn:dig:chia: link: {uri}"))?;
    // §5.3 ladder: first reachable base wins; fall back to the last (public
    // gateway) so a click always opens SOMETHING rather than silently failing.
    let base = LADDER_BASES
        .iter()
        .find(|b| probe(b))
        .copied()
        .unwrap_or(LADDER_BASES[LADDER_BASES.len() - 1]);
    let url = serve_url(base, &target);
    open(&url)?;
    Ok(url)
}

/// Is a §5.3 base reachable? A short HTTP GET to its root; ANY HTTP response
/// (even a 4xx/5xx status) counts as reachable — only a transport failure
/// (connection refused / DNS / timeout) means "down".
fn base_reachable(base: &str) -> bool {
    match ureq::get(base)
        .timeout(std::time::Duration::from_millis(600))
        .call()
    {
        Ok(_) => true,
        Err(ureq::Error::Status(_, _)) => true,
        Err(ureq::Error::Transport(_)) => false,
    }
}

/// Open a URL in the OS default browser.
fn open_in_browser(url: &str) -> Result<(), String> {
    use std::process::Command;
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    #[cfg(not(any(windows, unix)))]
    let mut cmd = {
        let _ = url;
        return Err("cannot open a browser on this OS".to_string());
    };
    cmd.status()
        .map_err(|e| format!("could not open the browser: {e}"))
        .and_then(|s| {
            if s.success() {
                Ok(())
            } else {
                Err(format!("browser opener exited with {:?}", s.code()))
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parse_chia_uri_host_and_path() {
        let t = parse_target("chia://abc123/index.html").unwrap();
        assert_eq!(t.store, "abc123");
        assert_eq!(t.path, "index.html");
    }

    #[test]
    fn parse_chia_uri_store_only() {
        let t = parse_target("chia://abc123").unwrap();
        assert_eq!(t.store, "abc123");
        assert_eq!(t.path, "");
        // Trailing slash is normalized away.
        assert_eq!(parse_target("chia://abc123/").unwrap().path, "");
    }

    #[test]
    fn parse_chia_uri_nested_path() {
        let t = parse_target("chia://store/a/b/c.txt").unwrap();
        assert_eq!(t.store, "store");
        assert_eq!(t.path, "a/b/c.txt");
    }

    #[test]
    fn parse_urn_dig_chia() {
        let t = parse_target("urn:dig:chia:mystore/path/file").unwrap();
        assert_eq!(t.store, "mystore");
        assert_eq!(t.path, "path/file");
        // Case-insensitive scheme/NID.
        assert_eq!(parse_target("URN:DIG:CHIA:S").unwrap().store, "S");
    }

    #[test]
    fn parse_rejects_non_dig_uris() {
        assert!(parse_target("https://example.com").is_none());
        assert!(parse_target("chia://").is_none());
        assert!(parse_target("urn:isbn:123").is_none());
        assert!(parse_target("").is_none());
        assert!(parse_target("chia:///onlypath").is_none());
    }

    #[test]
    fn serve_url_builds_the_node_local_path() {
        let t = SchemeTarget {
            store: "s1".into(),
            path: "a/b.html".into(),
        };
        assert_eq!(
            serve_url("http://dig.local", &t),
            "http://dig.local/s/s1/a/b.html"
        );
        // trailing slash on base is trimmed.
        assert_eq!(
            serve_url("http://localhost:9778/", &t),
            "http://localhost:9778/s/s1/a/b.html"
        );
    }

    #[test]
    fn serve_url_store_root_ends_in_slash() {
        let t = SchemeTarget {
            store: "s1".into(),
            path: "".into(),
        };
        assert_eq!(serve_url("http://dig.local", &t), "http://dig.local/s/s1/");
    }

    #[test]
    fn ladder_bases_are_the_5_3_order() {
        // §5.3: dig.local first, localhost second, rpc.dig.net last.
        assert_eq!(LADDER_BASES[0], "http://dig.local");
        assert!(LADDER_BASES[1].contains("localhost"));
        assert!(LADDER_BASES[2].contains("rpc.dig.net"));
    }

    #[test]
    fn matches_handle_url_invocation_extracts_the_uri() {
        let argv = vec![
            "dig-installer.exe".to_string(),
            "handle-url".to_string(),
            "chia://store/x".to_string(),
        ];
        assert_eq!(
            matches_handle_url_invocation(&argv),
            Some("chia://store/x".to_string())
        );
        // A normal invocation is not a handle-url.
        assert_eq!(
            matches_handle_url_invocation(&["dig-installer".to_string(), "--json".to_string()]),
            None
        );
        assert_eq!(matches_handle_url_invocation(&["x".to_string()]), None);
    }

    #[test]
    fn windows_handler_command_quotes_bin_and_passes_uri() {
        let cmd = windows_handler_command(&PathBuf::from(r"C:\Apps\DIG\dig-installer.exe"));
        assert!(cmd.contains("handle-url"));
        assert!(cmd.contains("%1"));
        assert!(cmd.starts_with('"'), "the bin path must be quoted: {cmd}");
    }

    #[test]
    fn linux_desktop_contents_declares_scheme_mimetypes() {
        let body =
            linux_desktop_contents(&PathBuf::from("/opt/dig/dig-installer"), &["chia", "urn"]);
        assert!(body.contains("MimeType=x-scheme-handler/chia;x-scheme-handler/urn;"));
        assert!(body.contains("handle-url %u"));
        assert!(body.contains("Type=Application"));
    }

    #[test]
    fn handle_url_opens_the_first_reachable_base() {
        let opened = std::cell::RefCell::new(String::new());
        let open = |u: &str| {
            *opened.borrow_mut() = u.to_string();
            Ok(())
        };
        // dig.local unreachable, localhost reachable → localhost wins (§5.3).
        let probe = |b: &str| b.contains("localhost");
        let url = handle_url_with("chia://store9/page.html", &probe, &open).unwrap();
        assert_eq!(url, "http://localhost:9778/s/store9/page.html");
        assert_eq!(*opened.borrow(), url);
    }

    #[test]
    fn handle_url_prefers_dig_local_when_reachable() {
        let open = |_: &str| Ok(());
        let probe = |_: &str| true; // all reachable → first (dig.local) wins
        let url = handle_url_with("chia://s/x", &probe, &open).unwrap();
        assert_eq!(url, "http://dig.local/s/s/x");
    }

    #[test]
    fn handle_url_falls_back_to_public_gateway_when_none_reachable() {
        let open = |_: &str| Ok(());
        let probe = |_: &str| false;
        let url = handle_url_with("chia://s", &probe, &open).unwrap();
        assert!(url.starts_with("https://rpc.dig.net/s/s/"), "got: {url}");
    }

    #[test]
    fn handle_url_rejects_non_dig_uris() {
        let open = |_: &str| Ok(());
        let probe = |_: &str| true;
        assert!(handle_url_with("https://example.com", &probe, &open).is_err());
    }

    #[test]
    fn scheme_result_serializes_with_stable_fields() {
        let r = SchemeResult {
            registered: true,
            schemes: vec!["chia".into()],
            note: "ok".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["registered"], true);
        assert_eq!(v["schemes"][0], "chia");
        assert_eq!(v["note"], "ok");
    }
}
