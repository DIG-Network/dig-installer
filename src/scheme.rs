//! OS URL-scheme handler registration for the DIG scheme set — `dig://`,
//! `chia://`, and best-effort `urn:` — all delegating to the single URI-resolve
//! authority, `dign open <uri>` (#567/#563).
//!
//! The installer used to carry its OWN copy of the URI parse + §5.3 ladder +
//! browser-open logic (a hidden `handle-url` subcommand). That duplicated
//! dig-node's shipped `dign open` command (dig-node v0.27.0; the `dign` alias
//! v0.31.0) and risked drifting from it. There must be exactly ONE thing that
//! knows how to resolve-and-open a DIG URI, and that is the node. So the
//! installer now only REGISTERS the OS handlers and points every one of them at
//! `dign open "%1"` — the node owns resolution end to end.
//!
//! Registered scheme set (a cross-repo canon — see the `canonical` skill):
//!   * `dig://`  — the primary DIG scheme.
//!   * `chia://` — legacy/compat scheme (links are migrating to `dig://`).
//!   * `urn:`    — best-effort, where the OS permits a generic `urn:` handler.
//!
//! Per-OS registration (all per-user — NO elevation needed):
//!   * **Windows:** `HKCU\Software\Classes\<scheme>` (`URL Protocol`) →
//!     `"<dign>" open "%1"`.
//!   * **Linux:** a `~/.local/share/applications/*.desktop` with
//!     `MimeType=x-scheme-handler/<scheme>;` + `xdg-mime default`, `Exec` =
//!     `"<dign>" open %u`.
//!   * **macOS:** LaunchServices binds a scheme to a `.app` bundle, not a bare
//!     CLI, so a CLI-only install cannot own the scheme — reported honestly as a
//!     best-effort no-op, never a silent fake success.
//!
//! ## Argument-injection safety (security-critical, #567)
//!
//! The clicked URI is fully attacker-controlled, so the command string MUST NOT
//! let it break out into extra tokens or a shell:
//!   * NO shell is ever invoked — the OS launches the handler via
//!     `ShellExecute`/`CreateProcess` (Windows) or the desktop entry `Exec`
//!     (Linux), NOT through `cmd /C` or `/bin/sh -c`. There is therefore no
//!     metacharacter interpolation of the URI.
//!   * On Windows the URI is delivered as the `%1` placeholder — a SINGLE
//!     substituted argument — so `dign` receives it as one `argv` element.
//!   * On Linux the desktop-entry `%u` field code is expanded by the launcher
//!     into one argument per the freedesktop spec; the URI is not word-split.
//! The installer contributes only the static, non-interpolated argv shape
//! (`open` + placeholder); the node's `dign open` is the sole parser.

use std::path::Path;

/// The schemes this installer registers, in registration order. `dig` and
/// `chia` are always registered; `urn` is best-effort (registered only where
/// the OS allows a generic `urn:` handler).
pub const DIG_SCHEME: &str = "dig";
pub const CHIA_SCHEME: &str = "chia";
pub const URN_SCHEME: &str = "urn";

/// The `dign` subcommand every handler delegates to. `dign open <uri>` is the
/// single URI-resolve-and-open authority (dig-node v0.27.0); the installer never
/// resolves a URI itself.
pub const DIGN_OPEN_SUBCOMMAND: &str = "open";

/// The Windows handler command string written to
/// `HKCU\Software\Classes\<scheme>\shell\open\command`: the quoted `dign` binary
/// path, the `open` subcommand, and the quoted `%1` URI placeholder. Pure.
///
/// The `%1` is substituted by the OS as a single argument (no shell), so a
/// crafted URI cannot inject extra tokens (see the module-level safety note).
pub fn windows_handler_command(dign_bin: &Path) -> String {
    format!("\"{}\" {DIGN_OPEN_SUBCOMMAND} \"%1\"", dign_bin.display())
}

/// The `.desktop` file body registering `dign open %u` as the handler for the
/// given scheme(s) on Linux. Pure (unit-tested); the file write +
/// `xdg-mime`/`update-desktop-database` calls are the I/O layer.
pub fn linux_desktop_contents(dign_bin: &Path, schemes: &[&str]) -> String {
    let mime: String = schemes
        .iter()
        .map(|s| format!("x-scheme-handler/{s};"))
        .collect();
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=DIG Network Link Handler\n\
         Comment=Open dig:// / chia:// links through the local DIG node\n\
         Exec=\"{}\" {DIGN_OPEN_SUBCOMMAND} %u\n\
         Terminal=false\n\
         NoDisplay=true\n\
         MimeType={mime}\n",
        dign_bin.display()
    )
}

/// The schemes registered for a given `with_urn` choice: always `dig` + `chia`,
/// plus `urn` when the OS supports a generic handler. Pure.
pub fn scheme_set(with_urn: bool) -> Vec<String> {
    let mut schemes = vec![DIG_SCHEME.to_string(), CHIA_SCHEME.to_string()];
    if with_urn {
        schemes.push(URN_SCHEME.to_string());
    }
    schemes
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// The outcome of registering (or, on dry-run, planning to register) the URL
/// scheme handlers. Never silent — `note` always explains the state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SchemeResult {
    /// The handlers were registered (or, on dry-run, would be).
    pub registered: bool,
    /// The schemes actually registered (e.g. `["dig", "chia", "urn"]`).
    pub schemes: Vec<String>,
    /// Human-readable detail — never silent.
    pub note: String,
}

/// Register the `dig://` + `chia://` (+ best-effort `urn:`) URL-scheme handlers,
/// each pointing at `dign_bin` run as `open %1`. Per-user, no elevation.
/// `dry_run` reports the intent without touching the OS.
pub fn register(dign_bin: &Path, with_urn: bool, dry_run: bool) -> SchemeResult {
    let schemes = scheme_set(with_urn);
    if dry_run {
        return SchemeResult {
            registered: false,
            schemes: schemes.clone(),
            note: format!(
                "would register the {} URL-scheme handler(s) → `dign open` \
                 (the local dig-node resolves and opens the clicked link)",
                schemes.join(", ")
            ),
        };
    }
    #[cfg(windows)]
    {
        register_windows(dign_bin, &schemes)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        register_linux(dign_bin, &schemes)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = dign_bin;
        macos_unsupported(schemes)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = dign_bin;
        SchemeResult {
            registered: false,
            schemes,
            note: "URL-scheme registration is not supported on this OS".to_string(),
        }
    }
}

/// Unregister the scheme handlers this installer created (idempotent — absent is
/// a clean no-op). Per-user, no elevation. Only removes handlers that point at
/// `dign open` (ours) — never clobbers a foreign registration.
pub fn unregister(dry_run: bool) -> SchemeResult {
    let schemes = scheme_set(true);
    if dry_run {
        return SchemeResult {
            registered: false,
            schemes,
            note: "would unregister the dig:// / chia:// / urn: URL-scheme handler(s)".to_string(),
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
    // CLI-only install cannot own `dig://`/`chia://`; the DIG Browser (a real
    // .app) registers them via its own `CFBundleURLTypes` when installed.
    // Reported honestly — never a silent fake success.
    SchemeResult {
        registered: false,
        schemes,
        note: "dig:// / chia:// handler registration on macOS requires a .app bundle (the DIG \
               Browser registers it when installed); skipped for this CLI install"
            .to_string(),
    }
}

#[cfg(windows)]
fn register_windows(dign_bin: &Path, schemes: &[String]) -> SchemeResult {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let cmd = windows_handler_command(dign_bin);
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
            "registered the {} URL-scheme handler(s) under HKCU\\Software\\Classes → `dign open`",
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
        // Only delete if it's OUR handler (the command delegates to `dign open`)
        // — never clobber a pre-existing/foreign registration.
        let ours = hkcu
            .open_subkey(format!("{base}\\shell\\open\\command"))
            .ok()
            .and_then(|k| k.get_value::<String, _>("").ok())
            .map(|v| is_our_handler_command(&v))
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

/// Does a registered handler command belong to us — i.e. does it delegate to
/// `dign open`? Used so unregister only removes DIG-owned handlers. Recognises
/// BOTH the current `dign open` form and the legacy installer `handle-url` form
/// (so an upgrade cleans up the old self-hosted handler too). Pure.
pub fn is_our_handler_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    (lower.contains("dign") && lower.contains(DIGN_OPEN_SUBCOMMAND)) || lower.contains("handle-url")
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
fn register_linux(dign_bin: &Path, schemes: &[String]) -> SchemeResult {
    use crate::proc::HideConsole;
    use std::process::Command;
    let refs: Vec<&str> = schemes.iter().map(String::as_str).collect();
    let body = linux_desktop_contents(dign_bin, &refs);
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
        let _ = Command::new("update-desktop-database")
            .arg(dir)
            .hide_console()
            .status();
    }
    for scheme in schemes {
        let _ = Command::new("xdg-mime")
            .args([
                "default",
                &desktop_name,
                &format!("x-scheme-handler/{scheme}"),
            ])
            .hide_console()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn scheme_set_always_has_dig_and_chia() {
        let s = scheme_set(false);
        assert_eq!(s, vec!["dig", "chia"]);
        let s = scheme_set(true);
        assert_eq!(s, vec!["dig", "chia", "urn"]);
    }

    #[test]
    fn windows_command_delegates_to_dign_open_with_quoted_bin_and_placeholder() {
        let cmd = windows_handler_command(&PathBuf::from(r"C:\Program Files\DIG\dign.exe"));
        assert_eq!(cmd, r#""C:\Program Files\DIG\dign.exe" open "%1""#);
        assert!(cmd.starts_with('"'), "the bin path must be quoted: {cmd}");
        assert!(cmd.contains(" open "));
        assert!(cmd.ends_with(r#""%1""#), "URI placeholder must be quoted: {cmd}");
    }

    #[test]
    fn windows_command_uses_no_shell_wrapper() {
        // Security: the command invokes dign directly — never `cmd /C` — so a
        // crafted URI cannot reach a shell interpreter.
        let cmd = windows_handler_command(&PathBuf::from(r"C:\DIG\dign.exe"));
        let lower = cmd.to_ascii_lowercase();
        assert!(!lower.contains("cmd"), "no shell wrapper: {cmd}");
        assert!(!lower.contains("/c "), "no /C shell flag: {cmd}");
    }

    #[test]
    fn linux_desktop_declares_scheme_mimetypes_and_dign_open() {
        let body = linux_desktop_contents(
            &PathBuf::from("/opt/dig/dign"),
            &["dig", "chia", "urn"],
        );
        assert!(body.contains(
            "MimeType=x-scheme-handler/dig;x-scheme-handler/chia;x-scheme-handler/urn;"
        ));
        assert!(body.contains(r#"Exec="/opt/dig/dign" open %u"#));
        assert!(body.contains("Type=Application"));
    }

    #[test]
    fn linux_exec_passes_uri_as_single_field_code_not_word_split() {
        // Security: `%u` is one launcher-expanded argument per the freedesktop
        // spec — the URI is not split on spaces, and no shell is invoked.
        let body = linux_desktop_contents(&PathBuf::from("/opt/dig/dign"), &["dig"]);
        assert!(body.contains(" open %u\n"));
        assert!(!body.to_ascii_lowercase().contains("sh -c"));
    }

    #[test]
    fn is_our_handler_command_recognises_dign_open_and_legacy() {
        assert!(is_our_handler_command(r#""C:\DIG\dign.exe" open "%1""#));
        assert!(is_our_handler_command(r#""/opt/dig/dign" open %u"#));
        // Legacy self-hosted installer handler is also recognised (upgrade cleanup).
        assert!(is_our_handler_command(
            r#""C:\DIG\dig-installer.exe" handle-url "%1""#
        ));
        // A foreign handler is NOT ours.
        assert!(!is_our_handler_command(
            r#""C:\Other\browser.exe" --open "%1""#
        ));
    }

    #[test]
    fn dry_run_register_reports_dign_open_intent_without_touching_os() {
        let r = register(&PathBuf::from("/opt/dig/dign"), true, true);
        assert!(!r.registered);
        assert_eq!(r.schemes, vec!["dig", "chia", "urn"]);
        assert!(r.note.contains("dign open"));
    }

    #[test]
    fn scheme_result_serializes_with_stable_fields() {
        let r = SchemeResult {
            registered: true,
            schemes: vec!["dig".into(), "chia".into()],
            note: "ok".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["registered"], true);
        assert_eq!(v["schemes"][0], "dig");
        assert_eq!(v["schemes"][1], "chia");
        assert_eq!(v["note"], "ok");
    }
}
