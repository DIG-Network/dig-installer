//! DIG Installer — Tauri backend.
//!
//! Exposes the commands the frontend (src/bridge.js) calls:
//!   - installer_meta                    → { version, compiler }
//!   - default_install_path              → per-OS default dir
//!   - component_update_status(path)     → per-component Install/Update/Skip preview (#309)
//!   - run_install(opts)                 → runs the real pipeline, streams events
//!   - cancel_install()                  → cooperatively cancels an in-flight install
//!
//! The install runs on a background thread so the UI stays responsive while it
//! streams `install://progress` / `install://error` / `install://done`.

mod install;

/// The headless privileged-install entrypoint the root `pkexec` child runs on
/// Linux (#638). Re-exported so `main.rs` can dispatch to it — BEFORE any Tauri
/// WebView is created — when this process is relaunched with the fixed
/// [`dig_installer::elevation::ELEVATED_INSTALL_ARG`] token. The install selection
/// arrives over STDIN. See [`install::run_elevated_privileged_install_from_stdin`].
#[cfg(all(unix, not(target_os = "macos")))]
pub use install::run_elevated_privileged_install_from_stdin;

/// The headless privileged-install entrypoint the root `osascript` child runs on
/// macOS (#639). Re-exported so `main.rs` can dispatch to it — BEFORE any Tauri
/// WebView is created — when this process is relaunched with the fixed
/// [`dig_installer::elevation::ELEVATED_INSTALL_ARG`] token. The install selection
/// arrives via a private temp-file path (the second positional argument), because
/// Authorization Services does not inherit the caller's stdin. See
/// [`install::run_elevated_privileged_install_from_file`].
#[cfg(target_os = "macos")]
pub use install::run_elevated_privileged_install_from_file;

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::Serialize;

use dig_installer::proc::HideConsole;
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Serialize)]
struct Meta {
    version: String,
    compiler: String,
}

struct InstallState {
    cancelled: Arc<AtomicBool>,
}

#[tauri::command]
fn installer_meta(app: AppHandle) -> Meta {
    // Best-effort: ask the bundled binary for its version so the UI shows the
    // truth. Falls back to the spec's 1.0.0 if the binary can't be queried yet.
    let version = bundled_version(&app).unwrap_or_else(|| "1.0.0".to_string());
    Meta {
        version,
        compiler: "1.0.0".to_string(),
    }
}

/// Returns the version of the **bundled `digstore` CLI** that this installer
/// will install — i.e. the semver printed by `digstore --version` from the
/// app's resources. This is the version the badge should display (distinct
/// from the installer app's own version). Falls back to "0.3.0" if the binary
/// can't be queried (e.g. missing in a dev run) so the UI never blanks out.
#[tauri::command]
fn bundled_digstore_version(app: AppHandle) -> String {
    bundled_version(&app).unwrap_or_else(|| "0.3.0".to_string())
}

fn bundled_version(app: &AppHandle) -> Option<String> {
    // Embedded single-file build: the version was captured at build time from
    // the binary that was compiled into this installer.
    if let Some(v) = option_env!("DIGSTORE_BUNDLED_VERSION") {
        return Some(v.to_string());
    }
    // Dev fallback: query the staged resource binary directly.
    let res = app.path().resource_dir().ok()?;
    let bin = res.join("bin").join(install::bin_name());
    let bin = if bin.exists() {
        bin
    } else {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("bin")
            .join(install::bin_name())
    };
    // The STAGED RESOURCE binary inside the app bundle, read for a version string to display — not an
    // installed binary, and this path runs unelevated in the WebView process (the privileged install is a
    // separate child, §4.1b/§4.1c). So there is no install root to verify and the root-exec guard has
    // nothing to say here (`clippy.toml`, #1748 WU4).
    #[allow(clippy::disallowed_methods)]
    let out = Command::new(&bin)
        .arg("--version")
        .hide_console()
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    // "digstore 0.1.0" → "0.1.0"
    s.split_whitespace().nth(1).map(|v| v.to_string())
}

#[tauri::command]
fn default_install_path() -> String {
    install::default_install_path()
}

/// The installed Chromium-family browsers on this machine (#609 detection), for
/// the conditional Browsers checklist step (#611). Read-only: it enumerates
/// browsers and where each one's managed-extension policy would be written; it
/// writes NOTHING (the #612 force-install writer does that). Returns an empty
/// list when no supported browser is found, which the GUI renders as its
/// (non-dead-end) empty state.
#[tauri::command]
fn detect_browsers() -> Vec<dig_installer::browsers::DetectedBrowser> {
    dig_installer::browsers::detect_installed()
}

/// Component-selection screen preview (issue #309): per-component Install/
/// Update/Skip status for dig-node/dig-dns, checked against `install_path`
/// BEFORE the user clicks Install.
#[tauri::command]
fn component_update_status(install_path: String) -> Vec<install::ComponentStatusDto> {
    install::component_update_status(&install_path)
}

#[tauri::command]
fn run_install(
    app: AppHandle,
    state: State<'_, InstallState>,
    opts: install::InstallOpts,
) -> Result<(), String> {
    state.cancelled.store(false, Ordering::SeqCst);
    let cancelled = state.cancelled.clone();
    // Run on a worker thread; the pipeline emits its own events.
    std::thread::spawn(move || {
        if cancelled.load(Ordering::SeqCst) {
            return;
        }
        // ALWAYS surface a failure: an early `?` in the pipeline (e.g. a missing
        // payload, a write/permission error) returns before its own error emit,
        // which would otherwise leave the UI hung with no message.
        if let Err(e) = install::run(&app, opts) {
            let _ = app.emit("install://error", install::InstallError { message: e });
        }
    });
    Ok(())
}

#[tauri::command]
fn cancel_install(state: State<'_, InstallState>) {
    state.cancelled.store(true, Ordering::SeqCst);
}

/// Where WebView2's user-data folder must live for THIS process (#1819).
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebviewDataDir {
    /// WebView2's own default, `%LOCALAPPDATA%\<bundle-id>\EBWebView`. Writable by definition for the
    /// account that owns it, and the correct scope for a browser profile.
    OwnProfile,
    /// The hardened machine-wide root under `%ProgramData%`, for a token whose own `%LOCALAPPDATA%`
    /// WebView2 cannot use.
    MachineRoot,
}

/// Decide the folder from the token we are running under.
///
/// Pure and injected rather than reading the ambient token itself, so both arms are testable — the
/// crate's own convention for a token-dependent decision (cf. `install::should_exec_verify`).
///
/// # The criterion is SYSTEM, *not* elevation (#1819)
///
/// This is the correction that actually fixed #1819. #715's rationale was specifically about
/// **LocalSystem**: as SYSTEM, `%LOCALAPPDATA%` is
/// `C:\Windows\system32\config\systemprofile\AppData\Local`, which WebView2 cannot create. The code
/// generalised that to *any* elevated token — and on Windows the GUI carries
/// `requestedExecutionLevel="requireAdministrator"` (#610), so it is **always** elevated. An
/// elevation-keyed condition is therefore always true and always pins the machine root, which is why
/// two rounds of "only pin when elevated" changed nothing at all.
///
/// UAC elevation does **not** change the profile: an elevated interactive user still has their own
/// `%LOCALAPPDATA%`, which is precisely where WebView2 wants to be and where every other elevated
/// WebView2 application puts its profile. Only a genuine SYSTEM token has no usable profile — and
/// SYSTEM is a configuration `install.rs` refuses outright (#499).
///
/// So: SYSTEM takes the machine root; everything else, elevated or not, is left alone.
#[cfg(windows)]
fn webview_data_dir_for(running_as_system: bool) -> WebviewDataDir {
    if running_as_system {
        WebviewDataDir::MachineRoot
    } else {
        WebviewDataDir::OwnProfile
    }
}

/// Point WebView2 at a writable user-data folder BEFORE the webview initializes (#715, #1819).
///
/// On Windows the Tauri UI renders in WebView2, whose data folder defaults to
/// `%LOCALAPPDATA%\<bundle-id>\EBWebView`. That default is right for an ordinary user token and
/// WRONG for a privileged one: as **LocalSystem** `%LOCALAPPDATA%` is
/// `C:\Windows\system32\config\systemprofile\AppData\Local`, which WebView2 cannot create, so it dies
/// with "couldn't create the data directory" before the UI loads. WebView2 reads
/// `WEBVIEW2_USER_DATA_FOLDER` at init, so setting it here (before `tauri::Builder::run`) fixes that.
///
/// # Why this is CONDITIONAL, and why the first two attempts at that failed (#1819)
///
/// This used to pin the machine root **unconditionally**, and WebView2 refused to start:
///
/// > Microsoft Edge can't read and write to this data directory: `C:\ProgramData\DigNetwork\installer\webview\EBWebView`
///
/// The machine root is deliberately `{SYSTEM:F, Administrators:F}`, protected and non-inheriting —
/// load-bearing for #565 and NOT to be widened — and it is simply not somewhere a WebView2 profile can
/// live. Measured: the DACL is correct (both ACEs carry `ContainerInherit, ObjectInherit`, owner
/// SYSTEM) and `EBWebView` was never created, so the directory was never malformed; it is the wrong
/// KIND of place.
///
/// **Two attempts keyed this on elevation and changed nothing**, because the GUI ships
/// `requestedExecutionLevel="requireAdministrator"` (#610) — it is *always* elevated, so
/// `elevated || system` is always true and always pinned. The criterion is SYSTEM alone; see
/// [`webview_data_dir_for`].
///
/// That failure also happens *before any UI exists*. The GUI's elevation gate and its #499 SYSTEM
/// refusal (`install.rs`) are command handlers that run only once the WebView is up — so a process
/// that cannot start its WebView cannot tell the user **anything**, including the one thing it wants
/// to say. A browser profile must never sit somewhere the process may be unable to use.
///
/// SYSTEM alone still takes the hardened root through the fail-closed
/// [`dig_installer::daemon_dir::ensure_webview_data_dir`] (SYSTEM-owned, protected DACL, no
/// reparse-point redirection) — never a bare `create_dir_all`, which a non-admin could pre-squat or
/// junction into a path a privileged WebView2 would then write through. If that hardening cannot be
/// established and verified we FAIL CLOSED rather than pin WebView2 to an unverified dir. `is_system`
/// fails CLOSED to "is SYSTEM", which is the safe direction here. No-op off Windows.
#[cfg(windows)]
fn pin_webview_data_dir() {
    // Ambient reads at the edge; the decision is the pure function above.
    let target = webview_data_dir_for(dig_installer::elevation::is_system());
    if target == WebviewDataDir::OwnProfile {
        // Leave WEBVIEW2_USER_DATA_FOLDER unset: WebView2's default is already correct and writable.
        return;
    }
    match dig_installer::daemon_dir::ensure_webview_data_dir() {
        Ok(dir) => std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", &dir),
        Err(e) => {
            eprintln!(
                "DIG Installer: refusing to launch — could not secure the WebView2 data \
                 directory: {e}"
            );
            std::process::exit(1);
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(windows)]
    pin_webview_data_dir();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(InstallState {
            cancelled: Arc::new(AtomicBool::new(false)),
        })
        .invoke_handler(tauri::generate_handler![
            installer_meta,
            bundled_digstore_version,
            default_install_path,
            detect_browsers,
            component_update_status,
            run_install,
            cancel_install
        ])
        .run(tauri::generate_context!())
        .expect("error while running DIG Installer");
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// An ordinary run — INCLUDING an elevated one — must be left on its own profile.
    ///
    /// This is the #1819 regression, and the reason two earlier attempts missed it: the GUI carries
    /// `requireAdministrator`, so it is ALWAYS elevated, and an elevation-keyed condition is always
    /// true. Keying on elevation here would make this test unreachable in production while still
    /// passing, which is the worst kind of green.
    #[test]
    fn an_interactive_user_elevated_or_not_uses_its_own_profile() {
        assert_eq!(webview_data_dir_for(false), WebviewDataDir::OwnProfile);
    }

    /// ...and the control: a SYSTEM token has no usable profile (`…\systemprofile\AppData\Local`,
    /// which WebView2 cannot create), so it must take the hardened machine root. Without this arm,
    /// "never pin" would satisfy the test above and regress #715.
    #[test]
    fn a_system_token_takes_the_hardened_machine_root() {
        assert_eq!(webview_data_dir_for(true), WebviewDataDir::MachineRoot);
    }

    /// The two outcomes must stay distinct. A refactor that collapsed them — returning one variant
    /// unconditionally — would pass exactly one of the tests above, so pin the pair.
    #[test]
    fn the_two_tokens_do_not_get_the_same_folder() {
        assert_ne!(
            webview_data_dir_for(true),
            webview_data_dir_for(false),
            "SYSTEM and an interactive user must not share a WebView2 profile decision"
        );
    }
}
