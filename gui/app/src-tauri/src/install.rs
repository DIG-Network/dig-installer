//! The real install pipeline.
//!
//! Replaces the prototype's timed animation with actual filesystem work, driven
//! from the bundled artifact (no network download on first install). Each phase
//! emits a `install://progress` event (pct / nowFile / styled log line). On
//! failure it emits `install://error`; on success, `install://done`.
//!
//! Phases (mirrors README → "Real install pipeline"):
//!   1. Resolve target for OS/arch.
//!   2. Verify bundled package checksum  [gated, offline]  → SHA-256 manifest.
//!   3. Unpack the digstore CLI (+ host runtime) into the install dir.
//!   4. Install selected components (shell completions, example store).
//!   5. Add digstore to PATH (user PATH on Windows; symlink in /usr/local/bin
//!      on macOS/Linux — elevation only where needed).
//!   6. Verify the install by running `digstore --version`.
//!   7. Install the OTHER selected DIG components (dig-node / dig-dns /
//!      dig-relay / DIG Browser, task #234) by delegating to the
//!      `dig-installer` library's own tested `run_report` orchestration —
//!      the same release-resolution/download/service-lifecycle machinery the
//!      CLI thin-shim uses (see [`plan_from_selection`]).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};
// `Manager` is only needed for `app.path()` in the resource-dir fallback.
#[cfg(not(embed_digstore))]
use tauri::Manager;

use dig_installer::proc::HideConsole;
use dig_installer::target::Os;

// ---- Embedded payload (single-file install) ----------------------------------
// When the release build staged a `digstore` binary, build.rs embedded it (and
// its SHA-256) so the installer is a single self-contained executable with no
// sidecar resource folder. Dev/`cargo check` builds without a staged binary do
// not set `embed_digstore` and fall back to the Tauri resource dir.
#[cfg(embed_digstore)]
const EMBEDDED_DIGSTORE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/digstore.bin"));
#[cfg(embed_digstore)]
const EMBEDDED_SHA256: &str = include_str!(concat!(env!("OUT_DIR"), "/digstore.sha256"));

// The DIG brand icon, embedded so the .dig file-type association has an icon to
// point at regardless of where the user runs the (single-file) installer.
// Only referenced from the `#[cfg(windows)]` half of `register_dig_association`
// (the ProgID DefaultIcon writes an .ico); cfg-gating the constant itself keeps
// non-Windows builds free of an unused-embedded-icon dead-code warning.
#[cfg(windows)]
const DIG_ICON_ICO: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/icons/icon.ico"));
#[cfg(all(unix, not(target_os = "macos")))]
const DIG_ICON_PNG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/icons/icon.png"));

#[derive(Debug, Deserialize, Serialize)]
pub struct InstallOpts {
    pub install_path: String,
    /// componentId -> enabled (cli is always true)
    pub selected: HashMap<String, bool>,
    /// The per-browser extension selection captured on the conditional Browsers
    /// step (#611): the `id`s of the detected Chromium browsers the user kept
    /// checked (e.g. `["chrome", "brave"]`), empty when the extension component
    /// is deselected. This is the selection the enterprise force-install writer
    /// (#612) consumes to decide which browsers' `ExtensionInstallForcelist`
    /// policy to write; the #611 pipeline only carries it, it does not act on it.
    #[serde(default)]
    pub selected_browsers: Vec<String>,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct Progress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "nowFile")]
    pub now_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct InstallError {
    pub message: String,
}

/// Binary name per-OS.
pub fn bin_name() -> &'static str {
    if cfg!(windows) {
        "digstore.exe"
    } else {
        "digstore"
    }
}

/// Default install location per the README:
///   Windows: %LOCALAPPDATA%\Programs\DigStore
///   macOS/Linux: /usr/local/digstore
pub fn default_install_path() -> String {
    if cfg!(windows) {
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("C:/Users/Public"));
        base.join("Programs")
            .join("DigStore")
            .to_string_lossy()
            .to_string()
    } else {
        "/usr/local/digstore".to_string()
    }
}

/// Locate the bundled artifact inside the app resource dir (dev fallback only;
/// release builds embed the binary — see `digstore_payload`).
#[cfg(not(embed_digstore))]
fn bundled_bin(app: &AppHandle) -> Result<PathBuf, String> {
    let res_dir = app
        .path()
        .resource_dir()
        .map_err(|e| format!("cannot resolve resource dir: {e}"))?;
    let candidate = res_dir.join("bin").join(bin_name());
    if candidate.exists() {
        return Ok(candidate);
    }
    // Dev fallback: when running `tauri dev`, resources may resolve relative to
    // the crate dir. Try the staging dir directly.
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("bin")
        .join(bin_name());
    if dev.exists() {
        return Ok(dev);
    }
    Err(format!(
        "bundled {} not found (looked in {} and {}). TODO: stage the release \
         binary into installer/app/src-tauri/resources/bin/ before building.",
        bin_name(),
        candidate.display(),
        dev.display()
    ))
}

fn emit_line(app: &AppHandle, line: impl Into<String>) {
    let _ = app.emit(
        "install://progress",
        Progress {
            line: Some(line.into()),
            ..Default::default()
        },
    );
}
fn emit_pct(app: &AppHandle, pct: f64, now_file: Option<&str>) {
    let _ = app.emit(
        "install://progress",
        Progress {
            pct: Some(pct),
            now_file: now_file.map(|s| s.to_string()),
            ..Default::default()
        },
    );
}

fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Resolve the `digstore` bytes to install plus the expected SHA-256 (when
/// known). Prefers the binary embedded at build time (single-file install);
/// falls back to the Tauri resource dir + `.sha256` sidecar for dev runs.
fn digstore_payload(app: &AppHandle) -> Result<(Vec<u8>, Option<String>), String> {
    #[cfg(embed_digstore)]
    {
        let _ = app; // resource dir unused when embedded
        Ok((
            EMBEDDED_DIGSTORE.to_vec(),
            Some(EMBEDDED_SHA256.trim().to_lowercase()),
        ))
    }
    #[cfg(not(embed_digstore))]
    {
        let src = bundled_bin(app)?;
        let bytes = fs::read(&src).map_err(|e| format!("read {}: {e}", src.display()))?;
        let manifest = src.with_file_name(format!("{}.sha256", bin_name()));
        let expected = fs::read_to_string(&manifest)
            .ok()
            .and_then(|s| s.split_whitespace().next().map(|x| x.to_lowercase()));
        Ok((bytes, expected))
    }
}

/// Run the whole pipeline. Returns Ok on full success; on the first failure it
/// emits `install://error` and returns Err (the caller has already streamed it).
pub fn run(app: &AppHandle, opts: InstallOpts) -> Result<(), String> {
    let install_dir = PathBuf::from(&opts.install_path);
    let lib_dir = install_dir.join("lib");

    // ---- Phase 0: enforce elevation (#492) ----
    // If the selection registers an OS service (dig-node / dig-dns / dig-relay)
    // the install needs Administrator/root. Check FIRST, before any unpack/
    // write, so an un-elevated run fails fast with NO partial state — never the
    // old "half-installed, falsely-successful" outcome (#493). digstore-only
    // (per-user) selections don't trip this.
    // #499: refuse to run as LocalSystem/SYSTEM, UNCONDITIONALLY (even a
    // digstore-only install as SYSTEM lands per-user state — PATH, .dig
    // association — in the wrong profile). A SYSTEM token also breaks the GUI's
    // own WebView2 (it writes to `…\systemprofile\…\EBWebView`). Elevation MUST
    // be a UAC elevation of the SAME interactive user — never a service /
    // scheduled-task / `psexec -s` relaunch that yields SYSTEM. Checked FIRST,
    // before any unpack/write, so a SYSTEM launch leaves NO partial state.
    if dig_installer::elevation::is_system() {
        let msg = "the DIG installer is running as LocalSystem/SYSTEM, not your user account. \
             A SYSTEM token cannot run the installer UI and writes settings to the wrong profile. \
             Close this and re-launch the installer normally as your own user — it will prompt for \
             Administrator via UAC, elevating YOUR account, not SYSTEM. Do NOT launch it via a \
             service, scheduled task, or psexec -s."
            .to_string();
        let _ = app.emit(
            "install://error",
            InstallError {
                message: msg.clone(),
            },
        );
        return Err(msg);
    }

    // Build the plan for the privileged/service components up front so the
    // elevation decision uses the AUTHORITATIVE `InstallPlan::requires_elevation`
    // rather than a hand-maintained id list. This closes two gaps the old
    // `["dig-node","dig-dns","dig-relay"]` check had (#610): (1) it missed the
    // default-on SYSTEM auto-update beacon (`auto_update`), and (2) it missed a
    // protected-root binary write on Windows. An unknown target fails CLOSED
    // (require elevation) so a privileged install can never proceed unprivileged.
    let extra_plan = plan_from_selection(&opts.selected);

    // Resolve the OS once so the digstore placement (#610) and the elevation
    // decision share a single, authoritative answer. An unresolved target fails
    // CLOSED: unknown OS ⇒ require elevation (below) and fall back to the
    // library default bin dir (which is the protected root on Windows).
    let os = dig_installer::target::Target::current().ok().map(|t| t.os);

    // #610 (NEW LPE the requireAdministrator switch opened): the now-elevated
    // (high-integrity) GUI process MUST NOT write-then-execute a binary from a
    // user-writable directory — medium-IL malware could swap the exe in the
    // write→exec window and gain the user's freshly-granted Administrator. The
    // bundled `digstore` CLI is unpacked AND executed (`digstore --version`,
    // Phase 6) by this process, so it is routed through the SAME protected-root
    // placement the CLI installer uses (`InstallPlan::bin_dir_for`): the
    // admin-only `%ProgramFiles%\DIG\bin` on Windows (the #565 "whole Windows
    // stack in Program Files" invariant), the elevation-free per-user
    // `~/.dig/bin` on unix (where digstore runs AS the user — not an escalation).
    // The user's chosen `install_dir` still receives the NON-executable install
    // artifacts (completions, example store, the .dig icon) — data this process
    // never executes, so no escalation window exists there. The user runs
    // digstore via PATH regardless of where the binary physically lives.
    let bin_dir = digstore_write_exec_dir(&extra_plan, os);

    // Elevation is required when the extra components need it (services / beacon
    // / hosts entry — the library's authoritative `requires_elevation`) OR the
    // GUI's own digstore placement lands in the admin-only protected root (#610):
    // writing into Program Files is itself a privileged operation, so a
    // digstore-only Windows GUI run must elevate too, exactly like the CLI.
    // #648: an enterprise force-install writes each browser's admin-only managed
    // policy (`HKLM`, `/etc/.../policies/managed`, `/Library/Managed Preferences`),
    // so a run that force-installs the extension needs elevation too — even a
    // browser-only selection with no downloadable component. Folded in here so the
    // fail-closed gate and the Linux pkexec relaunch cover the forcelist write.
    let needs_elevation = match os {
        Some(os) => {
            extra_plan.requires_elevation(os)
                || places_digstore_in_protected_root(os)
                || wants_extension_forcelist(&opts)
        }
        None => true,
    };
    let elevated = dig_installer::elevation::is_elevated();

    // How the PRIVILEGED portion (LocalSystem/root services, protected-root
    // binaries, hosts entry, the SYSTEM/root beacon) runs when this GUI process
    // is NOT already root:
    //   * Windows — the GUI elevated itself at launch (requireAdministrator
    //     manifest, #610), so `elevated` is already true and this never triggers.
    //   * Linux (#638) — the unelevated AppImage GUI relaunches its OWN executable
    //     as root ONE-SHOT via `pkexec` for the privileged step only (Phase 7),
    //     keeping the WebView unelevated. The `digstore --version` verify then
    //     runs in THIS still-unelevated parent (Phase 6) — a genuinely
    //     dropped-privilege context, never a root-exec of a user-writable binary
    //     (the #637 MUST-HONOR).
    //   * macOS (#639) — the unelevated `.app` GUI relaunches its OWN executable
    //     as root ONE-SHOT via `osascript … with administrator privileges` for the
    //     privileged step only (Phase 7), keeping the WebView unelevated. As on
    //     Linux, the `digstore --version` verify (Phase 6) runs in THIS still-
    //     unelevated parent — a genuinely dropped-privilege context (the #637
    //     MUST-HONOR), never a root-exec of a user-writable binary.
    #[cfg(all(unix, not(target_os = "macos")))]
    let relaunch_privileged_via_pkexec = needs_elevation && !elevated;
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    let relaunch_privileged_via_pkexec = false;
    #[cfg(target_os = "macos")]
    let relaunch_privileged_via_osascript = needs_elevation && !elevated;
    #[cfg(not(target_os = "macos"))]
    let relaunch_privileged_via_osascript = false;

    // The privileged portion is run by relaunching THIS process elevated (Linux
    // pkexec / macOS osascript) rather than in-process, whenever either native
    // relaunch path applies. One name so the fail-closed gate stays OS-agnostic.
    let relaunch_privileged = relaunch_privileged_via_pkexec || relaunch_privileged_via_osascript;

    // Fail-closed gate (nothing partial). We only PROCEED unprivileged when the
    // privileged step will be elevated by a native relaunch (Linux pkexec / macOS
    // osascript); otherwise an unprivileged run that needs elevation is the
    // historical hard stop (#492).
    if needs_elevation && !elevated && !relaunch_privileged {
        let msg = format!(
            "elevation required: {}. Re-run the installer as Administrator (Windows) / with sudo \
             (macOS/Linux). Nothing was changed.",
            dig_installer::elevation::reason()
        );
        let _ = app.emit(
            "install://error",
            InstallError {
                message: msg.clone(),
            },
        );
        return Err(msg);
    }

    // Linux elevation-gate FIRST: if the privileged step WILL need pkexec but
    // polkit is absent, refuse NOW — before any unpack/write — so a machine
    // without polkit never gets a half-install (design §2, fail-closed).
    #[cfg(all(unix, not(target_os = "macos")))]
    if relaunch_privileged_via_pkexec
        && dig_installer::elevation::resolve_system_tool("pkexec").is_none()
    {
        let msg = dig_installer::elevation::pkexec_unavailable_message().to_string();
        let _ = app.emit(
            "install://error",
            InstallError {
                message: msg.clone(),
            },
        );
        return Err(msg);
    }

    // macOS elevation-gate FIRST (mirrors the Linux polkit check): if the
    // privileged step WILL need osascript but osascript is somehow absent, refuse
    // NOW — before any unpack/write — so no half-install is ever left (#639,
    // fail-closed).
    #[cfg(target_os = "macos")]
    if relaunch_privileged_via_osascript
        && dig_installer::elevation::resolve_system_tool("osascript").is_none()
    {
        let msg = dig_installer::elevation::osascript_unavailable_message().to_string();
        let _ = app.emit(
            "install://error",
            InstallError {
                message: msg.clone(),
            },
        );
        return Err(msg);
    }

    // ---- Phase 1: resolve target ----
    emit_pct(app, 2.0, Some(bin_name()));
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    emit_line(
        app,
        format!(
            r#"<span class="dim">$</span> dig-installer --target {}"#,
            opts.install_path
        ),
    );
    emit_line(
        app,
        format!(
            r#"Resolving release <span class="ac">v1.0.0</span> · compiler 1.0.0 · module format 1 <span class="dim">({os}/{arch})</span>"#
        ),
    );

    let (payload, expected_sha) = digstore_payload(app)?;

    // ---- Phase 2: verify the package checksum [gated] ----
    // Offline integrity gate: recompute SHA-256 over the bytes we are about to
    // write and compare to the digest captured at build time (or the sidecar in
    // dev). This is a checksum, not cryptographic provenance — it proves the
    // payload is intact (no corruption/truncation), not authorship. A real
    // release additionally verifies a BLS detached signature over this digest
    // (the remaining TODO); the checksum check is the genuine, blocking gate
    // wired here and still aborts the install before any unpack/exec.
    emit_pct(app, 10.0, Some(bin_name()));
    let digest = sha256_bytes(&payload);
    match &expected_sha {
        Some(expected) if expected != &digest => {
            let msg = format!("package checksum mismatch: expected {expected}, got {digest}");
            let _ = app.emit(
                "install://error",
                InstallError {
                    message: msg.clone(),
                },
            );
            return Err(msg);
        }
        Some(_) => {
            emit_line(
                app,
                format!(
                    r#"<span class="ok">✓</span> Verified package checksum (SHA-256) <span class="dim">({}…)</span>"#,
                    &digest[..12]
                ),
            );
        }
        None => {
            // No expected digest available — surface honestly rather than faking a pass.
            emit_line(
                app,
                format!(
                    r#"<span class="warn">!</span> No checksum manifest; recorded digest <span class="dim">{}…</span>"#,
                    &digest[..12]
                ),
            );
        }
    }

    // ---- Phase 3: unpack the CLI (+ host runtime) ----
    emit_pct(app, 24.0, Some("bin/digstore"));
    fs::create_dir_all(&bin_dir).map_err(|e| format!("create {}: {e}", bin_dir.display()))?;
    let dest_bin = bin_dir.join(bin_name());
    fs::write(&dest_bin, &payload).map_err(|e| format!("unpack CLI: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = fs::metadata(&dest_bin)
            .map_err(|e| e.to_string())?
            .permissions();
        p.set_mode(0o755);
        let _ = fs::set_permissions(&dest_bin, p);
    }
    emit_line(
        app,
        format!(
            r#"Unpacking <span class="ac">DigStore CLI</span> → {}"#,
            bin_dir.display()
        ),
    );

    if *opts.selected.get("host").unwrap_or(&true) {
        emit_pct(app, 42.0, Some("lib/dig_host.wasm"));
        fs::create_dir_all(&lib_dir).map_err(|e| format!("create {}: {e}", lib_dir.display()))?;
        // The host runtime ships inside the CLI today; record the bound and
        // stage a marker so the install layout matches the spec. (TODO: when a
        // standalone dig_host artifact exists, copy it here.)
        let _ = fs::write(
            lib_dir.join("HOST_RUNTIME.txt"),
            "DigStore host runtime — bundled in digstore CLI (attestation + session ABI)\n",
        );
        emit_line(
            app,
            r#"Unpacking <span class="ac">Host Runtime</span> <span class="dim">(64 KiB → 16 MiB memory bounds)</span>"#,
        );
        emit_line(
            app,
            r#"Embedding trusted host keys <span class="dim">dig-host-key-v1:…</span>"#,
        );
        emit_line(
            app,
            r#"<span class="ok">✓</span> Content-defined chunking ready <span class="dim">(16/64/256 KiB)</span>"#,
        );
    }

    // ---- Phase 4: optional components ----
    if *opts.selected.get("completions").unwrap_or(&false) {
        emit_pct(app, 60.0, Some("share/completions/_digstore"));
        let comp_dir = install_dir.join("share").join("completions");
        let _ = fs::create_dir_all(&comp_dir);
        // Marker files — the digstore CLI does not yet emit completion scripts,
        // so write placeholders the layout expects. (TODO: `digstore completions
        // <shell>` once the CLI supports it.)
        for sh in ["bash", "zsh", "fish"] {
            let _ = fs::write(
                comp_dir.join(format!("digstore.{sh}")),
                format!("# digstore {sh} completion (generated by installer)\n"),
            );
        }
        emit_line(
            app,
            r#"Installing shell completions <span class="dim">bash · zsh · fish</span>"#,
        );
    }
    if *opts.selected.get("example").unwrap_or(&false) {
        emit_pct(app, 70.0, Some("examples/hello.wasm"));
        let ex_dir = install_dir.join("examples");
        let _ = fs::create_dir_all(&ex_dir);
        let _ = fs::write(
            ex_dir.join("README.txt"),
            "Sample urn:dig store — run `digstore clone <urn>` to explore.\n",
        );
        emit_line(
            app,
            r#"Unpacking <span class="ac">Example store</span> <span class="dim">(urn:dig:…)</span>"#,
        );
    }

    // ---- Phase 5: add to PATH ----
    if *opts.selected.get("path").unwrap_or(&true) {
        emit_pct(app, 82.0, Some("PATH"));
        match add_to_path(&bin_dir) {
            Ok(note) => {
                emit_line(
                    app,
                    format!(r#"Linking <span class="ac">digstore</span> → {note}"#),
                );
            }
            Err(e) => {
                // PATH failure is non-fatal to the binary being usable; surface
                // as a warning, not a hard error.
                emit_line(
                    app,
                    format!(
                        r#"<span class="warn">!</span> Could not update PATH automatically <span class="dim">({e})</span>"#
                    ),
                );
            }
        }
    }

    // ---- Phase 5.5: register the .dig file-type icon ----
    emit_pct(app, 88.0, Some(".dig association"));
    match register_dig_association(&install_dir) {
        Ok(note) => emit_line(
            app,
            format!(
                r#"Registering <span class="ac">.dig</span> file icon <span class="dim">({note})</span>"#
            ),
        ),
        Err(e) => emit_line(
            app,
            format!(
                r#"<span class="warn">!</span> Skipped .dig icon <span class="dim">({e})</span>"#
            ),
        ),
    }

    // ---- Phase 6: verify ----
    // #635 item 2 / #610: NEVER exec a user-writable binary under elevation — a
    // future root child (unix GUI elevation, #638/#639) must not root-exec
    // `~/.dig/bin/digstore`, which a lower-privileged process could swap. The
    // exec-verify runs here only when it is safe (unelevated, OR the CLI sits in
    // the admin-only protected root — see `should_exec_verify`); otherwise it is
    // DEFERRED to the unelevated GUI after the privileged step returns.
    emit_pct(app, 92.0, Some("digstore --version"));
    let bin_in_protected_root = bin_dir == dig_installer::paths::protected_bin_dir();
    if should_exec_verify(
        dig_installer::elevation::is_elevated(),
        bin_in_protected_root,
    ) {
        let out = Command::new(&dest_bin)
            .arg("--version")
            .hide_console()
            .output()
            .map_err(|e| {
                let msg = format!("verify failed: could not run {}: {e}", dest_bin.display());
                let _ = app.emit(
                    "install://error",
                    InstallError {
                        message: msg.clone(),
                    },
                );
                msg
            })?;
        if !out.status.success() {
            let msg = format!(
                "verify failed: `digstore --version` exited with {}",
                out.status.code().unwrap_or(-1)
            );
            let _ = app.emit(
                "install://error",
                InstallError {
                    message: msg.clone(),
                },
            );
            return Err(msg);
        }
        let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
        emit_line(
            app,
            format!(
                r#"<span class="ok">✓</span> Verifying install · <span class="ac">{}</span>"#,
                if ver.is_empty() {
                    "digstore --version".into()
                } else {
                    ver
                }
            ),
        );
    } else {
        // Elevated + a user-writable CLI: verification is deferred, NOT run here,
        // so no privileged process execs a user-writable binary (#635 item 2).
        emit_line(
            app,
            r#"<span class="dim">·</span> Deferring <span class="ac">digstore --version</span> to the unprivileged step <span class="dim">(no elevated exec of a user-writable binary)</span>"#,
        );
    }

    // ---- Phase 7: the other selected DIG components (task #234) ----
    // digstore itself was just unpacked from the bundled/embedded payload
    // above; dig-node / dig-dns / dig-relay / DIG Browser are NOT bundled, so
    // they are resolved + downloaded + registered here by delegating to the
    // exact same tested orchestration the `dig-installer` CLI thin-shim uses
    // (`dig_installer::run_report`) — this reuses its release resolution,
    // download, and (task #232) stop-before-write/start-after-write service
    // lifecycle rather than re-implementing any of it in the GUI.
    if extra_plan.with_dig_node
        || extra_plan.with_dig_dns
        || extra_plan.with_relay
        || extra_plan.with_browser
        // #389: the default-on chia:// scheme handler must register even when no
        // downloadable extra component is selected (e.g. a digstore-only GUI run).
        || extra_plan.register_scheme
        // #514: the default-on auto-update beacon is itself a downloadable
        // component (dig-updater + its worker sibling) — must run even when
        // no OTHER extra component is selected (e.g. a digstore-only GUI run).
        || extra_plan.auto_update
        // #648: the enterprise extension force-install is a privileged managed-
        // policy write — it must run inside the SAME elevated step (in-process
        // when already root, or the pkexec root child on Linux), so a
        // browser-only selection still reaches the privileged path.
        || wants_extension_forcelist(&opts)
    {
        emit_pct(app, 94.0, Some("additional components"));
        emit_line(
            app,
            "Installing the other selected DIG components:".to_string(),
        );
        // The privileged orchestration runs EITHER in-process (already root, or
        // Windows) OR — on unelevated Linux (#638) — as a one-shot `pkexec` root
        // relaunch of this executable. Both funnel through the SAME tested
        // `dig_installer::run_report` machinery; the pkexec path just moves that
        // call into a root child (headless, no WebView).
        #[cfg(all(unix, not(target_os = "macos")))]
        let privileged_result = if relaunch_privileged_via_pkexec {
            run_privileged_via_pkexec(app, &opts)
        } else {
            run_report_in_process(app, &extra_plan)
        };
        #[cfg(target_os = "macos")]
        let privileged_result = if relaunch_privileged_via_osascript {
            run_privileged_via_osascript(app, &opts)
        } else {
            run_report_in_process(app, &extra_plan)
        };
        // Windows (+ any non-unix): the process elevated itself at launch, so the
        // privileged orchestration always runs in-process.
        #[cfg(not(unix))]
        let privileged_result = run_report_in_process(app, &extra_plan);

        if let Err(msg) = privileged_result {
            let _ = app.emit(
                "install://error",
                InstallError {
                    message: msg.clone(),
                },
            );
            return Err(msg);
        }

        // #648: enterprise force-install the DIG extension into the user-selected
        // browsers via each browser's `ExtensionInstallForcelist` managed policy.
        // This is a privileged write, so it runs in the SAME elevated context as
        // the component install above:
        //   * Linux pkexec relaunch — the root child already performed the write
        //     (see `run_elevated_privileged_install_from_stdin`); this unelevated
        //     parent MUST NOT attempt the privileged write (#565/#637), so it only
        //     surfaces that the elevated step handled it.
        //   * otherwise (Windows requireAdministrator, already-root unix, macOS) —
        //     THIS process is the elevated context, so it does the write in-process.
        if wants_extension_forcelist(&opts) {
            // The privileged forcelist write is performed by the root relaunch
            // child on both native-relaunch platforms (Linux pkexec / macOS
            // osascript); Windows (already elevated) does it in-process below.
            let handled_in_child =
                relaunch_privileged_via_pkexec || relaunch_privileged_via_osascript;

            if handled_in_child {
                emit_line(
                    app,
                    format!(
                        r#"<span class="ok">✓</span> DIG extension force-installed in the elevated step for {} browser(s): {}"#,
                        opts.selected_browsers.len(),
                        opts.selected_browsers.join(", ")
                    ),
                );
            } else if let Err(msg) =
                configure_extension_forcelist_step(&opts, &mut |line| emit_line(app, line))
            {
                let _ = app.emit(
                    "install://error",
                    InstallError {
                        message: msg.clone(),
                    },
                );
                return Err(msg);
            }
        }
    }

    // Every selected component installed AND its service is verified RUNNING.
    emit_pct(app, 100.0, Some("done"));
    emit_line(app, r#"<span class="ok">✓</span> DIG is ready."#);

    let _ = app.emit("install://done", ());
    Ok(())
}

/// Build the install plan for the OTHER real DIG components (dig-node /
/// dig-dns / dig-relay / DIG Browser) from the GUI's selection map (task
/// #234). digstore itself is deliberately excluded (`with_digstore: false`)
/// — the GUI installs it via its own embedded/staged pipeline above, not
/// through this plan. Pure mapping (no I/O), so the selection→plan contract
/// — which components install, which are skipped when deselected/absent, and
/// that privileged components route to the protected root (#610) — is
/// unit-tested directly without mocking the network or a service manager.
fn plan_from_selection(selected: &HashMap<String, bool>) -> dig_installer::InstallPlan {
    let selected_on = |id: &str| *selected.get(id).unwrap_or(&false);
    dig_installer::InstallPlan {
        // #610 (re-opened #565 LPE): the privileged, service-executed components
        // this plan installs — the LocalSystem dig-node/dig-dns/dig-relay
        // services and the SYSTEM auto-update beacon — MUST land in the
        // admin-only protected root (`%ProgramFiles%\DIG\bin` / `/opt/dig/bin`),
        // never a user-writable dir a non-admin could plant a binary in. Using
        // the library's built-in `default_bin_dir()` (rather than the GUI's
        // user-chosen install path) keeps `has_custom_bin_dir()` FALSE, so
        // `InstallPlan::bin_dir_for` routes every privileged component through
        // `paths::protected_bin_dir()` — the exact same path the CLI uses — and
        // re-arms the #565 legacy-root migration + fail-loud ACL verify + binPath
        // audit on the GUI path. The GUI-owned `digstore` CLI is NOT installed via
        // this plan (`with_digstore: false`) but by the pipeline above — which,
        // per #610, ALSO routes it through `bin_dir_for("digstore", os)` (the
        // protected root on Windows) rather than the user's chosen dir, because
        // the elevated GUI both writes AND executes it: a user-writable location
        // would be a write→exec privilege-escalation vector under the elevated
        // process. The user's chosen install dir receives only NON-executable
        // artifacts (completions, example store, the .dig icon).
        bin_dir: dig_installer::paths::default_bin_dir(),
        with_digstore: false,
        digstore_version: None,
        with_dig_node: selected_on("dig-node"),
        dig_node_version: None,
        service: dig_installer::service::ServiceConfig::default(),
        with_browser: selected_on("browser"),
        browser_version: None,
        with_relay: selected_on("dig-relay"),
        relay_version: None,
        relay_service: dig_installer::ServiceConfigRelay::default(),
        with_dig_dns: selected_on("dig-dns"),
        dig_dns_version: None,
        dns_service: dig_installer::dns::DnsInstallConfig::default(),
        modify_path: true,
        // #389: register the chia:// (+ urn:) URL-scheme handler by default,
        // in sync with the CLI's default-on `register_scheme`. Toggleable from
        // the GUI: a `"register-scheme": false` selection opts out (mirrors the
        // CLI's `--no-register-scheme`); an absent key means the default (ON).
        register_scheme: *selected.get("register-scheme").unwrap_or(&true),
        // #424: open the dig-node peer-RPC firewall rule by default, in sync
        // with the CLI's default-on `open_firewall`. Toggleable from the GUI:
        // a `"open-firewall": false` selection opts out; an absent key means
        // the default (ON) — same convention as `register-scheme` above.
        open_firewall: *selected.get("open-firewall").unwrap_or(&true),
        // #514: install + register the DIG auto-update beacon by default, in
        // sync with the CLI's default-on `auto_update`. Toggleable from the
        // GUI: a `"auto-update": false` selection opts out; an absent key
        // means the default (ON) — same convention as the two options above.
        // The GUI wizard has no version-pin field for it (mirrors the other
        // extra components below).
        auto_update: *selected.get("auto-update").unwrap_or(&true),
        dig_updater_version: None,
        // #309: the GUI wizard has no force-reinstall toggle (the CLI's
        // `--force-reinstall` covers that advanced case) — a GUI-driven
        // install is always the version-aware install-or-update default.
        force_reinstall: false,
        dry_run: false,
    }
}

/// Does this install want the enterprise extension force-install? True only when
/// the `extension` component is selected AND the user kept at least one browser
/// checked on the Browsers step (#611). PURE — the single predicate that gates
/// both the elevation decision and the privileged forcelist write, so the two can
/// never disagree.
fn wants_extension_forcelist(opts: &InstallOpts) -> bool {
    opts.selected.get("extension").copied().unwrap_or(false) && !opts.selected_browsers.is_empty()
}

/// Perform the privileged `ExtensionInstallForcelist` write for the user-selected
/// browsers at the tracked channel, emitting one honest log line per browser
/// outcome via `emit`.
///
/// Delegates the actual policy write to the tested library primitive
/// ([`dig_installer::configure_extension_forcelist`], #612) — it does NOT
/// re-implement the writer. The extension id + `update_url` are compiled-in
/// constants inside that primitive; NO user-writable input becomes the policy
/// value (#565/#648 injection invariant). The channel is fixed to
/// [`Channel::Stable`] here — a channel SWITCH on an already-force-installed
/// browser is #613's beacon-follow job, not a fresh install.
///
/// MUST run only in an elevated context (its callers guarantee this). Returns
/// `Err` when ANY browser's write reported [`ForcelistAction::Failed`], so a
/// partial failure fails the whole install rather than reporting "ready" over a
/// silently-failed force-install.
fn configure_extension_forcelist_step(
    opts: &InstallOpts,
    emit: &mut dyn FnMut(String),
) -> Result<(), String> {
    use dig_installer::forcelist::Channel;

    if !wants_extension_forcelist(opts) {
        return Ok(());
    }

    emit(format!(
        r#"<span class="dim">·</span> Force-installing the DIG extension into {} browser(s) <span class="dim">(enterprise managed policy)</span>"#,
        opts.selected_browsers.len()
    ));

    let outcomes =
        dig_installer::configure_extension_forcelist(&opts.selected_browsers, Channel::Stable);
    let (lines, result) = summarize_forcelist_outcomes(&outcomes);
    for line in lines {
        emit(line);
    }
    result
}

/// Fold the per-browser forcelist [`ForcelistOutcome`]s into (log lines, overall
/// result). PURE — separated from the I/O-performing
/// [`configure_extension_forcelist_step`] so the honesty invariant (a single
/// `Failed` fails the whole step; nothing is ever silently swallowed) is directly
/// unit-tested without touching a registry, plist, or `/etc`.
///
/// Every outcome produces a log line; a `Failed` outcome additionally accumulates
/// into the returned `Err`, so the install surfaces exactly which browsers'
/// force-install did not land.
fn summarize_forcelist_outcomes(
    outcomes: &[dig_installer::forcelist::ForcelistOutcome],
) -> (Vec<String>, Result<(), String>) {
    use dig_installer::forcelist::ForcelistAction;

    let mut lines = Vec::with_capacity(outcomes.len());
    let mut failures = Vec::new();

    for o in outcomes {
        let (mark, verb) = match o.action {
            ForcelistAction::Wrote => ("ok", "force-installed"),
            ForcelistAction::AlreadyPresent => ("ok", "already force-installed"),
            ForcelistAction::Updated => ("ok", "updated"),
            ForcelistAction::Skipped => ("dim", "skipped"),
            ForcelistAction::Failed => ("err", "FAILED"),
            // Removal actions never arise on the install path, but render them
            // rather than panic if a future caller passes them through.
            ForcelistAction::Removed => ("ok", "removed"),
            ForcelistAction::NothingToRemove => ("dim", "nothing to remove"),
        };
        let note = if o.note.is_empty() {
            String::new()
        } else {
            format!(r#" <span class="dim">({})</span>"#, o.note)
        };
        lines.push(format!(
            r#"<span class="{mark}">{sym}</span> {verb}: {loc}{note}"#,
            sym = if mark == "err" { "✗" } else { "✓" },
            loc = o.location,
        ));
        if o.action == ForcelistAction::Failed {
            failures.push(format!("{} ({})", o.location, o.note));
        }
    }

    let result = if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the extension force-install failed for {} browser(s): {}",
            failures.len(),
            failures.join("; ")
        ))
    };
    (lines, result)
}

/// Run the privileged component orchestration ([`dig_installer::run_report`])
/// IN THIS PROCESS, streaming its log lines to the GUI. Used when the process is
/// already elevated (Windows requireAdministrator, or a root/sudo run). Returns
/// `Err(message)` when a component fails or the aggregate report is not ready —
/// the caller owns emitting `install://error`.
fn run_report_in_process(
    app: &AppHandle,
    extra_plan: &dig_installer::InstallPlan,
) -> Result<(), String> {
    // Fail-loud (#493): a completed-but-not-ready report (a selected component
    // didn't install or its service isn't RUNNING) is a FAILURE — never "ready".
    match dig_installer::run_report(extra_plan, &mut |line| emit_line(app, line)) {
        Ok(report) if !report.ready => Err(format!(
            "DIG is NOT ready — {} component(s) failed: {}. Re-run elevated \
             (Administrator/root) if elevation is the cause.",
            report.failures.len(),
            report.failures.join("; ")
        )),
        Ok(_) => Ok(()),
        Err(e) => Err(format!("installing additional components failed: {e}")),
    }
}

/// Run the privileged orchestration as ROOT via a one-shot `pkexec` relaunch of
/// THIS installer (Linux, #638).
///
/// The unelevated GUI `pkexec`-relaunches the installer with the fixed
/// [`ELEVATED_INSTALL_ARG`](dig_installer::elevation::ELEVATED_INSTALL_ARG) token
/// and streams the install selection to the root child over its STDIN — there is
/// NO plan file, so the plan-file TOCTOU class does not exist (a co-located user
/// has nothing to pre-seed, symlink-swap, or race). The root child runs
/// [`run_elevated_privileged_install_from_stdin`] (headless — it never starts the
/// WebView) and exits; polkit renders the native admin-auth dialog.
///
/// The relaunch target is resolved via
/// [`relaunch_target`](dig_installer::elevation::relaunch_target): when running as
/// an AppImage it is `$APPIMAGE` (the root-readable `.AppImage` file), NOT the
/// root-unreadable FUSE `current_exe()` — otherwise root's `pkexec` could not exec
/// the installer at all.
///
/// Fail-closed: a missing `pkexec`, a declined prompt, or a non-zero child status
/// is surfaced as an error with no "ready".
#[cfg(all(unix, not(target_os = "macos")))]
fn run_privileged_via_pkexec(app: &AppHandle, opts: &InstallOpts) -> Result<(), String> {
    let current = std::env::current_exe()
        .map_err(|e| format!("cannot resolve the installer executable path: {e}"))?;
    let appimage = std::env::var_os("APPIMAGE").map(PathBuf::from);
    let exe = dig_installer::elevation::relaunch_target(appimage.as_deref(), &current);

    // The selection is streamed to the root child over stdin — never a shared file
    // — so there is nothing to race. It is non-secret data (a component-id → bool
    // map + the user-chosen install path) and, regardless, the privileged routing
    // is INDEPENDENT of it: `plan_from_selection` sends every privileged binary to
    // the protected root (`/opt/dig/bin`) via `bin_dir_for`, never the user path,
    // so it can only toggle which official components install.
    let plan_json = serde_json::to_vec(opts).map_err(|e| format!("serialize plan: {e}"))?;

    emit_line(
        app,
        r#"<span class="dim">·</span> Requesting administrator authorization <span class="dim">(pkexec)</span>"#,
    );

    match dig_installer::elevation::relaunch_elevated(&exe, &plan_json) {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!(
            "the privileged install did not complete (pkexec child exited with {}). \
             If you dismissed the authorization prompt, re-run and approve it. Your \
             per-user files (the digstore CLI in ~/.dig/bin and PATH entry) were \
             installed; only the system-wide step (services + /opt/dig/bin) did not run.",
            s.code().unwrap_or(-1)
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// The headless privileged-install entrypoint the root `pkexec` child runs
/// (Linux, #638). Reads the plan the unelevated GUI streamed over STDIN, asserts
/// it is genuinely running as root, and executes ONLY the privileged component
/// orchestration ([`dig_installer::run_report`]) — routing every privileged binary
/// to the protected root (`/opt/dig/bin`). It NEVER starts the Tauri WebView (so no
/// GUI ever runs as root) and NEVER execs a user-writable binary. Progress is
/// written to stdout for the parent/logs.
///
/// Reading from stdin (rather than a path argument) is what eliminates the
/// plan-file TOCTOU: there is no filesystem object for a local user to swap.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn run_elevated_privileged_install_from_stdin() -> Result<(), String> {
    use std::io::Read;

    // Defence in depth: the child MUST actually be root. `relaunch_elevated` only
    // ever spawns this via pkexec, but assert it here so a mis-invocation can never
    // run the "privileged" path unprivileged and silently no-op.
    if !dig_installer::elevation::is_elevated() {
        return Err("the elevated install child is not running as root — refusing".to_string());
    }
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| format!("read plan from stdin: {e}"))?;
    let opts: InstallOpts =
        serde_json::from_str(&raw).map_err(|e| format!("parse plan from stdin: {e}"))?;
    let extra_plan = plan_from_selection(&opts.selected);
    match dig_installer::run_report(&extra_plan, &mut |line| println!("{line}")) {
        Ok(report) if !report.ready => Err(format!(
            "DIG is NOT ready — {} component(s) failed: {}",
            report.failures.len(),
            report.failures.join("; ")
        )),
        // #648: the enterprise extension force-install is a privileged managed-
        // policy write into `/etc/.../policies/managed`, so it belongs to THIS
        // root child — never the unelevated GUI parent. Runs after the components
        // succeed; a Failed forcelist write fails the whole privileged step (a
        // non-zero exit the parent surfaces), so the install never reports "ready"
        // while a force-install silently failed.
        Ok(_) => configure_extension_forcelist_step(&opts, &mut |line| println!("{line}")),
        Err(e) => Err(format!("privileged install failed: {e}")),
    }
}

/// Run the privileged orchestration as ROOT via a one-shot `osascript` relaunch
/// of THIS installer (macOS, #639).
///
/// The unelevated `.app` GUI relaunches its OWN executable with the fixed
/// [`ELEVATED_INSTALL_ARG`](dig_installer::elevation::ELEVATED_INSTALL_ARG) token
/// through `osascript … with administrator privileges` (Authorization Services
/// renders the native admin-auth dialog — works UNSIGNED, so it is NOT gated on
/// code-signing #536). The selection is handed to the root child through a PRIVATE
/// `0700`/`0600` temp file (Authorization Services does not inherit the caller's
/// stdin, so the Linux stdin channel is unavailable); see
/// [`relaunch_elevated_macos`](dig_installer::elevation::relaunch_elevated_macos)
/// for the TOCTOU/symlink reasoning. The root child runs
/// [`run_elevated_privileged_install_from_file`] (headless — it never starts the
/// WebView) and exits.
///
/// Unlike the Linux AppImage, a macOS `.app` binary lives on a normal
/// root-readable path (`/Applications`, `~/Applications`, `~/Downloads`), so
/// `current_exe()` is used directly — no FUSE/`$APPIMAGE` indirection is needed.
///
/// Fail-closed: a missing `osascript`, a declined prompt, or a non-zero child
/// status is surfaced as an error with no "ready".
#[cfg(target_os = "macos")]
fn run_privileged_via_osascript(app: &AppHandle, opts: &InstallOpts) -> Result<(), String> {
    let current = std::env::current_exe()
        .map_err(|e| format!("cannot resolve the installer executable path: {e}"))?;

    // The selection is written to a private temp file the root child reads (never
    // spliced into the osascript command). It is non-secret (a component-id → bool
    // map + the chosen install path) and, regardless, the privileged routing is
    // INDEPENDENT of it: `plan_from_selection` sends every privileged binary to the
    // protected root (`/opt/dig/bin`) via `bin_dir_for`, never the user path, so it
    // can only toggle which official components install.
    let plan_json = serde_json::to_vec(opts).map_err(|e| format!("serialize plan: {e}"))?;

    emit_line(
        app,
        r#"<span class="dim">·</span> Requesting administrator authorization <span class="dim">(osascript)</span>"#,
    );

    match dig_installer::elevation::relaunch_elevated_macos(&current, &plan_json) {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!(
            "the privileged install did not complete (osascript child exited with {}). \
             If you dismissed the authorization prompt, re-run and approve it. Your \
             per-user files (the digstore CLI in ~/.dig/bin and PATH entry) were \
             installed; only the system-wide step (services + /opt/dig/bin) did not run.",
            s.code().unwrap_or(-1)
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// The headless privileged-install entrypoint the root `osascript` child runs
/// (macOS, #639). Reads the plan the unelevated GUI staged into a private
/// `0700`/`0600` temp file — opened `O_NOFOLLOW` so a swapped symlink cannot
/// redirect the root read — asserts it is genuinely running as root, and executes
/// ONLY the privileged component orchestration ([`dig_installer::run_report`]) +
/// (when selected) the enterprise force-install, routing every privileged binary
/// to the protected root (`/opt/dig/bin`). It NEVER starts the Tauri WebView (so
/// no GUI ever runs as root) and NEVER execs a user-writable binary. Progress is
/// written to stdout for the parent/logs.
#[cfg(target_os = "macos")]
pub fn run_elevated_privileged_install_from_file(plan_path: &Path) -> Result<(), String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    // Defence in depth: the child MUST actually be root. `relaunch_elevated_macos`
    // only ever spawns this via osascript's `with administrator privileges`, but
    // assert it here so a mis-invocation can never run the "privileged" path
    // unprivileged and silently no-op.
    if !dig_installer::elevation::is_elevated() {
        return Err("the elevated install child is not running as root — refusing".to_string());
    }

    // O_NOFOLLOW: refuse to traverse a final-component symlink — defence in depth
    // on top of the private 0700 dir the parent created (a different local user
    // cannot enter it to plant one).
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(plan_path)
        .map_err(|e| format!("open plan {}: {e}", plan_path.display()))?;
    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .map_err(|e| format!("read plan {}: {e}", plan_path.display()))?;
    let opts: InstallOpts =
        serde_json::from_str(&raw).map_err(|e| format!("parse plan from file: {e}"))?;
    let extra_plan = plan_from_selection(&opts.selected);
    match dig_installer::run_report(&extra_plan, &mut |line| println!("{line}")) {
        Ok(report) if !report.ready => Err(format!(
            "DIG is NOT ready — {} component(s) failed: {}",
            report.failures.len(),
            report.failures.join("; ")
        )),
        // #648: the enterprise extension force-install is a privileged managed-
        // policy write into `/Library/Managed Preferences`, so it belongs to THIS
        // root child — never the unelevated GUI parent. A Failed forcelist write
        // fails the whole privileged step (a non-zero exit the parent surfaces).
        Ok(_) => configure_extension_forcelist_step(&opts, &mut |line| println!("{line}")),
        Err(e) => Err(format!("privileged install failed: {e}")),
    }
}

/// Does the GUI's own `digstore` CLI placement land in the admin-only protected
/// root on `os` (#610)?
///
/// The elevated GUI process unpacks AND executes digstore, so on any OS where it
/// lands in the protected root that write is a privileged operation and the run
/// MUST elevate first (a digstore-only Windows GUI run elevates too, matching the
/// CLI installer's #565 behaviour). True on Windows (the whole stack lives in
/// `%ProgramFiles%\DIG\bin`), false on unix (digstore is a user-run CLI in
/// `~/.dig/bin`, executed as the user — not an escalation). Pure, so every OS
/// branch is asserted directly.
fn places_digstore_in_protected_root(os: Os) -> bool {
    dig_installer::paths::is_privileged_component(os, "digstore")
}

/// The directory `run()` both WRITES and EXECUTES the bundled `digstore` CLI
/// from — the #610 write→exec dir.
///
/// This MUST come from the vetted #565 routing ([`InstallPlan::bin_dir_for`]),
/// NEVER an ad-hoc user-writable path, so a future elevated (root) run never
/// write-then-execs a binary a lower-privileged process could swap. On Windows
/// that is the admin-only protected root (`%ProgramFiles%\DIG\bin`); on unix it
/// is the elevation-free per-user `~/.dig/bin` (digstore runs AS the user — not
/// an escalation). An unresolved OS falls back to the library default bin dir
/// (which is the protected root on Windows) — never a bespoke directory.
///
/// Extracted as a pure fn so the routing is test-locked: a revert to a
/// hardcoded user-writable dir fails
/// [`digstore_write_exec_dir_uses_the_565_routing`].
fn digstore_write_exec_dir(plan: &dig_installer::InstallPlan, os: Option<Os>) -> PathBuf {
    os.map(|os| plan.bin_dir_for("digstore", os))
        .unwrap_or_else(dig_installer::paths::default_bin_dir)
}

/// Should Phase-6 exec-verification (`digstore --version`) run in THIS process,
/// given whether the process is `elevated` and whether the CLI was written into
/// the admin-only protected root (`bin_in_protected_root`)?
///
/// The #610 invariant: an elevated process MUST NOT `exec` a binary from a
/// user-writable directory — a lower-privileged attacker could swap it in the
/// write→exec window and inherit the freshly-granted privilege (the LPE class
/// the Windows fix closed, and the foundation the unix GUI elevation #638/#639
/// builds on). Verification is therefore SAFE — and runs here — iff either the
/// process is UNELEVATED (execing its own user binary is no escalation) OR the
/// binary sits in the protected root (root-owned, not user-writable, so
/// unswappable by a lower-privileged process). Otherwise it is DEFERRED to the
/// unelevated GUI (a future root child returns, and the GUI verifies) — the root
/// child never execs `~/.dig/bin/digstore`.
fn should_exec_verify(elevated: bool, bin_in_protected_root: bool) -> bool {
    !elevated || bin_in_protected_root
}

/// One component's live Install/Update/Skip status (issue #309), shaped for
/// the Components screen's pre-install preview.
#[derive(Debug, Serialize)]
pub struct ComponentStatusDto {
    pub component: String,
    /// `"install"` / `"update"` / `"skip"`, or `None` when the latest release
    /// couldn't be resolved (e.g. offline) — see `summary` for why.
    pub action: Option<String>,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    /// A human-readable line: the decision summary on success, or the
    /// resolution error when `action` is `None`.
    pub summary: String,
}

/// Check dig-node/dig-dns Install/Update/Skip status for the Components
/// screen's preview, BEFORE the user clicks Install (issue #309).
///
/// `digstore` is deliberately excluded: the GUI's own digstore install is a
/// bundled/embedded payload with no network "latest" to diff against (see the
/// module doc's Phase 7 note + `SPEC.md` §6) — its version is already shown
/// via the `bundled_digstore_version` command, unpacked fresh every run.
pub fn component_update_status(install_path: &str) -> Vec<ComponentStatusDto> {
    let bin_dir = PathBuf::from(install_path).join("bin");
    let target = match dig_installer::target::Target::current() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    dig_installer::update::check_updates(
        &bin_dir,
        &target,
        &dig_installer::update::live_latest_version_resolver,
    )
    .into_iter()
    .filter(|status| status.component != "digstore")
    .map(|status| match status.decision {
        Some(d) => ComponentStatusDto {
            component: status.component,
            action: Some(d.action.as_str().to_string()),
            installed_version: d.installed_version,
            latest_version: Some(d.latest_version),
            summary: d.summary,
        },
        None => ComponentStatusDto {
            component: status.component,
            action: None,
            installed_version: None,
            latest_version: None,
            summary: status
                .error
                .unwrap_or_else(|| "could not check for updates".to_string()),
        },
    })
    .collect()
}

/// Compute the new user-PATH string after appending `dir`.
///
/// Pure helper (no I/O, no env access) so the append logic is unit-testable
/// without touching the real machine PATH. Idempotent and case-insensitive on
/// Windows: if `dir` is already present (ignoring case and trailing
/// separators), the current PATH is returned unchanged so we never
/// double-append.
///
/// Returns `None` if no change is needed, `Some(new_path)` otherwise.
#[cfg(windows)]
fn user_path_append(current: &str, dir: &str) -> Option<String> {
    let dir_trimmed = dir.trim_end_matches('\\');
    let already = current
        .split(';')
        .map(|p| p.trim().trim_end_matches('\\'))
        .any(|p| p.eq_ignore_ascii_case(dir_trimmed));
    if already {
        return None;
    }
    if current.is_empty() {
        Some(dir.to_string())
    } else if current.ends_with(';') {
        Some(format!("{current}{dir}"))
    } else {
        Some(format!("{current};{dir}"))
    }
}

/// Add the install bin dir to PATH.
///   Windows: append to the USER PATH only (HKCU\Environment\Path), written as
///            REG_EXPAND_SZ with no truncation, then broadcast
///            WM_SETTINGCHANGE. No elevation, no machine-PATH involvement.
///   macOS/Linux: symlink the binary into /usr/local/bin (best-effort).
fn add_to_path(bin_dir: &Path) -> Result<String, String> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_EXPAND_SZ};
        use winreg::{RegKey, RegValue};

        let dir = bin_dir.to_string_lossy().to_string();
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        // Open the per-user environment key for read+write. It always exists,
        // but create_subkey is idempotent (opens if present) and returns the key.
        let (env, _disp) = hkcu
            .create_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
            .map_err(|e| format!("open HKCU\\Environment: {e}"))?;

        // Read ONLY the user PATH (not the merged process PATH). Missing value
        // is treated as empty so we create it below.
        let current: String = env.get_value("Path").unwrap_or_default();

        let new_path = match user_path_append(&current, &dir) {
            None => return Ok(format!("user PATH (already present): {dir}")),
            Some(p) => p,
        };

        // Write back as REG_EXPAND_SZ (so embedded %VARS% keep expanding) with
        // no length limit — unlike `setx`, which truncates at 1024 chars.
        let bytes = string_to_reg_expand_sz_bytes(&new_path);
        env.set_raw_value(
            "Path",
            &RegValue {
                vtype: REG_EXPAND_SZ,
                bytes,
            },
        )
        .map_err(|e| format!("write HKCU\\Environment\\Path: {e}"))?;

        broadcast_environment_change();
        Ok(format!("user PATH: {dir}"))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs as unixfs;
        let target = bin_dir.join("digstore");
        let link = PathBuf::from("/usr/local/bin/digstore");
        let _ = fs::remove_file(&link);
        unixfs::symlink(&target, &link)
            .map_err(|e| format!("symlink {} → {}: {e}", link.display(), target.display()))?;
        Ok(format!("{}", link.display()))
    }
}

/// Register the DIG brand icon as the icon for `.dig` files. Best-effort and
/// per-user on every platform — never elevates.
///   Windows: write the embedded `.ico` into the install dir, register a ProgID
///            under `HKCU\Software\Classes`, and notify the shell.
///   Linux:   install a shared-mime-info package + a hicolor mimetype icon for
///            `application/x-dig` under `~/.local/share`, then refresh caches.
///   macOS:   unsupported for a CLI-only install (a document type needs a
///            persistent `.app` to declare it); reported as skipped.
fn register_dig_association(install_dir: &Path) -> Result<String, String> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
        use winreg::RegKey;

        // Drop the icon next to the install so the ProgID points at a stable path.
        let icon_path = install_dir.join("digstore.ico");
        fs::write(&icon_path, DIG_ICON_ICO).map_err(|e| format!("write icon: {e}"))?;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let classes = "Software\\Classes";
        let prog_id = "DigStore.Store";

        // .dig -> ProgID
        let (ext, _) = hkcu
            .create_subkey_with_flags(format!("{classes}\\.dig"), KEY_WRITE)
            .map_err(|e| format!("create .dig key: {e}"))?;
        ext.set_value("", &prog_id)
            .map_err(|e| format!("set .dig default: {e}"))?;

        // ProgID description + DefaultIcon
        let (pid, _) = hkcu
            .create_subkey_with_flags(format!("{classes}\\{prog_id}"), KEY_WRITE)
            .map_err(|e| format!("create ProgID: {e}"))?;
        pid.set_value("", &"DigStore content-addressable store")
            .map_err(|e| format!("set ProgID default: {e}"))?;
        let (icon_key, _) = hkcu
            .create_subkey_with_flags(format!("{classes}\\{prog_id}\\DefaultIcon"), KEY_WRITE)
            .map_err(|e| format!("create DefaultIcon: {e}"))?;
        icon_key
            .set_value("", &format!("{},0", icon_path.display()))
            .map_err(|e| format!("set DefaultIcon: {e}"))?;

        notify_assoc_changed();
        Ok(format!("HKCU .dig → {prog_id}"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = install_dir; // not needed on Linux (per-user XDG dirs)
        let home = dirs::home_dir().ok_or("no home directory")?;
        let share = home.join(".local").join("share");

        // shared-mime-info package describing application/x-dig with *.dig.
        let mime_pkg_dir = share.join("mime").join("packages");
        fs::create_dir_all(&mime_pkg_dir).map_err(|e| format!("create mime dir: {e}"))?;
        let mime_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-dig">
    <comment>DigStore content-addressable store</comment>
    <glob pattern="*.dig"/>
  </mime-type>
</mime-info>
"#;
        fs::write(mime_pkg_dir.join("digstore.xml"), mime_xml)
            .map_err(|e| format!("write mime xml: {e}"))?;

        // hicolor mimetype icon: application-x-dig.png (freedesktop naming).
        let icon_dir = share
            .join("icons")
            .join("hicolor")
            .join("128x128")
            .join("mimetypes");
        fs::create_dir_all(&icon_dir).map_err(|e| format!("create icon dir: {e}"))?;
        fs::write(icon_dir.join("application-x-dig.png"), DIG_ICON_PNG)
            .map_err(|e| format!("write icon: {e}"))?;

        // Refresh caches (best-effort; ignore failures / missing tools). Each
        // tool is resolved to an ABSOLUTE path from a trusted system directory,
        // never via `$PATH` — no root-`PATH`-hijack / pwnkit-class surface if
        // this path is ever reached under elevation (#635 item 3). Fail-soft:
        // a missing tool simply skips its refresh.
        if let Some(tool) = dig_installer::elevation::resolve_system_tool("update-mime-database") {
            let _ = Command::new(tool).arg(share.join("mime")).status();
        }
        if let Some(tool) = dig_installer::elevation::resolve_system_tool("gtk-update-icon-cache") {
            let _ = Command::new(tool)
                .arg("-f")
                .arg(share.join("icons").join("hicolor"))
                .status();
        }
        Ok("~/.local/share MIME + icon".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = install_dir;
        Err("not supported for a CLI-only install".to_string())
    }
}

/// Tell the Windows shell that file associations changed so Explorer repaints
/// `.dig` icons without a logout.
#[cfg(windows)]
fn notify_assoc_changed() {
    use windows_sys::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};
    unsafe {
        SHChangeNotify(
            SHCNE_ASSOCCHANGED as i32,
            SHCNF_IDLIST,
            std::ptr::null(),
            std::ptr::null(),
        );
    }
}

/// Encode a string as the UTF-16LE, NUL-terminated byte buffer the registry
/// expects for REG_EXPAND_SZ.
#[cfg(windows)]
fn string_to_reg_expand_sz_bytes(s: &str) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut bytes = Vec::with_capacity(wide.len() * 2);
    for w in wide {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    bytes
}

/// Tell already-running processes that the environment changed, so new shells
/// (and Explorer) pick up the updated PATH without a reboot/logout.
#[cfg(windows)]
fn broadcast_environment_change() {
    use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    // "Environment" as a NUL-terminated UTF-16 string, passed as lParam.
    let param: Vec<u16> = "Environment"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut result: usize = 0;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST as HWND,
            WM_SETTINGCHANGE,
            0 as WPARAM,
            param.as_ptr() as LPARAM,
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        );
    }
}

#[cfg(test)]
mod plan_from_selection_tests {
    use super::{
        configure_extension_forcelist_step, plan_from_selection, summarize_forcelist_outcomes,
        wants_extension_forcelist, InstallOpts,
    };
    use dig_installer::forcelist::{ForcelistAction, ForcelistOutcome};
    use dig_installer::paths;
    use dig_installer::target::Os;
    use std::collections::HashMap;

    fn opts_with(extension: bool, browsers: &[&str]) -> InstallOpts {
        let mut selected = HashMap::new();
        selected.insert("extension".to_string(), extension);
        InstallOpts {
            install_path: "/opt/dig".to_string(),
            selected,
            selected_browsers: browsers.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn outcome(action: ForcelistAction, location: &str, note: &str) -> ForcelistOutcome {
        ForcelistOutcome {
            location: location.to_string(),
            action,
            note: note.to_string(),
        }
    }

    // #648: the force-install fires only when the extension component is selected
    // AND at least one browser is checked — the single gate the elevation
    // decision and the privileged write share.
    #[test]
    fn wants_forcelist_only_when_extension_selected_and_a_browser_is_chosen() {
        assert!(wants_extension_forcelist(&opts_with(true, &["chrome"])));
        // extension component deselected → no write, even if browsers are listed.
        assert!(!wants_extension_forcelist(&opts_with(false, &["chrome"])));
        // extension selected but every browser unchecked → nothing to write.
        assert!(!wants_extension_forcelist(&opts_with(true, &[])));
    }

    // #648 honesty invariant: a single Failed fails the whole step; a success mix
    // still reports a line per browser and returns Ok.
    #[test]
    fn summarize_forcelist_reports_a_line_per_browser_and_is_ok_when_none_failed() {
        let outcomes = vec![
            outcome(ForcelistAction::Wrote, "HKLM\\...\\Chrome", ""),
            outcome(
                ForcelistAction::AlreadyPresent,
                "HKLM\\...\\Brave",
                "idempotent",
            ),
            outcome(
                ForcelistAction::Skipped,
                "HKLM\\...\\Edge",
                "org policy present",
            ),
        ];
        let (lines, result) = summarize_forcelist_outcomes(&outcomes);
        assert_eq!(lines.len(), 3, "one honest log line per browser outcome");
        assert!(result.is_ok(), "no Failed outcome → the step succeeds");
    }

    #[test]
    fn summarize_forcelist_fails_the_step_when_any_browser_write_failed() {
        let outcomes = vec![
            outcome(ForcelistAction::Wrote, "HKLM\\...\\Chrome", ""),
            outcome(ForcelistAction::Failed, "HKLM\\...\\Brave", "access denied"),
        ];
        let (lines, result) = summarize_forcelist_outcomes(&outcomes);
        assert_eq!(lines.len(), 2);
        let err = result.expect_err("a Failed browser must fail the whole step");
        assert!(
            err.contains("Brave") && err.contains("access denied"),
            "the error names the failed browser + its cause, never swallows it: {err}"
        );
    }

    // #648: when the extension component is NOT selected, the step performs NO
    // policy write and emits nothing — a not-selected install never touches a
    // browser policy. (Exercises the real primitive with an empty selection.)
    #[test]
    fn forcelist_step_is_a_silent_noop_when_extension_not_selected() {
        let mut emitted = Vec::new();
        let result =
            configure_extension_forcelist_step(&opts_with(false, &["chrome"]), &mut |line| {
                emitted.push(line)
            });
        assert!(result.is_ok());
        assert!(
            emitted.is_empty(),
            "not-selected → no write, no log lines: {emitted:?}"
        );
    }

    // task #234: the selection→plan mapping is pure (no I/O), so every
    // selected/deselected/absent branch is asserted directly without mocking
    // the network or a service manager.

    // #611: the Browsers-step selection rides `InstallOpts.selected_browsers`.
    // It is optional on the wire (older frontends omit it) and defaults to an
    // empty list, and it round-trips the per-browser opt-in the GUI captured
    // for #612 to consume.
    #[test]
    fn install_opts_defaults_selected_browsers_to_empty_when_absent() {
        let opts: InstallOpts =
            serde_json::from_str(r#"{"install_path":"/opt/dig","selected":{"digstore":true}}"#)
                .expect("opts without selected_browsers should deserialize");
        assert!(opts.selected_browsers.is_empty());
    }

    #[test]
    fn install_opts_carries_the_selected_browser_ids() {
        let opts: InstallOpts = serde_json::from_str(
            r#"{"install_path":"/opt/dig","selected":{"extension":true},"selected_browsers":["chrome","brave"]}"#,
        )
        .expect("opts with selected_browsers should deserialize");
        assert_eq!(opts.selected_browsers, vec!["chrome", "brave"]);
    }

    // #638: the Linux pkexec relaunch streams the selection to the root child as
    // JSON over stdin (never a file, never spliced into the command). That requires
    // InstallOpts to round-trip losslessly through JSON — lock it so a field that
    // stops serializing (dropping it from the elevated child's plan) fails a test.
    #[test]
    fn install_opts_round_trips_through_json_for_the_elevated_stdin_handoff() {
        let mut selected = HashMap::new();
        selected.insert("dig-node".to_string(), true);
        selected.insert("auto-update".to_string(), false);
        let opts = InstallOpts {
            install_path: "/usr/local/digstore".to_string(),
            selected,
            selected_browsers: vec!["chrome".to_string(), "brave".to_string()],
        };
        let json = serde_json::to_string(&opts).expect("InstallOpts must serialize");
        let back: InstallOpts = serde_json::from_str(&json).expect("and deserialize");
        assert_eq!(back.install_path, opts.install_path);
        assert_eq!(back.selected, opts.selected);
        assert_eq!(back.selected_browsers, opts.selected_browsers);
    }

    #[test]
    fn nothing_selected_installs_nothing_extra() {
        let plan = plan_from_selection(&HashMap::new());
        assert!(
            !plan.with_digstore,
            "digstore is owned by the GUI's own pipeline, never this plan"
        );
        assert!(!plan.with_dig_node);
        assert!(!plan.with_dig_dns);
        assert!(!plan.with_relay);
        assert!(!plan.with_browser);
    }

    #[test]
    fn install_all_selects_every_optional_component() {
        let mut sel = HashMap::new();
        sel.insert("dig-node".to_string(), true);
        sel.insert("dig-dns".to_string(), true);
        sel.insert("dig-relay".to_string(), true);
        sel.insert("browser".to_string(), true);
        let plan = plan_from_selection(&sel);
        assert!(!plan.with_digstore);
        assert!(plan.with_dig_node);
        assert!(plan.with_dig_dns);
        assert!(plan.with_relay);
        assert!(plan.with_browser);
    }

    #[test]
    fn deselecting_a_component_skips_only_that_one() {
        let mut sel = HashMap::new();
        sel.insert("dig-node".to_string(), true);
        sel.insert("dig-dns".to_string(), false); // explicitly unchecked
        sel.insert("dig-relay".to_string(), true);
        sel.insert("browser".to_string(), true);
        let plan = plan_from_selection(&sel);
        assert!(plan.with_dig_node);
        assert!(!plan.with_dig_dns, "deselected component must be skipped");
        assert!(plan.with_relay);
        assert!(plan.with_browser);
    }

    // #610 regression (a): the GUI plan uses the built-in DEFAULT bin dir, NOT a
    // user-chosen custom dir — that is precisely what keeps `has_custom_bin_dir()`
    // false so the library's per-component protected-root routing engages. The
    // pre-fix GUI passed `%LOCALAPPDATA%\Programs\DigStore\bin` here (a custom
    // dir), which routed the WHOLE stack — including LocalSystem services — into
    // a user-writable dir (the #565 user→SYSTEM LPE).
    #[test]
    fn gui_plan_never_uses_a_custom_bin_dir() {
        let plan = plan_from_selection(&HashMap::new());
        assert_eq!(
            plan.bin_dir,
            paths::default_bin_dir(),
            "the GUI plan MUST use the built-in default bin dir, never a user-chosen one"
        );
        assert!(
            !plan.has_custom_bin_dir(),
            "a custom bin dir would defeat protected-root routing (#610/#565)"
        );
    }

    // #610 regression (b): a privileged/service-executed component (LocalSystem
    // dig-node/dig-dns services, the SYSTEM auto-update beacon) NEVER lands in a
    // user-writable dir — it resolves to the admin-only protected root, on every
    // OS, via the SAME `bin_dir_for`/`privileged_install_root` path the CLI uses.
    #[test]
    fn gui_plan_routes_privileged_components_to_the_protected_root() {
        let mut sel = HashMap::new();
        sel.insert("dig-node".to_string(), true);
        sel.insert("dig-dns".to_string(), true);
        let plan = plan_from_selection(&sel);

        // Windows: the whole stack is privileged → the protected Program Files root.
        for c in ["dig-node", "dig-dns", "dig-relay", "dig-updater"] {
            assert_eq!(
                plan.bin_dir_for(c, Os::Windows),
                paths::protected_bin_dir(),
                "{c} must route to the protected root on Windows"
            );
        }
        // unix: the machine-wide privileged binaries → /opt/dig/bin.
        for c in ["dig-dns", "dig-updater"] {
            assert_eq!(
                plan.bin_dir_for(c, Os::Linux),
                paths::protected_bin_dir(),
                "{c} must route to the protected root on unix"
            );
        }
        // And the #565 gates (migration + fail-loud ACL verify + audit) are armed
        // on the GUI path: the privileged install root is the protected root.
        assert_eq!(
            plan.privileged_install_root(Os::Windows),
            Some(paths::protected_bin_dir())
        );
        assert!(plan.installs_a_privileged_binary(Os::Windows));
    }

    // #610: the default GUI plan (services + beacon on) requires elevation on
    // every OS — no silent unprivileged install of privileged components.
    #[test]
    fn default_gui_plan_requires_elevation_on_every_os() {
        let plan = plan_from_selection(&HashMap::new());
        for os in [Os::Windows, Os::Linux, Os::MacOs] {
            assert!(
                plan.requires_elevation(os),
                "the default GUI plan installs services + the beacon → needs elevation on {os:?}"
            );
        }
    }

    // #610 regression (HIGH — the NEW LPE the requireAdministrator switch opened):
    // the elevated GUI unpacks AND executes the bundled digstore CLI, so it MUST
    // place + run it from the admin-only protected root on Windows — never a
    // user-writable dir a medium-IL process could swap in the write→exec window.
    // Pre-fix the GUI wrote digstore into user-writable `%LOCALAPPDATA%\...\bin`
    // and executed it inside the high-integrity process (admin-runs-user-writable
    // = LPE). Routed via the SAME `bin_dir_for` the CLI installer uses.
    #[test]
    fn gui_places_and_executes_digstore_from_the_protected_root_on_windows() {
        let plan = plan_from_selection(&HashMap::new());
        let dir = plan.bin_dir_for("digstore", Os::Windows);
        assert_eq!(
            dir,
            paths::protected_bin_dir(),
            "the elevated GUI must unpack + execute digstore from the admin-only \
             protected root on Windows, never a user-writable dir"
        );
        // NEVER a user-writable legacy AppData root (the pre-fix LPE location).
        for legacy in paths::legacy_privileged_roots(Os::Windows) {
            assert_ne!(dir, legacy, "digstore must not land in a user-writable dir");
        }
    }

    // #610: every binary the elevated process runs is routed to the protected
    // root on Windows — the digstore CLI (GUI-owned) AND the privileged
    // service/beacon binaries (library-owned via `run_report`).
    #[test]
    fn every_windows_executed_binary_lands_in_the_protected_root() {
        let mut sel = HashMap::new();
        sel.insert("dig-node".to_string(), true);
        sel.insert("dig-dns".to_string(), true);
        let plan = plan_from_selection(&sel);
        for c in [
            "digstore",
            "dig-node",
            "dig-dns",
            "dig-relay",
            "dig-updater",
        ] {
            assert_eq!(
                plan.bin_dir_for(c, Os::Windows),
                paths::protected_bin_dir(),
                "{c} is executed by the elevated GUI/services → must be protected-root"
            );
        }
    }

    // #610: digstore's protected-root placement drives elevation. On Windows it
    // lands in Program Files (privileged write) → a digstore-only GUI run must
    // elevate too; on unix it is a user-run CLI in ~/.dig/bin → no elevation from
    // digstore alone. `super::places_digstore_in_protected_root` is the pure
    // predicate `run()` ORs into its elevation decision.
    #[test]
    fn digstore_placement_requires_elevation_only_on_windows() {
        assert!(
            super::places_digstore_in_protected_root(Os::Windows),
            "digstore lands in Program Files on Windows → elevated write"
        );
        assert!(!super::places_digstore_in_protected_root(Os::Linux));
        assert!(!super::places_digstore_in_protected_root(Os::MacOs));
    }

    // #610: on unix the GUI digstore CLI stays in the elevation-free per-user
    // root (executed AS the user, so not an escalation) — matching the CLI.
    #[test]
    fn gui_places_digstore_in_the_user_root_on_unix() {
        let plan = plan_from_selection(&HashMap::new());
        for os in [Os::Linux, Os::MacOs] {
            assert_eq!(
                plan.bin_dir_for("digstore", os),
                paths::default_bin_dir(),
                "unix digstore is a user-run CLI in ~/.dig/bin, not the protected root"
            );
        }
    }

    // #637 run()-layer test-lock (#635 item 1): the dir run() WRITES AND
    // EXECUTES digstore from is resolved SOLELY via the vetted #565
    // `bin_dir_for` routing — never a bespoke user-writable path. This locks the
    // routing so a revert (e.g. hardcoding `~/.dig/bin` or an AppData dir back
    // into `run()`) fails a test rather than silently reopening the #610 LPE for
    // the future elevated unix run.
    #[test]
    fn digstore_write_exec_dir_uses_the_565_routing() {
        let plan = plan_from_selection(&HashMap::new());
        // The resolver's output MUST equal the library routing, verbatim, per OS.
        for os in [Os::Windows, Os::Linux, Os::MacOs] {
            assert_eq!(
                super::digstore_write_exec_dir(&plan, Some(os)),
                plan.bin_dir_for("digstore", os),
                "the write+exec dir must come from bin_dir_for on {os:?}"
            );
        }
        // Windows: the admin-only protected root — never a user-writable dir.
        let win = super::digstore_write_exec_dir(&plan, Some(Os::Windows));
        assert_eq!(win, paths::protected_bin_dir());
        for legacy in paths::legacy_privileged_roots(Os::Windows) {
            assert_ne!(
                win, legacy,
                "the elevated Windows write+exec dir must never be user-writable"
            );
        }
        // Unresolved OS falls back to the library default — never a bespoke path.
        assert_eq!(
            super::digstore_write_exec_dir(&plan, None),
            paths::default_bin_dir(),
            "an unresolved OS falls back to the vetted default bin dir"
        );
    }

    // #637 / #635 item 2 / #610: an elevated process must NOT exec a binary from
    // a user-writable dir. `should_exec_verify` is the pure gate `run()`'s
    // Phase-6 verify keys off; the truth table is locked here.
    #[test]
    fn exec_verify_is_gated_on_elevation_and_the_binary_location() {
        // Unelevated: always safe to exec our own binary (no escalation).
        assert!(super::should_exec_verify(false, false));
        assert!(super::should_exec_verify(false, true));
        // Elevated + protected-root binary (root-owned, unswappable): safe.
        assert!(super::should_exec_verify(true, true));
        // Elevated + user-writable binary: DEFERRED — the exact LPE this closes.
        assert!(
            !super::should_exec_verify(true, false),
            "an elevated run must never exec a user-writable binary"
        );
    }

    // #637 / #635 item 3: the association cache-refresh tools now resolve via the
    // library's `dig_installer::elevation::resolve_system_tool` (the single source
    // of truth for trusted absolute-path resolution, tested in the library) — no
    // duplicate resolver lives in the GUI crate.

    #[test]
    fn scheme_handler_defaults_on_in_sync_with_the_cli() {
        // #389: absent from the selection map -> ON by default, matching the
        // CLI's default-on `register_scheme` (GUI + CLI defaults in sync).
        let plan = plan_from_selection(&HashMap::new());
        assert!(
            plan.register_scheme,
            "the chia:// scheme handler defaults ON in the GUI, mirroring the CLI"
        );
    }

    #[test]
    fn scheme_handler_can_be_toggled_off() {
        // A GUI toggle sends `"register-scheme": false` — the same opt-out the
        // CLI's `--no-register-scheme` produces.
        let mut sel = HashMap::new();
        sel.insert("register-scheme".to_string(), false);
        let plan = plan_from_selection(&sel);
        assert!(
            !plan.register_scheme,
            "an explicit opt-out disables the handler"
        );
    }

    #[test]
    fn firewall_rule_defaults_on_in_sync_with_the_cli() {
        // #424: absent from the selection map -> ON by default, matching the
        // CLI's default-on `open_firewall` (GUI + CLI defaults in sync).
        let plan = plan_from_selection(&HashMap::new());
        assert!(
            plan.open_firewall,
            "the dig-node firewall rule defaults ON in the GUI, mirroring the CLI"
        );
    }

    #[test]
    fn firewall_rule_can_be_toggled_off() {
        // A GUI toggle sends `"open-firewall": false` — the same opt-out the
        // CLI's `--no-open-firewall` produces.
        let mut sel = HashMap::new();
        sel.insert("open-firewall".to_string(), false);
        let plan = plan_from_selection(&sel);
        assert!(
            !plan.open_firewall,
            "an explicit opt-out disables the firewall rule"
        );
    }

    #[test]
    fn auto_update_beacon_defaults_on_in_sync_with_the_cli() {
        // #514: absent from the selection map -> ON by default, matching the
        // CLI's default-on `auto_update` (GUI + CLI defaults in sync).
        let plan = plan_from_selection(&HashMap::new());
        assert!(
            plan.auto_update,
            "the auto-update beacon defaults ON in the GUI, mirroring the CLI"
        );
    }

    #[test]
    fn auto_update_beacon_can_be_toggled_off() {
        // A GUI toggle sends `"auto-update": false` — the same opt-out the
        // CLI's `--no-auto-update` produces.
        let mut sel = HashMap::new();
        sel.insert("auto-update".to_string(), false);
        let plan = plan_from_selection(&sel);
        assert!(
            !plan.auto_update,
            "an explicit opt-out disables the auto-update beacon"
        );
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::user_path_append;

    #[test]
    fn appends_when_absent() {
        assert_eq!(
            user_path_append(r"C:\Windows;C:\Tools", r"C:\Apps\DigStore\bin"),
            Some(r"C:\Windows;C:\Tools;C:\Apps\DigStore\bin".to_string())
        );
    }

    #[test]
    fn no_change_when_already_present() {
        assert_eq!(
            user_path_append(r"C:\Windows;C:\Apps\DigStore\bin", r"C:\Apps\DigStore\bin"),
            None
        );
    }

    #[test]
    fn idempotent_case_insensitive() {
        // Different case must NOT double-append.
        assert_eq!(
            user_path_append(r"C:\windows;c:\apps\digstore\BIN", r"C:\Apps\DigStore\bin"),
            None
        );
    }

    #[test]
    fn idempotent_ignores_trailing_backslash() {
        assert_eq!(
            user_path_append(r"C:\Apps\DigStore\bin\", r"C:\Apps\DigStore\bin"),
            None
        );
    }

    #[test]
    fn creates_value_when_empty() {
        assert_eq!(
            user_path_append("", r"C:\Apps\DigStore\bin"),
            Some(r"C:\Apps\DigStore\bin".to_string())
        );
    }

    #[test]
    fn handles_trailing_separator_without_blank_entry() {
        // A PATH that ends in ';' should not produce an empty segment.
        assert_eq!(
            user_path_append(r"C:\Windows;", r"C:\Apps\DigStore\bin"),
            Some(r"C:\Windows;C:\Apps\DigStore\bin".to_string())
        );
    }
}
