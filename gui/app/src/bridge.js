/* bridge.js — the single seam between the React UI and the host.
 *
 * In a packaged Tauri build it calls real Rust commands (invoke) and listens
 * to the `install://progress` / `install://error` / `install://done` events
 * streamed by the backend. In a plain browser (vite dev without Tauri, or the
 * static `vite preview`) it falls back to a faithful simulation so the UI is
 * still demonstrable. Everything the UI needs goes through here. */

let _invoke = null;
let _listen = null;
let _dialog = null;
let _shell = null;
let _clipboard = null;

const _tauri = typeof window !== "undefined" && !!window.__TAURI_INTERNALS__;

export function isTauri() {
  return _tauri;
}

async function api() {
  if (!_tauri) return null;
  if (!_invoke) {
    const core = await import("@tauri-apps/api/core");
    const event = await import("@tauri-apps/api/event");
    _invoke = core.invoke;
    _listen = event.listen;
  }
  return { invoke: _invoke, listen: _listen };
}

export async function getMeta() {
  const a = await api();
  if (!a) return { version: "1.0.0", compiler: "1.0.0" };
  try {
    return await a.invoke("installer_meta");
  } catch {
    return { version: "1.0.0", compiler: "1.0.0" };
  }
}

/* bundledDigstoreVersion — the semver of the bundled `digstore` CLI this
 * installer will install (from `digstore --version` in the app resources).
 * This is the version the badge shows, not the installer app's own version.
 * In a plain browser (no bundled binary) we fall back to the current ship
 * version so the badge never blanks out. */
export async function bundledDigstoreVersion() {
  const a = await api();
  if (!a) return "0.3.0";
  try {
    const v = await a.invoke("bundled_digstore_version");
    return typeof v === "string" && v.trim() ? v.trim() : "0.3.0";
  } catch {
    return "0.3.0";
  }
}

export async function defaultInstallPath() {
  const a = await api();
  if (!a) return "/usr/local/digstore";
  try {
    return await a.invoke("default_install_path");
  } catch {
    return "/usr/local/digstore";
  }
}

/* componentUpdateStatus — per-component Install/Update/Skip preview for the
 * Components screen (issue #309): checks dig-node/dig-dns against
 * `installPath` BEFORE the user clicks Install. In a plain browser (no
 * backend to check against) it falls back to a representative demo dataset —
 * same "still demonstrable outside Tauri" convention as `simulateInstall`
 * below — so the screen's Install/Update/Up-to-date pills are visible in a
 * plain `vite dev`/`preview` run, not just a packaged build. */
const SIM_COMPONENT_STATUS = [
  {
    component: "dig-node",
    action: "update",
    installed_version: "0.14.0",
    latest_version: "0.15.0",
    summary: "v0.14.0 → v0.15.0 (update)",
  },
  {
    component: "dig-dns",
    action: "skip",
    installed_version: "0.9.1",
    latest_version: "0.9.1",
    summary: "v0.9.1 (up to date)",
  },
];

export async function componentUpdateStatus(installPath) {
  const a = await api();
  if (!a) return SIM_COMPONENT_STATUS;
  try {
    return await a.invoke("component_update_status", { installPath });
  } catch {
    return [];
  }
}

/* detectBrowsers — the installed Chromium-family browsers (#609 detection),
 * for the conditional Browsers step (#611). Each entry is a `DetectedBrowser`
 * ({ id, display_name, kind, install_path, detected, policy_target }). In a
 * plain browser (no backend) it returns a representative demo list — the same
 * "still demonstrable outside Tauri" convention as `simulateInstall` — so the
 * checklist is visible in a `vite dev`/`preview` run, not just a packaged
 * build. A detection failure in a packaged build rejects so the step can show
 * its error/Retry state. */
const SIM_DETECTED_BROWSERS = [
  { id: "chrome", display_name: "Google Chrome", kind: "chromium-family", install_path: "/opt/google/chrome/chrome", detected: true },
  { id: "edge", display_name: "Microsoft Edge", kind: "chromium-family", install_path: "/opt/microsoft/msedge/msedge", detected: true },
  { id: "brave", display_name: "Brave", kind: "chromium-family", install_path: "/usr/bin/brave-browser", detected: true },
];

export async function detectBrowsers() {
  const a = await api();
  if (!a) return SIM_DETECTED_BROWSERS;
  return a.invoke("detect_browsers");
}

export async function pickFolder(current) {
  if (!_tauri) {
    const v = window.prompt("Install location", current);
    return v || null;
  }
  try {
    if (!_dialog) _dialog = await import("@tauri-apps/plugin-dialog");
    const dir = await _dialog.open({ directory: true, multiple: false, defaultPath: current, title: "Choose install location" });
    if (!dir) return null;
    // Tauri returns the chosen parent dir; append the product folder name so
    // the field reads like the per-OS default (…/DigStore).
    return dir;
  } catch {
    return null;
  }
}

export async function copyText(text) {
  if (_tauri) {
    try {
      if (!_clipboard) _clipboard = await import("@tauri-apps/plugin-clipboard-manager");
      await _clipboard.writeText(text);
      return;
    } catch {
      /* fall through to web clipboard */
    }
  }
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    /* clipboard unavailable */
  }
}

export async function launchTerminal(installPath) {
  const a = await api();
  if (a) {
    try {
      await a.invoke("launch_terminal", { installPath });
      return;
    } catch {
      /* ignore; nothing else to do in a desktop context */
    }
  }
  // browser fallback: no terminal available
  console.info("[installer] launch terminal (no-op in browser)", installPath);
}

export async function openDocs() {
  const url = "https://docs.dig.net/docs/digstore/what-is-digstore";
  if (_tauri) {
    try {
      if (!_shell) _shell = await import("@tauri-apps/plugin-shell");
      await _shell.open(url);
      return;
    } catch {
      /* fall through */
    }
  }
  try {
    window.open(url, "_blank");
  } catch {
    /* ignore */
  }
}

/* closeWindow — close the installer window (the Finish-view Close button, so
 * the user always has a one-click way out once the install is done). In Tauri
 * it asks the current window to close (the same `getCurrentWindow().close()`
 * the title-bar close control uses); in a plain browser (dev/preview) it falls
 * back to `window.close()` so the button is still demonstrable. */
export async function closeWindow() {
  if (_tauri) {
    try {
      const win = await import("@tauri-apps/api/window");
      await win.getCurrentWindow().close();
      return;
    } catch {
      /* fall through to the web fallback */
    }
  }
  try {
    window.close();
  } catch {
    /* nothing else to do outside a closable window */
  }
}

/* runInstall — drives the real pipeline. Resolves when the install finishes
 * (success or error). Streams updates through the callbacks. */
export async function runInstall(opts, { onProgress, onError, onDone }) {
  const a = await api();
  if (!a) return simulateInstall(opts, { onProgress, onError, onDone });

  // IMPORTANT: `run_install` spawns a worker thread and returns immediately, so
  // `invoke` resolves almost instantly — long before the pipeline finishes. The
  // listeners must therefore stay alive until `install://done` or
  // `install://error` arrives; tearing them down right after `invoke` (the old
  // try/finally) dropped every progress event after the first, freezing the UI
  // at ~2%.
  let unlistenP, unlistenE, unlistenD;
  const cleanup = () => {
    unlistenP && unlistenP();
    unlistenE && unlistenE();
    unlistenD && unlistenD();
    unlistenP = unlistenE = unlistenD = null;
  };
  return new Promise((resolve) => {
    (async () => {
      try {
        unlistenP = await a.listen("install://progress", (e) => onProgress(e.payload || {}));
        unlistenE = await a.listen("install://error", (e) => {
          onError(e.payload || { message: "unknown error" });
          cleanup();
          resolve();
        });
        unlistenD = await a.listen("install://done", () => {
          onDone();
          cleanup();
          resolve();
        });
        await a.invoke("run_install", {
          opts: {
            install_path: opts.installPath,
            selected: opts.selected,
            // The per-browser extension selection #612 consumes (the ids of the
            // detected browsers the user kept checked). Empty when the extension
            // component is deselected.
            selected_browsers: opts.selectedBrowsers || [],
          },
        });
        // Do NOT clean up here — wait for done/error above.
      } catch (err) {
        onError({ message: err?.message || String(err) });
        cleanup();
        resolve();
      }
    })();
  });
}

export async function cancelInstall() {
  const a = await api();
  if (!a) return;
  try {
    await a.invoke("cancel_install");
  } catch {
    /* nothing in flight */
  }
}

/* ---- browser-only simulation (parity with the prototype timings) ---- */
const SIM_LOG = [
  { t: 240, html: '<span class="dim">$</span> dig-installer --target {PATH}' },
  { t: 520, html: 'Resolving release <span class="ac">v1.0.0</span> · compiler 1.0.0 · module format 1' },
  { t: 900, html: '<span class="ok">✓</span> Verified package checksum <span class="dim">(SHA-256 manifest)</span>' },
  { t: 1300, html: 'Unpacking <span class="ac">DigStore CLI</span> → {PATH}/bin' },
  { t: 1750, html: 'Unpacking <span class="ac">Host Runtime</span> <span class="dim">(64 KiB → 16 MiB memory bounds)</span>' },
  { t: 2200, html: 'Embedding trusted host keys <span class="dim">dig-host-key-v1:…</span>' },
  { t: 2650, html: '<span class="ok">✓</span> Content-defined chunking ready <span class="dim">(16/64/256 KiB)</span>' },
  { t: 3050, html: 'Linking <span class="ac">digstore</span> → PATH' },
  { t: 3450, html: 'Installing shell completions <span class="dim">bash · zsh · fish</span>' },
  { t: 3850, html: '<span class="ok">✓</span> Verifying install · digstore --version' },
  { t: 4150, html: '<span class="ok">✓</span> DIG is ready.' },
];
const SIM_FILES = ["bin/digstore", "lib/dig_host.wasm", "lib/compiler.wasm", "share/completions/_digstore", "trusted/host-keys.toml", "examples/hello.wasm"];

function simulateInstall(opts, { onProgress, onError, onDone }) {
  return new Promise((resolve) => {
    const path = opts.installPath || "/usr/local/digstore";
    const timers = SIM_LOG.map((ev) =>
      setTimeout(() => onProgress({ line: ev.html.replaceAll("{PATH}", path) }), ev.t)
    );
    const start = performance.now();
    const dur = 4150;
    let raf;
    const tick = (now) => {
      const p = Math.min(100, ((now - start) / dur) * 100);
      onProgress({ pct: p, nowFile: SIM_FILES[Math.min(SIM_FILES.length - 1, Math.floor((p / 100) * SIM_FILES.length))] });
      if (p < 100) raf = requestAnimationFrame(tick);
      else {
        timers.forEach(clearTimeout);
        onDone();
        resolve();
      }
    };
    raf = requestAnimationFrame(tick);
  });
}
