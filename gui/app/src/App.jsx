import { useState, useEffect, useCallback, useRef } from "react";
import { TitleBar } from "./TitleBar.jsx";
import { Welcome } from "./steps/Welcome.jsx";
import { License } from "./steps/License.jsx";
import { Components } from "./steps/Components.jsx";
import { Browsers } from "./steps/Browsers.jsx";
import { Installing } from "./steps/Installing.jsx";
import { Finish } from "./steps/Finish.jsx";
import { LanguageSelector } from "./i18n/LanguageSelector.jsx";
import { FooterActions } from "./FooterActions.jsx";
import { NOW_FILES } from "./data.jsx";
import { computeSteps } from "./steps.js";
import glowD from "./assets/logos/D-glow-logo.svg";
import nebula from "./assets/logos/galaxy-background.webp";
import {
  isTauri,
  defaultInstallPath,
  pickFolder,
  runInstall,
  cancelInstall,
  openDocs,
  closeWindow,
  copyText,
  getMeta,
  bundledDigstoreVersion,
  componentUpdateStatus,
  detectBrowsers,
} from "./bridge.js";

const DEFAULT_META = { version: "1.0.0", compiler: "1.0.0" };
// Fallback for the bundled digstore CLI version until the backend answers
// (matches bridge.js' browser-sim fallback and the current ship version).
const DEFAULT_DIGSTORE_VERSION = "0.3.0";

export function App() {
  // chrome: pick the OS-appropriate window controls. Windows → "win",
  // macOS → "mac", else frameless dots. (Mirrors the prototype's tweak.)
  const [chrome] = useState(() => {
    const ua = navigator.userAgent || "";
    if (/Mac/i.test(ua)) return "mac";
    if (/Win/i.test(ua)) return "win";
    return "frameless";
  });

  const [meta, setMeta] = useState(DEFAULT_META);
  // #562: set when the install stages a reboot-deferred replace of a running
  // binary — the Finish step then shows a restart-required notice.
  const [restartRequired, setRestartRequired] = useState(false);
  // The bundled digstore CLI version this installer will install — shown on the
  // badge and the Welcome/Finish "version" chips (distinct from the installer
  // app's own version in `meta.version`).
  const [digstoreVersion, setDigstoreVersion] = useState(DEFAULT_DIGSTORE_VERSION);
  // Always start at Welcome — the installer never resumes a prior run's step.
  const [step, setStep] = useState(0);
  const [agreed, setAgreed] = useState(false);
  // The core DIG stack (dig-node + dig-dns) is pre-selected — the one-click
  // default path (digstore is always installed, added separately below). Per
  // task #491, `dig-relay` defaults OFF (advanced/optional — the node already
  // uses relay.dig.net) but stays user-checkable, and the DIG Browser is not
  // offered (hidden in `data.jsx`), so it is absent here entirely. `open-firewall`
  // (#424) and `auto-update` (#514) default ON, mirroring the CLI's default-on
  // `open_firewall`/`auto_update`.
  // The extension (#602/#611) is pre-checked; keeping it selected reveals the
  // conditional Browsers step (see `steps` below) where the user picks which
  // detected browsers get the managed extension.
  const [sel, setSel] = useState({
    "dig-node": true,
    "dig-dns": true,
    "dig-relay": false,
    extension: true,
    "open-firewall": true,
    "auto-update": true,
  });
  const [installPath, setInstallPath] = useState("/usr/local/digstore");
  // Per-component Install/Update/Skip preview (#309) for the Components
  // screen — `null` while unchecked/loading, so the screen can distinguish
  // "haven't checked yet" from "checked, nothing tracked".
  const [componentStatus, setComponentStatus] = useState(null);
  const [pct, setPct] = useState(0);
  const [lines, setLines] = useState([]);
  const [nowFile, setNowFile] = useState(NOW_FILES[0]);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(null);

  // Conditional Browsers step (#611): `browsers` is the detected list (`null`
  // until the host answers), `browserSel` the per-browser opt-in map (every
  // detected browser defaults ON), plus the loading/error async states and a
  // token that re-runs detection on Retry.
  const [browsers, setBrowsers] = useState(null);
  const [browserSel, setBrowserSel] = useState({});
  const [browsersLoading, setBrowsersLoading] = useState(false);
  const [browsersError, setBrowsersError] = useState(null);
  const [detectToken, setDetectToken] = useState(0);

  // The visible steps for the current selection: the Browsers step appears only
  // while the extension component is selected. Everything (rail, dots, nav, the
  // install trigger) keys off this one computed list rather than magic indices.
  const steps = computeSteps(sel);
  const cur = steps[step]?.id ?? "welcome";
  const nextId = steps[step + 1]?.id;

  const installToken = useRef(0); // bump to cancel/ignore stale install streams

  // Latest install inputs, read at call time so `startInstall` can stay stable
  // (deps: []). Without this, the async default-path resolve recreates
  // startInstall mid-install, re-running the effect → token bump → frozen UI.
  const installPathRef = useRef(installPath);
  const selRef = useRef(sel);
  const browsersRef = useRef(browsers);
  const browserSelRef = useRef(browserSel);
  useEffect(() => {
    installPathRef.current = installPath;
  }, [installPath]);
  useEffect(() => {
    selRef.current = sel;
  }, [sel]);
  useEffect(() => {
    browsersRef.current = browsers;
  }, [browsers]);
  useEffect(() => {
    browserSelRef.current = browserSel;
  }, [browserSel]);

  // No step persistence across runs: clear any key written by older builds so a
  // stale "dig_step" can never reopen the wizard mid-flow / on the Done screen.
  useEffect(() => {
    try {
      localStorage.removeItem("dig_step");
    } catch {
      /* ignore */
    }
  }, []);

  // Resolve the real per-OS default install path + version metadata from the backend.
  useEffect(() => {
    let alive = true;
    (async () => {
      const p = await defaultInstallPath();
      if (alive && p) setInstallPath(p);
      const m = await getMeta();
      if (alive && m) setMeta(m);
      // The badge/chips show the bundled digstore CLI version, not the app's.
      const dv = await bundledDigstoreVersion();
      if (alive && dv) setDigstoreVersion(dv);
    })();
    return () => {
      alive = false;
    };
  }, []);

  // Re-check per-component Install/Update/Skip status (#309) each time the
  // Components screen is shown, against whatever install path is current —
  // a fresh check per visit rather than a stale one from an earlier path.
  useEffect(() => {
    if (cur !== "components") return;
    let alive = true;
    setComponentStatus(null);
    (async () => {
      const status = await componentUpdateStatus(installPath);
      if (alive) setComponentStatus(status);
    })();
    return () => {
      alive = false;
    };
  }, [cur, installPath]);

  // Detect the installed browsers whenever the Browsers step is shown (and on
  // Retry, via `detectToken`). Every detected browser defaults to opted-IN;
  // a prior opt-out is preserved across a re-detect. All four async states
  // (loading / error / empty / success) are surfaced to the step (§6.1).
  useEffect(() => {
    if (cur !== "browsers") return;
    let alive = true;
    setBrowsersLoading(true);
    setBrowsersError(null);
    (async () => {
      try {
        const list = await detectBrowsers();
        if (!alive) return;
        setBrowsers(list);
        setBrowserSel((prev) => {
          const next = {};
          for (const b of list) next[b.id] = prev[b.id] ?? true;
          return next;
        });
      } catch (e) {
        if (alive) setBrowsersError(e?.message || String(e));
      } finally {
        if (alive) setBrowsersLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [cur, detectToken]);

  // Keep the step index valid if the visible-step count shrinks (e.g. the
  // extension is deselected on Components, removing the Browsers step).
  useEffect(() => {
    if (step >= steps.length) setStep(steps.length - 1);
  }, [steps.length, step]);

  // ---- the real install (replaces the prototype's rAF animation) ----
  const startInstall = useCallback(async () => {
    const token = ++installToken.current;
    setPct(0);
    setLines([]);
    setError(null);
    setNowFile(NOW_FILES[0]);

    // The browser selection #612 consumes: the ids of the detected browsers the
    // user kept checked (empty when the extension is deselected). Read from refs
    // at call time so `startInstall` stays dependency-free.
    const selectedBrowsers = selRef.current.extension
      ? (browsersRef.current || [])
          .filter((b) => browserSelRef.current[b.id])
          .map((b) => b.id)
      : [];

    await runInstall(
      {
        installPath: installPathRef.current,
        selected: { digstore: true, ...selRef.current },
        selectedBrowsers,
      },
      {
        onProgress: (p) => {
          if (token !== installToken.current) return;
          if (typeof p.pct === "number") setPct(p.pct);
          if (p.nowFile) setNowFile(p.nowFile);
          if (p.line) {
            setLines((prev) => [...prev, p.line]);
            // #562: the CLI emits a "RESTART REQUIRED" verdict when a running
            // binary's update was staged for a reboot. Surface it on Finish so a
            // reboot-deferred install never reads as fully done.
            if (/RESTART REQUIRED/i.test(p.line)) setRestartRequired(true);
          }
        },
        onError: (err) => {
          if (token !== installToken.current) return;
          setError({ title: "Installation failed", message: err.message || String(err) });
          setLines((prev) => [
            ...prev,
            `<span class="err">✗ ${escapeHtml(err.message || String(err))}</span>`,
          ]);
        },
        onDone: () => {
          if (token !== installToken.current) return;
          setPct(100);
          setNowFile("done");
        },
      }
    );
  }, []);

  useEffect(() => {
    if (cur === "installing") startInstall();
    // leaving the Installing step cancels any in-flight stream
    return () => {
      if (cur === "installing") {
        installToken.current++;
        cancelInstall();
      }
    };
  }, [cur, startInstall]);

  const toggle = (id) => setSel((s) => ({ ...s, [id]: !s[id] }));
  const toggleBrowser = (id) => setBrowserSel((s) => ({ ...s, [id]: !s[id] }));
  // Retry detection: clear the prior result and bump the token so the effect
  // above re-runs against the host.
  const retryDetect = () => {
    setBrowsers(null);
    setBrowsersError(null);
    setDetectToken((t) => t + 1);
  };

  const onChangeFolder = async () => {
    const dir = await pickFolder(installPath);
    if (dir) setInstallPath(dir);
  };

  const copyCmds = async () => {
    // Displayed lines mirror the prototype verbatim for design fidelity, but the
    // clipboard payload uses the real CLI's runnable form (this build's `init`
    // takes no positional store name; the store is created in the cwd's .dig).
    await copyText("digstore init\ndigstore add ./site\ndigstore commit -m \"v1\"");
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  const retry = () => {
    setError(null);
    startInstall();
  };

  const installing = cur === "installing";
  const installDone = installing && pct >= 100 && !error;
  const canContinue = cur === "license" ? agreed : installing ? installDone : true;

  // Welcome/Finish "version" chips should show the bundled digstore CLI version
  // being installed, not the installer app's own version.
  const digstoreMeta = { ...meta, version: digstoreVersion };

  // The primary button's label follows the CURRENT step's role in the flow:
  // the last step before Installing reads "Install" (whether that's Components
  // or, when the extension is selected, Browsers), so the label is correct
  // regardless of the conditional step.
  const primaryLabel =
    cur === "welcome"
      ? "Install DIG"
      : installing
      ? error
        ? "Retry"
        : installDone
        ? "Continue"
        : "Installing…"
      : nextId === "installing"
      ? "Install"
      : "Continue";

  const go = (n) => {
    if (n >= 0 && n < steps.length) setStep(n);
  };

  const next = async () => {
    if (installing && error) return retry();
    if (canContinue) go(step + 1);
  };

  return (
    <div className="win">
      <TitleBar chrome={chrome} />
      <div className="body">
        {/* rail — gains `installing` while the pipeline runs so the brand glow
            intensifies with progress (--rail-pct drives the glow strength). */}
        <div
          className={"rail" + (installing && !error ? " installing" : "")}
          style={{ "--rail-pct": installing ? pct / 100 : 0 }}
        >
          <div className="nebula" style={{ backgroundImage: `url(${nebula})` }}></div>
          <div className="rail-top">
            <div className="bigD">
              <img src={glowD} alt="DIG" />
            </div>
            <h1>DIG</h1>
            <div className="tagline">Everything you need for the DIG Network — the digstore CLI, your dig-node, and .dig name resolution.</div>
            <div className="ver-pill">
              <span className="dot"></span>digstore v{digstoreVersion}
            </div>
          </div>
          <div className="steps">
            {steps.map((s, i) => (
              <div
                key={s.id}
                className={"step" + (i === step ? " active" : i < step ? " done" : "")}
                onClick={() => i < step && !installing && go(i)}
              >
                <span className="idx">
                  {i < step ? (
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M4 12.5l5 5L20 6.5" />
                    </svg>
                  ) : (
                    i + 1
                  )}
                </span>
                {s.label}
              </div>
            ))}
          </div>
          <div className="rail-foot">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#7CE0A8" strokeWidth="2">
              <circle cx="12" cy="12" r="9" />
            </svg>
            A Proof-of-Stake Layer 2 on Chia
          </div>
        </div>

        {/* content */}
        <div className="content">
          <div className="pane" key={step}>
            {cur === "welcome" && <Welcome meta={digstoreMeta} />}
            {cur === "license" && <License agreed={agreed} setAgreed={setAgreed} />}
            {cur === "components" && (
              <Components sel={sel} toggle={toggle} path={installPath} onChange={onChangeFolder} status={componentStatus} />
            )}
            {cur === "browsers" && (
              <Browsers
                browsers={browsers}
                sel={browserSel}
                loading={browsersLoading}
                error={browsersError}
                onToggle={toggleBrowser}
                onRetry={retryDetect}
              />
            )}
            {cur === "installing" && <Installing pct={pct} lines={lines} nowFile={nowFile} error={error} />}
            {cur === "finish" && (
              <Finish
                path={installPath}
                onCopy={copyCmds}
                copied={copied}
                meta={digstoreMeta}
                restartRequired={restartRequired}
              />
            )}
          </div>
          <div className="footer">
            <div className="foot-left">
              <LanguageSelector />
              <div className="dots">
                {steps.map((s, i) => (
                  <span key={s.id} className={"d" + (i === step ? " on" : "")}></span>
                ))}
              </div>
            </div>

            {/* The action row wraps below the left cluster on a narrow window /
                long-label locale rather than clipping past the edge (#716). */}
            <FooterActions
              cur={cur}
              step={step}
              installing={installing}
              error={error}
              canContinue={canContinue}
              primaryLabel={primaryLabel}
              onBack={() => go(step - 1)}
              onViewLog={() => openLog(lines)}
              onOpenDocs={openDocs}
              onClose={closeWindow}
              onNext={next}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// "View log": in Tauri we could open a temp file; for now dump the rendered
// log lines into a new window/blob so the user can read/copy the full trace.
function openLog(lines) {
  const text = lines.map((l) => l.replace(/<[^>]+>/g, "")).join("\n");
  if (isTauri()) {
    // best-effort: copy to clipboard so it's recoverable everywhere
    copyText(text);
  }
  try {
    const w = window.open("", "_blank", "width=720,height=520");
    if (w) {
      w.document.title = "DigStore install log";
      w.document.body.style.cssText = "background:#0A0A20;color:#C5C1E0;font:12.5px ui-monospace,monospace;padding:18px;white-space:pre-wrap;";
      w.document.body.textContent = text;
    }
  } catch {
    /* popups blocked — clipboard copy above is the fallback */
  }
}
