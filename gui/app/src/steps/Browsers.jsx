/* Browsers.jsx — the conditional "choose your browsers" step (issue #611).
 *
 * Shown only when the DIG browser-extension component is selected. It asks the
 * host which Chromium-family browsers are installed (the #609 detection, via
 * the bridge) and renders a scrollable checklist so the user can opt OUT of any
 * browser before the extension is force-installed into it (#612 does the actual
 * managed-policy write; this step only captures the selection).
 *
 * professional-ui §6.1: all four async states are handled (loading / error /
 * empty / success), every detected browser is checked by default, each is
 * independently opt-out-able, the list scrolls when it exceeds the viewport,
 * and the step NEVER traps — Back and Continue live in the wizard footer and
 * stay usable in every state (including "none detected", which is a clear
 * message, not a dead-end). */

/**
 * @param {object}   props
 * @param {?Array}   props.browsers  detected browsers (#609 `DetectedBrowser`),
 *                                   or `null` while detection hasn't answered.
 * @param {Record<string, boolean>} props.sel  per-browser opt-in map (id → on).
 * @param {boolean}  props.loading   detection is in flight.
 * @param {?string}  props.error     detection failed (the message), else null.
 * @param {(id: string) => void} props.onToggle  flip one browser's opt-in.
 * @param {() => void}           props.onRetry   re-run detection after a failure.
 */
export function Browsers({ browsers, sel, loading, error, onToggle, onRetry }) {
  return (
    <div className="fade-key">
      <div className="eyebrow">Step 04 — Browsers</div>
      <h2>Choose your browsers</h2>
      <p className="lead" style={{ marginBottom: 24 }}>
        DIG installs as a managed extension in the browsers you choose, so <code>chia://</code> and{" "}
        <code>dig://</code> links resolve through your node. Every detected browser is selected —
        uncheck any you'd rather skip.
      </p>
      {renderState({ browsers, sel, loading, error, onToggle, onRetry })}
    </div>
  );
}

// Pick exactly one of the four async states. Kept as a small pure switch so the
// component body reads top-to-bottom and each state is independently obvious.
function renderState({ browsers, sel, loading, error, onToggle, onRetry }) {
  if (loading) return <DetectingState />;
  if (error) return <ErrorState onRetry={onRetry} />;
  if (browsers && browsers.length === 0) return <EmptyState />;
  if (browsers && browsers.length > 0) {
    return <BrowserList browsers={browsers} sel={sel} onToggle={onToggle} />;
  }
  // Nothing fetched yet and not explicitly loading — treat as detecting so the
  // step is never blank.
  return <DetectingState />;
}

/** Loading: detection is running. */
function DetectingState() {
  return (
    <div className="browser-detect" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      Detecting your installed browsers…
    </div>
  );
}

/** Error: detection failed — honest message plus a Retry (never a dead-end). */
function ErrorState({ onRetry }) {
  return (
    <div className="browser-error" role="alert">
      <p>We couldn't detect your browsers just now.</p>
      <p className="cd">
        You can retry, or continue — you can install the extension into your browsers manually later.
      </p>
      <button type="button" className="btn btn-secondary" onClick={onRetry}>
        Retry detection
      </button>
    </div>
  );
}

/** Empty: no Chromium-family browser found — a clear message, not a blocker. */
function EmptyState() {
  return (
    <div className="browser-empty">
      <p>No supported browsers were detected on this machine.</p>
      <p className="cd">
        The DIG stack still installs — you can add the extension to a Chromium browser manually any
        time. Continue to finish setup.
      </p>
    </div>
  );
}

/** Success: the scrollable, all-checked-default, per-browser opt-out checklist. */
function BrowserList({ browsers, sel, onToggle }) {
  return (
    <>
      <p className="field-label">Detected browsers</p>
      <div className="browser-list" role="group" aria-label="Browsers to install the extension into">
        {browsers.map((b) => (
          <label className="comp browser-row" key={b.id} data-browser={b.id}>
            <input
              type="checkbox"
              className="browser-check"
              checked={!!sel[b.id]}
              onChange={() => onToggle(b.id)}
            />
            <div className="browser-meta">
              <div className="ci">{b.display_name}</div>
              {b.install_path && <div className="cd">{b.install_path}</div>}
            </div>
          </label>
        ))}
      </div>
    </>
  );
}
