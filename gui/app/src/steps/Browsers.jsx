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
 * message, not a dead-end). Copy is externalized to react-intl (#654). */

import { FormattedMessage, useIntl } from "react-intl";

const code = (chunks) => <code>{chunks}</code>;

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
      <div className="eyebrow">
        <FormattedMessage id="browsers.eyebrow" defaultMessage="Step 04 — Browsers" />
      </div>
      <h2>
        <FormattedMessage id="browsers.title" defaultMessage="Choose your browsers" />
      </h2>
      <p className="lead" style={{ marginBottom: 24 }}>
        <FormattedMessage
          id="browsers.lead"
          defaultMessage="DIG installs as a managed extension in the browsers you choose, so <code>chia://</code> and <code>dig://</code> links resolve through your node. Every detected browser is selected — uncheck any you'd rather skip."
          values={{ code }}
        />
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
      <FormattedMessage id="browsers.detecting" defaultMessage="Detecting your installed browsers…" />
    </div>
  );
}

/** Error: detection failed — honest message plus a Retry (never a dead-end). */
function ErrorState({ onRetry }) {
  return (
    <div className="browser-error" role="alert">
      <p>
        <FormattedMessage
          id="browsers.error.title"
          defaultMessage="We couldn't detect your browsers just now."
        />
      </p>
      <p className="cd">
        <FormattedMessage
          id="browsers.error.body"
          defaultMessage="You can retry, or continue — you can install the extension into your browsers manually later."
        />
      </p>
      <button type="button" className="btn btn-secondary" onClick={onRetry}>
        <FormattedMessage id="browsers.error.retry" defaultMessage="Retry detection" />
      </button>
    </div>
  );
}

/** Empty: no Chromium-family browser found — a clear message, not a blocker. */
function EmptyState() {
  return (
    <div className="browser-empty">
      <p>
        <FormattedMessage
          id="browsers.empty.title"
          defaultMessage="No supported browsers were detected on this machine."
        />
      </p>
      <p className="cd">
        <FormattedMessage
          id="browsers.empty.body"
          defaultMessage="The DIG stack still installs — you can add the extension to a Chromium browser manually any time. Continue to finish setup."
        />
      </p>
    </div>
  );
}

/** Success: the scrollable, all-checked-default, per-browser opt-out checklist. */
function BrowserList({ browsers, sel, onToggle }) {
  const intl = useIntl();
  const groupLabel = intl.formatMessage({
    id: "browsers.groupLabel",
    defaultMessage: "Browsers to install the extension into",
  });
  return (
    <>
      <p className="field-label">
        <FormattedMessage id="browsers.detected" defaultMessage="Detected browsers" />
      </p>
      <div className="browser-list" role="group" aria-label={groupLabel}>
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
