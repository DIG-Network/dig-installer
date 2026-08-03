import { useEffect, useRef } from "react";
import { useIntl } from "react-intl";
import { Ic } from "../icons.jsx";

// `lines` are ordered arrays of `{text, cls}` segments emitted by the Rust
// pipeline. Each segment renders as an escaped React text child (never HTML —
// #2040), with `cls` (ok/ac/dim/err/warn) applied as a React-safe className, so
// an untrusted path/error/browser-name in `text` can never inject markup. The
// terminal auto-scrolls as lines append. On error, the progress fill tints red,
// the caret stops, and an error banner appears (new — the prototype has no error
// state). Copy is externalized to react-intl (#654).
export function Installing({ pct, lines, nowFile, error }) {
  const intl = useIntl();
  const termRef = useRef(null);
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [lines]);

  const done = pct >= 100 && !error;
  const title = error
    ? intl.formatMessage({ id: "installing.title.failed", defaultMessage: "Install failed" })
    : done
      ? intl.formatMessage({ id: "installing.title.complete", defaultMessage: "Install complete" })
      : intl.formatMessage({ id: "installing.title.running", defaultMessage: "Installing DIG" });
  const nowLabel = error
    ? intl.formatMessage({ id: "installing.status.stopped", defaultMessage: "stopped" })
    : done
      ? intl.formatMessage({ id: "installing.status.done", defaultMessage: "done" })
      : intl.formatMessage(
          { id: "installing.status.writing", defaultMessage: "writing  {file}" },
          { file: nowFile },
        );
  return (
    <div className="fade-key">
      <div className="eyebrow">
        {intl.formatMessage({ id: "installing.eyebrow", defaultMessage: "Step 04 — Installing" })}
      </div>
      <h2>{title}</h2>
      <div className="prog-wrap">
        <div className="prog-head">
          <span className="pct">{Math.floor(pct)}%</span>
          <span className="nowfile">{nowLabel}</span>
        </div>
        <div className="track">
          <div className={"fill" + (error ? " err" : "")} style={{ width: pct + "%" }}></div>
        </div>
        <div className="term" ref={termRef}>
          {lines.map((segs, i) => (
            <div className="ln" key={i}>
              {segs.map((s, j) => (
                <span key={j} className={s.cls || undefined}>{s.text}</span>
              ))}
            </div>
          ))}
          {!done && !error && (
            <div className="ln caret-line">
              <span className="ac">▍</span>
            </div>
          )}
        </div>
        {error && (
          <div className="err-banner">
            <span className="eic">{Ic.alert}</span>
            <div>
              <p className="et">
                {error.title ||
                  intl.formatMessage({
                    id: "installing.error.title",
                    defaultMessage: "Installation error",
                  })}
              </p>
              <p className="em">{error.message}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
