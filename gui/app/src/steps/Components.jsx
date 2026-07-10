import { Ic } from "../icons.jsx";
import { COMPONENTS } from "../data.jsx";

// The full DIG component catalogue (task #234): every component is listed and
// PRE-SELECTED by default ("install all" is the one-click default path); the
// user may deselect any optional one before installing. Each component's
// actual release/asset is resolved from GitHub at install time, so — unlike
// the old bundled-digstore prototype — sizes aren't known ahead of time and
// are intentionally not shown here (no invented numbers).
export function Components({ sel, toggle, path, onChange }) {
  const selectedCount = COMPONENTS.filter((c) => c.req || sel[c.id]).length;
  return (
    <div className="fade-key">
      <div className="eyebrow">Step 03 — Setup</div>
      <h2>Choose Components</h2>
      <p className="lead" style={{ marginBottom: 28 }}>
        Every component is pre-selected — installing all is the default, one-click path. Deselect
        anything you don't want; the CLI is required.
      </p>
      <p className="field-label">Install location</p>
      <div className="path-row">
        <div className="path-input">
          {Ic.folder}
          <span>{path}</span>
        </div>
        <button className="btn-ghost" onClick={onChange}>
          Change…
        </button>
      </div>
      <p className="field-label">Components</p>
      {COMPONENTS.map((c) => {
        const on = c.req || sel[c.id];
        return (
          <div className={"comp" + (c.req ? " req" : "")} key={c.id} onClick={() => !c.req && toggle(c.id)}>
            <div className={"check" + (on ? " on" : "")} style={{ width: 22, height: 22, flex: "0 0 22px" }}>
              {Ic.check}
            </div>
            <div>
              <div className="ci">{c.name}</div>
              <div className="cd">{c.desc}</div>
            </div>
            {c.req && <span className="pill-req">REQUIRED</span>}
          </div>
        );
      })}
      <div className="meta-chips" style={{ marginTop: 22 }}>
        <span className="chip">
          <span className="k">selected</span>
          <b>
            {selectedCount} of {COMPONENTS.length}
          </b>
        </span>
      </div>
    </div>
  );
}
