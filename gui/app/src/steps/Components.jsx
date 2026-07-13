import { Ic } from "../icons.jsx";
import { COMPONENTS } from "../data.jsx";

// The DIG component catalogue (task #234/#491). The core stack (digstore +
// dig-node + dig-dns) is pre-selected — installing it is the one-click default
// path. `dig-relay` is present but UNCHECKED by default (advanced; most users
// use the canonical relay.dig.net). A `hidden` component (currently the DIG
// Browser, #491) is not offered — filtered out here entirely. Each component's
// actual release/asset is resolved from GitHub at install time, so — unlike the
// old bundled-digstore prototype — sizes aren't known ahead of time and are
// intentionally not shown here (no invented numbers).
export function Components({ sel, toggle, path, onChange }) {
  // A `hidden` component (e.g. the DIG Browser, #491) is never offered.
  const offered = COMPONENTS.filter((c) => !c.hidden);
  const selectedCount = offered.filter((c) => c.req || sel[c.id]).length;
  return (
    <div className="fade-key">
      <div className="eyebrow">Step 03 — Setup</div>
      <h2>Choose Components</h2>
      <p className="lead" style={{ marginBottom: 28 }}>
        The core DIG stack is pre-selected — installing it is the default, one-click path. Check any
        optional extras you want, or deselect anything you don't; the CLI is required.
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
      {offered.map((c) => {
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
            {selectedCount} of {offered.length}
          </b>
        </span>
      </div>
    </div>
  );
}
