import { FormattedMessage, useIntl } from "react-intl";
import { Ic } from "../icons.jsx";
import { COMPONENTS, OPTIONS } from "../data.jsx";

// Components whose Install/Update/Skip status this screen previews (issue
// #309) — mirrors the Rust side's `update::tracked_components()` minus
// `digstore` (its GUI install is a bundled/embedded payload with no network
// "latest" to diff against; see `install.rs::component_update_status`).
const UPDATE_TRACKED_IDS = ["dig-node", "dig-dns"];

// react-intl descriptors for each machine-readable `action` label.
const ACTION_MESSAGES = {
  install: { id: "components.action.install", defaultMessage: "Install" },
  update: { id: "components.action.update", defaultMessage: "Update available" },
  skip: { id: "components.action.skip", defaultMessage: "Up to date" },
};

/// A single status pill next to a tracked component: "Install" / "Update
/// available" / "Up to date", or an honest "couldn't check" note when the
/// backend's version lookup failed (e.g. offline) — never a guessed verdict.
function StatusPill({ status }) {
  const intl = useIntl();
  if (!status.action) {
    return (
      <span className="pill-status unknown" title={status.summary}>
        <FormattedMessage id="components.updateUnavailable" defaultMessage="update check unavailable" />
      </span>
    );
  }
  const label = ACTION_MESSAGES[status.action];
  return (
    <span className={"pill-status " + status.action} title={status.summary}>
      {label ? intl.formatMessage(label) : status.action}
    </span>
  );
}

// The DIG component catalogue (task #234/#491). The core stack (digstore +
// dig-node + dig-dns) is pre-selected — installing it is the one-click default
// path. `dig-relay` is present but UNCHECKED by default (advanced; most users
// use the canonical relay.dig.net). A `hidden` component (currently the DIG
// Browser, #491) is not offered — filtered out here entirely. Each component's
// actual release/asset is resolved from GitHub at install time, so — unlike the
// old bundled-digstore prototype — sizes aren't known ahead of time and are
// intentionally not shown here (no invented numbers). `status` (#309) is the
// live per-component Install/Update/Skip preview from `App.jsx`: `null` while
// it's still loading, an array once the backend has answered. Copy is
// externalized to react-intl (#654).
export function Components({ sel, toggle, path, onChange, status }) {
  const intl = useIntl();
  // A `hidden` component (e.g. the DIG Browser, #491) is never offered.
  const offered = COMPONENTS.filter((c) => !c.hidden);
  const selectedCount = offered.filter((c) => c.req || sel[c.id]).length;
  // An option only makes sense alongside the component it configures (#424 —
  // "open the firewall for dig-node" is meaningless without dig-node itself),
  // so it drops out of the list the moment that component is unchecked.
  const activeOptions = OPTIONS.filter((o) => !o.requires || sel[o.requires]);
  const statusFor = (id) => (status || []).find((s) => s.component === id);
  return (
    <div className="fade-key">
      <div className="eyebrow">
        <FormattedMessage id="components.eyebrow" defaultMessage="Step 03 — Setup" />
      </div>
      <h2>
        <FormattedMessage id="components.title" defaultMessage="Choose Components" />
      </h2>
      <p className="lead" style={{ marginBottom: 28 }}>
        <FormattedMessage
          id="components.lead"
          defaultMessage="The core DIG stack is pre-selected — installing it is the default, one-click path. Check any optional extras you want, or deselect anything you don't; the CLI is required."
        />
      </p>
      <p className="field-label">
        <FormattedMessage id="components.location" defaultMessage="Install location" />
      </p>
      <div className="path-row">
        <div className="path-input">
          {Ic.folder}
          <span>{path}</span>
        </div>
        <button className="btn-ghost" onClick={onChange}>
          <FormattedMessage id="components.change" defaultMessage="Change…" />
        </button>
      </div>
      <p className="field-label">
        <FormattedMessage id="components.components" defaultMessage="Components" />
      </p>
      {offered.map((c) => {
        const on = c.req || sel[c.id];
        const st = statusFor(c.id);
        const tracked = UPDATE_TRACKED_IDS.includes(c.id);
        return (
          <div className={"comp" + (c.req ? " req" : "")} key={c.id} onClick={() => !c.req && toggle(c.id)}>
            <div className={"check" + (on ? " on" : "")} style={{ width: 22, height: 22, flex: "0 0 22px" }}>
              {Ic.check}
            </div>
            <div>
              <div className="ci">{intl.formatMessage(c.name)}</div>
              <div className="cd">{intl.formatMessage(c.desc)}</div>
            </div>
            {c.req && (
              <span className="pill-req">
                <FormattedMessage id="components.required" defaultMessage="REQUIRED" />
              </span>
            )}
            {!c.req &&
              tracked &&
              (st ? (
                <StatusPill status={st} />
              ) : (
                status === null && (
                  <span className="pill-status checking">
                    <FormattedMessage id="components.checking" defaultMessage="checking…" />
                  </span>
                )
              ))}
          </div>
        );
      })}
      {activeOptions.length > 0 && (
        <>
          <p className="field-label" style={{ marginTop: 18 }}>
            <FormattedMessage id="components.options" defaultMessage="Options" />
          </p>
          {activeOptions.map((o) => {
            const on = sel[o.id];
            return (
              <div className="comp" key={o.id} onClick={() => toggle(o.id)}>
                <div className={"check" + (on ? " on" : "")} style={{ width: 22, height: 22, flex: "0 0 22px" }}>
                  {Ic.check}
                </div>
                <div>
                  <div className="ci">{intl.formatMessage(o.name)}</div>
                  <div className="cd">{intl.formatMessage(o.desc)}</div>
                </div>
              </div>
            );
          })}
        </>
      )}
      <div className="meta-chips" style={{ marginTop: 22 }}>
        <span className="chip">
          <span className="k">
            <FormattedMessage id="components.selected" defaultMessage="selected" />
          </span>
          <b>
            <FormattedMessage
              id="components.selectedCount"
              defaultMessage="{count} of {total}"
              values={{ count: selectedCount, total: offered.length }}
            />
          </b>
        </span>
      </div>
    </div>
  );
}
