import { FormattedMessage, useIntl } from "react-intl";
import { FEATURES } from "../data.jsx";

// Rich-text tag renderers shared by the lead copy (react-intl chunk callbacks).
const bold = (chunks) => <b>{chunks}</b>;

export function Welcome({ meta }) {
  const intl = useIntl();
  return (
    <div className="fade-key">
      <div className="eyebrow">DIG Network · digstore · dig-node · dig-dns</div>
      <h2>
        <FormattedMessage
          id="welcome.title"
          defaultMessage="Install <gt>DIG</gt>"
          values={{ gt: (chunks) => <span className="gt">{chunks}</span> }}
        />
      </h2>
      <p className="lead">
        <FormattedMessage
          id="welcome.lead"
          defaultMessage="Your front door to the DIG Network. This installer sets up the full stack in one step — the <b>DigStore</b> CLI, your local <b>dig-node</b>, and <b>dig-dns</b> name resolution. DigStore turns content into a portable, encrypted, self-defending WASM module: each commit is a <b>capsule</b> you publish to <b>DIGHUb</b> (the blind host) and serve through your dig-node. Publishing a capsule costs a small amount of <b>$DIG</b>; reading is free."
          values={{ b: bold }}
        />
      </p>
      <div className="feats">
        {FEATURES.map((f, i) => (
          <div className="feat" key={i}>
            <div className="ic">{f.ic}</div>
            <div>
              <h4>{intl.formatMessage(f.h)}</h4>
              <p>{intl.formatMessage(f.p)}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="meta-chips">
        <span className="chip">
          <span className="k">
            <FormattedMessage id="welcome.meta.version" defaultMessage="version" />
          </span>
          <b>{meta.version}</b>
        </span>
        <span className="chip">
          <span className="k">
            <FormattedMessage id="welcome.meta.installSize" defaultMessage="install size" />
          </span>
          <b>~46 MB</b>
        </span>
        <span className="chip">
          <span className="k">
            <FormattedMessage id="welcome.meta.platforms" defaultMessage="platforms" />
          </span>
          macOS · Linux · Windows
        </span>
        <span className="chip">
          <span className="k">
            <FormattedMessage id="welcome.meta.license" defaultMessage="license" />
          </span>
          GPL-2.0
        </span>
      </div>
    </div>
  );
}
