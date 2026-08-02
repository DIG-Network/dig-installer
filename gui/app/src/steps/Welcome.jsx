import { FormattedMessage, useIntl } from "react-intl";
import { FEATURES } from "../data.jsx";

// Rich-text tag renderers shared by the lead copy (react-intl chunk callbacks).
const bold = (chunks) => <b>{chunks}</b>;

export function Welcome({ meta }) {
  const intl = useIntl();
  return (
    <div className="fade-key">
      <div className="eyebrow">
        <FormattedMessage
          id="welcome.eyebrow"
          defaultMessage="DIG Network · node · desktop app · store · name resolution"
        />
      </div>
      <h2>
        <FormattedMessage
          id="welcome.title"
          defaultMessage="Install the <gt>DIG Network</gt>"
          values={{ gt: (chunks) => <span className="gt">{chunks}</span> }}
        />
      </h2>
      <p className="lead">
        <FormattedMessage
          id="welcome.lead"
          defaultMessage="Your front door to the DIG Network. One install sets up everything you need — your own <b>dig-node</b>, the <b>DIG app</b> that keeps your keys in your system tray, <b>.dig</b> name resolution, and the <b>DigStore</b> tools for publishing. Reading content is always free; publishing a <b>capsule</b> to <b>DIGHUb</b> moves a little <b>$DIG</b>. Automatic updates keep the whole stack current."
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
