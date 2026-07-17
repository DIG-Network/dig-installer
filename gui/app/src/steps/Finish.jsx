import { FormattedMessage, useIntl } from "react-intl";
import { Ic } from "../icons.jsx";

const bold = (chunks) => <b>{chunks}</b>;
const code = (chunks) => <code>{chunks}</code>;

export function Finish({ path, onCopy, copied, meta, restartRequired = false }) {
  const intl = useIntl();
  return (
    <div className="fade-key finish">
      <div className="seal">
        <div className="ring"></div>
        {Ic.check}
      </div>
      <h2>
        <FormattedMessage
          id="finish.title"
          defaultMessage="The DIG stack is <gt>installed</gt>"
          values={{ gt: (chunks) => <span className="gt">{chunks}</span> }}
        />
      </h2>
      {restartRequired && (
        <div className="notice restart-required" role="status">
          <FormattedMessage
            id="finish.restart"
            defaultMessage="<b>Restart required.</b> A component that was running has its update staged — restart your computer to finish applying it."
            values={{ b: bold }}
          />
        </div>
      )}
      <p className="lead">
        <FormattedMessage
          id="finish.lead"
          defaultMessage="The <b>DigStore</b> CLI, your <b>dig-node</b>, and <b>dig-dns</b> are ready. Initialize your first store, then commit a <b>capsule</b> (<code>storeId:rootHash</code> — one immutable generation) and push it to <b>DIGHUb</b>."
          values={{ b: bold, code }}
        />
      </p>
      <div className="recap">
        <span className="chip">
          <span className="k">
            <FormattedMessage id="finish.recap.version" defaultMessage="version" />
          </span>
          <b>{meta.version}</b>
        </span>
        <span className="chip">
          <span className="k">
            <FormattedMessage id="finish.recap.location" defaultMessage="location" />
          </span>
          {path}
        </span>
        <span className="chip">
          <span
            className="dot"
            style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--ok)", display: "inline-block" }}
          ></span>
          <FormattedMessage id="finish.recap.onPath" defaultMessage="digstore on PATH" />
        </span>
      </div>
      <div className="next">
        <div className="nh">
          <FormattedMessage id="finish.next.heading" defaultMessage="Next steps" />
        </div>
        <div className="cmd">
          <button className="copy" onClick={onCopy}>
            {copied ? Ic.check : Ic.copy}
            {copied
              ? intl.formatMessage({ id: "finish.copy.copied", defaultMessage: "Copied" })
              : intl.formatMessage({ id: "finish.copy.copy", defaultMessage: "Copy" })}
          </button>
          <div className="c-line">
            <span className="p">$</span> <span className="cmd-t">digstore init my-store</span>{"   "}
            <span className="cc">
              # <FormattedMessage id="finish.cmd.init" defaultMessage="create a store" />
            </span>
          </div>
          <div className="c-line">
            <span className="p">$</span> <span className="cmd-t">digstore add ./site</span>{"      "}
            <span className="cc">
              # <FormattedMessage id="finish.cmd.add" defaultMessage="stage content" />
            </span>
          </div>
          <div className="c-line">
            <span className="p">$</span> <span className="cmd-t">digstore commit -m "v1"</span>{"  "}
            <span className="cc">
              # <FormattedMessage id="finish.cmd.commit" defaultMessage="compile + publish a capsule to DIGHUb" />
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
