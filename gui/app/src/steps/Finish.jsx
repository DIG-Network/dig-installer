import { Ic } from "../icons.jsx";

export function Finish({ path, onCopy, copied, meta, restartRequired = false }) {
  return (
    <div className="fade-key finish">
      <div className="seal">
        <div className="ring"></div>
        {Ic.check}
      </div>
      <h2>
        The DIG stack is <span className="gt">installed</span>
      </h2>
      {restartRequired && (
        <div className="notice restart-required" role="status">
          <b>Restart required.</b> A component that was running has its update staged — restart your computer to
          finish applying it.
        </div>
      )}
      <p className="lead">
        The <b>DigStore</b> CLI, your <b>dig-node</b>, and <b>dig-dns</b> are ready. Initialize your first store, then
        commit a <b>capsule</b> (<code>storeId:rootHash</code> — one immutable generation) and push it to <b>DIGHUb</b>.
      </p>
      <div className="recap">
        <span className="chip">
          <span className="k">version</span>
          <b>{meta.version}</b>
        </span>
        <span className="chip">
          <span className="k">location</span>
          {path}
        </span>
        <span className="chip">
          <span
            className="dot"
            style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--ok)", display: "inline-block" }}
          ></span>
          digstore on PATH
        </span>
      </div>
      <div className="next">
        <div className="nh">Next steps</div>
        <div className="cmd">
          <button className="copy" onClick={onCopy}>
            {copied ? Ic.check : Ic.copy}
            {copied ? "Copied" : "Copy"}
          </button>
          <div className="c-line">
            <span className="p">$</span> <span className="cmd-t">digstore init my-store</span>{"   "}
            <span className="cc"># create a store</span>
          </div>
          <div className="c-line">
            <span className="p">$</span> <span className="cmd-t">digstore add ./site</span>{"      "}
            <span className="cc"># stage content</span>
          </div>
          <div className="c-line">
            <span className="p">$</span> <span className="cmd-t">digstore commit -m "v1"</span>{"  "}
            <span className="cc"># compile + publish a capsule to DIGHUb</span>
          </div>
        </div>
      </div>
    </div>
  );
}
