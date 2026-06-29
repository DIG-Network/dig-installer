import { FEATURES } from "../data.jsx";

export function Welcome({ meta }) {
  return (
    <div className="fade-key">
      <div className="eyebrow">DIG Network · DigStore CLI · Host Runtime</div>
      <h2>
        Install <span className="gt">DigStore</span>
      </h2>
      <p className="lead">
        Your front door to the DIG Network. <b>DigStore</b> turns content into a portable, encrypted, self-defending
        WASM module: each commit is a <b>capsule</b> you publish to <b>DIGHUb</b> (the blind host) and serve through a
        local <b>dig-node</b>. Publishing a capsule costs a small amount of <b>$DIG</b>; reading is free.
      </p>
      <div className="feats">
        {FEATURES.map((f, i) => (
          <div className="feat" key={i}>
            <div className="ic">{f.ic}</div>
            <div>
              <h4>{f.h}</h4>
              <p>{f.p}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="meta-chips">
        <span className="chip">
          <span className="k">version</span>
          <b>{meta.version}</b>
        </span>
        <span className="chip">
          <span className="k">install size</span>
          <b>~46 MB</b>
        </span>
        <span className="chip">
          <span className="k">platforms</span>macOS · Linux · Windows
        </span>
        <span className="chip">
          <span className="k">license</span>GPL-2.0
        </span>
      </div>
    </div>
  );
}
