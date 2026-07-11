import { FEATURES } from "../data.jsx";

export function Welcome({ meta }) {
  return (
    <div className="fade-key">
      <div className="eyebrow">DIG Network · digstore · dig-node · dig-dns</div>
      <h2>
        Install <span className="gt">DIG</span>
      </h2>
      <p className="lead">
        Your front door to the DIG Network. This installer sets up the full stack in one step — the <b>DigStore</b> CLI,
        your local <b>dig-node</b>, and <b>dig-dns</b> name resolution. DigStore turns content into a portable, encrypted,
        self-defending WASM module: each commit is a <b>capsule</b> you publish to <b>DIGHUb</b> (the blind host) and serve
        through your dig-node. Publishing a capsule costs a small amount of <b>$DIG</b>; reading is free.
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
