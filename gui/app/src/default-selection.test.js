import { describe, expect, it } from "vitest";
import { COMPONENTS, OPTIONS, defaultSelection } from "./data.jsx";

// The initial checkbox state used to be a hand-written literal in `App.jsx` while
// `data.jsx` carried its own `on` flags, and the two silently disagreed: `dig-app`
// was `on: true` in the catalogue and absent from the literal, so it rendered
// UNCHECKED and the flag was dead metadata. `defaultSelection()` derives the state
// from the catalogues, which makes `on` load-bearing — and makes the default set
// assertable as BEHAVIOUR rather than as the source text of a literal.
describe("defaultSelection", () => {
  const sel = defaultSelection();

  it("pre-checks the one-click core path (#1820)", () => {
    // digstore is `req` — always installed, so always on.
    expect(sel.digstore).toBe(true);
    expect(sel["dig-node"]).toBe(true);
    expect(sel["dig-app"]).toBe(true);
    expect(sel["dig-dns"]).toBe(true);
    expect(sel.extension).toBe(true);
  });

  it("leaves dig-relay unchecked — advanced, opt-in only (#491)", () => {
    // Present (the user can still check it), but never pre-selected: every node
    // already uses the canonical relay.dig.net.
    expect(sel).toHaveProperty("dig-relay");
    expect(sel["dig-relay"]).toBe(false);
  });

  it("does not offer the DIG Browser at all (#491)", () => {
    // `hidden` entries are absent rather than false, so nothing downstream can
    // read them back as an offered-but-unchecked component.
    expect(sel).not.toHaveProperty("browser");
  });

  it("defaults every install option ON", () => {
    for (const option of OPTIONS) {
      expect(sel[option.id]).toBe(true);
    }
  });

  it("covers every offered catalogue entry, so a new component cannot be forgotten", () => {
    const offered = [...COMPONENTS, ...OPTIONS].filter((entry) => !entry.hidden).map((e) => e.id);
    expect(Object.keys(sel).sort()).toEqual(offered.sort());
  });

  it("returns a fresh object each call, so a caller cannot mutate the default", () => {
    const first = defaultSelection();
    first["dig-node"] = false;
    expect(defaultSelection()["dig-node"]).toBe(true);
  });
});
