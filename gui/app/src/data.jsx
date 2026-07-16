/* Static data arrays — copy lifted verbatim from the prototype
   (design/installer/installer-app.jsx). Keep technically accurate to
   product/digstore-spec.txt (URN shape, AES-256-GCM, merkle, attestation). */
import { Ic } from "./icons.jsx";

export const STEPS = ["Welcome", "License", "Components", "Install", "Done"];

export const FEATURES = [
  {
    ic: Ic.git,
    h: "A Git-shaped workflow",
    p: "init, add, commit, log, diff, checkout, clone — the verbs you already know. Each commit advances your store to a new capsule; chunking, encryption and WASM compilation stay under the surface.",
  },
  {
    ic: Ic.lock,
    h: "Encrypted at rest, by URN",
    p: "Every URN is a key. Content is chunked, SHA-256 addressed, and sealed with an AES-256-GCM key derived from the URN itself.",
  },
  {
    ic: Ic.shield,
    h: "Publish to DIGHUb, serve anywhere",
    p: "Each capsule compiles to one portable .wasm that defends itself — merkle proofs and host attestation. Push it to DIGHUb (the blind host) and read it back through a local dig-node or any DIG client.",
  },
];

// The REAL DIG component catalogue (task #234) — `id` values map 1:1 to the
// component identifiers the Rust install pipeline understands (mirrors the
// `dig-installer --help-json` "components" list: digstore, dig-node,
// dig-relay, dig-dns, browser). The default one-click path installs the core
// DIG stack (digstore + dig-node + dig-dns); digstore is `req: true` (the CLI
// itself, always installed). `dig-relay` is `on: false` (task #491 — advanced/
// optional: most users use the canonical relay.dig.net, so it is present +
// selectable but NOT pre-checked). `browser` is `hidden: true` (task #491 —
// not offered in the installer for now; the entry is kept for easy re-enable,
// and `Components.jsx` does not render a `hidden` component). This mirrors the
// CLI defaults (`InstallPlan::default()`: dig-relay + browser are opt-in only,
// `--with-relay`/`--with-browser`).
export const COMPONENTS = [
  {
    id: "digstore",
    name: "DigStore CLI",
    desc: "The digstore command — init, add, commit, log, clone. Added to PATH.",
    req: true,
  },
  {
    id: "dig-node",
    name: "dig-node",
    desc: "Your local DIG node — installed as an OS service so store reads/writes hit your own machine first.",
    on: true,
  },
  {
    id: "dig-dns",
    name: "dig-dns",
    desc: "Local *.dig name resolution as an OS service, so a browser can open http://<store>.dig directly. Skipped automatically if not yet released.",
    on: true,
  },
  {
    id: "extension",
    name: "DIG browser extension",
    desc: "Installs the DIG extension as a managed extension in your Chromium browsers, so chia:// and dig:// links resolve through your node. Next you'll choose which browsers — uncheck any to skip.",
    on: true,
  },
  {
    id: "dig-relay",
    name: "dig-relay (advanced)",
    desc: "Run your own NAT-traversal relay. Optional — every node already uses the canonical relay.dig.net by default.",
    on: false,
  },
  {
    id: "browser",
    name: "DIG Browser",
    desc: "The DIG-native desktop browser — chia:// and dig:// links resolve natively. Downloads the native installer.",
    hidden: true, // HIDDEN for now (re-enable later) — not offered in the installer.
  },
];

// Toggleable install OPTIONS (distinct from COMPONENTS above — these configure
// how a component installs rather than selecting a downloadable artifact).
// `id` values map 1:1 to the `selected` map keys the Rust install pipeline
// reads (`gui/app/src-tauri/src/install.rs` `plan_from_selection`). Each
// entry's `requires` names the component id it only makes sense alongside —
// `Components.jsx` hides it when that component is unchecked.
export const OPTIONS = [
  {
    id: "open-firewall",
    name: "Open the firewall for dig-node",
    desc: "Lets other DIG nodes reach yours directly on its peer-to-peer port (9444), scoped to the dig-node program only. Declining is safe — your node still works via the relay fallback.",
    requires: "dig-node",
    on: true,
  },
  {
    id: "auto-update",
    name: "Keep DIG up to date automatically (recommended)",
    desc: "Installs the DIG update beacon, which checks daily for new signed releases of the DIG stack and installs them automatically. Turn this off any time.",
    on: true,
  },
];

// Files surfaced in the progress header "writing <file>" while the real
// pipeline runs (the Rust side overrides these with the actual current file).
export const NOW_FILES = [
  "bin/digstore",
  "lib/dig_host.wasm",
  "lib/compiler.wasm",
  "share/completions/_digstore",
  "trusted/host-keys.toml",
  "examples/hello.wasm",
];
