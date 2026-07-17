/* Static data arrays — copy lifted verbatim from the prototype
   (design/installer/installer-app.jsx). Keep technically accurate to
   product/digstore-spec.txt (URN shape, AES-256-GCM, merkle, attestation).

   #654: the human-readable copy is externalized to react-intl message
   descriptors ({ id, defaultMessage }); the consuming step components format
   them with `useIntl().formatMessage(...)`. The `defaultMessage` IS the English
   source catalog (formatjs `extract` reads it), and non-English locales fall
   back to it until translated — so the visible copy is unchanged. Structural
   fields (`id`, `req`, `on`, `hidden`, `requires`, `ic`) stay plain data. */
import { defineMessages } from "react-intl";
import { Ic } from "./icons.jsx";

export const STEPS = ["Welcome", "License", "Components", "Install", "Done"];

// Feature-card copy for the Welcome step.
const featureMessages = defineMessages({
  gitHeading: {
    id: "welcome.feature.git.heading",
    defaultMessage: "A Git-shaped workflow",
  },
  gitBody: {
    id: "welcome.feature.git.body",
    defaultMessage:
      "init, add, commit, log, diff, checkout, clone — the verbs you already know. Each commit advances your store to a new capsule; chunking, encryption and WASM compilation stay under the surface.",
  },
  lockHeading: {
    id: "welcome.feature.lock.heading",
    defaultMessage: "Encrypted at rest, by URN",
  },
  lockBody: {
    id: "welcome.feature.lock.body",
    defaultMessage:
      "Every URN is a key. Content is chunked, SHA-256 addressed, and sealed with an AES-256-GCM key derived from the URN itself.",
  },
  shieldHeading: {
    id: "welcome.feature.shield.heading",
    defaultMessage: "Publish to DIGHUb, serve anywhere",
  },
  shieldBody: {
    id: "welcome.feature.shield.body",
    defaultMessage:
      "Each capsule compiles to one portable .wasm that defends itself — merkle proofs and host attestation. Push it to DIGHUb (the blind host) and read it back through a local dig-node or any DIG client.",
  },
});

export const FEATURES = [
  { ic: Ic.git, h: featureMessages.gitHeading, p: featureMessages.gitBody },
  { ic: Ic.lock, h: featureMessages.lockHeading, p: featureMessages.lockBody },
  { ic: Ic.shield, h: featureMessages.shieldHeading, p: featureMessages.shieldBody },
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
const componentMessages = defineMessages({
  digstoreName: { id: "component.digstore.name", defaultMessage: "DigStore CLI" },
  digstoreDesc: {
    id: "component.digstore.desc",
    defaultMessage: "The digstore command — init, add, commit, log, clone. Added to PATH.",
  },
  digNodeName: { id: "component.dig-node.name", defaultMessage: "dig-node" },
  digNodeDesc: {
    id: "component.dig-node.desc",
    defaultMessage:
      "Your local DIG node — installed as an OS service so store reads/writes hit your own machine first.",
  },
  digDnsName: { id: "component.dig-dns.name", defaultMessage: "dig-dns" },
  digDnsDesc: {
    id: "component.dig-dns.desc",
    defaultMessage:
      "Local *.dig name resolution as an OS service, so a browser can open http://your-store.dig directly. Skipped automatically if not yet released.",
  },
  extensionName: { id: "component.extension.name", defaultMessage: "DIG browser extension" },
  extensionDesc: {
    id: "component.extension.desc",
    defaultMessage:
      "Installs the DIG extension as a managed extension in your Chromium browsers, so chia:// and dig:// links resolve through your node. Next you'll choose which browsers — uncheck any to skip.",
  },
  digRelayName: { id: "component.dig-relay.name", defaultMessage: "dig-relay (advanced)" },
  digRelayDesc: {
    id: "component.dig-relay.desc",
    defaultMessage:
      "Run your own NAT-traversal relay. Optional — every node already uses the canonical relay.dig.net by default.",
  },
  browserName: { id: "component.browser.name", defaultMessage: "DIG Browser" },
  browserDesc: {
    id: "component.browser.desc",
    defaultMessage:
      "The DIG-native desktop browser — chia:// and dig:// links resolve natively. Downloads the native installer.",
  },
});

export const COMPONENTS = [
  {
    id: "digstore",
    name: componentMessages.digstoreName,
    desc: componentMessages.digstoreDesc,
    req: true,
  },
  {
    id: "dig-node",
    name: componentMessages.digNodeName,
    desc: componentMessages.digNodeDesc,
    on: true,
  },
  {
    id: "dig-dns",
    name: componentMessages.digDnsName,
    desc: componentMessages.digDnsDesc,
    on: true,
  },
  {
    id: "extension",
    name: componentMessages.extensionName,
    desc: componentMessages.extensionDesc,
    on: true,
  },
  {
    id: "dig-relay",
    name: componentMessages.digRelayName,
    desc: componentMessages.digRelayDesc,
    on: false,
  },
  {
    id: "browser",
    name: componentMessages.browserName,
    desc: componentMessages.browserDesc,
    hidden: true, // HIDDEN for now (re-enable later) — not offered in the installer.
  },
];

// Toggleable install OPTIONS (distinct from COMPONENTS above — these configure
// how a component installs rather than selecting a downloadable artifact).
// `id` values map 1:1 to the `selected` map keys the Rust install pipeline
// reads (`gui/app/src-tauri/src/install.rs` `plan_from_selection`). Each
// entry's `requires` names the component id it only makes sense alongside —
// `Components.jsx` hides it when that component is unchecked.
const optionMessages = defineMessages({
  firewallName: {
    id: "option.open-firewall.name",
    defaultMessage: "Open the firewall for dig-node",
  },
  firewallDesc: {
    id: "option.open-firewall.desc",
    defaultMessage:
      "Lets other DIG nodes reach yours directly on its peer-to-peer port (9444), scoped to the dig-node program only. Declining is safe — your node still works via the relay fallback.",
  },
  autoUpdateName: {
    id: "option.auto-update.name",
    defaultMessage: "Keep DIG up to date automatically (recommended)",
  },
  autoUpdateDesc: {
    id: "option.auto-update.desc",
    defaultMessage:
      "Installs the DIG update beacon, which checks daily for new signed releases of the DIG stack and installs them automatically. Turn this off any time.",
  },
});

export const OPTIONS = [
  {
    id: "open-firewall",
    name: optionMessages.firewallName,
    desc: optionMessages.firewallDesc,
    requires: "dig-node",
    on: true,
  },
  {
    id: "auto-update",
    name: optionMessages.autoUpdateName,
    desc: optionMessages.autoUpdateDesc,
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
