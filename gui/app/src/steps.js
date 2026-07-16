/* steps.js — the wizard's step model.
 *
 * The installer's flow is mostly fixed, but the "Browsers" step is CONDITIONAL
 * (issue #611): it appears only when the user keeps the browser-extension
 * component selected. Rather than scatter magic step indices through App.jsx
 * (the old `step === 2` / `=== 3` style, which breaks the moment a step is
 * inserted), the UI derives ONE ordered list of visible steps from the current
 * selection and keys the rail, footer dots, and next/back navigation off it.
 * This module is that single source of truth — pure and index-free, so the
 * conditional-insertion contract is unit-tested without rendering React. */

/** The always-present steps, in order. `id` is the stable machine key the UI
 *  switches rendering + navigation on; `label` is the human name shown in the
 *  rail and dots. */
export const BASE_STEPS = [
  { id: "welcome", label: "Welcome" },
  { id: "license", label: "License" },
  { id: "components", label: "Components" },
  { id: "installing", label: "Install" },
  { id: "finish", label: "Done" },
];

/** The conditional step: choose which detected browsers get the managed DIG
 *  extension. Slotted in only when the extension component is selected. */
export const BROWSERS_STEP = { id: "browsers", label: "Browsers" };

/**
 * The ordered list of steps visible for the given component selection.
 *
 * The Browsers step is inserted immediately after Components (and thus
 * immediately before Installing) exactly when `sel.extension` is truthy, so a
 * user who declines the extension never sees it and one who keeps it always
 * chooses browsers before anything is installed.
 *
 * @param {Record<string, boolean>} [sel] the component/option selection map.
 * @returns {{id: string, label: string}[]} the visible steps, in flow order.
 */
export function computeSteps(sel) {
  if (!sel || !sel.extension) return BASE_STEPS;
  return BASE_STEPS.flatMap((step) =>
    step.id === "components" ? [step, BROWSERS_STEP] : [step]
  );
}
