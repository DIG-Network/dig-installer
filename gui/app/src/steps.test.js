import { describe, it, expect } from "vitest";
import { computeSteps, BASE_STEPS, BROWSERS_STEP } from "./steps.js";

// The conditional-step model is the load-bearing GUI change for #611: the
// Browsers step must appear ONLY when the extension component is selected, and
// must slot in exactly between Components and Installing so the rail, dots, and
// next/back navigation all key off one computed list. These tests pin that
// contract independently of any React rendering.
describe("computeSteps", () => {
  it("omits the Browsers step when the extension is not selected", () => {
    const steps = computeSteps({ "dig-node": true });
    expect(steps.map((s) => s.id)).toEqual(BASE_STEPS.map((s) => s.id));
    expect(steps.some((s) => s.id === "browsers")).toBe(false);
  });

  it("omits the Browsers step for empty/absent selection", () => {
    expect(computeSteps({}).some((s) => s.id === "browsers")).toBe(false);
    expect(computeSteps(undefined).some((s) => s.id === "browsers")).toBe(false);
  });

  it("inserts the Browsers step directly after Components when the extension is selected", () => {
    const ids = computeSteps({ extension: true }).map((s) => s.id);
    expect(ids).toEqual(["welcome", "license", "components", "browsers", "installing", "finish"]);
  });

  it("keeps Browsers immediately before Installing (never a dead-end after it)", () => {
    const ids = computeSteps({ extension: true }).map((s) => s.id);
    expect(ids[ids.indexOf("browsers") + 1]).toBe("installing");
  });

  it("exposes a human label for the Browsers step", () => {
    expect(BROWSERS_STEP.label).toBeTruthy();
  });
});
