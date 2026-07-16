import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Vitest config for the installer GUI's component/unit suite (issue #611).
// jsdom + React Testing Library render + interact with the React steps; the
// Tauri bridge is stubbed per-test. Coverage is scoped to the UI logic this
// suite actually exercises — the pure step model, the browser-checklist step,
// and the Components catalogue/step — and gated at the ecosystem ≥80% floor
// (CLAUDE.md §2.3). The wider legacy app (App shell, install streaming bridge)
// predates this suite and is covered incrementally, not gated here.
export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.js"],
    include: ["src/**/*.test.{js,jsx}"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      include: ["src/steps.js", "src/steps/Browsers.jsx", "src/steps/Components.jsx"],
      thresholds: { lines: 80, functions: 80, branches: 80, statements: 80 },
    },
  },
});
