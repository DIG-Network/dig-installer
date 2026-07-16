// Strict ESLint for the DIG installer GUI (#643): recommended JS + React +
// react-hooks rules, zero errors (CI-gated by the `gui js lint` job). Flat
// config (ESLint 9). The frontend is JSX + browser globals; tests add the
// vitest/jsdom globals.
import js from "@eslint/js";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default [
  { ignores: ["dist/**", "coverage/**", "src-tauri/**", "node_modules/**"] },
  js.configs.recommended,
  {
    files: ["**/*.{js,jsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.browser },
    },
    plugins: { react, "react-hooks": reactHooks },
    settings: { react: { version: "detect" } },
    rules: {
      ...react.configs.flat.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      // The app uses the automatic JSX runtime (Vite/@vitejs/plugin-react), so
      // React need not be in scope per file.
      "react/react-in-jsx-scope": "off",
      "react/prop-types": "off",
      // Cosmetic-only: bare quotes/apostrophes in JSX text are valid and
      // readable; this rule is noise for user-facing copy (which the #642 i18n
      // work externalizes anyway). Off by design.
      "react/no-unescaped-entities": "off",
    },
  },
  {
    // Node-run files (build/stage scripts, config, tests) get Node + vitest
    // globals (process/console/etc.).
    files: [
      "**/*.test.{js,jsx}",
      "**/*.config.js",
      "**/*.mjs",
      "scripts/**",
      "src/test/**",
      "vitest.setup.*",
    ],
    languageOptions: {
      globals: { ...globals.node, ...globals.vitest },
    },
  },
];
