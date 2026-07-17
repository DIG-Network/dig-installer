import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// #654 i18n-completeness gate (§6.6: no hardcoded copy). Every wizard step must
// externalize its user-facing prose to react-intl. This scans each step source,
// removes the legitimate English source (`defaultMessage="…"`), comments, and
// JSX expressions, then fails if any *prose* JSX text node remains — proving no
// un-externalized sentence can silently ship.

const here = dirname(fileURLToPath(import.meta.url));
const stepsDir = join(here, "..", "steps");

const STEP_FILES = [
  "Welcome.jsx",
  "License.jsx",
  "Components.jsx",
  "Browsers.jsx",
  "Installing.jsx",
  "Finish.jsx",
];

// Raw JSX text nodes that are intentionally NOT translated — brand/wordmark
// strings, shell commands, and symbol/format literals.
const ALLOWED_LITERALS = new Set([
  "DIG Network · digstore · dig-node · dig-dns",
  "macOS · Linux · Windows",
  "digstore init my-store",
  "digstore add ./site",
  'digstore commit -m "v1"',
]);

/** Strip comments, `defaultMessage` values, and `{…}` expressions, and
 *  neutralize arrow `=>` so it isn't mistaken for a JSX `>` delimiter. */
function stripNonProse(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "") // block comments
    .replace(/\/\/[^\n]*/g, "") // line comments
    .replace(/defaultMessage=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g, "defaultMessage=_") // i18n source
    .replace(/=>/g, "=") // arrow functions are not JSX close tags
    .replace(/\{[^{}]*\}/g, "{}"); // JSX expressions (single level is enough here)
}

// A captured "text node" that carries JS syntax is code that happens to sit
// between a `>` and a `<` (e.g. a helper body before the return) — never prose.
const CODE_MARKERS = /[;=(){}]|\b(import|export|function|return|const|useIntl|intl)\b/;

/** A JSX text node counts as prose if it has ≥2 words of ≥3 letters. */
function isProse(text) {
  if (CODE_MARKERS.test(text)) return false;
  const words = text.match(/[A-Za-z]{3,}/g) || [];
  return words.length >= 2;
}

/** Extract trimmed JSX text nodes (between `>` and the next `<`). */
function textNodes(src) {
  const nodes = [];
  const re = />([^<>]*)</g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const t = m[1].replace(/\s+/g, " ").trim();
    if (t) nodes.push(t);
  }
  return nodes;
}

describe("wizard step i18n completeness (#654 / §6.6)", () => {
  for (const file of STEP_FILES) {
    it(`${file} externalizes all prose to react-intl`, () => {
      const src = readFileSync(join(stepsDir, file), "utf8");

      // The step must actually use react-intl.
      expect(src).toMatch(/from "react-intl"/);

      const offenders = textNodes(stripNonProse(src)).filter(
        (t) => isProse(t) && !ALLOWED_LITERALS.has(t),
      );
      expect(offenders, `hardcoded prose in ${file}: ${JSON.stringify(offenders)}`).toEqual([]);
    });
  }
});
