// The DIG ecosystem's canonical 14-locale set (CLAUDE.md §6.6, the `canonical`
// skill). This is a cross-repo canon — the SAME 14 codes every DIG frontend
// ships; do not add/drop one here without updating the canon. Display names are
// each locale's own endonym so the selector reads natively.
export const LOCALES = [
  { code: "en", name: "English" },
  { code: "zh-CN", name: "简体中文" },
  { code: "zh-TW", name: "繁體中文" },
  { code: "ko", name: "한국어" },
  { code: "ja", name: "日本語" },
  { code: "ru", name: "Русский" },
  { code: "es", name: "Español" },
  { code: "pt-BR", name: "Português (Brasil)" },
  { code: "fr", name: "Français" },
  { code: "de", name: "Deutsch" },
  { code: "tr", name: "Türkçe" },
  { code: "vi", name: "Tiếng Việt" },
  { code: "id", name: "Bahasa Indonesia" },
  { code: "hi", name: "हिन्दी" },
];

export const DEFAULT_LOCALE = "en";

const LOCALE_CODES = LOCALES.map((l) => l.code);
const STORAGE_KEY = "dig-installer.locale";

/** Is `code` one of the supported 14 locales? */
export function isSupported(code) {
  return LOCALE_CODES.includes(code);
}

/**
 * Resolve a browser/navigator language tag onto a supported locale: an exact
 * match wins (e.g. `zh-CN`); otherwise the base language is matched to the first
 * supported regional variant (e.g. `zh` → `zh-CN`, `pt` → `pt-BR`); else null.
 */
export function matchLocale(tag) {
  if (!tag) return null;
  if (isSupported(tag)) return tag;
  const base = tag.split("-")[0].toLowerCase();
  if (isSupported(base)) return base;
  const regional = LOCALE_CODES.find((c) => c.split("-")[0].toLowerCase() === base);
  return regional || null;
}

/**
 * The initial locale: a persisted user choice wins; otherwise the first
 * navigator.languages entry that maps to a supported locale; else English.
 * Pure aside from reading localStorage/navigator (guarded for non-browser test
 * environments).
 */
export function getInitialLocale() {
  try {
    const saved = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (saved && isSupported(saved)) return saved;
  } catch {
    /* localStorage unavailable — fall through to detection */
  }
  const langs = globalThis.navigator?.languages || [globalThis.navigator?.language];
  for (const tag of langs || []) {
    const m = matchLocale(tag);
    if (m) return m;
  }
  return DEFAULT_LOCALE;
}

/** Persist the user's locale choice (no-op if storage is unavailable). */
export function persistLocale(code) {
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, code);
  } catch {
    /* storage unavailable — the choice simply won't persist */
  }
}
