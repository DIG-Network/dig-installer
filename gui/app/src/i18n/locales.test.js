import { describe, it, expect } from "vitest";
import { LOCALES, isSupported, matchLocale, DEFAULT_LOCALE } from "./locales.js";

describe("locales (canonical 14-locale set)", () => {
  it("ships exactly the 14 canonical locales", () => {
    expect(LOCALES).toHaveLength(14);
    const codes = LOCALES.map((l) => l.code);
    for (const c of ["en", "zh-CN", "zh-TW", "ko", "ja", "ru", "es", "pt-BR", "fr", "de", "tr", "vi", "id", "hi"]) {
      expect(codes).toContain(c);
    }
  });

  it("every locale has an endonym display name", () => {
    for (const l of LOCALES) expect(l.name.length).toBeGreaterThan(0);
  });

  it("isSupported accepts canonical codes and rejects others", () => {
    expect(isSupported("en")).toBe(true);
    expect(isSupported("zh-CN")).toBe(true);
    expect(isSupported("xx")).toBe(false);
  });

  it("matchLocale resolves exact, base-language, and regional-variant tags", () => {
    expect(matchLocale("zh-CN")).toBe("zh-CN"); // exact
    expect(matchLocale("fr-CA")).toBe("fr"); // base language
    expect(matchLocale("zh")).toBe("zh-CN"); // base → first regional variant
    expect(matchLocale("pt")).toBe("pt-BR");
    expect(matchLocale("xx-YY")).toBeNull();
    expect(matchLocale("")).toBeNull();
  });

  it("English is the default", () => {
    expect(DEFAULT_LOCALE).toBe("en");
  });
});
