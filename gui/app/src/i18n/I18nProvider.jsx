import { createContext, useCallback, useContext, useMemo, useState } from "react";
import { IntlProvider } from "react-intl";
import { DEFAULT_LOCALE, getInitialLocale, persistLocale } from "./locales.js";

// The i18n layer for the installer GUI (#642). Uses react-intl's inline
// `defaultMessage` pattern: the English source copy lives on each
// `<FormattedMessage>` and IS the extractable source catalog (formatjs
// `extract` emits en.json from it). Non-English locales fall back to that
// English `defaultMessage` until their catalog is supplied, so shipping the 14
// canonical locales requires no per-string translation up front — the selector,
// detection, and persistence all work today and translations drop in later.

const LocaleContext = createContext({ locale: DEFAULT_LOCALE, setLocale: () => {} });

/** Access the active locale + a setter (persists the choice). */
export function useLocale() {
  return useContext(LocaleContext);
}

/**
 * Wrap the app: detect the initial locale (persisted choice → navigator →
 * English), expose it + a persisting setter via context, and provide react-intl.
 * Missing-translation errors are swallowed (expected while catalogs are
 * English-only) so the console stays clean; real formatting errors still throw.
 */
export function I18nProvider({ children }) {
  const [locale, setLocaleState] = useState(getInitialLocale);

  const setLocale = useCallback((code) => {
    persistLocale(code);
    setLocaleState(code);
  }, []);

  const ctx = useMemo(() => ({ locale, setLocale }), [locale, setLocale]);

  return (
    <LocaleContext.Provider value={ctx}>
      <IntlProvider
        locale={locale}
        defaultLocale={DEFAULT_LOCALE}
        messages={{}}
        onError={(err) => {
          if (err.code !== "MISSING_TRANSLATION") throw err;
        }}
      >
        {children}
      </IntlProvider>
    </LocaleContext.Provider>
  );
}
