import { useIntl } from "react-intl";
import { LOCALES } from "./locales.js";
import { useLocale } from "./I18nProvider.jsx";

/**
 * The locale picker mounted in the app shell (#642): a native <select> of the
 * 14 canonical locales that switches + persists the active locale. Labelled for
 * assistive tech; brand/scheme literals in copy are preserved by the message
 * formatter, not here.
 */
export function LanguageSelector() {
  const { locale, setLocale } = useLocale();
  const intl = useIntl();
  const label = intl.formatMessage({
    id: "language.selector.label",
    defaultMessage: "Language",
  });
  return (
    <label className="lang-selector" title={label} aria-label={label}>
      <select value={locale} onChange={(e) => setLocale(e.target.value)}>
        {LOCALES.map((l) => (
          <option key={l.code} value={l.code}>
            {l.name}
          </option>
        ))}
      </select>
    </label>
  );
}
