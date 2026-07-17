import { render } from "@testing-library/react";
import { IntlProvider } from "react-intl";

// Render a component under a minimal react-intl provider (#654). Step components
// use `<FormattedMessage>`/`useIntl`, which require an `IntlProvider` ancestor;
// the app supplies one via `I18nProvider`, so isolated component tests wrap with
// this equivalent. English-only: each message's inline `defaultMessage` IS the
// rendered text, so the asserted DOM copy is identical to the pre-i18n markup.
export function renderWithIntl(ui, options) {
  return render(
    <IntlProvider
      locale="en"
      defaultLocale="en"
      messages={{}}
      onError={(err) => {
        if (err.code !== "MISSING_TRANSLATION") throw err;
      }}
    >
      {ui}
    </IntlProvider>,
    options,
  );
}
