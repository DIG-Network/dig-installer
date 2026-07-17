import { describe, it, expect } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithIntl } from "../test/renderWithIntl.jsx";
import { Welcome } from "./Welcome.jsx";
import { License } from "./License.jsx";
import { Installing } from "./Installing.jsx";

// #654: every migrated step must render cleanly under react-intl. This catches
// message-format mistakes (e.g. a stray `<…>` in a `defaultMessage` parsed as a
// rich-text tag) at test time, per step, not only in the interactive app.

describe("wizard steps render under react-intl (#654)", () => {
  it("Welcome renders its lead and feature copy", () => {
    renderWithIntl(<Welcome meta={{ version: "1.9.0" }} />);
    expect(screen.getByText(/Your front door to the DIG Network/)).toBeInTheDocument();
    expect(screen.getByText("A Git-shaped workflow")).toBeInTheDocument();
  });

  it("License renders the GPL summary and the agreement checkbox label", () => {
    renderWithIntl(<License agreed={false} setAgreed={() => {}} />);
    expect(screen.getAllByText(/GNU General Public License/).length).toBeGreaterThan(0);
    expect(screen.getByText(/agree to the DigStore License Agreement/)).toBeInTheDocument();
  });

  it("Installing renders the running title", () => {
    renderWithIntl(<Installing pct={10} lines={[]} nowFile="bin/dig-store" error={null} />);
    expect(screen.getByText("Installing DIG")).toBeInTheDocument();
  });

  it("Installing renders the complete title", () => {
    renderWithIntl(<Installing pct={100} lines={[]} nowFile="" error={null} />);
    expect(screen.getByText("Install complete")).toBeInTheDocument();
  });

  it("Installing renders the failed title and error banner", () => {
    renderWithIntl(<Installing pct={40} lines={[]} nowFile="" error={{ message: "boom" }} />);
    expect(screen.getByText("Install failed")).toBeInTheDocument();
    expect(screen.getByText("Installation error")).toBeInTheDocument();
  });
});
