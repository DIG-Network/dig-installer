import { describe, it, expect, vi } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Components } from "./Components.jsx";
import { COMPONENTS, defaultSelection } from "../data.jsx";
import { renderWithIntl } from "../test/renderWithIntl.jsx";

// The extension component's rendered label (its `name` is now a react-intl
// descriptor whose `defaultMessage` IS the English text — #654).
const extName = () => ext().name.defaultMessage;

// The two rows the dig-app → dig-node dependency lock pairs up (#1800).
const appName = () => comp("dig-app").name.defaultMessage;
const nodeRow = () => screen.getByText(comp("dig-node").name.defaultMessage).closest(".comp");

// The default selection the wizard seeds (App.jsx `sel`) — the SAME
// `defaultSelection()` the app calls, not a copy of it. This used to be a
// hand-written literal and had already drifted: it omitted `dig-app`, so every
// render here took the unlocked path and no test ever saw the real screen.
const defaultSel = defaultSelection();

const renderStep = (sel = defaultSel, toggle = () => {}) =>
  renderWithIntl(<Components sel={sel} toggle={toggle} path="/opt/dig" onChange={() => {}} status={[]} />);

describe("Components step — the extension entry (#611)", () => {
  it("offers an extension component in the catalogue", () => {
    const ext = COMPONENTS.find((c) => c.id === "extension");
    expect(ext).toBeDefined();
    expect(ext.on).toBe(true); // checked by default
    expect(ext.hidden).toBeFalsy(); // actually rendered
  });

  it("renders the extension row, checked by default", () => {
    renderStep();
    const row = screen.getByText(extName()).closest(".comp");
    expect(row).toBeInTheDocument();
    expect(row.querySelector(".check")).toHaveClass("on");
  });

  it("toggles the extension selection when its row is clicked", async () => {
    const toggle = vi.fn();
    renderStep(defaultSel, toggle);
    await userEvent.click(screen.getByText(extName()).closest(".comp"));
    expect(toggle).toHaveBeenCalledWith("extension");
  });

  it("shows the extension row unchecked when the user has opted out", () => {
    renderStep({ ...defaultSel, extension: false });
    const row = screen.getByText(extName()).closest(".comp");
    expect(row.querySelector(".check")).not.toHaveClass("on");
  });
});

describe("Components step — the dig-app → dig-node dependency lock (#1800)", () => {
  it("keeps dig-node checked and un-toggleable while dig-app is selected", async () => {
    const toggle = vi.fn();
    renderStep(defaultSel, toggle);
    const row = nodeRow();
    expect(row.querySelector(".check")).toHaveClass("on");
    await userEvent.click(row);
    expect(toggle).not.toHaveBeenCalled();
  });

  // Locked implies CHECKED, not merely un-toggleable: dig-node is installed for a
  // dig-app user either way, so a row left unchecked would misreport the install.
  // The UI mirror of the backend's forces-dig-node-even-when-explicitly-deselected
  // test — and what makes the "checked" half of the assertion above non-vacuous,
  // since the default selection already has dig-node on.
  it("shows dig-node checked even when the selection map explicitly deselects it", () => {
    renderStep({ ...defaultSel, "dig-node": false });
    expect(nodeRow().querySelector(".check")).toHaveClass("on");
  });

  it("names the dependent on the locked dig-node row, rather than greying it out unexplained", () => {
    renderStep();
    const pill = nodeRow().querySelector(".pill-req");
    expect(pill).toBeInTheDocument();
    expect(pill).toHaveTextContent(`NEEDED BY ${appName()}`);
  });

  // The escape hatch, and the control on the assertions above: without it an
  // implementation that simply pinned dig-node on forever would satisfy every one
  // of them while trapping the user (§6.1).
  it("toggles dig-node again once dig-app is deselected", async () => {
    const toggle = vi.fn();
    renderStep({ ...defaultSel, "dig-app": false }, toggle);
    await userEvent.click(nodeRow());
    expect(toggle).toHaveBeenCalledWith("dig-node");
  });
});

// Catalogue lookup by the component id the install pipeline uses.
function comp(id) {
  return COMPONENTS.find((c) => c.id === id);
}

function ext() {
  return comp("extension");
}
