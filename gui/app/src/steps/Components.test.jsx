import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Components } from "./Components.jsx";
import { COMPONENTS } from "../data.jsx";

// The default selection the wizard seeds (App.jsx `sel`) — the extension is
// pre-checked per #602 Piece A item 1.
const defaultSel = {
  "dig-node": true,
  "dig-dns": true,
  "dig-relay": false,
  extension: true,
  "open-firewall": true,
  "auto-update": true,
};

const renderStep = (sel = defaultSel, toggle = () => {}) =>
  render(<Components sel={sel} toggle={toggle} path="/opt/dig" onChange={() => {}} status={[]} />);

describe("Components step — the extension entry (#611)", () => {
  it("offers an extension component in the catalogue", () => {
    const ext = COMPONENTS.find((c) => c.id === "extension");
    expect(ext).toBeDefined();
    expect(ext.on).toBe(true); // checked by default
    expect(ext.hidden).toBeFalsy(); // actually rendered
  });

  it("renders the extension row, checked by default", () => {
    renderStep();
    const row = screen.getByText(ext().name).closest(".comp");
    expect(row).toBeInTheDocument();
    expect(row.querySelector(".check")).toHaveClass("on");
  });

  it("toggles the extension selection when its row is clicked", async () => {
    const toggle = vi.fn();
    renderStep(defaultSel, toggle);
    await userEvent.click(screen.getByText(ext().name).closest(".comp"));
    expect(toggle).toHaveBeenCalledWith("extension");
  });

  it("shows the extension row unchecked when the user has opted out", () => {
    renderStep({ ...defaultSel, extension: false });
    const row = screen.getByText(ext().name).closest(".comp");
    expect(row.querySelector(".check")).not.toHaveClass("on");
  });
});

function ext() {
  return COMPONENTS.find((c) => c.id === "extension");
}
