import { screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { Finish } from "./Finish.jsx";
import { renderWithIntl } from "../test/renderWithIntl.jsx";

const meta = { version: "1.9.0" };

describe("Finish", () => {
  it("does not show a restart notice on a clean install", () => {
    renderWithIntl(<Finish path="C:/x" onCopy={() => {}} copied={false} meta={meta} />);
    expect(screen.queryByText(/Restart required/i)).toBeNull();
  });

  it("shows a restart-required notice when a reboot-deferred replace occurred (#562)", () => {
    renderWithIntl(<Finish path="C:/x" onCopy={() => {}} copied={false} meta={meta} restartRequired />);
    expect(screen.getByText(/Restart required/i)).toBeTruthy();
    // Announced to assistive tech.
    expect(screen.getByRole("status")).toBeTruthy();
  });
});
