import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { FooterActions } from "./FooterActions.jsx";

const base = {
  cur: "welcome",
  step: 0,
  installing: false,
  error: null,
  canContinue: true,
  primaryLabel: "Continue",
  onBack: () => {},
  onViewLog: () => {},
  onOpenDocs: () => {},
  onClose: () => {},
  onNext: () => {},
};

describe("FooterActions", () => {
  // Regression for #716: the Done screen's overflowing footer had the language
  // selector + dots + Open Documentation + Close + Launch Terminal all on one
  // row, clipping Launch Terminal at the window edge. Launch Terminal is
  // removed; the Done screen shows exactly Open Documentation + Close.
  it("Done screen shows Open Documentation + Close and NO Launch Terminal", () => {
    render(<FooterActions {...base} cur="finish" step={4} />);
    expect(screen.getByRole("button", { name: "Open Documentation" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Launch Terminal/i })).toBeNull();
    // The generic step-advance primary is suppressed on the Done screen.
    expect(screen.queryByRole("button", { name: "Continue" })).toBeNull();
  });

  it("Close is the primary action on the Done screen and fires its handler", async () => {
    const onClose = vi.fn();
    render(<FooterActions {...base} cur="finish" step={4} onClose={onClose} />);
    const close = screen.getByRole("button", { name: "Close" });
    expect(close.className).toContain("btn-primary");
    close.click();
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("non-finish steps render the single step-advance primary", () => {
    render(<FooterActions {...base} cur="components" step={2} />);
    expect(screen.getByRole("button", { name: "Continue" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Back" })).toBeInTheDocument();
  });

  it("hides Back on the first step", () => {
    render(<FooterActions {...base} cur="welcome" step={0} primaryLabel="Install DIG" />);
    expect(screen.queryByRole("button", { name: "Back" })).toBeNull();
    expect(screen.getByRole("button", { name: "Install DIG" })).toBeInTheDocument();
  });
});
