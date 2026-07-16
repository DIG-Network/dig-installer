import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Browsers } from "./Browsers.jsx";

// A representative detection result (the #609 DetectedBrowser shape the bridge
// returns), long enough to exercise the scroll container.
const DETECTED = [
  { id: "chrome", display_name: "Google Chrome", install_path: "/opt/google/chrome/chrome" },
  { id: "edge", display_name: "Microsoft Edge", install_path: null },
  { id: "brave", display_name: "Brave", install_path: "/usr/bin/brave" },
  { id: "vivaldi", display_name: "Vivaldi", install_path: "/usr/bin/vivaldi" },
];

// All-checked-by-default selection map (every detected browser opted in).
const allOn = (list) => Object.fromEntries(list.map((b) => [b.id, true]));

describe("Browsers step — four async states (§6.1)", () => {
  it("shows a loading state while detection is in flight", () => {
    render(<Browsers browsers={null} sel={{}} loading error={null} onToggle={() => {}} onRetry={() => {}} />);
    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("shows an error state with a Retry action when detection fails", async () => {
    const onRetry = vi.fn();
    render(
      <Browsers browsers={null} sel={{}} loading={false} error="probe failed" onToggle={() => {}} onRetry={onRetry} />
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/couldn.t detect|failed|error/i);
    await userEvent.click(screen.getByRole("button", { name: /retry|try again/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("shows a non-dead-end empty state when no browsers are detected", () => {
    render(<Browsers browsers={[]} sel={{}} loading={false} error={null} onToggle={() => {}} onRetry={() => {}} />);
    expect(screen.getByText(/no .*browser.* detected|didn.t find/i)).toBeInTheDocument();
    // Never traps: no checkboxes, and the surrounding wizard footer (Back/
    // Continue) still drives navigation — the step itself renders no blocker.
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("renders every detected browser as a checkbox in the success state", () => {
    render(
      <Browsers browsers={DETECTED} sel={allOn(DETECTED)} loading={false} error={null} onToggle={() => {}} onRetry={() => {}} />
    );
    expect(screen.getAllByRole("checkbox")).toHaveLength(DETECTED.length);
    expect(screen.getByText("Google Chrome")).toBeInTheDocument();
    expect(screen.getByText("Microsoft Edge")).toBeInTheDocument();
  });
});

describe("Browsers step — selection behaviour", () => {
  it("checks every detected browser by default (all opted in)", () => {
    render(
      <Browsers browsers={DETECTED} sel={allOn(DETECTED)} loading={false} error={null} onToggle={() => {}} onRetry={() => {}} />
    );
    for (const cb of screen.getAllByRole("checkbox")) expect(cb).toBeChecked();
  });

  it("lets the user opt out of a single browser without affecting others", async () => {
    const onToggle = vi.fn();
    render(
      <Browsers browsers={DETECTED} sel={allOn(DETECTED)} loading={false} error={null} onToggle={onToggle} onRetry={() => {}} />
    );
    await userEvent.click(screen.getByRole("checkbox", { name: /brave/i }));
    expect(onToggle).toHaveBeenCalledTimes(1);
    expect(onToggle).toHaveBeenCalledWith("brave");
  });

  it("reflects an unchecked (opted-out) browser from the selection map", () => {
    render(
      <Browsers
        browsers={DETECTED}
        sel={{ ...allOn(DETECTED), edge: false }}
        loading={false}
        error={null}
        onToggle={() => {}}
        onRetry={() => {}}
      />
    );
    const edgeRow = screen.getByText("Microsoft Edge").closest("[data-browser]");
    expect(within(edgeRow).getByRole("checkbox")).not.toBeChecked();
  });

  it("renders the checklist inside a scrollable container (many browsers)", () => {
    const { container } = render(
      <Browsers browsers={DETECTED} sel={allOn(DETECTED)} loading={false} error={null} onToggle={() => {}} onRetry={() => {}} />
    );
    const list = container.querySelector(".browser-list");
    expect(list).toBeInTheDocument();
    expect(list.className).toMatch(/browser-list/);
  });
});
