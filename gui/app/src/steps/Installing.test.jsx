import { describe, it, expect } from "vitest";
import { renderWithIntl } from "../test/renderWithIntl.jsx";
import { Installing } from "./Installing.jsx";

describe("Installing log is injection-safe (#2040)", () => {
  it("renders a segment's text as literal characters, never as HTML", () => {
    const payload = '<img src=x onerror="alert(1)">';
    const lines = [[{ text: `installing to ${payload}`, cls: "ac" }]];
    const { container } = renderWithIntl(
      <Installing pct={30} lines={lines} nowFile="x" error={null} />,
    );
    // the payload never becomes a real element…
    expect(container.querySelector("img")).toBeNull();
    // …it appears verbatim as text, and its class is applied safely
    const span = container.querySelector(".term .ln .ac");
    expect(span).not.toBeNull();
    expect(span.textContent).toContain(payload);
  });
});
