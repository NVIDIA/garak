import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import InfoTooltip from "../InfoTooltip";
import { describe, it, expect } from "vitest";

describe("InfoTooltip", () => {
  it("toggles content on click and closes on outside click", () => {
    render(
      <div>
        <InfoTooltip text="Hello world" />
        <button>outside</button>
      </div>
    );

    // Initially hidden
    expect(screen.queryByText("Hello world")).toBeNull();

    // Click icon to show
    fireEvent.click(screen.getByLabelText("More info"));
    expect(screen.getByText("Hello world")).toBeInTheDocument();

    // Click outside to hide
    fireEvent.mouseDown(document.body);
    expect(screen.queryByText("Hello world")).toBeNull();
  });

  it("toggles show/hide on repeated icon clicks with children content", () => {
    render(
      <InfoTooltip>
        <span data-testid="custom">Custom</span>
      </InfoTooltip>
    );
    const icon = screen.getByLabelText("More info");
    fireEvent.click(icon);
    expect(screen.getByTestId("custom")).toBeInTheDocument();
    fireEvent.click(icon); // hide again
    expect(screen.queryByTestId("custom")).toBeNull();
  });
}); 