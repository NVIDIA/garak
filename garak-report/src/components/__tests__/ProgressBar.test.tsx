/**
 * @file ProgressBar.test.tsx
 * @description Tests for the ProgressBar component.
 */

import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import ProgressBar from "../ProgressBar";

describe("ProgressBar", () => {
  it("renders green portion for pass percentage", () => {
    const { container } = render(<ProgressBar passPercent={75} hasFailures={true} />);
    
    const bars = container.querySelectorAll("div > div");
    expect(bars.length).toBeGreaterThan(0);
  });

  it("shows red portion only when hasFailures is true", () => {
    const { container: withFailures } = render(<ProgressBar passPercent={75} hasFailures={true} />);
    const { container: withoutFailures } = render(<ProgressBar passPercent={75} hasFailures={false} />);
    
    // With failures should have 2 colored divs (green + red)
    const withFailuresBars = withFailures.querySelectorAll("div > div > div");
    // Without failures should have 1 colored div (green only)
    const withoutFailuresBars = withoutFailures.querySelectorAll("div > div > div");
    
    expect(withFailuresBars.length).toBe(2);
    expect(withoutFailuresBars.length).toBe(1);
  });

  it("shows 100% green when passPercent is 100", () => {
    const { container } = render(<ProgressBar passPercent={100} hasFailures={false} />);
    
    const greenBar = container.querySelector("div > div > div");
    expect(greenBar).toHaveStyle({ width: "100%" });
  });

  it("shows 0% green when passPercent is 0", () => {
    const { container } = render(<ProgressBar passPercent={0} hasFailures={true} />);
    
    // Only red bar should be visible
    const bars = container.querySelectorAll("div > div > div");
    expect(bars.length).toBe(1);
  });

  it("uses custom height when provided", () => {
    const { container } = render(<ProgressBar passPercent={50} hasFailures={true} height={12} />);
    
    const wrapper = container.querySelector("div > div");
    expect(wrapper).toHaveStyle({ height: "12px" });
  });
});
