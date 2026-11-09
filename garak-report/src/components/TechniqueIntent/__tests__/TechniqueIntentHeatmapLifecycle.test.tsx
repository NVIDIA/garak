/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { largeView } from "./heatmapFixtures";
import TestHeatmap from "./HeatmapHarness";
import { render, screen, fireEvent } from "@testing-library/react";
import { StrictMode } from "react";
import { describe, it, expect, vi, afterEach } from "vitest";
import { buildMatrixView } from "../../../utils/techniqueIntentRollup";
afterEach(() => vi.unstubAllGlobals());
describe("heatmap lifecycle", () => {
  it("attaches measurement when results arrive after an empty view", () => {
    const observe = vi.fn(),
      disconnect = vi.fn();
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe = observe;
        disconnect = disconnect;
      }
    );
    const { rerender, unmount } = render(<TestHeatmap view={buildMatrixView({})} />);
    expect(observe, "an empty view has no viewport").not.toHaveBeenCalled();
    rerender(<TestHeatmap view={largeView(20)} />);
    expect(observe, "the new viewport is observed").toHaveBeenCalledOnce();
    unmount();
    expect(disconnect, "the observer follows its element's lifetime").toHaveBeenCalledOnce();
  });
  it("pairs observation and cleanup in Strict Mode", () => {
    const observe = vi.fn(),
      disconnect = vi.fn();
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe = observe;
        disconnect = disconnect;
      }
    );
    const { unmount } = render(
      <StrictMode>
        <TestHeatmap view={largeView(20)} />
      </StrictMode>
    );
    expect(observe).toHaveBeenCalledTimes(2);
    expect(disconnect).toHaveBeenCalledOnce();
    unmount();
    expect(disconnect).toHaveBeenCalledTimes(2);
  });
  it("adapts an overview to a different column count without copied initial state", () => {
    const { rerender } = render(<TestHeatmap view={largeView(20)} />);
    rerender(<TestHeatmap view={largeView(52)} />);
    expect(
      screen.getByText("1 techniques · 52 intents"),
      "overview follows current data"
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Zoom out" })).toBeDisabled();
  });
  it("zooms in and returns to the full overview", () => {
    render(<TestHeatmap view={largeView(20)} />);
    fireEvent.click(screen.getByRole("button", { name: "Zoom in" }));
    expect(screen.getByText("1 techniques · Intents 1–10 of 20")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Zoom out" }));
    expect(screen.getByText("1 techniques · 20 intents")).toBeVisible();
    for (let n = 0; n < 5; n++) fireEvent.click(screen.getByRole("button", { name: "Zoom in" }));
    expect(
      screen.getByRole("button", { name: "Zoom in" }),
      "one intent is the inner limit"
    ).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Reset zoom" }));
    expect(screen.getByText("1 techniques · 20 intents")).toBeVisible();
  });
});
