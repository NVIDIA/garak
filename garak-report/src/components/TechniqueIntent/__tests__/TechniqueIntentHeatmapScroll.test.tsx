/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { view, dispatch } from "./heatmapFixtures";
import TestHeatmap from "./HeatmapHarness";
import { render, screen, fireEvent, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { HeatmapEvent } from "../../../types/TechniqueIntentHeatmap";
const targets: HeatmapEvent[] = [
  { componentType: "series", data: { rowKey: "t1", colKey: "i1", value: [0, 0, 0] } },
  { componentType: "yAxis", value: "t1" },
  { componentType: "xAxis", value: "i1" },
];
const descriptor = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollIntoView");
const scroll = vi.fn();
beforeEach(() => {
  scroll.mockClear();
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: scroll,
  });
});
afterEach(() => {
  if (descriptor) Object.defineProperty(HTMLElement.prototype, "scrollIntoView", descriptor);
  else Reflect.deleteProperty(HTMLElement.prototype, "scrollIntoView");
  vi.unstubAllGlobals();
});
describe("heatmap detail scrolling", () => {
  it.each(targets)("reveals selected $componentType details once", event => {
    vi.stubGlobal("matchMedia", () => ({ matches: false }));
    render(<TestHeatmap view={view} />);
    expect(scroll).not.toHaveBeenCalled();
    dispatch("click", event);
    expect(scroll).toHaveBeenCalledExactlyOnceWith({ behavior: "smooth", block: "start" });
    const target = scroll.mock.contexts[0] as HTMLElement;
    expect(
      within(target).getByRole("button", { name: "Clear selection" }),
      "scroll targets details"
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Zoom in" }));
    dispatch("click", event);
    expect(scroll, "zoom and deselection do not scroll again").toHaveBeenCalledTimes(1);
  });
  it("respects reduced-motion preferences", () => {
    vi.stubGlobal("matchMedia", () => ({ matches: true }));
    render(<TestHeatmap view={view} />);
    dispatch("click", targets[0]);
    expect(scroll).toHaveBeenCalledExactlyOnceWith({ behavior: "auto", block: "start" });
  });
});
