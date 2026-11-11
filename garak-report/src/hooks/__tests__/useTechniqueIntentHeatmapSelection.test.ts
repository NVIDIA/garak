/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { view } from "./heatmapFixtures";
import { renderHook } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { useTechniqueIntentHeatmapOptions } from "../useTechniqueIntentHeatmapOptions";

describe("useTechniqueIntentHeatmapSelection", () => {
  it.each(["cell", "technique", "intent"] as const)("outlines a persistent %s selection", axis => {
    const selection =
      axis === "cell"
        ? { axis, technique: "demon:one", intent: "i1" }
        : { axis, key: axis === "technique" ? "demon:one" : "i1" };
    const { result } = renderHook(() =>
      useTechniqueIntentHeatmapOptions(view, false, { selection })
    );
    const outline = result.current.option.graphic.elements[0];
    expect(outline.ignore, "the selected axis or pairing has an outline").toBe(false);
    expect(outline.z, "the outline is drawn above tiles and hover bands").toBeGreaterThan(50);
    expect(outline.silent, "the overlay does not intercept clicks or tooltips").toBe(true);
    const { grid } = result.current.option;
    if (axis === "technique") {
      expect(outline.shape.width, "a row uses one continuous full-width outline").toBe(
        1200 - grid.left - grid.right
      );
    } else if (axis === "intent") {
      expect(outline.shape.height, "a column uses one continuous full-height outline").toBe(
        result.current.height - grid.top - grid.bottom
      );
    }
    expect(
      result.current.option.series[0].data.every(point => point.itemStyle.borderWidth === 0.5),
      "tiles retain their normal grid borders"
    ).toBe(true);
  });

  it("clears the overlay and hides off-screen cell selections without losing them", () => {
    const { result, rerender } = renderHook(
      ({ selection, colStart }) =>
        useTechniqueIntentHeatmapOptions(view, false, { selection, colStart, colSpan: 1 }),
      {
        initialProps: {
          selection: { axis: "cell" as const, technique: "demon:one", intent: "i1" },
          colStart: 0,
        },
      }
    );
    expect(
      result.current.option.graphic.elements[0].ignore,
      "the selected cell is initially visible"
    ).toBe(false);
    rerender({ selection: { axis: "cell", technique: "demon:one", intent: "i1" }, colStart: 1 });
    expect(
      result.current.option.graphic.elements[0].ignore,
      "off-screen selections are not outlined over another cell"
    ).toBe(true);
    rerender({ selection: { axis: "cell", technique: "demon:one", intent: "i1" }, colStart: 0 });
    expect(
      result.current.option.graphic.elements[0].ignore,
      "panning back restores the same outline"
    ).toBe(false);
  });
});
