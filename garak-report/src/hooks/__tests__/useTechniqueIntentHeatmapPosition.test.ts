/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { view } from "./heatmapFixtures";
import { renderHook } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { useTechniqueIntentHeatmapOptions } from "../useTechniqueIntentHeatmapOptions";

describe("useTechniqueIntentHeatmapPosition", () => {
  it("anchors previews beside the cell and keeps them inside the chart", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    const position = result.current.option.tooltip.position;
    const dom = document.createElement("div");
    const size = { viewSize: [1200, 600], contentSize: [320, 280] };
    const cell = { x: 300, y: 100, width: 20, height: 24 };
    const first = position([301, 101], {}, dom, cell, size);
    expect(
      position([319, 123], {}, dom, cell, size),
      "movement within a cell does not move the preview"
    ).toEqual(first);
    expect(first, "preview sits to the right with a gap").toEqual([332, 100]);
    expect(
      position([1190, 590], {}, dom, { ...cell, x: 1180, y: 576 }, size),
      "right and bottom edges flip and constrain the preview"
    ).toEqual([848, 320]);
    expect(
      position([100, 400], {}, dom, { ...cell, x: 100, y: 400 }, { ...size, viewSize: [390, 600] }),
      "narrow charts place the preview above the cell"
    ).toEqual([0, 108]);
    expect(
      position([100, 10], {}, dom, { ...cell, x: 100, y: 10 }, { ...size, viewSize: [390, 600] }),
      "top-edge previews fit below the cell"
    ).toEqual([0, 46]);
  });

  it("keeps taller previews visible when the chart starts near the viewport bottom", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    const host = document.createElement("div");
    const dom = host.appendChild(document.createElement("div"));
    vi.spyOn(host, "getBoundingClientRect").mockReturnValue({
      top: window.innerHeight - 100,
    } as DOMRect);
    const [, y] = result.current.option.tooltip.position(
      [100, 20],
      {},
      dom,
      { x: 100, y: 20, width: 20, height: 24 },
      { contentSize: [320, 350], viewSize: [1200, 600] }
    );
    expect(y, "previews may extend above the chart to stay on screen").toBeLessThan(0);
    expect(
      y + window.innerHeight - 100 + 350,
      "the preview ends inside the viewport"
    ).toBeLessThanOrEqual(window.innerHeight - 8);
  });
});
