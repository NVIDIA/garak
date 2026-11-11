/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { counts } from "./heatmapFixtures";
import { renderHook } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { useTechniqueIntentHeatmapOptions } from "../useTechniqueIntentHeatmapOptions";
import { buildMatrixView } from "../../utils/techniqueIntentRollup";
import type { HeatmapSelection } from "../../types/TechniqueIntentHeatmap";
describe("heatmap data lifetime", () => {
  it("keeps full summaries cached and limits interaction work to visible tiles", () => {
    const original = buildMatrixView(
      Object.fromEntries(
        Array.from({ length: 50 }, (_, r) => [
          `t${r}`,
          Object.fromEntries(Array.from({ length: 500 }, (_, c) => [`i${c}`, counts(1)])),
        ])
      )
    );
    const cell = vi.fn(original.cell),
      view = { ...original, cell };
    const { result, rerender } = renderHook(
      ({ selection }: { selection: HeatmapSelection | null }) =>
        useTechniqueIntentHeatmapOptions(view, false, { selection, colSpan: 10 }),
      { initialProps: { selection: null as HeatmapSelection | null } }
    );
    const groups = result.current.groups;
    cell.mockClear();
    rerender({ selection: { axis: "cell", technique: "t0", intent: "i0" } });
    expect(result.current.groups, "selection does not rebuild report summaries").toBe(groups);
    expect(groups.intent.size, "summaries retain off-screen intents").toBe(500);
    expect(result.current.option.series[0].data, "only the visible window is plotted").toHaveLength(
      500
    );
    expect(
      cell.mock.calls.length,
      "selection avoids rescanning all 25,000 intersections"
    ).toBeLessThanOrEqual(1000);
  });
});
