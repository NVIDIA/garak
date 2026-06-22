/**
 * @file useTechniqueIntentHeatmapOptions.test.ts
 * @description Verifies the technique × intent heatmap option builder: cell
 *              projection from a MatrixView, worst-first row ordering, the
 *              cursor-following tooltip, and the 5-bucket legend.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { renderHook } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import {
  useTechniqueIntentHeatmapOptions,
  type HeatmapCell,
} from "../useTechniqueIntentHeatmapOptions";
import { buildMatrixView } from "../../utils/techniqueIntentRollup";
import { CHART_DIMENSIONS } from "../../constants";
import type { TechniqueIntentMatrix } from "../../types/ReportEntry";

const matrix: TechniqueIntentMatrix = {
  "demon:Fictionalizing:Roleplaying:User_persona": {
    T009ignore: { score: 0, n_evaluations: 40, detectors_used: ["dan.DAN"] },
  },
  "demon:Language:Code_and_encode:Token": {
    S005hate: { score: 0.998, n_evaluations: 1850, detectors_used: ["safe.det"] },
  },
};

const view = buildMatrixView(matrix, "leaf");

describe("useTechniqueIntentHeatmapOptions", () => {
  it("fills the full row×col grid, projecting populated entries with a pass rate", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    const cells = result.current.series[0].data as HeatmapCell[];
    // 2 techniques × 2 intents = 4 cells; only the 2 diagonal pairs have data.
    expect(cells).toHaveLength(4);
    const populated = cells.filter(c => !c.empty);
    expect(populated).toHaveLength(2);
    populated.forEach(c => {
      expect(c.value).toHaveLength(3);
      expect(c.value[2]).toBeGreaterThanOrEqual(0);
    });
  });

  it("renders un-evaluated pairs as neutral N/A cells, not 0%", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    const cells = result.current.series[0].data as Array<
      HeatmapCell & { itemStyle?: { color?: string }; label?: { formatter?: () => string } }
    >;
    const na = cells.filter(c => c.empty);
    expect(na).toHaveLength(2); // the two off-diagonal pairs
    na.forEach(c => {
      expect(c.value[2]).toBeNull(); // no percentage, so it never colors via the risk ramp
      expect(c.itemStyle?.color).toBeTruthy(); // explicit neutral fill overrides the visualMap
      expect(c.label?.formatter?.()).toBe("N/A");
    });
  });

  it("orders rows worst-first and inverts the y-axis so they render at the top", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    expect(result.current.yAxis.inverse).toBe(true);
    // The 0% row is the most vulnerable and sorts first.
    expect(result.current.yAxis.data[0]).toContain("User_persona");
  });

  it("emits a 5-bucket piecewise legend aligned to the DEFCON scale", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    expect(result.current.visualMap.pieces).toHaveLength(5);
  });

  it("uses a cursor-following tooltip with an offset", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    expect(result.current.tooltip.position([100, 200])).toEqual([112, 212]);
  });

  it("formats the tooltip with the technique row, intent column and pass rate", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    const worst = (result.current.series[0].data as HeatmapCell[]).find(c => c.score === 0)!;
    const html = result.current.tooltip.formatter({ data: worst });
    expect(html).toContain(worst.rowLabel);
    expect(html).toContain(worst.colLabel);
    expect(html).toContain("Pass rate: 0%");
  });

  it("reuses the shared grid constant (with extra bottom room for the legend)", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    expect(result.current.grid.left).toBe(CHART_DIMENSIONS.grid.left);
    expect(result.current.grid.containLabel).toBe(true);
    expect(result.current.grid.bottom).toBe(60);
  });

  it("gives each populated cell a fixed black/white label colour, never inheriting the fill", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    type LabeledCell = HeatmapCell & { label?: { color?: string } };
    const populated = (result.current.series[0].data as LabeledCell[]).filter(c => !c.empty);
    populated.forEach(c => {
      expect(["#111827", "#ffffff"]).toContain(c.label?.color);
    });
  });

  it("outlines the hovered cell without dimming others or recolouring its label", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    const emphasis = result.current.series[0].emphasis;
    expect(emphasis.itemStyle.borderWidth).toBeGreaterThan(0); // crisp outline on hover
    expect(emphasis.focus).toBeUndefined(); // no blur/dim of the rest of the grid
    expect(emphasis.label).toBeUndefined(); // label colour is pinned per-cell, not here

    // Each populated cell pins its label colour in the emphasis state too.
    type LabeledCell = HeatmapCell & { emphasis?: { label?: { color?: string } } };
    const populated = (result.current.series[0].data as LabeledCell[]).filter(c => !c.empty);
    populated.forEach(c => {
      expect(["#111827", "#ffffff"]).toContain(c.emphasis?.label?.color);
    });
  });
});
