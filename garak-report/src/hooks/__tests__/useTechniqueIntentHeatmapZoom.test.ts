/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { counts, view } from "./heatmapFixtures";
import { renderHook } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { useTechniqueIntentHeatmapOptions } from "../useTechniqueIntentHeatmapOptions";
import { buildMatrixView } from "../../utils/techniqueIntentRollup";

describe("useTechniqueIntentHeatmapZoom", () => {
  it("shows all techniques with horizontal intent labels", () => {
    const larger = buildMatrixView(
      Object.fromEntries(
        Array.from({ length: 20 }, (_, row) => [
          `t${row}`,
          Object.fromEntries(Array.from({ length: 20 }, (_, col) => [`i${col}`, counts(1)])),
        ])
      )
    );
    const { result } = renderHook(() =>
      useTechniqueIntentHeatmapOptions(larger, false, { colSpan: 8 })
    );
    expect(result.current.rowCount, "every technique remains visible").toBe(20);
    expect(result.current.colCount, "columns retain enough width for labels").toBeLessThanOrEqual(
      8
    );
    expect(result.current.option.xAxis.axisLabel.rotate, "labels read horizontally").toBe(0);
    expect(result.current.option.dataZoom[0].zoomLock, "the intent window can be expanded").toBe(
      false
    );
  });

  it("preserves the navigated window when a selection changes", () => {
    const larger = buildMatrixView(
      Object.fromEntries(
        Array.from({ length: 20 }, (_, row) => [
          `t${row}`,
          Object.fromEntries(Array.from({ length: 20 }, (_, col) => [`i${col}`, counts(1)])),
        ])
      )
    );
    const { result } = renderHook(() =>
      useTechniqueIntentHeatmapOptions(larger, false, {
        colStart: 7,
        colSpan: 8,
        selection: { axis: "technique", key: "t1" },
      })
    );
    expect(
      result.current.option.dataZoom.map(zoom => zoom.startValue),
      "selection retains the intent position"
    ).toEqual([7]);
  });

  it("zooms out to the full matrix without changing scores", () => {
    const large = buildMatrixView({
      t: Object.fromEntries(Array.from({ length: 52 }, (_, i) => [`i${i}`, counts(0.4)])),
    });
    const { result } = renderHook(() =>
      useTechniqueIntentHeatmapOptions(large, false, { width: 1200, colSpan: 52 })
    );
    expect(result.current.colCount, "all intents fit in the overview").toBe(52);
    expect(
      result.current.option.series[0].data[0].label.show,
      "dense cells defer percentages to hover and detail"
    ).toBe(false);
    expect(
      result.current.option.series[0].data[0].value[2],
      "zoom leaves the pass rate unchanged"
    ).toBe(0.4);
  });

  it("reduces the visible column count on narrow screens without shrinking text", () => {
    const { result } = renderHook(() =>
      useTechniqueIntentHeatmapOptions(view, false, { width: 390, colSpan: 1 })
    );
    expect(result.current.colCount, "a narrow screen shows fewer readable columns").toBe(1);
    expect(result.current.option.yAxis.axisLabel.width, "row labels stay inside the chart").toBe(
      120
    );
  });
});
