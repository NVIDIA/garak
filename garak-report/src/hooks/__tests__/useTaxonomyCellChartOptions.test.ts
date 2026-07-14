/**
 * @file useTaxonomyCellChartOptions.test.ts
 * @description Tests for the taxonomy cell bar-chart options hook.
 */

import { renderHook } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { useTaxonomyCellChartOptions } from "../useTaxonomyCellChartOptions";
import { CHART_OPACITY } from "../../constants";
import type { AxisCell } from "../../utils/techniqueIntentRollup";

vi.mock("../useSeverityColor", () => ({
  default: () => ({ getSeverityColorByLevel: (defcon: number) => `defcon-${defcon}` }),
}));

const cellOf = (otherKey: string, score: number): AxisCell => ({
  otherKey,
  otherLabel: otherKey,
  cell: {
    row: "t",
    col: otherKey,
    score,
    nEvaluations: 100,
    leafCount: 1,
    detectors: [],
    leaves: [],
  },
});

const seriesData = (option: unknown) =>
  (option as { series: { data: { value: number; itemStyle: { opacity: number } }[] }[] }).series[0]
    .data;

describe("useTaxonomyCellChartOptions", () => {
  const cells = [cellOf("a", 0.02), cellOf("b", 1)];

  it("plots one worst-first bar per cell as a 0-100 percentage", () => {
    const { result } = renderHook(() => useTaxonomyCellChartOptions(cells, null));
    const data = seriesData(result.current.option);
    expect(data.map(d => d.value), "scores rendered as integer percentages").toEqual([2, 100]);
  });

  it("dims non-selected bars when a selection is active", () => {
    const { result } = renderHook(() => useTaxonomyCellChartOptions(cells, "a"));
    const data = seriesData(result.current.option);
    expect(data[0].itemStyle.opacity, "selected bar stays full").toBe(CHART_OPACITY.full);
    expect(data[1].itemStyle.opacity, "other bars dim").toBe(CHART_OPACITY.dimmed);
  });

  it("grows the chart height with the number of cells", () => {
    const few = renderHook(() => useTaxonomyCellChartOptions(cells, null));
    const many = renderHook(() =>
      useTaxonomyCellChartOptions([...cells, cellOf("c", 0.5), cellOf("d", 0.5)], null),
    );
    expect(many.result.current.height, "more cells need more vertical space").toBeGreaterThan(
      few.result.current.height,
    );
  });
});
