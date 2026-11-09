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
    nAttempts: 100,
    passed: Math.round(score * 100),
    nones: 0,
    nDetectors: 1,
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
    expect(
      data.map(d => d.value),
      "scores rendered as integer percentages"
    ).toEqual([2, 100]);
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
      useTaxonomyCellChartOptions([...cells, cellOf("c", 0.5), cellOf("d", 0.5)], null)
    );
    expect(many.result.current.height, "more cells need more vertical space").toBeGreaterThan(
      few.result.current.height
    );
  });

  it("keeps an unscored result out of the numeric pass-rate scale", () => {
    const unknown = cellOf("unknown", 1);
    unknown.cell = { ...unknown.cell, score: null, passed: 0, nEvaluations: 0, nones: 210 };
    const { result } = renderHook(() => useTaxonomyCellChartOptions([unknown], null));
    expect(
      seriesData(result.current.option)[0].value,
      "missing verdicts are never plotted as zero pass rate"
    ).toBeNull();
    expect(
      result.current.option.tooltip.formatter({ dataIndex: 0 }),
      "the preview retains unscored results"
    ).toContain("210 undetermined results");
  });

  it("escapes supplied taxonomy names in the chart preview", () => {
    const named = { ...cellOf("custom", 1), otherLabel: "Intent <img src=x>" };
    const { result } = renderHook(() => useTaxonomyCellChartOptions([named], null));
    expect(
      result.current.option.tooltip.formatter({ dataIndex: 0 }),
      "taxonomy text cannot become tooltip HTML"
    ).toContain("Intent &lt;img src=x&gt;");
  });

  it("uses the readable name on the axis while retaining the full identity for selection", () => {
    const named = {
      ...cellOf("X", 1),
      otherLabel: "Readable intent (X)",
      otherName: "Readable intent",
    };
    const { result } = renderHook(() => useTaxonomyCellChartOptions([named], null));
    expect(
      result.current.option.yAxis.axisLabel.formatter(named.otherLabel, 0),
      "chart labels put the human name first"
    ).toBe("Readable intent");
    expect(
      result.current.option.yAxis.data,
      "clicks still resolve the complete pairing identity"
    ).toEqual([named.otherLabel]);
  });
});
