/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import "./heatmapFixtures";
import { renderHook } from "@testing-library/react";
import { init } from "echarts";
import { describe, expect, it } from "vitest";
import { useTechniqueIntentHeatmapOptions } from "../useTechniqueIntentHeatmapOptions";
import { buildMatrixView } from "../../utils/techniqueIntentRollup";

const sample = (n: number, score = 1) => ({
  score,
  passed: n * score,
  total_evaluated: n,
  nones: 0,
});
const view = buildMatrixView({
  t: {
    one: sample(1),
    many: sample(200),
    below: sample(11),
    boundary: sample(12),
    failure: sample(1, 0),
  },
  other: { missing: sample(200) },
});

describe("heatmap evaluation counts", () => {
  it("distinguishes sparse evidence without changing pass-rate colours or marking untested cells", () => {
    const { result, rerender } = renderHook(
      ({ minEvaluations }) => useTechniqueIntentHeatmapOptions(view, true, { minEvaluations }),
      { initialProps: { minEvaluations: 12 } }
    );
    const cells = () =>
      Object.fromEntries(
        result.current.option.series[0].data
          .filter(point => point.rowKey === "t")
          .map(point => [point.colKey, point])
      );
    expect(cells().one.itemStyle.color, "identical observed pass rates retain identical hues").toBe(
      cells().many.itemStyle.color
    );
    for (const key of ["one", "below", "failure"])
      expect(
        cells()[key].itemStyle.decal,
        `${key} is visibly qualified by its low count`
      ).toBeDefined();
    for (const key of ["boundary", "many", "missing"])
      expect(
        cells()[key].itemStyle.decal,
        `${key} must not receive a low-count pattern`
      ).toBeUndefined();
    expect(cells().missing.itemStyle.color, "untested remains empty").toBe("transparent");
    rerender({ minEvaluations: 0 });
    expect(
      cells().one.itemStyle.decal,
      "a zero threshold disables the count qualification"
    ).toBeUndefined();
  });

  it("adds counts only when zoom leaves enough space for the labels", () => {
    const { result, rerender } = renderHook(
      ({ width }) => useTechniqueIntentHeatmapOptions(view, false, { width }),
      { initialProps: { width: 1600 } }
    );
    const one = () =>
      result.current.option.series[0].data.find(
        point => point.rowKey === "t" && point.colKey === "one"
      )!;
    expect(one().label.formatter, "a readable tile includes its denominator").toBe("100%\nn=1");
    rerender({ width: 700 });
    expect(one().label.formatter, "narrow tiles keep their compact percentage").toBe("100%");
  });

  it.each([false, true])(
    "renders the pattern while preserving measured failures in dark=%s",
    isDark => {
      const { result } = renderHook(() =>
        useTechniqueIntentHeatmapOptions(view, isDark, { minEvaluations: 12 })
      );
      const chart = init(null, undefined, {
        renderer: "svg",
        ssr: true,
        width: 1200,
        height: result.current.height,
      });
      try {
        chart.setOption(result.current.option);
        const svg = chart.renderToSVGString();
        expect(svg, "the actual ECharts renderer creates a pattern").toContain("<pattern");
        expect(svg, "the pattern is applied to tiles").toContain("url(#");
        expect(svg, "a measured failure retains the red KUI fill").toContain("rgb(194,30,30)");
        expect(svg, "evaluation counts render inside readable cells").toContain("n=1");
      } finally {
        chart.dispose();
      }
    }
  );
});
