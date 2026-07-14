/**
 * @file useTaxonomyBreakdownChartOptions.test.ts
 * @description Verifies the 1D taxonomy breakdown bar-chart option builder:
 *              worst-first ordering, label/tooltip formatting, and that it
 *              reuses the shared grid constants.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { renderHook } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import {
  useTaxonomyBreakdownChartOptions,
  type BarDatum,
} from "../useTaxonomyBreakdownChartOptions";
import { CHART_DIMENSIONS } from "../../constants";
import type { TaxonomyScoreMap } from "../../types/ReportEntry";

const techniqueData: TaxonomyScoreMap = {
  "demon:Language:Code_and_encode:Token": {
    score: 0.998,
    n_evaluations: 1850,
    detectors_used: ["safe.det"],
    probes: ["encoding.InjectBase64"],
  },
  "demon:Fictionalizing:Roleplaying:User_persona": {
    score: 0,
    n_evaluations: 40,
    detectors_used: ["dan.DAN"],
    probes: ["dan.Dan_11_0"],
  },
};

const intentData: TaxonomyScoreMap = {
  S005hate: { score: 0.5, n_evaluations: 120, detectors_used: [] },
  T009ignore: { score: 0.1, n_evaluations: 200, detectors_used: [] },
};

describe("useTaxonomyBreakdownChartOptions", () => {
  it("orders bars worst-first (lowest score at index 0)", () => {
    const { result } = renderHook(() =>
      useTaxonomyBreakdownChartOptions(techniqueData, "technique"),
    );
    const data = result.current.series[0].data as Array<BarDatum & { value: number }>;
    expect(data).toHaveLength(2);
    // 0% pass rate is the most vulnerable, so it sorts first.
    expect(data[0].score).toBe(0);
    expect(data[1].score).toBe(0.998);
  });

  it("derives readable technique labels and keeps the full label for the tooltip", () => {
    const { result } = renderHook(() =>
      useTaxonomyBreakdownChartOptions(techniqueData, "technique"),
    );
    const worst = (result.current.series[0].data as BarDatum[])[0];
    // Shortened category-axis label drops the `demon:` prefix; the tooltip keeps
    // the full breadcrumb.
    expect(result.current.xAxis.data[0]).not.toContain("demon:");
    expect(result.current.xAxis.data[0]).toContain("User_persona");
    expect(worst.fullLabel).toContain("Roleplaying");
  });

  it("formats the tooltip with the full label and aggregation metric", () => {
    const { result } = renderHook(() =>
      useTaxonomyBreakdownChartOptions(techniqueData, "technique", false, "lower quartile"),
    );
    const worst = (result.current.series[0].data as BarDatum[])[0];
    const html = result.current.tooltip.formatter({ data: worst });
    expect(html).toContain(worst.fullLabel);
    expect(html).toContain("Lower quartile");
    expect(html).toContain("0%");
    expect(html).toContain("Evaluations: 40");
  });

  it("passes intent codes through verbatim as labels", () => {
    const { result } = renderHook(() => useTaxonomyBreakdownChartOptions(intentData, "intent"));
    const worst = (result.current.series[0].data as BarDatum[])[0];
    expect(worst.score).toBe(0.1); // 0.1 score sorts first
    expect(worst.fullLabel).toBe("T009ignore");
    expect(result.current.xAxis.data[0]).toBe("T009ignore");
  });

  it("renders vertical bars: categories on the x-axis, pass rate on the y-axis", () => {
    const { result } = renderHook(() =>
      useTaxonomyBreakdownChartOptions(techniqueData, "technique"),
    );
    expect(result.current.xAxis.type).toBe("category");
    expect(result.current.yAxis.type).toBe("value");
    expect(result.current.yAxis.max).toBe(100);
    expect(result.current.xAxis.axisLabel.rotate).toBe(CHART_DIMENSIONS.axis.labelRotation);
  });

  it("reuses the shared grid constant", () => {
    const { result } = renderHook(() =>
      useTaxonomyBreakdownChartOptions(techniqueData, "technique"),
    );
    expect(result.current.grid.left).toBe(CHART_DIMENSIONS.grid.left);
    expect(result.current.grid.containLabel).toBe(true);
    expect(result.current.grid.right).toBe(CHART_DIMENSIONS.grid.right);
  });

  it("returns an empty series for an empty map without throwing", () => {
    const { result } = renderHook(() => useTaxonomyBreakdownChartOptions({}, "technique"));
    expect(result.current.series[0].data).toHaveLength(0);
    expect(result.current.tooltip.formatter({ data: undefined as unknown as BarDatum })).toBe("");
  });

  type StyledBar = BarDatum & { itemStyle: { opacity: number } };

  it("keeps every bar at full opacity when no coordinated-hover key is set", () => {
    const { result } = renderHook(() =>
      useTaxonomyBreakdownChartOptions(techniqueData, "technique"),
    );
    const data = result.current.series[0].data as StyledBar[];
    data.forEach(d => expect(d.itemStyle.opacity).toBe(1));
  });

  it("rolls bars up to the heatmap's grouped level, keyed and labelled to match", () => {
    const grouped: TaxonomyScoreMap = {
      "demon:Fictionalizing:Roleplaying:DAN_and_target_persona": {
        score: 0.3,
        n_evaluations: 100,
        detectors_used: [],
      },
      "demon:Fictionalizing:Roleplaying:User_persona": { score: 0, n_evaluations: 40, detectors_used: [] },
    };
    const { result } = renderHook(() =>
      useTaxonomyBreakdownChartOptions(grouped, "technique", false, undefined, { level: "grouped" }),
    );
    const data = result.current.series[0].data as BarDatum[];
    expect(data).toHaveLength(1); // two leaves collapse into one subcategory bar
    expect(data[0].key).toBe("demon:Fictionalizing:Roleplaying"); // matches heatmap rowKey
    expect(result.current.xAxis.data[0]).toBe("Fictionalizing › Roleplaying"); // matches rowLabel
    expect(data[0].score).toBe(0); // conservative worst-leaf score
  });

  it("dims bars whose grouped key differs from the hovered selection", () => {
    // The 0% bar rolls up to demon:Fictionalizing:Roleplaying; the other does not.
    const { result } = renderHook(() =>
      useTaxonomyBreakdownChartOptions(techniqueData, "technique", false, undefined, {
        activeKey: "demon:Fictionalizing:Roleplaying",
        level: "grouped",
      }),
    );
    const data = result.current.series[0].data as StyledBar[];
    expect(data[0].itemStyle.opacity).toBe(1); // worst bar matches the hovered group
    expect(data[1].itemStyle.opacity).toBeLessThan(1); // unrelated bar is dimmed
  });
});
