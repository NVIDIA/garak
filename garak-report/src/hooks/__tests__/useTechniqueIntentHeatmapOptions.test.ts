/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { colours, counts, view } from "./heatmapFixtures";
import { renderHook } from "@testing-library/react";
import { color, init, setPlatformAPI } from "echarts";
import { describe, it, expect } from "vitest";
import { useTechniqueIntentHeatmapOptions } from "../useTechniqueIntentHeatmapOptions";
import { buildMatrixView } from "../../utils/techniqueIntentRollup";

describe("useTechniqueIntentHeatmapOptions", () => {
  it.each([false, true])("keeps axis hover visible on the current theme (dark=%s)", isDark => {
    document.documentElement.style.setProperty("--background-color-interaction-hover", "#0000000d");
    try {
      const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view, isDark));
      const channels = color.parse(result.current.hoverColour);
      expect(channels?.slice(0, 3), "hover contrasts with the chart background").toEqual(
        isDark ? [255, 255, 255] : [0, 0, 0]
      );
    } finally {
      document.documentElement.style.removeProperty("--background-color-interaction-hover");
    }
  });
  it("keeps an untested pairing distinct from a measured zero pass rate", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    const cells = result.current.option.series[0].data;
    expect(cells, "the full two by two grid is present").toHaveLength(4);
    expect(cells[0].label.formatter, "zero is measured and includes its evaluation count").toBe(
      "0%\nn=100"
    );
    expect(cells[3].label.formatter, "missing results remain explicit").toBe("—");
    expect(cells[3].itemStyle.color, "untested cells have no risk colour").toBe("transparent");
  });

  it("interpolates pass rates across the existing KUI risk ramp", () => {
    const scaleView = buildMatrixView({
      t: Object.fromEntries([0, 0.25, 0.5, 0.75, 1].map((s, i) => [`i${i}`, counts(s)])),
    });
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(scaleView));
    const data = result.current.option.series[0].data;
    expect(
      data.map(cell => color.parse(cell.itemStyle.color)),
      "the full pass-rate scale uses KUI colour stops"
    ).toEqual(colours.map(colour => color.parse(colour)));
    expect(data[0].label.color, "dark red supports white text").toBe("#ffffff");
    expect(data[2].label.color, "gold supports black text").toBe("#000000");
    expect(data[4].label.color, "deep green supports white text").toBe("#ffffff");
    expect(result.current.option.visualMap.type, "ECharts uses the same continuous scale").toBe(
      "continuous"
    );
  });

  it.each([0.05, 0.4, 0.8, 0.99])("has no colour jump at DEFCON boundary %s", boundary => {
    const adjacent = buildMatrixView({
      t: { below: counts(boundary - 0.001), above: counts(boundary + 0.001) },
    });
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(adjacent));
    const [below, above] = result.current.option.series[0].data.map(cell =>
      color.parse(cell.itemStyle.color)!
    );
    expect(
      Math.max(...below.slice(0, 3).map((channel, i) => Math.abs(channel - above[i]))),
      "nearby percentages stay visually close across risk classifications"
    ).toBeLessThanOrEqual(3);
  });

  it("distinguishes scores within the same DEFCON band", () => {
    const sameBand = buildMatrixView({ t: { low: counts(0.1), high: counts(0.3) } });
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(sameBand));
    const [low, high] = result.current.option.series[0].data;
    expect(low.itemStyle.color, "fill reflects the score rather than its band").not.toBe(
      high.itemStyle.color
    );
  });

  it("retains raw axis keys while formatting readable labels", () => {
    const labelled = buildMatrixView({ t: { i1: { ...counts(0), name: "Intent label" } } });
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(labelled));
    expect(result.current.option.xAxis.data, "events identify the intent by code").toEqual(["i1"]);
    expect(
      result.current.option.xAxis.axisLabel.formatter("i1"),
      "axis displays code and name"
    ).toBe("i1\nIntent label");
  });

  it("guides both hovered axes without changing the tooltip to an axis aggregate", () => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    expect(result.current.option.tooltip.trigger, "hover describes a single pairing").toBe("item");
    expect(
      result.current.option.series[0].emphasis.disabled,
      "hover bands remain distinct from selection outlines"
    ).toBe(true);
    for (const axis of [result.current.option.xAxis, result.current.option.yAxis]) {
      expect(axis.axisPointer.type, "subtle bands identify the intersecting row and column").toBe(
        "shadow"
      );
      expect(
        axis.axisPointer.triggerEmphasis,
        "hover guides do not override persistent selection"
      ).toBe(false);
    }
  });

  it.each([false, true])("renders real heatmap tiles, including N/A, in dark=%s", isDark => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view, isDark));
    setPlatformAPI({ measureText: text => ({ width: String(text).length * 7 }) });
    const chart = init(null, undefined, {
      renderer: "svg",
      ssr: true,
      width: 1200,
      height: result.current.height,
    });
    try {
      chart.setOption(result.current.option);
      const svg = chart.renderToSVGString();
      expect(svg, "ECharts renders an explicit untested tile").toContain("—");
      expect(svg, "zero pass rates remain visible").toContain("0%");
      expect(svg, "zero pass rate uses the KUI red endpoint").toContain("rgb(194,30,30)");
    } finally {
      chart.dispose();
    }
  });
});
