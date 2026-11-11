/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { counts, view } from "./heatmapFixtures";
import { renderHook } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { useTechniqueIntentHeatmapOptions } from "../useTechniqueIntentHeatmapOptions";
import { buildMatrixView } from "../../utils/techniqueIntentRollup";

describe("useTechniqueIntentHeatmapLabels", () => {
  it("angles full intent codes in the overview without ellipses or a tall name header", () => {
    const code = "C002controversial";
    const dense = buildMatrixView({
      t: Object.fromEntries(
        Array.from({ length: 52 }, (_, i) => [
          `${code}${i}`,
          { ...counts(0.4), name: "A long readable intent name" },
        ])
      ),
    });
    const { result } = renderHook(() =>
      useTechniqueIntentHeatmapOptions(dense, false, { width: 1440, colSpan: 52 })
    );
    const labels = result.current.option.xAxis.axisLabel;
    expect(labels.rotate, "dense intent codes tilt only as needed").toBeGreaterThan(0);
    expect(labels.rotate, "labels remain as horizontal as space allows").toBeLessThan(85);
    expect(labels.formatter(`${code}0`), "the taxonomy code is never shortened").toBe(`${code}0`);
    expect(labels.width, "codes have no truncation width").toBeUndefined();
    expect(labels.overflow, "no ellipsis is added to overview codes").toBeUndefined();
    expect(
      result.current.option.grid.top,
      "only enough space for rotated codes is reserved"
    ).toBeLessThan(180);
  });

  it.each([false, true])("alternates readable KUI label tones in dark=%s", isDark => {
    const variable = isDark ? "--color-gray-300" : "--color-gray-600";
    const muted = isDark ? "#a7a7a7" : "#636363";
    document.documentElement.style.setProperty(variable, muted);
    try {
      const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view, isDark));
      const color = result.current.option.xAxis.axisLabel.color;
      expect(color(view.cols[0]), "the first label retains the normal text tone").not.toBe(muted);
      expect(color(view.cols[1]), "the neighbouring label uses a readable neutral tone").toBe(
        muted
      );
    } finally {
      document.documentElement.style.removeProperty(variable);
    }
  });

  it("flattens labels when the viewport grows and keeps short codes horizontal", () => {
    const dense = buildMatrixView({
      t: Object.fromEntries(
        Array.from({ length: 52 }, (_, i) => [`C002controversial${i}`, counts(0.4)])
      ),
    });
    const { result, rerender } = renderHook(
      ({ width }) => useTechniqueIntentHeatmapOptions(dense, false, { width, colSpan: 52 }),
      { initialProps: { width: 1440 } }
    );
    const narrowAngle = result.current.option.xAxis.axisLabel.rotate;
    rerender({ width: 2560 });
    expect(
      result.current.option.xAxis.axisLabel.rotate,
      "more space needs less rotation"
    ).toBeLessThan(narrowAngle);
    const short = buildMatrixView({
      t: Object.fromEntries(
        Array.from({ length: 52 }, (_, i) => [String.fromCharCode(65 + i), counts(0.4)])
      ),
    });
    const { result: shortResult } = renderHook(() =>
      useTechniqueIntentHeatmapOptions(short, false, { width: 1440, colSpan: 52 })
    );
    expect(
      shortResult.current.option.xAxis.axisLabel.rotate,
      "short labels stay horizontal at the same density"
    ).toBe(0);
    expect(shortResult.current.option.xAxis.axisLabel.interval, "all short labels fit").toBe(0);
  });
});
