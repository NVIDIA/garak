/**
 * @file useDetectorChartOptions.test.ts
 * @description Tests for detector chart options hook.
 */

import { renderHook } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { useDetectorChartOptions } from "../useDetectorChartOptions";
import type { Detector } from "../../types/ProbesChart";

// Mock dependencies
vi.mock("../useTooltipFormatter", () => ({
  useTooltipFormatter: () => () => "tooltip",
}));

vi.mock("../useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByComment: () => "#00ff00",
    getDefconColor: () => "#ff0000",
  }),
}));

const createMockDetector = (overrides: Partial<Detector> = {}): Detector => ({
  detector_name: "test.Detector",
  detector_descr: "Test detector",
  absolute_score: 0.9,
  absolute_defcon: 5,
  absolute_comment: "minimal risk",
  relative_score: 0.5,
  relative_defcon: 5,
  relative_comment: "average",
  detector_defcon: 5,
  calibration_used: true,
  total_evaluated: 100,
  passed: 90,
  ...overrides,
});

describe("useDetectorChartOptions", () => {
  it("returns chart options for detectors", () => {
    const detectors: Detector[] = [
      createMockDetector({ detector_name: "detector.A" }),
      createMockDetector({ detector_name: "detector.B" }),
    ];

    const { result } = renderHook(() => useDetectorChartOptions(detectors, false));

    expect(result.current.option).toBeDefined();
    expect(result.current.chartHeight).toBeGreaterThan(0);
    expect(result.current.hasData).toBe(true);
  });

  it("sorts detectors reverse alphabetically (Z at top, A at bottom)", () => {
    const detectors: Detector[] = [
      createMockDetector({ detector_name: "zebra.Detector" }),
      createMockDetector({ detector_name: "alpha.Detector" }),
      createMockDetector({ detector_name: "middle.Detector" }),
    ];

    const { result } = renderHook(() => useDetectorChartOptions(detectors, false));

    // Y-axis data should be reverse alphabetical for natural chart reading
    const yAxisData = result.current.option.yAxis?.data as string[];
    expect(yAxisData[0]).toContain("zebra.Detector");
    expect(yAxisData[1]).toContain("middle.Detector");
    expect(yAxisData[2]).toContain("alpha.Detector");
  });

  it("returns hasData=false when no detectors have valid zscore", () => {
    const detectors: Detector[] = [
      createMockDetector({
        detector_name: "detector.A",
        relative_score: "n/a" as unknown as number, // invalid zscore
      }),
    ];

    const { result } = renderHook(() => useDetectorChartOptions(detectors, false));

    expect(result.current.hasData).toBe(false);
  });

  it("shows detector names in y-axis labels (without counts)", () => {
    const detectors: Detector[] = [
      createMockDetector({
        detector_name: "test.Detector",
        total_evaluated: 100,
        hit_count: 15,
      }),
    ];

    const { result } = renderHook(() => useDetectorChartOptions(detectors, false));

    // Y-axis labels show just detector names (counts are in results table)
    const yAxisData = result.current.option.yAxis?.data as string[];
    expect(yAxisData[0]).toBe("test.Detector");
    expect(yAxisData[0]).not.toContain("(");
  });

  it("handles empty detector array", () => {
    const detectors: Detector[] = [];

    const { result } = renderHook(() => useDetectorChartOptions(detectors, false));

    expect(result.current.hasData).toBe(false);
    expect(result.current.chartHeight).toBeGreaterThan(0);
  });

  it("adjusts chart height based on number of detectors", () => {
    const fewDetectors: Detector[] = [createMockDetector()];
    const manyDetectors: Detector[] = Array.from({ length: 10 }, (_, i) =>
      createMockDetector({ detector_name: `detector.${i}` })
    );

    const { result: fewResult } = renderHook(() =>
      useDetectorChartOptions(fewDetectors, false)
    );
    const { result: manyResult } = renderHook(() =>
      useDetectorChartOptions(manyDetectors, false)
    );

    expect(manyResult.current.chartHeight).toBeGreaterThan(fewResult.current.chartHeight);
  });
});
