/**
 * @file useDetectorChartOptions.test.ts
 * @description Tests for detector chart options hook, including sorting behavior.
 */

import { renderHook } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { useDetectorChartOptions } from "../useDetectorChartOptions";
import type { Probe } from "../../types/ProbesChart";
import type { GroupedDetectorEntry } from "../../types/Detector";

// Mock dependencies
vi.mock("../useTooltipFormatter", () => ({
  useTooltipFormatter: () => () => "tooltip",
}));

vi.mock("../useDetectorsChartSeries", () => ({
  useDetectorsChartSeries: () => (detectors: unknown[]) => ({
    pointSeries: { data: [] },
    lineSeries: { data: [] },
    naSeries: { data: [] },
    visible: detectors,
  }),
}));

vi.mock("../useSeverityColor", () => ({
  default: () => ({
    getDefconColor: () => "#ff0000",
  }),
}));

describe("useDetectorChartOptions", () => {
  const mockProbe: Probe = {
    probe_name: "test.TestProbe",
    summary: {
      probe_name: "test.TestProbe",
      probe_score: 0.5,
      probe_severity: 2,
      probe_descr: "Test",
      probe_tier: 1,
    },
    detectors: [],
  };

  it("sorts entries alphabetically by label", () => {
    const entries: GroupedDetectorEntry[] = [
      {
        probeName: "test.Zebra",
        label: "Zebra",
        zscore: 1.0,
        detector_score: 50,
        comment: "test",
        total_evaluated: 100,
        passed: 50,
        color: "#000",
        unavailable: false,
        detector_defcon: 2,
        absolute_defcon: 2,
        relative_defcon: 2,
      },
      {
        probeName: "test.Alpha",
        label: "Alpha",
        zscore: 0.5,
        detector_score: 80,
        comment: "test",
        total_evaluated: 100,
        passed: 80,
        color: "#000",
        unavailable: false,
        detector_defcon: 3,
        absolute_defcon: 3,
        relative_defcon: 3,
      },
      {
        probeName: "test.Middle",
        label: "Middle",
        zscore: -0.5,
        detector_score: 30,
        comment: "test",
        total_evaluated: 100,
        passed: 30,
        color: "#000",
        unavailable: false,
        detector_defcon: 1,
        absolute_defcon: 1,
        relative_defcon: 1,
      },
    ];

    const { result } = renderHook(() =>
      useDetectorChartOptions(mockProbe, "test.Detector", entries, false, false)
    );

    // Verify entries are sorted reverse alphabetically (Z at top, A at bottom)
    // This makes the chart read naturally with A at bottom when rendered
    expect(result.current.visible[0].label).toBe("Zebra");
    expect(result.current.visible[1].label).toBe("Middle");
    expect(result.current.visible[2].label).toBe("Alpha");
  });

  it("maintains alphabetical order regardless of zscore values", () => {
    const entries: GroupedDetectorEntry[] = [
      {
        probeName: "test.Charlie",
        label: "Charlie",
        zscore: 5.0, // highest zscore
        detector_score: 90,
        comment: "test",
        total_evaluated: 100,
        passed: 90,
        color: "#000",
        unavailable: false,
        detector_defcon: 4,
        absolute_defcon: 4,
        relative_defcon: 4,
      },
      {
        probeName: "test.Alpha",
        label: "Alpha",
        zscore: -5.0, // lowest zscore
        detector_score: 10,
        comment: "test",
        total_evaluated: 100,
        passed: 10,
        color: "#000",
        unavailable: false,
        detector_defcon: 1,
        absolute_defcon: 1,
        relative_defcon: 1,
      },
      {
        probeName: "test.Bravo",
        label: "Bravo",
        zscore: 0.0,
        detector_score: 50,
        comment: "test",
        total_evaluated: 100,
        passed: 50,
        color: "#000",
        unavailable: false,
        detector_defcon: 2,
        absolute_defcon: 2,
        relative_defcon: 2,
      },
    ];

    const { result } = renderHook(() =>
      useDetectorChartOptions(mockProbe, "test.Detector", entries, false, false)
    );

    // Should be reverse alphabetical (Charlie, Bravo, Alpha), NOT by zscore
    expect(result.current.visible[0].label).toBe("Charlie");
    expect(result.current.visible[1].label).toBe("Bravo");
    expect(result.current.visible[2].label).toBe("Alpha");
  });
});
