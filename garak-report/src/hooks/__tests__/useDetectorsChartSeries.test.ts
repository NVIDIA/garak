import { renderHook } from "@testing-library/react";
import { useDetectorsChartSeries } from "../useDetectorsChartSeries";
import type { ChartDetector } from "../../types/ProbesChart";
import { vi, describe, it, expect } from "vitest";

vi.mock("../useZScoreHelpers", () => ({
  useZScoreHelpers: () => ({
    clampZ: (z: number) => Math.max(-3, Math.min(3, z)),
  }),
}));

vi.mock("../useRenderLineItem", () => ({
  useRenderLineItem: () => vi.fn(),
}));

const mockDetectors: ChartDetector[] = [
  {
    label: "D1",
    zscore: 1.5,
    detector_score: 90,
    color: "#f00",
    comment: "ok",
  },
  {
    label: "D2",
    zscore: -1.0, // ✅ valid number
    detector_score: null,
    color: "#ccc",
    comment: "Unavailable", // ✅ determines N/A status
  },
];

describe("useDetectorsChartSeries", () => {
  it("builds series with hideUnavailable = true", () => {
    const { result } = renderHook(() => useDetectorsChartSeries());
    const { pointSeries, lineSeries, naSeries, visible } = result.current(mockDetectors, true);

    expect(visible).toHaveLength(1);
    expect(visible[0].label).toBe("D1");

    expect(pointSeries.data).toHaveLength(1);
    expect(pointSeries.data[0]).toMatchObject({
      value: [1.5, 0], // Now uses index instead of label
      name: "D1",
      comment: "ok",
    });

    expect(lineSeries.data).toHaveLength(1);
    expect(lineSeries.data[0]).toMatchObject({
      value: [1.5, 0, "#f00"], // Now uses index instead of label
      name: "D1",
      zscore: 1.5,
      detector_score: 90,
      comment: "ok",
    });

    expect(naSeries.data).toHaveLength(0);
  });

  it("builds series with hideUnavailable = false (includes N/A series)", () => {
    const { result } = renderHook(() => useDetectorsChartSeries());
    const { pointSeries, lineSeries, naSeries, visible } = result.current(mockDetectors, false);

    // Should include all detectors in visible
    expect(visible).toHaveLength(2);

    // Point series should have both detectors
    expect(pointSeries.data).toHaveLength(2);

    // Line series should have both detectors
    expect(lineSeries.data).toHaveLength(2);

    // N/A series should include the unavailable detector (D2)
    expect(naSeries.data).toHaveLength(1);
    expect(naSeries.data[0]).toMatchObject({
      value: [0, "D2"],
      name: "D2",
      zscore: -1.0,
      detector_score: null,
      comment: "Unavailable",
      symbol: "rect",
      symbolSize: [30, 20],
    });

    // Check that N/A series has correct label formatting
    expect(naSeries.data[0].label).toMatchObject({
      show: true,
      formatter: "N/A",
      color: "#444",
      fontSize: 10,
    });

    // Check that N/A series has correct styling
    expect(naSeries.data[0].itemStyle).toMatchObject({
      borderColor: "#999",
      borderWidth: 1,
    });
  });
});
