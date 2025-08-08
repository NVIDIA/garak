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
      value: [1.5, "D1"],
      name: "D1",
      comment: "ok",
    });

    expect(lineSeries.data).toHaveLength(1);
    expect(lineSeries.data[0]).toMatchObject({
      value: [1.5, "D1", "#f00"],
      name: "D1",
      zscore: 1.5,
      detector_score: 90,
      comment: "ok",
    });

    expect(naSeries.data).toHaveLength(0);
  });
});
