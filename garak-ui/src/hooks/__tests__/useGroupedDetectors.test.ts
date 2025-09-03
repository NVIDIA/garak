import { renderHook } from "@testing-library/react";
import { useGroupedDetectors } from "../useGroupedDetectors";
import { vi, describe, it, expect } from "vitest";
import type { Probe } from "../../types/ProbesChart";
import theme from "../../styles/theme";

// Mock useSeverityColor
vi.mock("../useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByComment: (comment: string) => {
      return comment === "low" ? "#bbf7d0" : comment === "high" ? "#fecaca" : "#e5e7eb";
    },
  }),
}));

it("handles probe_name with no dots", () => {
  const probeC = {
    ...probeA,
    probe_name: "uncategorized",
    summary: { ...probeA.summary, probe_name: "uncategorized" },
  };

  const { result } = renderHook(() => useGroupedDetectors(probeC, [probeC]));

  expect(result.current["det-A"][0].label).toBe("uncategorized");
});

it("sets detector_score to null if absolute_score is 0", () => {
  const zeroScoreProbe: Probe = {
    ...probeA,
    detectors: [
      {
        ...probeA.detectors[0],
        absolute_score: 0,
      },
    ],
  };

  const { result } = renderHook(() => useGroupedDetectors(zeroScoreProbe, [zeroScoreProbe]));

  expect(result.current["det-A"][0].detector_score).toBeNull();
});

it("defaults comment to 'Unavailable' when zscore_comment is missing", () => {
  const modifiedProbe: Probe = {
    ...probeA,
    detectors: [
      {
        ...probeA.detectors[0],
        zscore_comment: undefined as unknown as string,
      },
    ],
  };

  const { result } = renderHook(() => useGroupedDetectors(modifiedProbe, [modifiedProbe]));

  expect(result.current["det-A"][0].comment).toBe("Unavailable");
});

const probeA: Probe = {
  probe_name: "module.category1",
  summary: {
    probe_name: "module.category1",
    probe_score: 0.6,
    probe_severity: 2,
    probe_descr: "desc",
    probe_tier: 1,
  },
  detectors: [
    {
      detector_name: "det-A",
      detector_descr: "some detector",
      absolute_score: 0.7,
      absolute_defcon: 2,
      absolute_comment: "high",
      zscore: 1.2,
      zscore_defcon: 2,
      zscore_comment: "high",
      detector_defcon: 2,
      calibration_used: true,
    },
  ],
};

const probeB: Probe = {
  probe_name: "module.category2",
  summary: {
    probe_name: "module.category2",
    probe_score: 0.4,
    probe_severity: 1,
    probe_descr: "desc",
    probe_tier: 1,
  },
  detectors: [
    {
      detector_name: "det-A",
      detector_descr: "some detector",
      absolute_score: 0.5,
      absolute_defcon: 3,
      absolute_comment: "low",
      zscore: NaN, // invalid
      zscore_defcon: 3,
      zscore_comment: "Unavailable",
      detector_defcon: 3,
      calibration_used: false,
    },
  ],
};

describe("useGroupedDetectors", () => {
  it("groups by detector_name and includes entries for each probe", () => {
    const { result } = renderHook(() => useGroupedDetectors(probeA, [probeA, probeB]));

    const grouped = result.current;
    expect(Object.keys(grouped)).toContain("det-A");
    expect(grouped["det-A"]).toHaveLength(2);
  });

  it("sets correct label and zscore values", () => {
    const { result } = renderHook(() => useGroupedDetectors(probeA, [probeA, probeB]));

    const entries = result.current["det-A"];
    expect(entries[0].label).toBe("category1");
    expect(entries[0].zscore).toBe(1.2);
    expect(entries[1].label).toBe("category2");
    expect(entries[1].zscore).toBeNull();
  });

  it("applies correct color for current and other probes", () => {
    const { result } = renderHook(() => useGroupedDetectors(probeA, [probeA, probeB]));

    const entries = result.current["det-A"];
    expect(entries[0].color).toBe("#fecaca"); // current probe with "high" comment -> red color
    expect(entries[1].color).toBe(theme.colors.tk150); // other probe fallback
  });

  it("calculates detector_score correctly", () => {
    const { result } = renderHook(() => useGroupedDetectors(probeA, [probeA, probeB]));

    const entries = result.current["det-A"];
    expect(entries[0].detector_score).toBe(70); // 0.7 * 100
    expect(entries[1].detector_score).toBe(50); // 0.5 * 100
  });

  it("marks unavailable entries", () => {
    const { result } = renderHook(() => useGroupedDetectors(probeA, [probeA, probeB]));

    const entries = result.current["det-A"];
    expect(entries[1].unavailable).toBe(true);
    expect(entries[0].unavailable).toBe(false);
  });
});
