import { renderHook } from "@testing-library/react";
import { useProbeTooltip } from "../useProbeTooltip";
import type { Probe } from "../../types/ProbesChart";
import { describe, it, expect } from "vitest";

const sampleData: (Probe & {
  label: string;
  value: number;
  color: string;
  severity?: number;
  severityLabel?: string;
})[] = [
  {
    probe_name: "probe-1",
    summary: {
      probe_name: "probe-1",
      probe_score: 0.5,
      probe_severity: 2,
      probe_descr: "desc",
      probe_tier: 1,
    },
    detectors: [],
    label: "probe-1",
    value: 50,
    color: "#ff0",
    severity: 2,
    severityLabel: "medium",
  },
];

describe("useProbeTooltip", () => {
  it("returns correct tooltip content for known probe", () => {
    const { result } = renderHook(() => useProbeTooltip(sampleData));
    const tooltip = result.current({ name: "probe-1", value: 50 });

    expect(tooltip).toContain("<strong>probe-1</strong>");
    expect(tooltip).toContain("Score: 50.00%");
    expect(tooltip).toContain(
      'Severity: <span style="color: #ff0; font-weight: 600">medium</span>'
    );
  });

  it("handles unknown probe name", () => {
    const { result } = renderHook(() => useProbeTooltip(sampleData));
    const tooltip = result.current({ name: "unknown", value: 42 });

    expect(tooltip).toContain("<strong>unknown</strong>");
    expect(tooltip).toContain("Score: 42.00%");
    expect(tooltip).toContain(
      'Severity: <span style="color: #999; font-weight: 600">Unknown</span>'
    );
  });
});
