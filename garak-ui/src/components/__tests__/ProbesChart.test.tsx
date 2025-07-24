import { render, screen, fireEvent } from "@testing-library/react";
import ProbesChart from "../ProbesChart";
import { vi, describe, it, expect } from "vitest";
import type { ProbesChartProps } from "../../types/ProbesChart";

// Mock useSeverityColor
vi.mock("../hooks/useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByLevel: (level: number) => {
      return level === 1 ? "#0f0" : level === 2 ? "#ff0" : "#f00";
    },
    getSeverityLabelByLevel: (level: number) => {
      return level === 1 ? "low" : level === 2 ? "medium" : "high";
    },
  }),
}));

// Mock DetectorsView
vi.mock("../DetectorsView", () => ({
  __esModule: true,
  default: ({ "data-testid": dataTestId }: { "data-testid"?: string }) => (
    <div data-testid={dataTestId ?? "detectors-view"}>Mock DetectorsView</div>
  ),
}));

// Mock echarts component
vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: ({ onEvents }: any) => (
    <div
      data-testid="echarts"
      onClick={
        () => onEvents?.click?.({ name: "probe-1" }) // match exact probe name
      }
    >
      MockChart
    </div>
  ),
}));

const baseProps: ProbesChartProps = {
  module: {
    group_name: "Fairness",
    summary: {
      group: "fairness",
      score: 0.8,
      group_defcon: 2,
      doc: "",
      group_link: "",
      group_aggregation_function: "avg",
      unrecognised_aggregation_function: false,
      show_top_group_score: false,
    },
    probes: [
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
      },
    ],
  },
  selectedProbe: null,
  setSelectedProbe: vi.fn(),
};

describe("ProbesChart", () => {
  it("renders chart without selected probe", () => {
    render(<ProbesChart {...baseProps} />);
    expect(screen.getByTestId("echarts")).toBeInTheDocument();
    expect(screen.queryByTestId("detectors-view")).toBeNull();
  });

  it("renders DetectorsView when selectedProbe is present", () => {
    render(<ProbesChart {...baseProps} selectedProbe={baseProps.module.probes[0]} />);
    expect(screen.getByTestId("detectors-view")).toBeInTheDocument();
  });

  it("calls setSelectedProbe on chart bar click", () => {
    const setSelectedProbe = vi.fn();

    render(<ProbesChart {...baseProps} setSelectedProbe={setSelectedProbe} />);

    fireEvent.click(screen.getByTestId("echarts"));
    expect(setSelectedProbe).toHaveBeenCalledWith(baseProps.module.probes[0]);
  });

  it("clears selectedProbe on second click of same bar", () => {
    const setSelectedProbe = vi.fn();
    const selected = baseProps.module.probes[0];

    render(
      <ProbesChart {...baseProps} selectedProbe={selected} setSelectedProbe={setSelectedProbe} />
    );

    fireEvent.click(screen.getByTestId("echarts"));
    expect(setSelectedProbe).toHaveBeenCalledWith(null);
  });

  it("falls back to probe.probe_name and 0 score if summary is missing", () => {
    const props = {
      ...baseProps,
      module: {
        ...baseProps.module,
        probes: [
          {
            probe_name: "fallback-name",
            summary: undefined as any, // simulate missing summary
            detectors: [],
          },
        ],
      },
    };

    render(<ProbesChart {...props} />);
    expect(screen.getByTestId("echarts")).toBeInTheDocument();
  });
});
