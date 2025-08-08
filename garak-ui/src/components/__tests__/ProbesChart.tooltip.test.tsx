import "@testing-library/jest-dom";
import { render } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

// Mock dependencies
vi.mock("../../hooks/useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByLevel: () => "#000",
    getSeverityLabelByLevel: () => "label",
  }),
}));

vi.mock("../../hooks/useProbeTooltip", () => ({
  useProbeTooltip: () => () => "",
}));

// Capture option passed to echarts
let capturedOption: any = null;
vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: ({ option }: any) => {
    capturedOption = option;
    return <div data-testid="echarts" />;
  },
}));

import ProbesChart from "../ProbesChart";
import type { ProbesChartProps } from "../../types/ProbesChart";

describe("ProbesChart tooltip clamp", () => {
  const baseProps: ProbesChartProps = {
    module: {
      group_name: "group",
      summary: {
        group: "g",
        score: 0.5,
        group_defcon: 2,
        doc: "",
        group_link: "",
        group_aggregation_function: "avg",
        unrecognised_aggregation_function: false,
        show_top_group_score: false,
      },
      probes: [
        {
          probe_name: "p1",
          summary: {
            probe_name: "p1",
            probe_score: 0.2,
            probe_severity: 2,
            probe_descr: "",
            probe_tier: 1,
          },
          detectors: [],
        },
      ],
    },
    selectedProbe: null,
    setSelectedProbe: vi.fn(),
  };

  it("clamps right overflow", () => {
    // narrow viewport
    const originalWidth = document.documentElement.clientWidth;
    Object.defineProperty(document.documentElement, "clientWidth", { value: 300, configurable: true });

    render(<ProbesChart {...baseProps} />);

    const positionFn = capturedOption.tooltip.position;
    const fakeDom = document.createElement("div");
    Object.defineProperty(fakeDom, "offsetWidth", { value: 200 });

    const [clampedX] = positionFn([150, 20], null, fakeDom);
    expect(clampedX).toBeLessThanOrEqual(90);

    // restore
    Object.defineProperty(document.documentElement, "clientWidth", { value: originalWidth, configurable: true });
  });

  it("clamps left overflow", () => {
    render(<ProbesChart {...baseProps} />);

    const positionFn = capturedOption.tooltip.position;
    const container = document.createElement("div");
    Object.defineProperty(container, "getBoundingClientRect", { value: () => ({ left: 100 }) });

    const fakeDom = document.createElement("div");
    container.appendChild(fakeDom);
    Object.defineProperty(fakeDom, "offsetWidth", { value: 50 });

    const [clampedX] = positionFn([-50, 10], null, fakeDom);
    expect(clampedX).toBe(-90); // 10 - 100
  });

  it("invokes bar label formatter", () => {
    render(<ProbesChart {...baseProps} />);

    const labelFormatter = capturedOption.series[0].data[0].label.formatter;
    expect(labelFormatter({ value: 42 })).toBe("42%");
  });
}); 