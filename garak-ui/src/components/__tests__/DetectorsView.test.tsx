// src/components/__tests__/DetectorsView.test.tsx
import { render, screen, fireEvent } from "@testing-library/react";
import DetectorsView from "../DetectorsView";
import { vi, describe, expect, it, beforeEach } from "vitest";
import * as useGroupedDetectorsModule from "../../hooks/useGroupedDetectors";
import * as useZScoreHelpersModule from "../../hooks/useZScoreHelpers";
import type { Probe } from "../../types/ProbesChart";

vi.mock("../../hooks/useGroupedDetectors");
vi.mock("../../hooks/useZScoreHelpers");
vi.mock("echarts-for-react", () => ({
  default: ({ onEvents }: any) => {
    return <div data-testid="echarts" onClick={() => onEvents?.click?.({ name: "Detector A1" })} />;
  },
}));

const mockProbe: Probe = {
  probe_name: "probe-1",
  summary: {
    probe_name: "probe-1",
    probe_score: 0.9,
    probe_severity: 1,
    probe_descr: "mock",
    probe_tier: 1,
  },
  detectors: [],
};

const allProbes = [
  mockProbe,
  {
    ...mockProbe,
    probe_name: "Detector A1",
  },
];

const detectorGroupMock = {
  "Category A": [
    {
      label: "Detector A1",
      zscore: 1.5,
      detector_score: 90,
      color: "#00f",
      comment: "high score",
    },
    {
      label: "Detector A2",
      zscore: null,
      detector_score: null,
      color: "#ccc",
      comment: "Unavailable",
    },
  ],
};

const zHelperMock = {
  formatZ: (z: number | null) => (z == null ? "N/A" : z.toFixed(2)),
  clampZ: (z: number) => Math.max(-3, Math.min(3, z)),
};

const mockEcharts = true;
describe("DetectorsView", () => {
  beforeEach(() => {
    vi.resetModules();
    if (mockEcharts) {
      vi.mock("echarts-for-react", () => ({
        default: ({ option, onEvents }: any) => {
          // expose option for tests
          (globalThis as any).__ECHARTS_OPTION__ = option;
          return <div data-testid="echarts" onClick={() => onEvents?.click?.({ name: "Detector A1" })} />;
        },
      }));
    }
    vi.mocked(useGroupedDetectorsModule.useGroupedDetectors).mockReturnValue(detectorGroupMock);
    vi.mocked(useZScoreHelpersModule.useZScoreHelpers).mockReturnValue(zHelperMock);
    // no clamp hook now
  });

  it("renders detector group heading and chart", () => {
    render(<DetectorsView probe={mockProbe} allProbes={allProbes} setSelectedProbe={() => {}} />);
    expect(screen.getByText("Category A")).toBeInTheDocument();
    expect(screen.getByTestId("echarts")).toBeInTheDocument();
  });

  it("renders tooltip using formatter with detectorType", async () => {
    const formatTooltipMock = vi.fn().mockReturnValue("mock-tooltip");

    vi.doMock("../../hooks/useTooltipFormatter", () => ({
      useTooltipFormatter: () => formatTooltipMock,
    }));

    let capturedFormatter: ((params: any) => any) | undefined;

    // Override the ECharts mock to capture `formatter`
    vi.doMock("echarts-for-react", () => ({
      default: ({ option }: any) => {
        capturedFormatter = option.tooltip.formatter;
        return <div data-testid="echarts" />;
      },
    }));

    const { default: DetectorsViewReloaded } = await import("../DetectorsView");
    render(
      <DetectorsViewReloaded probe={mockProbe} allProbes={allProbes} setSelectedProbe={() => {}} />
    );

    expect(typeof capturedFormatter).toBe("function");

    const fakeParams = { data: { foo: "bar" } };
    capturedFormatter?.(fakeParams);

    expect(formatTooltipMock).toHaveBeenCalledWith({
      data: fakeParams.data,
      detectorType: "Category A",
    });
  });

  it("shows N/A message when all entries are unavailable and hideUnavailable is true", async () => {
    const allNAGroup = {
      "Category B": [
        {
          label: "Detector B1",
          zscore: null,
          detector_score: null,
          color: "#ccc",
          comment: "Unavailable",
        },
      ],
    };

    vi.mocked(useGroupedDetectorsModule.useGroupedDetectors).mockReturnValue(allNAGroup);

    render(<DetectorsView probe={mockProbe} allProbes={allProbes} setSelectedProbe={() => {}} />);

    expect(screen.getByText("All entries are unavailable (N/A).")).toBeInTheDocument();
  });

  it("toggles unavailable entries via checkbox", () => {
    render(<DetectorsView probe={mockProbe} allProbes={allProbes} setSelectedProbe={() => {}} />);
    const checkbox = screen.getByLabelText("Hide N/A") as HTMLInputElement;
    expect(checkbox.checked).toBe(true);
    fireEvent.click(checkbox);
    expect(checkbox.checked).toBe(false);
  });

  it("sorts detectors with valid zscores", () => {
    const validZscores = {
      "Category Sorted": [
        { label: "Low", zscore: 0.1, detector_score: 10, color: "#111", comment: "low" },
        { label: "High", zscore: 2.5, detector_score: 90, color: "#999", comment: "high" },
      ],
    };

    vi.mocked(useGroupedDetectorsModule.useGroupedDetectors).mockReturnValue(validZscores);

    render(<DetectorsView probe={mockProbe} allProbes={allProbes} setSelectedProbe={() => {}} />);

    expect(screen.getByText("Category Sorted")).toBeInTheDocument();
  });

  it("does nothing when clicked label has no match", () => {
    const setSelectedProbe = vi.fn();

    render(<DetectorsView probe={mockProbe} allProbes={[]} setSelectedProbe={setSelectedProbe} />);

    fireEvent.click(screen.getByTestId("echarts"));
    expect(setSelectedProbe).not.toHaveBeenCalled();
  });

  it("calls setSelectedProbe on chart click", () => {
    const setSelectedProbe = vi.fn();
    render(
      <DetectorsView probe={mockProbe} allProbes={allProbes} setSelectedProbe={setSelectedProbe} />
    );

    fireEvent.click(screen.getByTestId("echarts"));
    expect(setSelectedProbe).toHaveBeenCalledWith(
      expect.objectContaining({ probe_name: "Detector A1" })
    );
  });

  it("tooltip.position clamps overflow", async () => {
    // narrow viewport to test
    const originalWidth = document.documentElement.clientWidth;
    Object.defineProperty(document.documentElement, "clientWidth", { value: 300, configurable: true });

    // Mock ECharts to capture option
    vi.doMock("echarts-for-react", () => ({
      __esModule: true,
      default: ({ option }: any) => {
        (globalThis as any).capturedOption = option;
        return <div />;
      },
    }));

    const { default: DetectorsViewReloaded2 } = await import("../DetectorsView");
    render(<DetectorsViewReloaded2 probe={mockProbe} allProbes={allProbes} setSelectedProbe={()=>{}} />);

    const option = (globalThis as any).capturedOption;
    const positionFn = option.tooltip.position;

    const fakeDom = document.createElement("div");
    Object.defineProperty(fakeDom, "offsetWidth", { value: 200 });

    const [clampedX] = positionFn([150,10], null, fakeDom);
    expect(clampedX).toBeLessThanOrEqual(90);

    Object.defineProperty(document.documentElement, "clientWidth", { value: originalWidth, configurable: true });
  });

  it("tooltip.position clamps left overflow", async () => {
    // viewport stays default wide

    vi.doMock("echarts-for-react", () => ({
      __esModule: true,
      default: ({ option }: any) => {
        (globalThis as any).capturedOptionLeft = option;
        return <div />;
      },
    }));

    const { default: DetectorsViewReloaded } = await import("../DetectorsView");

    render(<DetectorsViewReloaded probe={mockProbe} allProbes={allProbes} setSelectedProbe={()=>{}} />);

    const optionLeft = (globalThis as any).capturedOptionLeft;
    const positionFn = optionLeft.tooltip.position;

    // Create parent container at left 100
    const container = document.createElement("div");
    Object.defineProperty(container, "getBoundingClientRect", {
      value: () => ({ left: 100 }),
    });

    const fakeDom = document.createElement("div");
    container.appendChild(fakeDom);
    Object.defineProperty(fakeDom, "offsetWidth", { value: 50 });

    const [clampedX] = positionFn([-50, 10], null, fakeDom);
    expect(clampedX).toBe(-90); // margin(10) - containerLeft(100)
  });

  it("tooltip.position uses 0 width when offsetWidth undefined", async () => {
    const originalWidth = document.documentElement.clientWidth;
    Object.defineProperty(document.documentElement, "clientWidth", { value: 300, configurable: true });

    vi.doMock("echarts-for-react", () => ({
      __esModule: true,
      default: ({ option }: any) => {
        (globalThis as any).capturedOptionNoWidth = option;
        return <div />;
      },
    }));

    const { default: DetectorsViewReloaded } = await import("../DetectorsView");
    render(<DetectorsViewReloaded probe={mockProbe} allProbes={allProbes} setSelectedProbe={()=>{}} />);

    const optionNoWidth = (globalThis as any).capturedOptionNoWidth;
    const positionFn = optionNoWidth.tooltip.position;

    const fakeDom = document.createElement("div"); // no offsetWidth defined -> undefined

    const [clampedX] = positionFn([295, 15], null, fakeDom);
    expect(clampedX).toBe(290); // 300 - 0 - 10

    Object.defineProperty(document.documentElement, "clientWidth", { value: originalWidth, configurable: true });
  });
});
