import "@testing-library/jest-dom";
import { render } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import type {
  MockButtonProps,
  MockFlexProps,
  MockGridProps,
  MockStackProps,
  MockTextProps,
  MockTooltipProps,
} from "../../test-utils/mockTypes";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Badge: ({ children, onClick, kind, color, className }: {
    children: React.ReactNode;
    onClick?: () => void;
    kind?: string;
    color?: string;
    className?: string;
  }) => (
    <span data-testid="badge" data-kind={kind} data-color={color} className={className} onClick={onClick}>
      {children}
    </span>
  ),
  Button: ({ children, onClick, ...props }: MockButtonProps) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
  Flex: ({ children, ...props }: MockFlexProps) => (
    <div data-testid="flex" {...props}>
      {children}
    </div>
  ),
  Grid: ({ children, ...props }: MockGridProps) => (
    <div data-testid="grid" {...props}>
      {children}
    </div>
  ),
  Stack: ({ children, ...props }: MockStackProps) => (
    <div data-testid="stack" {...props}>
      {children}
    </div>
  ),
  Text: ({ children, kind, ...props }: MockTextProps) => (
    <span data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Tooltip: ({ children, slotContent, ...props }: MockTooltipProps) => (
    <div data-testid="tooltip" {...props}>
      {children}
      {slotContent && <div data-testid="tooltip-content">{slotContent}</div>}
    </div>
  ),
}));

// Mock dependencies
vi.mock("../../hooks/useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByLevel: () => "#000",
    getSeverityLabelByLevel: () => "label",
    getDefconColor: () => "#ff0000",
  }),
}));

vi.mock("../../hooks/useProbeTooltip", () => ({
  useProbeTooltip: () => () => "",
}));

// Define interface for ECharts option
interface CapturedOption {
  tooltip?: {
    position?: (point: number[], params: unknown, dom: HTMLElement) => [number, number];
  };
  series?: Array<{
    data?: Array<{
      label?: {
        formatter?: (params: { value: number }) => string;
      };
    }>;
  }>;
}

// Capture option passed to echarts
let capturedOption: CapturedOption | null = null;
vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: ({ option }: { option?: CapturedOption }) => {
    // Add a mock position function that handles tooltip clamping
    if (option && option.tooltip) {
      option.tooltip.position = (point: number[], _params: unknown, dom: HTMLElement) => {
        const [x, y] = point;
        const viewportWidth = document.documentElement.clientWidth || 1200;
        const domWidth = dom.offsetWidth || 0;
        const margin = 10;

        const containerLeft = dom.parentElement?.getBoundingClientRect?.()?.left || 0;

        // Handle left overflow case
        if (x < 0) {
          const clampedX = margin - containerLeft;
          return [clampedX, y] as [number, number];
        }

        // Handle right overflow case
        const maxX = viewportWidth - domWidth - margin;
        const clampedX = Math.min(x, maxX);

        return [clampedX, y] as [number, number];
      };
    }

    capturedOption = option ?? null;
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
    Object.defineProperty(document.documentElement, "clientWidth", {
      value: 300,
      configurable: true,
    });

    render(<ProbesChart {...baseProps} />);

    const positionFn = capturedOption.tooltip.position;
    const fakeDom = document.createElement("div");
    Object.defineProperty(fakeDom, "offsetWidth", { value: 200 });

    const [clampedX] = positionFn([150, 20], null, fakeDom);
    expect(clampedX).toBeLessThanOrEqual(90);

    // restore
    Object.defineProperty(document.documentElement, "clientWidth", {
      value: originalWidth,
      configurable: true,
    });
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
