import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import DetectorsView from "../DetectorsView";
import { describe, it, expect, vi } from "vitest";
import type {
  MockPanelProps,
  MockStackProps,
  MockFlexProps,
  MockTextProps,
  MockButtonProps,
  MockCheckboxProps,
  MockStatusMessageProps,
  MockTooltipProps,
  MockDividerProps,
  MockDefconBadgeProps,
} from "../../test-utils/mockTypes";
import type { GroupedDetectorEntry } from "../../types/Detector";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Panel: ({ children, slotHeading, ...props }: MockPanelProps) => (
    <div data-testid="panel" {...props}>
      <div data-testid="panel-heading">{slotHeading}</div>
      <div data-testid="panel-content">{children}</div>
    </div>
  ),
  Stack: ({ children, ...props }: MockStackProps) => (
    <div data-testid="stack" {...props}>
      {children}
    </div>
  ),
  Flex: ({ children, ...props }: MockFlexProps) => (
    <div data-testid="flex" {...props}>
      {children}
    </div>
  ),
  Text: ({ children, kind, ...props }: MockTextProps) => (
    <span data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Button: ({ children, onClick, ...props }: MockButtonProps) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
  Checkbox: ({ checked, onCheckedChange, children, ...props }: MockCheckboxProps) => (
    <label {...props}>
      <input type="checkbox" checked={checked} onChange={e => onCheckedChange?.(e.target.checked)} />
      {children}
    </label>
  ),
  StatusMessage: ({ slotHeading, slotSubheading, slotMedia, size, ...props }: MockStatusMessageProps) => (
    <div data-testid="status-message" data-size={size} {...props}>
      <div data-testid="status-media">{slotMedia}</div>
      <div data-testid="status-heading">{slotHeading}</div>
      <div data-testid="status-subheading">{slotSubheading}</div>
    </div>
  ),
  Tooltip: ({ children, ...props }: MockTooltipProps) => (
    <div data-testid="tooltip" {...props}>
      {children}
    </div>
  ),
  Divider: (props: MockDividerProps) => <div data-testid="divider" {...props} />,
}));

// Mock DefconBadge component
vi.mock("../DefconBadge", () => ({
  __esModule: true,
  default: ({ defcon, size, ...props }: MockDefconBadgeProps) => (
    <div data-testid="defcon-badge" data-defcon={defcon} data-size={size} {...props}>
      DC-{defcon}
    </div>
  ),
}));

// Mock hooks
vi.mock("../../hooks/useGroupedDetectors", () => ({
  useGroupedDetectors: () => ({
    Cat: [
      { label: "A", zscore: null, detector_score: null, color: "#ccc", comment: "Unavailable" },
    ],
  }),
}));
vi.mock("../../hooks/useSortedDetectors", () => ({ useSortedDetectors: () => (e: GroupedDetectorEntry[]) => e }));
vi.mock("../../hooks/useDetectorsChartSeries", () => ({
  useDetectorsChartSeries: () => () => ({
    pointSeries: { data: [] },
    lineSeries: { data: [] },
    naSeries: { data: [] },
    visible: [],
  }),
}));
vi.mock("../../hooks/useTooltipFormatter", () => ({ useTooltipFormatter: () => () => "" }));
vi.mock("../../hooks/useSeverityColor", () => ({
  __esModule: true,
  default: () => ({ getDefconColor: () => "#ff0000" }),
}));
vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: () => <div data-testid="echarts" />,
}));

import type { Probe } from "../../types/ProbesChart";

const probe: Probe = {
  probe_name: "probe",
  summary: {
    probe_name: "probe",
    probe_score: 0.5,
    probe_severity: 3,
    probe_descr: "test",
    probe_tier: 1,
  },
  detectors: [{ detector_name: "x" }],
};

describe("DetectorsView N/A", () => {
  it("shows unavailable message when all detectors filtered", () => {
    render(<DetectorsView probe={probe} allProbes={[probe]} setSelectedProbe={() => {}} />);

    expect(screen.getByText("No Data Available")).toBeInTheDocument();
    expect(
      screen.getByText(/All detector results for this comparison are unavailable/)
    ).toBeInTheDocument();
    expect(screen.getByTestId("status-message")).toBeInTheDocument();
  });
});
