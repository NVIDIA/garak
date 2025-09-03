import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import DetectorsView from "../DetectorsView";
import { describe, it, expect, vi } from "vitest";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Panel: ({ children, slotHeading, ...props }: any) => (
    <div data-testid="panel" {...props}>
      <div data-testid="panel-heading">{slotHeading}</div>
      <div data-testid="panel-content">{children}</div>
    </div>
  ),
  Stack: ({ children, ...props }: any) => <div data-testid="stack" {...props}>{children}</div>,
  Flex: ({ children, ...props }: any) => <div data-testid="flex" {...props}>{children}</div>,
  Text: ({ children, kind, ...props }: any) => <span data-kind={kind} {...props}>{children}</span>,
  Button: ({ children, onClick, ...props }: any) => <button onClick={onClick} {...props}>{children}</button>,
  Checkbox: ({ checked, onChange, children, ...props }: any) => (
    <label {...props}>
      <input type="checkbox" checked={checked} onChange={onChange} />
      {children}
    </label>
  ),
  StatusMessage: ({ slotHeading, slotSubheading, slotMedia, size, ...props }: any) => (
    <div data-testid="status-message" data-size={size} {...props}>
      <div data-testid="status-media">{slotMedia}</div>
      <div data-testid="status-heading">{slotHeading}</div>
      <div data-testid="status-subheading">{slotSubheading}</div>
    </div>
  ),
  Tooltip: ({ children, ...props }: any) => <div data-testid="tooltip" {...props}>{children}</div>,
  Divider: (props: any) => <div data-testid="divider" {...props} />,
}));

// Mock DefconBadge component
vi.mock("../DefconBadge", () => ({
  __esModule: true,
  default: ({ defcon, size, ...props }: any) => (
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
vi.mock("../../hooks/useSortedDetectors", () => ({ useSortedDetectors: () => (e: any) => e }));
vi.mock("../../hooks/useDetectorsChartSeries", () => ({ useDetectorsChartSeries: () => () => ({ pointSeries:{}, lineSeries:{}, naSeries:{}, visible:[] })}));
vi.mock("../../hooks/useTooltipFormatter", () => ({ useTooltipFormatter: () => () => "" }));
vi.mock("../../hooks/useSeverityColor", () => ({
  __esModule: true,
  default: () => ({ getDefconColor: () => "#ff0000" }),
}));
vi.mock("echarts-for-react", () => ({ __esModule:true, default: () => <div data-testid="echarts" /> }));

const probe = { probe_name: "probe", detectors:[{detector_name:"x"}] } as any;

describe("DetectorsView N/A", () => {
  it("shows unavailable message when all detectors filtered", () => {
    render(<DetectorsView probe={probe} allProbes={[probe]} setSelectedProbe={()=>{}} />);
    
    expect(screen.getByText("No Data Available")).toBeInTheDocument();
    expect(screen.getByText(/All detector results for this comparison are unavailable/)).toBeInTheDocument();
    expect(screen.getByTestId("status-message")).toBeInTheDocument();
  });
}); 