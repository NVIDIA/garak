// src/components/__tests__/DetectorsView.test.tsx
import { render, screen } from "@testing-library/react";
import DetectorsView from "../DetectorsView";
import { vi, describe, expect, it, beforeEach } from "vitest";
import type { Probe, Detector } from "../../types/ProbesChart";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Panel: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="panel">{children}</div>
  ),
  Stack: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="stack">{children}</div>
  ),
  Flex: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="flex">{children}</div>
  ),
  Text: ({ children, kind }: { children: React.ReactNode; kind?: string }) => (
    <span data-kind={kind}>{children}</span>
  ),
  Badge: ({ children, color }: { children: React.ReactNode; color?: string }) => (
    <span data-testid="badge" data-color={color}>{children}</span>
  ),
  Button: ({ children }: { children: React.ReactNode }) => (
    <button>{children}</button>
  ),
  Divider: () => <hr data-testid="divider" />,
  StatusMessage: ({ slotHeading }: { slotHeading: React.ReactNode }) => (
    <div data-testid="status-message">{slotHeading}</div>
  ),
  Tooltip: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="tooltip">{children}</div>
  ),
}));

// Mock DefconBadge component
vi.mock("../DefconBadge", () => ({
  __esModule: true,
  default: ({ defcon }: { defcon: number }) => (
    <div data-testid="defcon-badge" data-defcon={defcon}>
      DC-{defcon}
    </div>
  ),
}));

// Mock ProgressBar component
vi.mock("../ProgressBar", () => ({
  __esModule: true,
  default: ({ passPercent, hasFailures }: { passPercent: number; hasFailures: boolean }) => (
    <div data-testid="progress-bar" data-pass={passPercent} data-failures={hasFailures}>
      {passPercent}%
    </div>
  ),
}));

// Mock ECharts
vi.mock("echarts-for-react", () => ({
  default: () => <div data-testid="echarts" />,
}));

// Mock hooks
vi.mock("../../hooks/useSeverityColor", () => ({
  __esModule: true,
  default: () => ({
    getSeverityColorByComment: () => "#00ff00",
    getDefconColor: () => "#ff0000",
    getSeverityLabelByLevel: (level: number) => `Risk Level ${level}`,
    getDefconBadgeColor: () => "red",
  }),
}));

vi.mock("../../hooks/useTooltipFormatter", () => ({
  useTooltipFormatter: () => () => "mock tooltip",
}));

const createMockDetector = (overrides: Partial<Detector> = {}): Detector => ({
  detector_name: "test.Detector",
  detector_descr: "Test detector",
  absolute_score: 0.9,
  absolute_defcon: 5,
  absolute_comment: "minimal risk",
  relative_score: 0.5,
  relative_defcon: 5,
  relative_comment: "average",
  detector_defcon: 5,
  calibration_used: true,
  total_evaluated: 100,
  hit_count: 10,
  ...overrides,
});

const createMockProbe = (overrides: Partial<Probe> = {}): Probe => ({
  probe_name: "test.Probe",
  summary: {
    probe_name: "test.Probe",
    probe_score: 0.9,
    probe_severity: 5,
    probe_descr: "Test probe description",
    probe_tier: 1,
  },
  detectors: [createMockDetector()],
  ...overrides,
});

describe("DetectorsView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders panel with probe name", () => {
    const probe = createMockProbe();
    render(<DetectorsView probe={probe} />);

    expect(screen.getByTestId("panel")).toBeInTheDocument();
    expect(screen.getByText("test.Probe")).toBeInTheDocument();
  });

  it("displays probe description", () => {
    const probe = createMockProbe();
    render(<DetectorsView probe={probe} />);

    expect(screen.getByText("Test probe description")).toBeInTheDocument();
  });

  it("displays prompt count when available", () => {
    const probe = createMockProbe({
      summary: {
        probe_name: "test.Probe",
        probe_score: 0.85,
        probe_severity: 4,
        probe_descr: "Test",
        probe_tier: 1,
        prompt_count: 100,
      },
    });
    render(<DetectorsView probe={probe} />);

    expect(screen.getByText(/100.*prompts/)).toBeInTheDocument();
  });

  it("renders DEFCON badge with correct level", () => {
    const probe = createMockProbe({
      summary: {
        probe_name: "test.Probe",
        probe_score: 0.5,
        probe_severity: 2,
        probe_descr: "Test",
        probe_tier: 1,
      },
    });
    render(<DetectorsView probe={probe} />);

    const defconBadge = screen.getAllByTestId("defcon-badge")[0];
    expect(defconBadge).toHaveAttribute("data-defcon", "2");
  });

  it("renders Detector Breakdown section", () => {
    const probe = createMockProbe();
    render(<DetectorsView probe={probe} />);

    expect(screen.getByText("Detector Breakdown")).toBeInTheDocument();
  });

  it("renders Relative Performance section", () => {
    const probe = createMockProbe();
    render(<DetectorsView probe={probe} />);

    expect(screen.getByText("Relative Performance")).toBeInTheDocument();
  });

  it("renders detector names in the table", () => {
    const probe = createMockProbe({
      detectors: [
        createMockDetector({ detector_name: "detector.Alpha" }),
        createMockDetector({ detector_name: "detector.Beta" }),
      ],
    });
    render(<DetectorsView probe={probe} />);

    expect(screen.getByText("detector.Alpha")).toBeInTheDocument();
    expect(screen.getByText("detector.Beta")).toBeInTheDocument();
  });

  it("sorts detectors alphabetically", () => {
    const probe = createMockProbe({
      detectors: [
        createMockDetector({ detector_name: "z.Last" }),
        createMockDetector({ detector_name: "a.First" }),
      ],
    });
    render(<DetectorsView probe={probe} />);

    // Both detectors should be rendered
    expect(screen.getByText("a.First")).toBeInTheDocument();
    expect(screen.getByText("z.Last")).toBeInTheDocument();
  });
});
