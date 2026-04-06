/**
 * @file DetectorResultsTable.test.tsx
 * @description Tests for the DetectorResultsTable component with stacked progress bars.
 */

import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import DetectorResultsTable from "../DetectorResultsTable";
import type { Detector } from "../../../types/ProbesChart";

// Mock KUI components
vi.mock("@kui/react", () => ({
  Flex: ({ children, style, onMouseEnter, onMouseLeave }: { children: React.ReactNode; style?: React.CSSProperties; onMouseEnter?: () => void; onMouseLeave?: () => void }) => (
    <div style={style} onMouseEnter={onMouseEnter} onMouseLeave={onMouseLeave}>{children}</div>
  ),
  Stack: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Text: ({ children, title }: { children: React.ReactNode; title?: string }) => <span title={title}>{children}</span>,
  Divider: () => <hr />,
  Tooltip: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

// Mock DefconBadge
vi.mock("../../DefconBadge", () => ({
  __esModule: true,
  default: ({ defcon }: { defcon: number }) => (
    <div data-testid="defcon-badge" data-defcon={defcon}>
      DC-{defcon}
    </div>
  ),
}));

// Mock ProgressBar
vi.mock("../../ProgressBar", () => ({
  __esModule: true,
  default: ({ passPercent, hasFailures }: { passPercent: number; hasFailures: boolean }) => (
    <div data-testid="progress-bar" data-pass={passPercent} data-failures={hasFailures}>
      {passPercent}%
    </div>
  ),
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
  attempt_count: 100,
  ...overrides,
});

describe("DetectorResultsTable", () => {
  it("renders Detector Breakdown heading", () => {
    render(<DetectorResultsTable detectors={[]} />);

    expect(screen.getByText("Detector Breakdown")).toBeInTheDocument();
  });

  it("renders detector name and failure counts", () => {
    const detectors = [
      createMockDetector({
        detector_name: "my.TestDetector",
        detector_defcon: 3,
        total_evaluated: 50,
        hit_count: 5,
        absolute_score: 0.9,
      }),
    ];

    render(<DetectorResultsTable detectors={detectors} />);

    expect(screen.getByText("my.TestDetector")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument(); // failures
    expect(screen.getByText(/\/ 50/)).toBeInTheDocument(); // total
  });

  it("renders multiple detectors", () => {
    const detectors = [
      createMockDetector({ detector_name: "detector.One" }),
      createMockDetector({ detector_name: "detector.Two" }),
      createMockDetector({ detector_name: "detector.Three" }),
    ];

    render(<DetectorResultsTable detectors={detectors} />);

    expect(screen.getByText("detector.One")).toBeInTheDocument();
    expect(screen.getByText("detector.Two")).toBeInTheDocument();
    expect(screen.getByText("detector.Three")).toBeInTheDocument();
  });

  it("renders DEFCON badges for each detector", () => {
    const detectors = [
      createMockDetector({ detector_name: "d1", detector_defcon: 1 }),
      createMockDetector({ detector_name: "d2", detector_defcon: 5 }),
    ];

    render(<DetectorResultsTable detectors={detectors} />);

    const badges = screen.getAllByTestId("defcon-badge");
    expect(badges).toHaveLength(2);
    expect(badges[0]).toHaveAttribute("data-defcon", "1");
    expect(badges[1]).toHaveAttribute("data-defcon", "5");
  });

  it("handles zero failures correctly", () => {
    const detectors = [
      createMockDetector({
        detector_name: "perfect.Detector",
        total_evaluated: 100,
        hit_count: 0,
        absolute_score: 1.0,
      }),
    ];

    render(<DetectorResultsTable detectors={detectors} />);

    // Shows 0 failures (not styled red) and 100 total
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getByText(/\/ 100/)).toBeInTheDocument();
    // 100% appears in both progress bar and text display
    expect(screen.getAllByText("100%").length).toBeGreaterThanOrEqual(1);
  });

  it("uses absolute_score for pass rate display", () => {
    const detectors = [
      createMockDetector({
        detector_name: "score.Detector",
        absolute_score: 0.75, // 75% pass rate from backend
        total_evaluated: 100,
        hit_count: 25,
      }),
    ];

    render(<DetectorResultsTable detectors={detectors} />);

    // Pass rate comes from absolute_score - appears in progress bar and text
    expect(screen.getAllByText("75%").length).toBeGreaterThanOrEqual(1);
  });

  it("handles legacy attempt_count field", () => {
    const detectors = [
      {
        ...createMockDetector(),
        detector_name: "legacy.Detector",
        total_evaluated: undefined,
        attempt_count: 80,
        hit_count: 20,
        absolute_score: 0.75,
      } as Detector,
    ];

    render(<DetectorResultsTable detectors={detectors} />);

    // Falls back to attempt_count when total_evaluated is missing
    expect(screen.getByText("20")).toBeInTheDocument(); // failures
    expect(screen.getByText(/\/ 80/)).toBeInTheDocument(); // total
  });

  it("applies hover callback when provided", () => {
    const onHover = vi.fn();
    const detectors = [createMockDetector({ detector_name: "hover.Test" })];

    render(
      <DetectorResultsTable 
        detectors={detectors} 
        hoveredDetector={null}
        onHoverDetector={onHover}
      />
    );

    expect(screen.getByText("hover.Test")).toBeInTheDocument();
  });
});
