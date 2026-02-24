import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import ProbesChart from "../ProbesChart";
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

vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: () => <div data-testid="chart" />,
}));
vi.mock("../DetectorsView", () => ({ __esModule: true, default: () => <div /> }));
vi.mock("../../hooks/useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByLevel: () => "#000",
    getSeverityLabelByLevel: () => "",
    getDefconColor: () => "#ff0000",
  }),
}));

import type { Module } from "../../types/ProbesChart";

const moduleData: Module = {
  group_name: "m",
  summary: {
    group: "g",
    score: 0,
    group_defcon: 5,
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
        probe_severity: 5,
        probe_descr: "",
        probe_tier: 1,
      },
      detectors: [],
    },
  ],
};

describe("ProbesChart slider", () => {
  it("renders without slider after removal", () => {
    const setSel = vi.fn();
    render(<ProbesChart module={moduleData} selectedProbe={null} setSelectedProbe={setSel} />);
    expect(screen.queryByRole("slider")).toBeNull();
  });
});
