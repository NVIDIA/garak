import { render, screen } from "@testing-library/react";
import DefconBadge from "../DefconBadge";
import { describe, it, expect, vi } from "vitest";
import type { MockBadgeProps } from "../../test-utils/mockTypes";

// Mock Kaizen Badge component
vi.mock("@kui/react", () => ({
  Badge: ({ children, title, color, kind, ...props }: MockBadgeProps) => (
    <span title={title} data-color={color} data-kind={kind} {...props}>
      {children}
    </span>
  ),
}));

// Mock the useSeverityColor hook
vi.mock("../../hooks/useSeverityColor", () => ({
  default: () => ({
    getDefconBadgeColor: (defcon: number) => {
      switch (defcon) {
        case 1:
          return "red";
        case 2:
          return "yellow";
        case 3:
          return "green";
        case 4:
          return "green";
        case 5:
          return "teal";
        default:
          return "gray";
      }
    },
    getSeverityLabelByLevel: (defcon: number) => {
      switch (defcon) {
        case 1:
          return "Critical";
        case 2:
          return "Poor";
        case 3:
          return "Average";
        case 4:
          return "Good";
        case 5:
          return "Excellent";
        default:
          return "Unknown";
      }
    },
  }),
}));

describe("DefconBadge", () => {
  it("renders DEFCON level correctly", () => {
    render(<DefconBadge defcon={1} />);
    expect(screen.getByText("DC-1")).toBeInTheDocument();
  });

  it("renders N/A for null defcon", () => {
    render(<DefconBadge defcon={null} />);
    expect(screen.getByText("N/A")).toBeInTheDocument();
  });

  it("renders N/A for zero defcon", () => {
    render(<DefconBadge defcon={0} />);
    expect(screen.getByText("N/A")).toBeInTheDocument();
  });

  it("shows label when showLabel is true", () => {
    render(<DefconBadge defcon={5} showLabel={true} />);
    expect(screen.getByText("DC-5")).toBeInTheDocument();
    expect(screen.getByText("Excellent")).toBeInTheDocument();
  });

  it("applies correct title attribute", () => {
    render(<DefconBadge defcon={3} />);
    const badge = screen.getByText("DC-3");
    expect(badge).toHaveAttribute("title", "DEFCON 3: Average");
  });

  it("uses correct badge properties", () => {
    render(<DefconBadge defcon={2} />);
    const badge = screen.getByText("DC-2");
    expect(badge).toHaveAttribute("data-color", "yellow");
    expect(badge).toHaveAttribute("data-kind", "solid");
  });

  it("uses correct color for N/A badge", () => {
    render(<DefconBadge defcon={null} />);
    const badge = screen.getByText("N/A");
    expect(badge).toHaveAttribute("data-color", "gray");
    expect(badge).toHaveAttribute("data-kind", "outline");
  });
});
