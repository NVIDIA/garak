import { render, screen } from "@testing-library/react";
import DefconBadge from "../DefconBadge";
import { describe, it, expect, vi } from "vitest";

// Mock the useSeverityColor hook
vi.mock("../../hooks/useSeverityColor", () => ({
  default: () => ({
    getDefconColor: (defcon: number) => {
      switch (defcon) {
        case 1: return "#b91c1c"; // red-700
        case 2: return "#f87171"; // red-400
        case 3: return "#fde047"; // yellow-300
        case 4: return "#4ade80"; // green-400
        case 5: return "#16a34a"; // green-600
        default: return "#6b7280"; // gray-500
      }
    },
    getSeverityLabelByLevel: (defcon: number) => {
      switch (defcon) {
        case 1: return "Very Bad";
        case 2: return "Below Average";
        case 3: return "Average";
        case 4: return "Good";
        case 5: return "Excellent";
        default: return "Unknown";
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

  it("applies correct size classes", () => {
    const { rerender } = render(<DefconBadge defcon={2} size="sm" />);
    expect(screen.getByText("DC-2")).toHaveClass("px-1.5", "py-0.5", "text-xs");

    rerender(<DefconBadge defcon={2} size="md" />);
    expect(screen.getByText("DC-2")).toHaveClass("px-2", "py-1", "text-sm");

    rerender(<DefconBadge defcon={2} size="lg" />);
    expect(screen.getByText("DC-2")).toHaveClass("px-3", "py-1.5", "text-base");

    rerender(<DefconBadge defcon={2} size="xl" />);
    expect(screen.getByText("DC-2")).toHaveClass("px-3", "py-1.5", "text-lg");
  });
}); 