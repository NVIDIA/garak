import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import ColorLegend from "../ColorLegend";
import { describe, it, expect, vi } from "vitest";
import type { MockFlexProps, MockTextProps, MockButtonProps } from "../../test-utils/mockTypes";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Flex: ({ children, ...props }: MockFlexProps) => (
    <div data-testid="flex" {...props}>
      {children}
    </div>
  ),
  Text: ({ children, ...props }: MockTextProps) => <span {...props}>{children}</span>,
  Button: ({ children, onClick, "aria-label": ariaLabel, ...props }: MockButtonProps) => (
    <button onClick={onClick} aria-label={ariaLabel} {...props}>
      {children}
    </button>
  ),
}));

// Mock useSeverityColor hook
vi.mock("../../hooks/useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByLevel: (level: number) => {
      const colors: Record<number, string> = {
        1: "#fecaca", // red-200
        2: "#fef08a", // yellow-200
        3: "#bbf7d0", // green-200
        4: "#bbf7d0", // green-200
        5: "#7dd3fc", // teal-200
      };
      return colors[level] || "#e5e7eb";
    },
    getSeverityLabelByLevel: (level: number) => {
      const labels: Record<number, string> = {
        1: "Critical",
        2: "Poor",
        3: "Average",
        4: "Good",
        5: "Excellent",
      };
      return labels[level] || "Unknown";
    },
  }),
}));

describe("ColorLegend", () => {
  it("renders five severity items", () => {
    render(<ColorLegend />);
    const labels = ["Critical", "Poor", "Average", "Good", "Excellent"];
    labels.forEach(label => expect(screen.getByText(label)).toBeInTheDocument());

    // Each label should have a preceding color square
    const squares = labels.map(l => screen.getByLabelText(l));
    expect(squares).toHaveLength(5);
    // Ensure first square has non-empty background color
    const style = window.getComputedStyle(squares[0]);
    expect(style.backgroundColor).not.toBe("");
  });

  it("renders hide button and calls onClose when clicked", () => {
    const onClose = vi.fn();
    render(<ColorLegend onClose={onClose} />);

    const button = screen.getByRole("button", { name: /hide legend/i });
    expect(button).toBeInTheDocument();

    fireEvent.click(button);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does not render hide button when onClose is not provided", () => {
    render(<ColorLegend />);
    const button = screen.queryByRole("button", { name: /hide legend/i });
    expect(button).toBeNull();
  });
});
