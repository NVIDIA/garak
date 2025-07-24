import { render, screen } from "@testing-library/react";
import CustomTooltip from "../CustomTooltip";
import { vi, describe, it, expect } from "vitest";

// Mock the useSeverityColor hook
vi.mock("../hooks/useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByComment: (comment: string) => {
      if (comment === "low") return "green";
      if (comment === "medium") return "orange";
      if (comment === "high") return "rgb(156, 163, 175)";
      return "black";
    },
  }),
}));

const mockPayload = [
  {
    payload: {
      detector_name: "ExampleDetector",
      detector_score: 0.75,
      zscore: 1.23,
      zscore_comment: "high",
    },
  },
];

describe("CustomTooltip", () => {
  it("renders nothing when inactive", () => {
    const { container } = render(<CustomTooltip active={false} payload={mockPayload} />);
    expect(container.firstChild).toBeNull();
  });

  it("renders nothing when payload is missing", () => {
    const { container } = render(<CustomTooltip active={true} payload={[]} />);
    expect(container.firstChild).toBeNull();
  });

  it("renders tooltip content correctly when active and payload is valid", () => {
    render(<CustomTooltip active={true} payload={mockPayload} />);
    expect(screen.getByText("ExampleDetector")).toBeInTheDocument();
    expect(screen.getByText("Score: 0.75")).toBeInTheDocument();
    expect(screen.getByText(/high \(Z-score: 1.23\)/)).toBeInTheDocument();
  });

  it("uses correct color based on zscore_comment", () => {
    const { container } = render(<CustomTooltip active={true} payload={mockPayload} />);
    const span = container.querySelector("span");
    expect(span).toHaveStyle("color: rgb(156, 163, 175)");
  });
});
