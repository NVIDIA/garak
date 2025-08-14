import { render, screen, fireEvent } from "@testing-library/react";
import Module from "../Module";
import { vi, describe, it, expect } from "vitest";

vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: () => <div data-testid="probes-chart">MockChart</div>,
}));

// Mock severity color
vi.mock("../hooks/useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByLevel: (level: number) => {
      return level === 1 ? "green" : level === 2 ? "orange" : "red";
    },
  }),
}));

// Mock ProbesChart
vi.mock("./ProbesChart", () => ({
  __esModule: true,
  default: () => <div>Mock ProbesChart</div>,
}));

vi.mock("../ProbesChart", () => ({
  __esModule: true,
  default: () => <div>Mock ProbesChart</div>,
}));

const mockModule = {
  group_name: "Bias",
  summary: {
    group: "bias",
    score: 0.76,
    group_defcon: 2,
    doc: "This module evaluates fairness.",
    group_link: "https://example.com/bias",
    group_aggregation_function: "average",
    unrecognised_aggregation_function: false,
    show_top_group_score: false,
  },
  probes: [],
};

describe("Module", () => {
  it("renders module header with score and name", () => {
    render(<Module module={mockModule} />);
    expect(screen.getByText("76%")).toBeInTheDocument();
    expect(screen.getByText("Bias")).toBeInTheDocument();
  });

  it("renders link with HTML content and prevents propagation", () => {
    render(<Module module={mockModule} />);
    const link = screen.getByRole("link", { name: /This module/i });
    expect(link).toHaveAttribute("href", "https://example.com/bias");

    // Confirm stopPropagation is called
    const stop = vi.fn();
    const event = new MouseEvent("click", { bubbles: true });
    Object.defineProperty(event, "stopPropagation", { value: stop });
    link.dispatchEvent(event);
    expect(stop).toHaveBeenCalled();
  });

  it("toggles ProbesChart when header is clicked", () => {
    render(<Module module={mockModule} />);
    expect(screen.queryByText(/ProbesChart/)).toBeNull();

    fireEvent.click(screen.getByText("Bias"));
    expect(screen.getByText(/ProbesChart/)).toBeInTheDocument();

    fireEvent.click(screen.getByText("Bias"));
    expect(screen.queryByText(/ProbesChart/)).toBeNull();
  });

  it("uses correct border and background color", () => {
    const { container } = render(<Module module={mockModule} />);
    const box = container.firstChild as HTMLElement;

    expect(box).toHaveStyle("border-color: rgb(248, 113, 113)"); // orange for defcon 2
    expect(screen.getByText("76%").parentElement).toHaveStyle("background: rgb(248, 113, 113)");
  });

  it("renders correct arrow icons for open and closed states", () => {
    render(<Module module={mockModule} />);
    // Closed state: downward arrow
    expect(screen.getByText("▼")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Bias"));
    // Open state: upward arrow  
    expect(screen.getByText("▲")).toBeInTheDocument();
  });
});
