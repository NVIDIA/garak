import { render, screen, fireEvent } from "@testing-library/react";
import Footer from "../Footer";
import { describe, it, expect } from "vitest";

const mockCalibration = {
  model_count: 8,
  date: "2025-06-26T15:00:00Z",
};

describe("Footer", () => {
  it("renders static text and button", () => {
    render(<Footer calibration={null} />);
    expect(screen.getByText("About this comparison")).toBeInTheDocument();
    expect(screen.getByText(/Generated with/i)).toBeInTheDocument();
    expect(screen.getByText(/garak/i)).toBeInTheDocument();
  });

  it("reveals z-score info when button is clicked", () => {
    render(<Footer calibration={null} />);
    fireEvent.click(screen.getByText("About this comparison"));

    expect(screen.getByText(/Positive Z-scores mean better than average/i)).toBeInTheDocument();
    expect(
      screen.getByText(/The middle 10% of models score -0.125 to \+0.125/i)
    ).toBeInTheDocument();
  });

  it("shows calibration details if provided", () => {
    render(<Footer calibration={mockCalibration} />);
    fireEvent.click(screen.getByText("About this comparison"));

    expect(screen.getByText("Calibration Details")).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
    expect(screen.getByText(/built at/i)).toBeInTheDocument();
  });

  it("toggles details off on second click", () => {
    render(<Footer calibration={null} />);
    const btn = screen.getByText("About this comparison");

    fireEvent.click(btn);
    expect(screen.getByText(/Positive Z-scores/i)).toBeInTheDocument();

    fireEvent.click(btn);
    expect(screen.queryByText(/Positive Z-scores/i)).toBeNull();
  });
});
