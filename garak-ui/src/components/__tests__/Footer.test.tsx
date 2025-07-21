import { render, screen, fireEvent } from "@testing-library/react";
import Footer from "../Footer";
import { describe, it, expect } from "vitest";

const mockCalibration = {
  model_count: 8,
  calibration_date: "2023-10-01T12:00:00Z",
  model_list: "model1, model2, model3, model4, model5",
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

  it("shows model count and formatted date from calibration", () => {
    render(<Footer calibration={mockCalibration} />);
    fireEvent.click(screen.getByText("About this comparison"));

    expect(screen.getByText("Calibration Details")).toBeInTheDocument();
    expect(screen.getByText("Calibration Details").closest("div")).toHaveTextContent(/8 models/);
    expect(
      screen.getByText(new Date(mockCalibration.calibration_date).toLocaleString())
    ).toBeInTheDocument();
  });
});
