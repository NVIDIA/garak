import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import CalibrationSummary from "../CalibrationSummary";

const mockCalibration = {
  calibration_date: "2025-06-25T12:00:00Z",
  model_count: 3,
  model_list: "Model A, Model B, Model C",
};

describe("CalibrationSummary", () => {
  it("renders both buttons", () => {
    render(<CalibrationSummary calibration={mockCalibration} />);
    expect(screen.getByText("Calibration Summary")).toBeInTheDocument();
    expect(screen.getByText("Calibration Models")).toBeInTheDocument();
  });

  it("toggles Calibration Summary section", () => {
    render(<CalibrationSummary calibration={mockCalibration} />);
    const summaryButton = screen.getByText("Calibration Summary");

    fireEvent.click(summaryButton);
    expect(screen.getByText("Date:")).toBeInTheDocument();
    expect(screen.getByText("Model Count:")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();

    fireEvent.click(summaryButton);
    expect(screen.queryByText("Date:")).not.toBeInTheDocument();
  });

  it("toggles Models Evaluated section", () => {
    render(<CalibrationSummary calibration={mockCalibration} />);
    const modelsButton = screen.getByText("Calibration Models");

    fireEvent.click(modelsButton);
    expect(screen.getByText("Model A")).toBeInTheDocument();
    expect(screen.getByText("Model B")).toBeInTheDocument();
    expect(screen.getByText("Model C")).toBeInTheDocument();

    fireEvent.click(modelsButton);
    expect(screen.queryByText("Model A")).not.toBeInTheDocument();
  });

  it("switches between sections", () => {
    render(<CalibrationSummary calibration={mockCalibration} />);
    const summaryButton = screen.getByText("Calibration Summary");
    const modelsButton = screen.getByText("Calibration Models");

    fireEvent.click(summaryButton);
    expect(screen.getByText("Date:")).toBeInTheDocument();

    fireEvent.click(modelsButton);
    expect(screen.queryByText("Date:")).not.toBeInTheDocument();
    expect(screen.getByText("Model A")).toBeInTheDocument();
  });
});
