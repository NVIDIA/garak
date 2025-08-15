import { render, screen, fireEvent } from "@testing-library/react";
import ReportDetails from "../ReportDetails";
import { vi, describe, it, expect } from "vitest";

// Mock SetupSection and CalibrationSummary
vi.mock("./SetupSection", () => ({
  __esModule: true,
  default: () => <div data-testid="setup-section">Mock SetupSection</div>,
}));

vi.mock("./CalibrationSummary", () => ({
  __esModule: true,
  default: () => <div data-testid="calibration-summary">Mock CalibrationSummary</div>,
}));

const setupData = {
  "transient.run_id": "abc-123",
  "transient.starttime_iso": "2025-06-26T10:00:00Z",
  "_config.version": "0.9.1",
  "plugins.model_type": "transformer",
  "plugins.model_name": "gpt-x",
};

const calibrationData = {
  calibration_date: "2025-06-25T08:00:00Z",
  model_count: 5,
  model_list: "Model A, Model B, Model C",
};

describe("ReportDetails", () => {
  it("renders basic summary card content", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} />);

    expect(screen.getByText(/Report for abc-123/)).toBeInTheDocument();
    expect(screen.getByText(/Garak Version:/)).toBeInTheDocument();
    expect(screen.getByText("0.9.1")).toBeInTheDocument();
    expect(screen.queryByTestId("setup-section")).not.toBeInTheDocument();
  });

  it("opens the sidebar on click", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} />);

    fireEvent.click(screen.getByText(/Report for abc-123/));
    expect(screen.getByText("Report Details")).toBeInTheDocument();
    expect(screen.getByTestId("setup-section")).toBeInTheDocument();
    expect(screen.queryByTestId("calibration-summary")).not.toBeInTheDocument();
  });

  it("shows calibration section if data is provided", () => {
    render(<ReportDetails setupData={setupData} calibrationData={calibrationData} />);
    fireEvent.click(screen.getByText(/Report for abc-123/));

    expect(screen.getByTestId("calibration-summary")).toBeInTheDocument();
  });

  it("closes the sidebar on backdrop click", () => {
    render(<ReportDetails setupData={setupData} calibrationData={calibrationData} />);
    fireEvent.click(screen.getByText(/Report for abc-123/));

    fireEvent.click(screen.getByRole("presentation")); // backdrop click
    expect(screen.queryByText("Report Details")).not.toBeInTheDocument();
  });

  it("closes the sidebar on × button", () => {
    render(<ReportDetails setupData={setupData} calibrationData={calibrationData} />);
    fireEvent.click(screen.getByText(/Report for abc-123/));

    fireEvent.click(screen.getByLabelText("Close"));
    expect(screen.queryByText("Report Details")).not.toBeInTheDocument();
  });
});
