import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import CalibrationSummary from "../CalibrationSummary";
import type {
  MockTabsProps,
  MockTabItem,
  MockTextProps,
  MockStackProps,
  MockFlexProps,
} from "../../test-utils/mockTypes";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Tabs: ({ items }: MockTabsProps) => (
    <div data-testid="tabs">
      {items.map((item: MockTabItem, index: number) => (
        <div key={index} data-testid={`tab-${index}`}>
          <div data-testid={`tab-trigger-${index}`}>{item.children}</div>
          <div data-testid={`tab-content-${index}`}>{item.slotContent}</div>
        </div>
      ))}
    </div>
  ),
  Text: ({ children, kind, ...props }: MockTextProps) => (
    <span data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Stack: ({ children, ...props }: MockStackProps) => (
    <div data-testid="stack" {...props}>
      {children}
    </div>
  ),
  Flex: ({ children, ...props }: MockFlexProps) => (
    <div data-testid="flex" {...props}>
      {children}
    </div>
  ),
}));

const mockCalibration = {
  calibration_date: "2025-06-25T12:00:00Z",
  model_count: 3,
  model_list: "Model A, Model B, Model C",
};

describe("CalibrationSummary", () => {
  it("renders both tab labels", () => {
    render(<CalibrationSummary calibration={mockCalibration} />);
    expect(screen.getByText("Calibration Summary")).toBeInTheDocument();
    expect(screen.getByText("Calibration Models")).toBeInTheDocument();
  });

  it("renders calibration summary content", () => {
    render(<CalibrationSummary calibration={mockCalibration} />);
    expect(screen.getByText("Date:")).toBeInTheDocument();
    expect(screen.getByText("Model Count:")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(
      screen.getByText(new Date(mockCalibration.calibration_date).toLocaleString())
    ).toBeInTheDocument();
  });

  it("renders calibration models content", () => {
    render(<CalibrationSummary calibration={mockCalibration} />);
    expect(screen.getByText("Models:")).toBeInTheDocument();
    expect(screen.getByText("Model A")).toBeInTheDocument();
    expect(screen.getByText("Model B")).toBeInTheDocument();
    expect(screen.getByText("Model C")).toBeInTheDocument();
  });

  it("renders correct tab structure", () => {
    render(<CalibrationSummary calibration={mockCalibration} />);
    expect(screen.getByTestId("tabs")).toBeInTheDocument();
    expect(screen.getByTestId("tab-0")).toBeInTheDocument();
    expect(screen.getByTestId("tab-1")).toBeInTheDocument();
  });

  it("splits model list correctly", () => {
    const calibrationWithManyModels = {
      ...mockCalibration,
      model_list: "Model X, Model Y, Model Z, Model W",
    };

    render(<CalibrationSummary calibration={calibrationWithManyModels} />);
    expect(screen.getByText("Model X")).toBeInTheDocument();
    expect(screen.getByText("Model Y")).toBeInTheDocument();
    expect(screen.getByText("Model Z")).toBeInTheDocument();
    expect(screen.getByText("Model W")).toBeInTheDocument();
  });
});
