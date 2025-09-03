import { render, screen, fireEvent } from "@testing-library/react";
import ReportDetails from "../ReportDetails";
import { vi, describe, it, expect } from "vitest";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  PageHeader: ({ children, slotHeading, slotSubheading, slotActions, ...props }: any) => (
    <div data-testid="page-header" {...props}>
      <div data-testid="page-header-subheading">{slotSubheading}</div>
      <div data-testid="page-header-heading">{slotHeading}</div>
      <div data-testid="page-header-actions">{slotActions}</div>
      <div data-testid="page-header-content">{children}</div>
    </div>
  ),
  SidePanel: ({ children, slotHeading, open, onInteractOutside, ...props }: any) => (
    open ? (
      <div {...props}>
        <div data-testid="side-panel-heading">{slotHeading}</div>
        <div data-testid="side-panel-content">{children}</div>
        <div role="presentation" onClick={onInteractOutside} data-testid="side-panel-backdrop"></div>
        <button aria-label="Close" onClick={onInteractOutside}>×</button>
      </div>
    ) : null
  ),
  Badge: ({ children, color, kind, ...props }: any) => (
    <span data-testid="badge" data-color={color} data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Button: ({ children, onClick, kind, ...props }: any) => (
    <button onClick={onClick} data-kind={kind} {...props}>
      {children}
    </button>
  ),
  Text: ({ children, onClick, kind, ...props }: any) => (
    <span onClick={onClick} data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Flex: ({ children, ...props }: any) => <div data-testid="flex" {...props}>{children}</div>,
  Accordion: ({ items }: any) => (
    <div data-testid="accordion">
      {items.map((item: any, index: number) => (
        <div key={index} data-testid={`accordion-item-${index}`}>
          <div data-testid={`accordion-trigger-${index}`}>{item.slotTrigger}</div>
          <div data-testid={`accordion-content-${index}`}>{item.slotContent}</div>
        </div>
      ))}
    </div>
  ),
}));

// Mock SetupSection and CalibrationSummary
vi.mock("../SetupSection", () => ({
  __esModule: true,
  default: () => <div data-testid="setup-section">Mock SetupSection</div>,
}));

vi.mock("../CalibrationSummary", () => ({
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
  it("renders page header with report info", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} />);

    expect(screen.getByTestId("report-summary")).toBeInTheDocument();
    expect(screen.getByText("Report for")).toBeInTheDocument();
    expect(screen.getByText("abc-123")).toBeInTheDocument();
    expect(screen.getByText(/Garak Version: 0.9.1/)).toBeInTheDocument();
    expect(screen.getByText(/Model Type: transformer/)).toBeInTheDocument();
    expect(screen.getByText(/Model Name: gpt-x/)).toBeInTheDocument();
    expect(screen.queryByTestId("report-sidebar")).not.toBeInTheDocument();
  });

  it("opens the sidebar when More info button is clicked", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} />);

    fireEvent.click(screen.getByText("More info"));
    expect(screen.getByTestId("report-sidebar")).toBeInTheDocument();
    expect(screen.getByText("Report Details")).toBeInTheDocument();
    expect(screen.getByTestId("setup-section")).toBeInTheDocument();
    expect(screen.queryByTestId("calibration-summary")).not.toBeInTheDocument();
  });

  it("opens the sidebar when report ID is clicked", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} />);

    fireEvent.click(screen.getByText("abc-123"));
    expect(screen.getByTestId("report-sidebar")).toBeInTheDocument();
    expect(screen.getByText("Report Details")).toBeInTheDocument();
  });

  it("shows calibration section if data is provided", () => {
    render(<ReportDetails setupData={setupData} calibrationData={calibrationData} />);
    fireEvent.click(screen.getByText("More info"));

    expect(screen.getByTestId("calibration-summary")).toBeInTheDocument();
    expect(screen.getByTestId("accordion")).toBeInTheDocument();
    expect(screen.getByText("Setup Section")).toBeInTheDocument();
    expect(screen.getByText("Calibration Details")).toBeInTheDocument();
  });

  it("closes the sidebar on backdrop click", () => {
    render(<ReportDetails setupData={setupData} calibrationData={calibrationData} />);
    fireEvent.click(screen.getByText("More info"));

    expect(screen.getByTestId("report-sidebar")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("side-panel-backdrop"));
    expect(screen.queryByTestId("report-sidebar")).not.toBeInTheDocument();
  });

  it("closes the sidebar on close button click", () => {
    render(<ReportDetails setupData={setupData} calibrationData={calibrationData} />);
    fireEvent.click(screen.getByText("More info"));

    expect(screen.getByTestId("report-sidebar")).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("Close"));
    expect(screen.queryByTestId("report-sidebar")).not.toBeInTheDocument();
  });

  it("renders badges with correct information", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} />);

    const badges = screen.getAllByTestId("badge");
    expect(badges).toHaveLength(4); // Garak Version, Model Type, Model Name, Start Time
    
    expect(screen.getByText(/Garak Version: 0.9.1/)).toHaveAttribute("data-color", "green");
    expect(screen.getByText(/Model Type: transformer/)).toHaveAttribute("data-kind", "outline");
  });

  it("renders accordion with correct structure", () => {
    render(<ReportDetails setupData={setupData} calibrationData={calibrationData} />);
    fireEvent.click(screen.getByText("More info"));

    expect(screen.getByTestId("accordion")).toBeInTheDocument();
    expect(screen.getByTestId("accordion-item-0")).toBeInTheDocument();
    expect(screen.getByTestId("accordion-item-1")).toBeInTheDocument();
  });
});
