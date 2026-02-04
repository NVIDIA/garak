import { render, screen, fireEvent } from "@testing-library/react";
import ReportDetails from "../ReportDetails";
import { vi, describe, it, expect } from "vitest";
import type {
  MockPanelProps,
  MockStackProps,
  MockPageHeaderProps,
  MockSidePanelProps,
  MockBadgeProps,
  MockButtonProps,
  MockTextProps,
  MockFlexProps,
  MockAccordionProps,
  MockAccordionItem,
  MockTabsProps,
  MockTabItem,
} from "../../test-utils/mockTypes";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Panel: ({ children, slotHeading, elevation, ...props }: MockPanelProps) => (
    <div data-testid="panel" data-elevation={elevation} {...props}>
      <div data-testid="panel-heading">{slotHeading}</div>
      <div data-testid="panel-content">{children}</div>
    </div>
  ),
  Stack: ({ children, ...props }: MockStackProps) => (
    <div data-testid="stack" {...props}>
      {children}
    </div>
  ),
  PageHeader: ({ children, slotHeading, slotSubheading, slotActions, ...props }: MockPageHeaderProps) => (
    <div data-testid="page-header" {...props}>
      <div data-testid="page-header-subheading">{slotSubheading}</div>
      <div data-testid="page-header-heading">{slotHeading}</div>
      <div data-testid="page-header-actions">{slotActions}</div>
      <div data-testid="page-header-content">{children}</div>
    </div>
  ),
  SidePanel: ({ children, slotHeading, open, onInteractOutside, ...props }: MockSidePanelProps) =>
    open ? (
      <div {...props}>
        <div data-testid="side-panel-heading">{slotHeading}</div>
        <div data-testid="side-panel-content">{children}</div>
        <div
          role="presentation"
          onClick={onInteractOutside}
          data-testid="side-panel-backdrop"
        ></div>
        <button aria-label="Close" onClick={onInteractOutside}>
          ×
        </button>
      </div>
    ) : null,
  Badge: ({ children, color, kind, ...props }: MockBadgeProps) => (
    <span data-testid="badge" data-color={color} data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Button: ({ children, onClick, kind, ...props }: MockButtonProps) => (
    <button onClick={onClick} data-kind={kind} {...props}>
      {children}
    </button>
  ),
  Text: ({ children, onClick, kind, ...props }: MockTextProps) => (
    <span onClick={onClick} data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Flex: ({ children, ...props }: MockFlexProps) => (
    <div data-testid="flex" {...props}>
      {children}
    </div>
  ),
  Accordion: ({ items }: MockAccordionProps) => (
    <div data-testid="accordion">
      {items.map((item: MockAccordionItem, index: number) => (
        <div key={index} data-testid={`accordion-item-${index}`}>
          <div data-testid={`accordion-trigger-${index}`}>{item.slotTrigger}</div>
          <div data-testid={`accordion-content-${index}`}>{item.slotContent}</div>
        </div>
      ))}
    </div>
  ),
  Tabs: ({ items }: MockTabsProps) => (
    <div data-testid="tabs">
      {items.map((item: MockTabItem, index: number) => (
        <div key={index} data-testid={`tab-${index}`}>
          <div data-testid={`tab-trigger-${index}`}>{item.slotTrigger}</div>
          <div data-testid={`tab-content-${index}`}>{item.slotContent}</div>
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

const mockMeta = {
  target_type: "transformer",
  target_name: "gpt-x",
  model_type: "transformer",
  model_name: "gpt-x",
  run_uuid: "abc-123",
  setup: {},
  calibration: null,
};

describe("ReportDetails", () => {
  it("renders page header with report info", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} meta={mockMeta} />);

    expect(screen.getByTestId("report-summary")).toBeInTheDocument();
    expect(screen.getByText("Report for")).toBeInTheDocument();
    expect(screen.getByText("transformer:gpt-x")).toBeInTheDocument();
    expect(screen.getByText(/Garak Version: 0.9.1/)).toBeInTheDocument();
    expect(screen.queryByTestId("report-sidebar")).not.toBeInTheDocument();
  });

  it("opens the sidebar when panel is clicked", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} meta={mockMeta} />);

    fireEvent.click(screen.getByTestId("report-summary"));
    expect(screen.getByTestId("report-sidebar")).toBeInTheDocument();
    expect(screen.getByText("Report Details")).toBeInTheDocument();
    expect(screen.getByTestId("setup-section")).toBeInTheDocument();
    expect(screen.queryByTestId("calibration-summary")).not.toBeInTheDocument();
  });

  it("opens the sidebar when report ID is clicked", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} meta={mockMeta} />);

    // The heading is now "transformer:gpt-x", not the UUID
    fireEvent.click(screen.getByText("transformer:gpt-x"));
    expect(screen.getByTestId("report-sidebar")).toBeInTheDocument();
    expect(screen.getByText("Report Details")).toBeInTheDocument();
  });

  it("shows calibration section if data is provided", () => {
    render(
      <ReportDetails setupData={setupData} calibrationData={calibrationData} meta={mockMeta} />
    );
    fireEvent.click(screen.getByTestId("report-summary"));

    expect(screen.getByTestId("calibration-summary")).toBeInTheDocument();
    expect(screen.getByTestId("accordion")).toBeInTheDocument();
    expect(screen.getByText("Setup Section")).toBeInTheDocument();
    expect(screen.getByText("Calibration Details")).toBeInTheDocument();
  });

  it("closes the sidebar on backdrop click", () => {
    render(
      <ReportDetails setupData={setupData} calibrationData={calibrationData} meta={mockMeta} />
    );
    fireEvent.click(screen.getByTestId("report-summary"));

    expect(screen.getByTestId("report-sidebar")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("side-panel-backdrop"));
    expect(screen.queryByTestId("report-sidebar")).not.toBeInTheDocument();
  });

  it("closes the sidebar on close button click", () => {
    render(
      <ReportDetails setupData={setupData} calibrationData={calibrationData} meta={mockMeta} />
    );
    fireEvent.click(screen.getByTestId("report-summary"));

    expect(screen.getByTestId("report-sidebar")).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("Close"));
    expect(screen.queryByTestId("report-sidebar")).not.toBeInTheDocument();
  });

  it("renders badges with correct information", () => {
    render(<ReportDetails setupData={setupData} calibrationData={null} meta={mockMeta} />);

    const badges = screen.getAllByTestId("badge");
    expect(badges).toHaveLength(2); // Garak Version and Start Time only

    expect(screen.getByText(/Garak Version: 0.9.1/)).toHaveAttribute("data-color", "green");
    expect(screen.getByText(/Start Time:/)).toHaveAttribute("data-kind", "outline");
  });

  it("renders accordion with correct structure", () => {
    render(
      <ReportDetails setupData={setupData} calibrationData={calibrationData} meta={mockMeta} />
    );
    fireEvent.click(screen.getByTestId("report-summary"));

    expect(screen.getByTestId("accordion")).toBeInTheDocument();
    expect(screen.getByTestId("accordion-item-0")).toBeInTheDocument();
    expect(screen.getByTestId("accordion-item-1")).toBeInTheDocument();
  });

  it("shows aggregation unknown badge when meta.aggregation_unknown is true", () => {
    const metaWithUnknownAggregation = {
      ...mockMeta,
      aggregation_unknown: true,
    };

    render(
      <ReportDetails
        setupData={setupData}
        calibrationData={null}
        meta={metaWithUnknownAggregation}
      />
    );

    // Should show the yellow warning badge
    const badges = screen.getAllByTestId("badge");
    expect(badges.length).toBeGreaterThanOrEqual(3); // Garak Version, Start Time, and Aggregation Unknown

    expect(screen.getByText("Aggregation Method Unknown")).toBeInTheDocument();
    expect(screen.getByText("Aggregation Method Unknown")).toHaveAttribute("data-color", "yellow");
  });

  it("uses fallback chain for heading when target info is missing", () => {
    const minimalMeta = {
      target_type: null,
      target_name: null,
      model_type: null,
      model_name: null,
      run_uuid: null,
      setup: {},
      calibration: null,
    };

    const minimalSetupData = {
      "transient.run_id": "fallback-id-123",
      "transient.starttime_iso": "2025-06-26T10:00:00Z",
      "_config.version": "0.9.1",
    };

    render(
      <ReportDetails setupData={minimalSetupData} calibrationData={null} meta={minimalMeta} />
    );

    // Should use fallback from setupData["transient.run_id"]
    expect(screen.getByText("fallback-id-123")).toBeInTheDocument();
  });
});
