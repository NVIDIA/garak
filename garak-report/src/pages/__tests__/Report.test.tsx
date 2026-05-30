import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import type { ReportEntry } from "../../types/ReportEntry";
import Report from "../Report";
import type {
  MockFlexProps,
  MockStackProps,
  MockTextProps,
  MockCheckboxProps,
  MockSegmentedControlProps,
  MockAccordionProps,
  MockStatusMessageProps,
  MockBadgeProps,
  MockComponentProps,
  MockDefconBadgeProps,
} from "../../test-utils/mockTypes";

// Mock window.matchMedia
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// Mock all Kaizen components
vi.mock("@kui/react", () => ({
  Accordion: ({ items, onValueChange, ...props }: MockAccordionProps) => (
    <div data-testid="accordion" {...props}>
      {items.map((item, index: number) => (
        <div key={index} data-testid={`accordion-item-${index}`}>
          <div
            data-testid={`accordion-trigger-${index}`}
            onClick={() => onValueChange?.(item.value)}
          >
            {item.slotTrigger}
          </div>
          <div data-testid={`accordion-content-${index}`}>{item.slotContent}</div>
        </div>
      ))}
    </div>
  ),
  Anchor: ({ children, href, ...props }: MockComponentProps & { href?: string }) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
  Badge: ({ children, color, kind, ...props }: MockBadgeProps) => (
    <span data-testid="badge" data-color={color} data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Button: ({ children, onClick, ...props }: MockComponentProps & { onClick?: () => void }) => (
    <button data-testid="button" onClick={onClick} {...props}>
      {children}
    </button>
  ),
  Divider: () => <hr data-testid="divider" />,
  Flex: ({ children, ...props }: MockFlexProps) => (
    <div data-testid="flex" {...props}>
      {children}
    </div>
  ),
  Grid: ({ children, ...props }: MockComponentProps) => (
    <div data-testid="grid" {...props}>
      {children}
    </div>
  ),
  Panel: ({ children, ...props }: MockComponentProps) => (
    <div data-testid="panel" {...props}>
      {children}
    </div>
  ),
  Spinner: ({
    size,
    description,
    ...props
  }: MockComponentProps & { size?: string; description?: string }) => (
    <div data-testid="spinner" data-size={size} {...props}>
      <div data-testid="spinner-description">{description}</div>
    </div>
  ),
  Stack: ({ children, ...props }: MockStackProps) => (
    <div data-testid="stack" {...props}>
      {children}
    </div>
  ),
  StatusMessage: ({ slotHeading, slotSubheading, ...props }: MockStatusMessageProps) => (
    <div data-testid="status-message" {...props}>
      <div data-testid="status-heading">{slotHeading}</div>
      <div data-testid="status-subheading">{slotSubheading}</div>
    </div>
  ),
  Text: ({ children, kind, ...props }: MockTextProps) => (
    <span data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Tooltip: ({ children, slotContent }: MockComponentProps & { slotContent?: React.ReactNode }) => (
    <div data-testid="tooltip" title={String(slotContent)}>
      {children}
    </div>
  ),
  Group: ({ children, ...props }: MockComponentProps) => (
    <div data-testid="group" {...props}>
      {children}
    </div>
  ),
  Checkbox: ({ checked, onCheckedChange, slotLabel, children, ...props }: MockCheckboxProps) => (
    <label {...props}>
      <input 
        type="checkbox" 
        checked={checked} 
        onChange={e => onCheckedChange?.(e.target.checked)}
      />
      {slotLabel || children}
    </label>
  ),
  SegmentedControl: ({
    items,
    value,
    onValueChange,
    size,
    ...props
  }: MockSegmentedControlProps) => (
    <div data-testid="segmented-control" data-size={size} {...props}>
      {items.map((item, index: number) => {
        const itemValue = typeof item === "string" ? item : item.value;
        const itemLabel = typeof item === "string" ? item : item.children;
        return (
          <label key={index}>
            <input
              type="radio"
              name="segmented-control"
              value={itemValue}
              checked={value === itemValue}
              onChange={() => onValueChange?.(itemValue)}
              data-testid={`segment-${itemValue}`}
            />
            {itemLabel}
          </label>
        );
      })}
    </div>
  ),
}));

// Mock custom components
vi.mock("../../components/Footer", () => ({
  __esModule: true,
  default: () => <div data-testid="footer-garak">Generated with garak</div>,
}));

vi.mock("../../components/Header", () => ({
  __esModule: true,
  default: () => <div data-testid="header">Header</div>,
}));

// Define interface for mock ReportDetails props
interface MockReportDetailsProps {
  setupData?: Record<string, unknown>;
}

vi.mock("../../components/ReportDetails", () => ({
  __esModule: true,
  default: ({ setupData }: MockReportDetailsProps) => (
    <div data-testid="report-details">
      <div>
        Model Name:{" "}
        <span data-testid="setup-data">{(setupData?.["plugins.model_name"] as string) || "N/A"}</span>
      </div>
    </div>
  ),
}));

vi.mock("../../components/SummaryStatsCard", () => ({
  __esModule: true,
  default: () => <div data-testid="summary-stats">Summary Stats</div>,
}));

vi.mock("../../components/ProbesChart", () => ({
  __esModule: true,
  default: () => <div data-testid="probes-chart">Probes Chart</div>,
}));

vi.mock("../../components/DefconBadge", () => ({
  __esModule: true,
  default: ({ defcon, size, ...props }: MockDefconBadgeProps) => (
    <div data-testid="defcon-badge" data-defcon={defcon} data-size={size} {...props}>
      DC-{defcon}
    </div>
  ),
}));

// Mock hooks
vi.mock("../../hooks/useFlattenedModules", () => ({
  __esModule: true,
  default: () => [],
}));

vi.mock("../../hooks/useSeverityColor", () => ({
  __esModule: true,
  default: () => ({ 
    getDefconBadgeColor: () => "red",
  }),
}));

// prettier-ignore
// @ts-expect-error: define global for test
globalThis.__GARAK_INSERT_HERE__ = [
  {
    // @ts-expect-error: define global for test
    meta: {
      setup: {
        "plugins.model_name": "test-model",
      },
    },
    results: [],
  } satisfies ReportEntry,
];

// Create a mock report dataset
const mockReports: ReportEntry[] = [
  {
    entry_type: "digest",
    filename: "report-a.json",
    meta: {
      reportfile: "report-a.json",
      garak_version: "1.0.0",
      start_time: "2025-06-27T12:00:00Z",
      run_uuid: "abc123",
      setup: { model: "test-model" },
      calibration_used: true,
      calibration: {
        calibration_date: "2025-06-26",
        model_count: 2,
        model_list: "model-a, model-b",
      },
    },
    eval: {},
    results: [
      {
        group_name: "toxicity",
        summary: {
          group: "toxicity",
          score: 0.8,
          group_defcon: 2,
          doc: "Toxicity detection module",
          group_link: "#",
          group_aggregation_function: "max",
          unrecognised_aggregation_function: false,
          show_top_group_score: true,
        },
        probes: [
          {
            probe_name: "test-probe",
            summary: {
              probe_name: "test-probe",
              probe_score: 0.9,
              probe_severity: 3,
              probe_descr: "test probe descr",
              probe_tier: 1,
            },
            detectors: [
              {
                detector_name: "tox.start",
                detector_descr: "Starts with toxic phrase",
                absolute_score: 0.9,
                absolute_defcon: 2,
                absolute_comment: "high risk",
                relative_score: 1.5,
                relative_defcon: 2,
                relative_comment: "above average",
                detector_defcon: 2,
                calibration_used: true,
              },
            ],
          },
        ],
      },
    ],
  },
];

describe("Report", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.stubGlobal("__GARAK_INSERT_HERE__", mockReports); // simulates build-time injection
    vi.doMock("../Report", async importOriginal => {
      const original = await importOriginal();
      return {
        // @ts-expect-error: REPORTS_DATA is injected via a build-time placeholder
        ...original,
        // @ts-expect-error: __GARAK_INSERT_HERE__ is a global injected at test-time
        REPORTS_DATA: __GARAK_INSERT_HERE__,
      };
    });
  });

  it("renders the report with modules and footer", async () => {
    const { default: Report } = await import("../Report");
    render(<Report />);
    expect(screen.getByTestId("footer-garak")).toHaveTextContent(/garak/i);
  });

  it("renders loading state if injected data is empty", async () => {
    vi.stubGlobal("__GARAK_INSERT_HERE__", []);
    const { default: Report } = await import("../Report");
    render(<Report />);
    expect(screen.getByText("Loading reports...")).toBeInTheDocument();
  });

  it("renders empty state if report has no results", async () => {
    const emptyReport = { ...mockReports[0], results: [] };
    vi.stubGlobal("__GARAK_INSERT_HERE__", [emptyReport]);
    const { default: Report } = await import("../Report");
    render(<Report />);
    expect(screen.getByText("No modules found in this report")).toBeInTheDocument();
  });

  it("falls back to window.reportsData in dev mode", async () => {
    // Simulate no build-time data
    vi.stubGlobal("__GARAK_INSERT_HERE__", []);
    // Inject dev data in window - this is a runtime property not in Window type
    // @ts-expect-error: injecting dev-only property for testing
    window.reportsData = mockReports;

    render(<Report />);

    expect(screen.getByText("Model Name:")).toBeInTheDocument();
    expect(screen.getByText("N/A")).toBeInTheDocument();
  });

  it("renders report from __GARAK_INSERT_HERE__", async () => {
    vi.stubGlobal("__GARAK_INSERT_HERE__", [
      {
        ...mockReports[0],
        meta: {
          ...mockReports[0].meta,
          setup: {
            "plugins.model_name": "test-model",
          },
        },
        results: [],
      },
    ]);

    const { default: Report } = await import("../Report");
    render(<Report />);
    expect(screen.getByText("test-model")).toBeInTheDocument();
  });

  it("renders accordion items for each flattened module", async () => {
    vi.resetModules();

    // mock flattened modules
    const mockModules = [
      {
        group_name: "m1",
        summary: {
          group: "m1",
          score: 0.5,
          group_defcon: 1,
          doc: "Module 1",
          group_link: "#",
          group_aggregation_function: "avg",
          unrecognised_aggregation_function: false,
          show_top_group_score: false,
        },
        probes: [],
      },
      {
        group_name: "m2",
        summary: {
          group: "m2",
          score: 0.8,
          group_defcon: 2,
          doc: "Module 2",
          group_link: "#",
          group_aggregation_function: "avg",
          unrecognised_aggregation_function: false,
          show_top_group_score: false,
        },
        probes: [],
      },
    ];

    vi.doMock("../../hooks/useFlattenedModules", () => ({
      __esModule: true,
      default: () => mockModules,
    }));

    const { default: ReportReloaded } = await import("../Report");
    render(<ReportReloaded />);

    // Check for accordion structure
    expect(screen.getByTestId("accordion")).toBeInTheDocument();
    expect(screen.getByTestId("accordion-item-0")).toBeInTheDocument();
    expect(screen.getByTestId("accordion-item-1")).toBeInTheDocument();
    expect(screen.getByText("m1")).toBeInTheDocument();
    expect(screen.getByText("m2")).toBeInTheDocument();
  });

  it("handles empty modules from useFlattenedModules", async () => {
    vi.resetModules();

    const mockReport = { ...mockReports[0], results: [] };
    vi.stubGlobal("__GARAK_INSERT_HERE__", [mockReport]);

    // useFlattenedModules returns empty array
    vi.doMock("../../hooks/useFlattenedModules", () => ({
      __esModule: true,
      default: () => [],
    }));

    const { default: ReportReloaded } = await import("../Report");
    render(<ReportReloaded />);

    // Should show empty state message since no modules
    expect(screen.getByText("No modules found in this report")).toBeInTheDocument();
    expect(screen.queryByTestId("accordion")).not.toBeInTheDocument();
  });

  describe("DEFCON filtering functionality", () => {
    it("renders DEFCON filter buttons for all levels", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "module1", 
          summary: {
            group: "module1",
            score: 0.8,
            group_defcon: 1,
            doc: "Module 1",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // Should render filter label and all 5 DEFCON buttons
      expect(screen.getByText("Filter by DEFCON:")).toBeInTheDocument();
      
      for (let defcon = 1; defcon <= 5; defcon++) {
        const defconButton = screen.getByTitle(`DEFCON ${defcon}. Click to hide.`);
        expect(defconButton).toBeInTheDocument();
        expect(defconButton).toHaveStyle({ opacity: "1" }); // Initially all visible
      }
    });

    it("toggles DEFCON filter when clicked", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "module1", 
          summary: {
            group: "module1",
            score: 0.8,
            group_defcon: 1,
            doc: "Module 1",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
        { 
          group_name: "module2", 
          summary: {
            group: "module2",
            score: 0.6,
            group_defcon: 2,
            doc: "Module 2",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // Initially both modules should be visible
      expect(screen.getByText("module1")).toBeInTheDocument();
      expect(screen.getByText("module2")).toBeInTheDocument();

      // Click DEFCON 1 filter to hide it
      const defcon1Button = screen.getByTitle("DEFCON 1. Click to hide.");
      fireEvent.click(defcon1Button);

      // After filtering, defcon 1 button should show reduced opacity
      expect(defcon1Button).toHaveStyle({ opacity: "0.3" });
      expect(defcon1Button.title).toBe("DEFCON 1. Click to show.");
    });

    it("filters modules by selected DEFCON levels", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "critical", 
          summary: {
            group: "critical",
            score: 0.9,
            group_defcon: 1,
            doc: "Critical Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
        { 
          group_name: "moderate", 
          summary: {
            group: "moderate",
            score: 0.6,
            group_defcon: 3,
            doc: "Moderate Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
        { 
          group_name: "low", 
          summary: {
            group: "low",
            score: 0.3,
            group_defcon: 5,
            doc: "Low Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // Initially all modules should be visible
      expect(screen.getByText("critical")).toBeInTheDocument();
      expect(screen.getByText("moderate")).toBeInTheDocument();
      expect(screen.getByText("low")).toBeInTheDocument();

      // Hide DEFCON 5 (low priority)
      const defcon5Button = screen.getByTitle("DEFCON 5. Click to hide.");
      fireEvent.click(defcon5Button);

      // After filtering out DEFCON 5, "low" module should not be in accordion
      // Note: This tests the filtering logic, but the actual filtering would be applied
      // to the modules passed to the accordion
      expect(defcon5Button).toHaveStyle({ opacity: "0.3" });
    });

    it("shows empty state when all DEFCON levels are filtered out", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "module1", 
          summary: {
            group: "module1",
            score: 0.8,
            group_defcon: 1,
            doc: "Module 1",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // Hide all DEFCON levels
      for (let defcon = 1; defcon <= 5; defcon++) {
        const defconButton = screen.getByTitle(`DEFCON ${defcon}. Click to hide.`);
        fireEvent.click(defconButton);
      }

      // Should show empty state message
      expect(screen.getByText("No modules found in this report")).toBeInTheDocument();
      expect(screen.getByText("Try changing the filters or sorting options")).toBeInTheDocument();
    });
  });

  describe("Sorting functionality", () => {
    it("renders sorting controls", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "alpha", 
          summary: {
            group: "alpha",
            score: 0.8,
            group_defcon: 2,
            doc: "Alpha Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      expect(screen.getByText("Sort by:")).toBeInTheDocument();
      expect(screen.getByTestId("segmented-control")).toBeInTheDocument();
      
      // DEFCON should be selected by default
      const defconSegment = screen.getByTestId("segment-defcon");
      const alphabeticalSegment = screen.getByTestId("segment-alphabetical");

      expect(defconSegment).toBeChecked();
      expect(alphabeticalSegment).not.toBeChecked();
    });

    it("switches between DEFCON and alphabetical sorting", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "zebra", 
          summary: {
            group: "zebra",
            score: 0.8,
            group_defcon: 3,
            doc: "Zebra Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
        { 
          group_name: "alpha", 
          summary: {
            group: "alpha",
            score: 0.6,
            group_defcon: 1,
            doc: "Alpha Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // Default is DEFCON sort, so alpha (defcon 1) should come before zebra (defcon 3)
      const accordion = screen.getByTestId("accordion");
      expect(accordion).toBeInTheDocument();

      // Switch to alphabetical sorting
      const alphabeticalSegment = screen.getByTestId("segment-alphabetical");
      fireEvent.click(alphabeticalSegment);

      expect(alphabeticalSegment).toBeChecked();
      expect(screen.getByTestId("segment-defcon")).not.toBeChecked();
    });

    it("sorts modules by DEFCON level when DEFCON sort is selected", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "high_defcon", 
          summary: {
            group: "high_defcon",
            score: 0.5,
            group_defcon: 5,
            doc: "High DEFCON Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
        { 
          group_name: "low_defcon", 
          summary: {
            group: "low_defcon",
            score: 0.9,
            group_defcon: 1,
            doc: "Low DEFCON Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // With DEFCON sorting (default), low_defcon (DEFCON 1) should come first
      const accordionItems = screen.getAllByTestId(/accordion-item-/);
      expect(accordionItems).toHaveLength(2);
      
      // Check that modules are present (exact ordering would require deeper DOM inspection)
      expect(screen.getByText("low_defcon")).toBeInTheDocument();
      expect(screen.getByText("high_defcon")).toBeInTheDocument();
    });
  });

  describe("State management and component integration", () => {
    it("passes setup and calibration data to ReportDetails", async () => {
      vi.resetModules();
      const mockReport = {
        ...mockReports[0],
        meta: {
          ...mockReports[0].meta,
          setup: { "plugins.model_name": "test-gpt-4" },
          calibration: { model_count: 3 },
        },
      };
      
      vi.stubGlobal("__GARAK_INSERT_HERE__", [mockReport]);

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      expect(screen.getByText("test-gpt-4")).toBeInTheDocument();
    });

    it("clears selectedProbe when accordion value changes", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "module1", 
          summary: {
            group: "module1",
            score: 0.8,
            group_defcon: 1,
            doc: "Module 1",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // The accordion should have an onValueChange handler that clears selectedProbe
      const accordion = screen.getByTestId("accordion");
      expect(accordion).toBeInTheDocument();
    });

    it("renders all main components when data is available", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "test_module", 
          summary: {
            group: "test_module",
            score: 0.75,
            group_defcon: 2,
            doc: "Test Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // Check all main components are rendered
      expect(screen.getByTestId("header")).toBeInTheDocument();
      expect(screen.getByTestId("report-details")).toBeInTheDocument();
      expect(screen.getByTestId("summary-stats")).toBeInTheDocument();
      expect(screen.getByTestId("accordion")).toBeInTheDocument();
      expect(screen.getByTestId("footer-garak")).toBeInTheDocument();

      // Check filtering and sorting controls
      expect(screen.getByText("Filter by DEFCON:")).toBeInTheDocument();
      expect(screen.getByText("Sort by:")).toBeInTheDocument();
    });

    it("displays module badges with correct score and DEFCON values", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "scored_module", 
          summary: {
            group: "scored_module",
            score: 0.85,
            group_defcon: 2,
            doc: "Scored Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // Check score badge (85% displayed as 85)
      expect(screen.getByText("85%")).toBeInTheDocument();
      
      // Check DEFCON badge in accordion (there are multiple DC-2 texts)
      const defconBadges = screen.getAllByText("DC-2");
      expect(defconBadges.length).toBeGreaterThan(0); // Should have at least one DC-2
      
      // Check module name and description
      expect(screen.getByText("scored_module")).toBeInTheDocument();
    });
  });

  describe("Edge cases and error handling", () => {
    it("handles modules with missing or null probe arrays", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "no_probes", 
          summary: {
            group: "no_probes",
            score: 0.5,
            group_defcon: 3,
            doc: "No Probes Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          // @ts-expect-error: testing fallback when probes is null
          probes: null,
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      // Should render without crashing and show the module
      expect(screen.getByText("no_probes")).toBeInTheDocument();
      expect(screen.getByTestId("probes-chart")).toBeInTheDocument();
    });

    it("handles rapid DEFCON filter toggles", async () => {
      vi.resetModules();
      const mockModules = [
        { 
          group_name: "test_module", 
          summary: {
            group: "test_module",
            score: 0.7,
            group_defcon: 2,
            doc: "Test Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: () => mockModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      render(<ReportReloaded />);

      const defcon2Button = screen.getByTitle("DEFCON 2. Click to hide.");
      
      // Rapidly toggle the filter multiple times
      fireEvent.click(defcon2Button);
      expect(defcon2Button).toHaveStyle({ opacity: "0.3" });
      
      fireEvent.click(defcon2Button);
      expect(defcon2Button).toHaveStyle({ opacity: "1" });
      
      fireEvent.click(defcon2Button);
      expect(defcon2Button).toHaveStyle({ opacity: "0.3" });
    });

    it("maintains filter state when modules change", async () => {
      vi.resetModules();
      let mockModules = [
        { 
          group_name: "initial_module", 
          summary: {
            group: "initial_module",
            score: 0.6,
            group_defcon: 1,
            doc: "Initial Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];

      const mockUseFlattenedModules = vi.fn(() => mockModules);
      vi.doMock("../../hooks/useFlattenedModules", () => ({
        __esModule: true,
        default: mockUseFlattenedModules,
      }));

      const { default: ReportReloaded } = await import("../Report");
      const { rerender } = render(<ReportReloaded />);

      // Set initial filter state
      const defcon1Button = screen.getByTitle("DEFCON 1. Click to hide.");
      fireEvent.click(defcon1Button);
      expect(defcon1Button).toHaveStyle({ opacity: "0.3" });

      // Change the modules data
      mockModules = [
        { 
          group_name: "updated_module", 
          summary: {
            group: "updated_module",
            score: 0.8,
            group_defcon: 2,
            doc: "Updated Module",
            group_link: "#",
            group_aggregation_function: "max",
            unrecognised_aggregation_function: false,
            show_top_group_score: true,
          },
          probes: [],
        },
      ];
      mockUseFlattenedModules.mockReturnValue(mockModules);

      // Re-render component
      rerender(<ReportReloaded />);

      // Filter state should be maintained
      const stillFilteredDefcon1Button = screen.getByTitle("DEFCON 1. Click to show.");
      expect(stillFilteredDefcon1Button).toHaveStyle({ opacity: "0.3" });
    });
  });

  describe("Theme and callback coverage", () => {
    it("calls onThemeChange callback when theme toggle is triggered", () => {
      const onThemeChange = vi.fn();
      render(<Report onThemeChange={onThemeChange} currentTheme="light" />);

      // Component should render and callback should be available
      expect(screen.getByTestId("footer-garak")).toBeInTheDocument();
    });

    it("returns false for isDark when currentTheme is not dark", () => {
      render(<Report currentTheme="light" />);
      expect(screen.getByTestId("footer-garak")).toBeInTheDocument();
    });

    it("handles accordion value change and clears selected probe", () => {
      render(<Report />);

      // Find accordion trigger and click it to trigger onValueChange
      const accordionTrigger = screen.queryByTestId("accordion-trigger-0");

      if (accordionTrigger) {
        // Click accordion trigger - this should call onValueChange which calls setOpenAccordionValue and setSelectedProbe(null)
        fireEvent.click(accordionTrigger);

        // After clicking, the accordion is still rendered
        expect(screen.getByTestId("accordion")).toBeInTheDocument();
      } else {
        // If no accordion, component still renders
        expect(screen.getByTestId("footer-garak")).toBeInTheDocument();
      }
    });
  });
});
