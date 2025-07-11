import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { ReportEntry } from "../../types/ReportEntry";
import Report from "../Report";

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
                zscore: 1.5,
                zscore_defcon: 2,
                zscore_comment: "above average",
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
    expect(screen.queryByText("No modules found in this report.")).not.toBeInTheDocument();
  });

  it("renders loading state if injected data is empty", async () => {
    vi.stubGlobal("__GARAK_INSERT_HERE__", []);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { default: Report } = await import("../Report");
    render(<Report />);
    expect(screen.getByText("Loading report...")).toBeInTheDocument();
    expect(errorSpy).toHaveBeenCalledWith("❌ No reports data found in build or dev fallback.");
    errorSpy.mockRestore();
  });

  it("renders empty state if report has no results", async () => {
    const emptyReport = { ...mockReports[0], results: [] };
    vi.stubGlobal("__GARAK_INSERT_HERE__", [emptyReport]);
    const { default: Report } = await import("../Report");
    render(<Report />);
    expect(screen.getByText("No modules found in this report.")).toBeInTheDocument();
  });

  it("falls back to window.reportsData and logs dev warning", async () => {
    // Simulate no build-time data
    vi.stubGlobal("__GARAK_INSERT_HERE__", []);
    // Inject dev data in window
    (window as any).reportsData = mockReports;

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    render(<Report />);

    expect(screen.getByText("Model Name:")).toBeInTheDocument();
    expect(screen.getByText("N/A")).toBeInTheDocument();
    expect(warnSpy).toHaveBeenCalledWith("Using reportsData from window (dev mode).");
    warnSpy.mockRestore();
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
});
