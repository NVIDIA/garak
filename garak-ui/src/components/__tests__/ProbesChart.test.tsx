import { render, screen, fireEvent } from "@testing-library/react";
import ProbesChart from "../ProbesChart";
import { vi, describe, it, expect } from "vitest";
import type { ProbesChartProps } from "../../types/ProbesChart";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Button: ({ children, onClick, ...props }: any) => <button onClick={onClick} {...props}>{children}</button>,
  Flex: ({ children, ...props }: any) => <div data-testid="flex" {...props}>{children}</div>,
  Grid: ({ children, ...props }: any) => <div data-testid="grid" {...props}>{children}</div>,
  Stack: ({ children, ...props }: any) => <div data-testid="stack" {...props}>{children}</div>,
  Text: ({ children, kind, ...props }: any) => <span data-kind={kind} {...props}>{children}</span>,
  Tooltip: ({ children, slotContent, ...props }: any) => (
    <div data-testid="tooltip" {...props}>
      {children}
      {slotContent && <div data-testid="tooltip-content">{slotContent}</div>}
    </div>
  ),
}));

// Mock useSeverityColor
vi.mock("../../hooks/useSeverityColor", () => ({
  default: () => ({
    getSeverityColorByLevel: (level: number) => {
      return level === 1 ? "#0f0" : level === 2 ? "#ff0" : "#f00";
    },
    getSeverityLabelByLevel: (level: number) => {
      return level === 1 ? "low" : level === 2 ? "medium" : "high";
    },
    getDefconColor: () => "#ff0000",
  }),
}));

// Mock DetectorsView
vi.mock("../DetectorsView", () => ({
  __esModule: true,
  default: ({ "data-testid": dataTestId, probe, allProbes, setSelectedProbe }: any) => (
    <div data-testid={dataTestId ?? "detectors-view"}>
      <div data-testid="detector-probe-name">{probe?.summary?.probe_name}</div>
      <div data-testid="detector-all-probes-count">{allProbes?.length}</div>
      <button onClick={() => setSelectedProbe?.(null)} data-testid="detector-clear-btn">Clear</button>
    </div>
  ),
}));

// Mock ColorLegend
vi.mock("../ColorLegend", () => ({
  __esModule: true,
  default: () => <div data-testid="color-legend">Mock ColorLegend</div>,
}));

// Mock useProbeTooltip
vi.mock("../../hooks/useProbeTooltip", () => ({
  useProbeTooltip: () => (data: any) => `Tooltip for ${data.name}: ${data.value}%`,
}));

// Mock echarts component with configurable behavior
let mockClickName = "probe-1";
vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: ({ onEvents }: any) => (
    <div
      data-testid="echarts"
      onClick={() => onEvents?.click?.({ name: mockClickName })}
    >
      MockChart
    </div>
  ),
}));

const baseProps: ProbesChartProps = {
  module: {
    group_name: "Fairness",
    summary: {
      group: "fairness",
      score: 0.8,
      group_defcon: 2,
      doc: "",
      group_link: "",
      group_aggregation_function: "avg",
      unrecognised_aggregation_function: false,
      show_top_group_score: false,
    },
    probes: [
      {
        probe_name: "probe-1",
        summary: {
          probe_name: "probe-1",
          probe_score: 0.5,
          probe_severity: 2,
          probe_descr: "desc",
          probe_tier: 1,
        },
        detectors: [],
      },
    ],
  },
  selectedProbe: null,
  setSelectedProbe: vi.fn(),
};

describe("ProbesChart", () => {
  it("renders chart without selected probe", () => {
    render(<ProbesChart {...baseProps} />);
    expect(screen.getByTestId("echarts")).toBeInTheDocument();
    expect(screen.queryByTestId("detectors-view")).toBeNull();
  });

  it("renders DetectorsView when selectedProbe is present", () => {
    render(<ProbesChart {...baseProps} selectedProbe={baseProps.module.probes[0]} />);
    expect(screen.getByTestId("detectors-view")).toBeInTheDocument();
  });

  it("calls setSelectedProbe on chart bar click", () => {
    const setSelectedProbe = vi.fn();

    render(<ProbesChart {...baseProps} setSelectedProbe={setSelectedProbe} />);

    fireEvent.click(screen.getByTestId("echarts"));
    expect(setSelectedProbe).toHaveBeenCalledWith(baseProps.module.probes[0]);
  });

  it("clears selectedProbe on second click of same bar", () => {
    const setSelectedProbe = vi.fn();
    const selected = baseProps.module.probes[0];

    render(
      <ProbesChart {...baseProps} selectedProbe={selected} setSelectedProbe={setSelectedProbe} />
    );

    fireEvent.click(screen.getByTestId("echarts"));
    expect(setSelectedProbe).toHaveBeenCalledWith(null);
  });

  it("falls back to probe.probe_name and 0 score if summary is missing", () => {
    const props = {
      ...baseProps,
      module: {
        ...baseProps.module,
        probes: [
          {
            probe_name: "fallback-name",
            summary: undefined as any, // simulate missing summary
            detectors: [],
          },
        ],
      },
    };

    render(<ProbesChart {...props} />);
    expect(screen.getByTestId("echarts")).toBeInTheDocument();
  });

  describe("Empty state handling", () => {
    it("shows empty message when no probes are available", () => {
      const emptyProps = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: [],
        },
      };

      render(<ProbesChart {...emptyProps} />);
      expect(screen.getByText("No probes meet the current filter.")).toBeInTheDocument();
      expect(screen.queryByTestId("echarts")).not.toBeInTheDocument();
    });

    it("renders chart when probes are available", () => {
      render(<ProbesChart {...baseProps} />);
      expect(screen.getByTestId("echarts")).toBeInTheDocument();
      expect(screen.queryByText("No probes meet the current filter.")).not.toBeInTheDocument();
    });
  });

  describe("Data transformation and probe mapping", () => {
    it("transforms probe data correctly with all fields", () => {
      const propsWithMultipleProbes = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: [
            {
              probe_name: "fairness.bias.gender",
              summary: {
                probe_name: "fairness.bias.gender",
                probe_score: 0.75,
                probe_severity: 1,
                probe_descr: "Gender bias probe",
                probe_tier: 1,
              },
              detectors: [],
            },
            {
              probe_name: "fairness.bias.race",
              summary: {
                probe_name: "fairness.bias.race",
                probe_score: 0.25,
                probe_severity: 3,
                probe_descr: "Race bias probe",
                probe_tier: 2,
              },
              detectors: [],
            },
          ],
        },
      };

      render(<ProbesChart {...propsWithMultipleProbes} />);
      
      // Should render chart with multiple probes
      expect(screen.getByTestId("echarts")).toBeInTheDocument();
      expect(screen.getByText("Probe scores")).toBeInTheDocument();
    });

    it("handles probe data with missing summary fields", () => {
      const propsWithPartialData = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: [
            {
              probe_name: "incomplete.probe",
              summary: {
                probe_name: "incomplete.probe",
                probe_score: undefined as any,
                probe_severity: undefined as any,
                probe_descr: "Incomplete probe",
                probe_tier: 1,
              },
              detectors: [],
            },
          ],
        },
      };

      render(<ProbesChart {...propsWithPartialData} />);
      
      // Should render without crashing
      expect(screen.getByTestId("echarts")).toBeInTheDocument();
    });

    it("uses probe_name as fallback when summary.probe_name is missing", () => {
      const propsWithMissingName = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: [
            {
              probe_name: "fallback.probe.name",
              summary: {
                probe_name: undefined as any,
                probe_score: 0.5,
                probe_severity: 2,
                probe_descr: "Probe with missing summary name",
                probe_tier: 1,
              },
              detectors: [],
            },
          ],
        },
      };

      render(<ProbesChart {...propsWithMissingName} />);
      expect(screen.getByTestId("echarts")).toBeInTheDocument();
    });
  });

  describe("Tooltip and info functionality", () => {
    it("renders info button with tooltip content", () => {
      render(<ProbesChart {...baseProps} />);
      
      expect(screen.getByTestId("tooltip")).toBeInTheDocument();
      
      // Check tooltip content is present
      expect(screen.getByTestId("tooltip-content")).toBeInTheDocument();
      expect(screen.getByText(/A probe is a predefined set of prompts/)).toBeInTheDocument();
      expect(screen.getByText(/Each bar shows the percentage of prompts/)).toBeInTheDocument();
      
      // Check ColorLegend is rendered in tooltip
      expect(screen.getByTestId("color-legend")).toBeInTheDocument();
    });

    it("displays probe scores title", () => {
      render(<ProbesChart {...baseProps} />);
      expect(screen.getByText("Probe scores")).toBeInTheDocument();
    });
  });

  describe("Grid layout behavior", () => {
    it("renders single column grid when no probe is selected", () => {
      render(<ProbesChart {...baseProps} />);
      
      const grid = screen.getByTestId("grid");
      expect(grid).toBeInTheDocument();
      expect(grid).toHaveAttribute("cols", "1");
      expect(screen.queryByTestId("detectors-view")).not.toBeInTheDocument();
    });

    it("renders two column grid when probe is selected", () => {
      const selectedProps = {
        ...baseProps,
        selectedProbe: baseProps.module.probes[0],
      };

      render(<ProbesChart {...selectedProps} />);
      
      const grid = screen.getByTestId("grid");
      expect(grid).toBeInTheDocument();
      expect(grid).toHaveAttribute("cols", "2");
      expect(screen.getByTestId("detectors-view")).toBeInTheDocument();
    });
  });

  describe("DetectorsView integration", () => {
    it("passes correct props to DetectorsView when probe is selected", () => {
      const selectedProbe = baseProps.module.probes[0];
      const setSelectedProbe = vi.fn();
      const propsWithSelection = {
        ...baseProps,
        selectedProbe,
        setSelectedProbe,
      };

      render(<ProbesChart {...propsWithSelection} />);

      // Check DetectorsView receives correct props
      expect(screen.getByTestId("detector-probe-name")).toHaveTextContent("probe-1");
      expect(screen.getByTestId("detector-all-probes-count")).toHaveTextContent("1");
      
      // Test that DetectorsView can clear selection
      const clearButton = screen.getByTestId("detector-clear-btn");
      fireEvent.click(clearButton);
      expect(setSelectedProbe).toHaveBeenCalledWith(null);
    });

    it("passes all probes to DetectorsView", () => {
      const multiProbeProps = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: [
            ...baseProps.module.probes,
            {
              probe_name: "probe-2",
              summary: {
                probe_name: "probe-2",
                probe_score: 0.3,
                probe_severity: 1,
                probe_descr: "Second probe",
                probe_tier: 1,
              },
              detectors: [],
            },
          ],
        },
        selectedProbe: baseProps.module.probes[0],
      };

      render(<ProbesChart {...multiProbeProps} />);
      expect(screen.getByTestId("detector-all-probes-count")).toHaveTextContent("2");
    });
  });

  describe("Probe selection and interaction", () => {
    it("selects probe when chart bar is clicked", () => {
      const setSelectedProbe = vi.fn();
      
      render(<ProbesChart {...baseProps} setSelectedProbe={setSelectedProbe} />);

      fireEvent.click(screen.getByTestId("echarts"));
      expect(setSelectedProbe).toHaveBeenCalledWith(baseProps.module.probes[0]);
    });

    it("deselects probe when same probe is clicked again", () => {
      const setSelectedProbe = vi.fn();
      const selectedProbe = baseProps.module.probes[0];
      
      render(<ProbesChart {...baseProps} selectedProbe={selectedProbe} setSelectedProbe={setSelectedProbe} />);

      fireEvent.click(screen.getByTestId("echarts"));
      expect(setSelectedProbe).toHaveBeenCalledWith(null);
    });

    it("switches selection when different probe is clicked", () => {
      const setSelectedProbe = vi.fn();
      const multiProbeProps = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: [
            baseProps.module.probes[0],
            {
              probe_name: "probe-2",
              summary: {
                probe_name: "probe-2",
                probe_score: 0.8,
                probe_severity: 3,
                probe_descr: "Second probe",
                probe_tier: 1,
              },
              detectors: [],
            },
          ],
        },
        selectedProbe: baseProps.module.probes[0], // First probe selected
        setSelectedProbe,
      };

      // Set mock to simulate clicking second probe
      mockClickName = "probe-2";

      render(<ProbesChart {...multiProbeProps} />);

      fireEvent.click(screen.getByTestId("echarts"));
      expect(setSelectedProbe).toHaveBeenCalledWith(multiProbeProps.module.probes[1]);
      
      // Reset mock for other tests
      mockClickName = "probe-1";
    });

    it("handles click on non-existent probe gracefully", () => {
      const setSelectedProbe = vi.fn();

      // Set mock to simulate clicking non-existent probe
      mockClickName = "non-existent-probe";

      render(<ProbesChart {...baseProps} setSelectedProbe={setSelectedProbe} />);

      fireEvent.click(screen.getByTestId("echarts"));
      // Should not call setSelectedProbe for non-existent probe
      expect(setSelectedProbe).not.toHaveBeenCalled();
      
      // Reset mock for other tests
      mockClickName = "probe-1";
    });
  });

  describe("Edge cases and data scenarios", () => {
    it("handles probes with zero scores", () => {
      const zeroScoreProps = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: [
            {
              probe_name: "zero.score.probe",
              summary: {
                probe_name: "zero.score.probe",
                probe_score: 0,
                probe_severity: 5,
                probe_descr: "Zero score probe",
                probe_tier: 1,
              },
              detectors: [],
            },
          ],
        },
      };

      render(<ProbesChart {...zeroScoreProps} />);
      expect(screen.getByTestId("echarts")).toBeInTheDocument();
    });

    it("handles probes with maximum scores", () => {
      const maxScoreProps = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: [
            {
              probe_name: "max.score.probe",
              summary: {
                probe_name: "max.score.probe",
                probe_score: 1.0,
                probe_severity: 1,
                probe_descr: "Max score probe",
                probe_tier: 1,
              },
              detectors: [],
            },
          ],
        },
      };

      render(<ProbesChart {...maxScoreProps} />);
      expect(screen.getByTestId("echarts")).toBeInTheDocument();
    });

    it("handles probes with complex hierarchical names", () => {
      const hierarchicalProps = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: [
            {
              probe_name: "very.deep.nested.probe.name.structure",
              summary: {
                probe_name: "very.deep.nested.probe.name.structure",
                probe_score: 0.42,
                probe_severity: 2,
                probe_descr: "Complex nested probe",
                probe_tier: 1,
              },
              detectors: [],
            },
          ],
        },
      };

      render(<ProbesChart {...hierarchicalProps} />);
      expect(screen.getByTestId("echarts")).toBeInTheDocument();
    });

    it("handles large number of probes", () => {
      const manyProbes = Array.from({ length: 20 }, (_, i) => ({
        probe_name: `probe-${i}`,
        summary: {
          probe_name: `probe-${i}`,
          probe_score: Math.random(),
          probe_severity: (i % 5) + 1,
          probe_descr: `Probe ${i}`,
          probe_tier: 1,
        },
        detectors: [],
      }));

      const manyProbesProps = {
        ...baseProps,
        module: {
          ...baseProps.module,
          probes: manyProbes,
        },
      };

      render(<ProbesChart {...manyProbesProps} />);
      expect(screen.getByTestId("echarts")).toBeInTheDocument();
    });

    it("maintains state consistency during rapid interactions", () => {
      const setSelectedProbe = vi.fn();
      const probe1 = baseProps.module.probes[0];
      
      const { rerender } = render(
        <ProbesChart {...baseProps} setSelectedProbe={setSelectedProbe} />
      );

      // Simulate rapid clicks
      fireEvent.click(screen.getByTestId("echarts"));
      expect(setSelectedProbe).toHaveBeenCalledWith(probe1);

      // Rerender with probe selected
      rerender(
        <ProbesChart {...baseProps} selectedProbe={probe1} setSelectedProbe={setSelectedProbe} />
      );

      // Click again to deselect
      fireEvent.click(screen.getByTestId("echarts"));
      expect(setSelectedProbe).toHaveBeenCalledWith(null);
    });
  });
});
