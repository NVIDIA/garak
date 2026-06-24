/**
 * @file TaxonomyAxisList.test.tsx
 * @description Tests the accordion taxonomy lists: the matrix-backed
 *              TaxonomyAxisList (chart + single-child + inline detail paths) and
 *              the marginal-only FlatTaxonomyList fallback.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import type { ComponentProps } from "react";
import TaxonomyAxisList, { FlatTaxonomyList } from "../TaxonomyAxisList";
import type { MatrixCell, MatrixView } from "../../../utils/techniqueIntentRollup";
import type { TaxonomyScoreMap } from "../../../types/ReportEntry";
import type {
  MockAccordionProps,
  MockBadgeProps,
  MockFlexProps,
  MockGridProps,
  MockPanelProps,
  MockStackProps,
  MockStatusMessageProps,
  MockTextProps,
  MockTooltipProps,
} from "../../../test-utils/mockTypes";

// Render the accordion fully (trigger + content) so nested detail/chart mount.
vi.mock("@kui/react", () => ({
  Accordion: ({ items, onValueChange }: MockAccordionProps) => (
    <div data-testid="accordion">
      {items.map(item => (
        <div key={item.value} data-testid="accordion-item">
          <button data-testid="accordion-trigger" onClick={() => onValueChange?.(item.value)}>
            {item.slotTrigger}
          </button>
          <div data-testid="accordion-content">{item.slotContent}</div>
        </div>
      ))}
    </div>
  ),
  Badge: ({ children }: MockBadgeProps) => <span data-testid="badge">{children}</span>,
  Divider: () => <hr data-testid="divider" />,
  Flex: ({ children }: MockFlexProps) => <div>{children}</div>,
  Grid: ({ children, cols }: MockGridProps) => (
    <div data-testid="grid" data-cols={String(cols)}>
      {children}
    </div>
  ),
  Panel: ({ children }: MockPanelProps) => <div data-testid="panel">{children}</div>,
  Stack: ({ children }: MockStackProps) => <div>{children}</div>,
  StatusMessage: ({ slotHeading, slotSubheading }: MockStatusMessageProps) => (
    <div data-testid="status-message">
      <div data-testid="status-heading">{slotHeading}</div>
      <div>{slotSubheading}</div>
    </div>
  ),
  Text: ({ children }: MockTextProps) => <span>{children}</span>,
  Tooltip: ({ children, slotContent }: MockTooltipProps) => (
    <div>
      {children}
      <span data-testid="tooltip-content">{slotContent}</span>
    </div>
  ),
}));

interface ClickParams {
  componentType?: string;
  dataIndex?: number;
  value?: unknown;
}
let chartClick: ((params: ClickParams) => void) | undefined;
vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: ({ onEvents }: { onEvents: { click: (p: ClickParams) => void } }) => {
    chartClick = onEvents.click;
    return <div data-testid="echarts" />;
  },
}));

const detectors = ["dan.DAN", "dan.AntiDAN", "toxicity"]; // two families: "dan" and "other"

const cell = (over: Partial<MatrixCell>): MatrixCell => ({
  row: "techA",
  col: "i1",
  score: 0.1,
  nEvaluations: 100,
  leafCount: 1,
  detectors: [],
  leaves: [],
  ...over,
});

// techA: 3 intents (chart path, worst-first); the worst pools 2 leaves.
// techB: 1 failing intent (single-child detail). techC: 1 clean intent.
const cellMap: Record<string, MatrixCell> = {
  "techA|i1": cell({
    col: "i1",
    score: 0.1,
    leafCount: 2,
    detectors,
    leaves: [
      { technique: "demon:A:Sub:One", intent: "i1", score: 0.1, nEvaluations: 60, detectors },
      { technique: "demon:A:Sub:Two", intent: "i1", score: 0.3, nEvaluations: 40, detectors },
    ],
  }),
  "techA|i2": cell({ col: "i2", score: 0.5, detectors }),
  "techA|i3": cell({ col: "i3", score: 1 }),
  "techB|i1": cell({ row: "techB", col: "i1", score: 0.4, detectors }),
  "techC|i1": cell({ row: "techC", col: "i1", score: 1 }),
};

const view: MatrixView = {
  level: "leaf",
  rows: ["techA", "techB", "techC"],
  cols: ["i1", "i2", "i3"],
  rowLabel: key => key,
  colLabel: key => key,
  cell: (row, col) => cellMap[`${row}|${col}`],
  leafCount: 6,
  reducible: false,
};

const allDefcons = [1, 2, 3, 4, 5];

const renderList = (props: Partial<ComponentProps<typeof TaxonomyAxisList>> = {}) =>
  render(
    <TaxonomyAxisList
      view={view}
      axis="technique"
      selectedDefcons={allDefcons}
      sortBy="defcon"
      openValue=""
      onOpenChange={vi.fn()}
      {...props}
    />,
  );

describe("TaxonomyAxisList", () => {
  it("renders one accordion entry per visible primary group", () => {
    renderList();
    expect(screen.getAllByTestId("accordion-item"), "a row per technique").toHaveLength(3);
  });

  it("renders the chart for multi-cell groups and a single-child detail otherwise", () => {
    renderList();
    expect(screen.getByTestId("echarts"), "multi-intent technique shows the bar chart").toBeInTheDocument();
    // techB (single failing cell) renders its detail inline, including detectors.
    expect(screen.getByText("Detectors (3)"), "single-child failing detail lists detectors").toBeInTheDocument();
  });

  it("shows a pooled-pairs detail when a rolled-up bar is selected", () => {
    renderList();
    act(() => chartClick?.({ componentType: "series", dataIndex: 0 })); // worst-first => the pooled cell
    expect(screen.getByText("Pooled pairs (2)"), "selecting a pooled cell reveals its leaves").toBeInTheDocument();
  });

  it("renders the clean 'no failures' state for a 100% cell", () => {
    renderList();
    expect(screen.getByText("No failures recorded"), "clean single-child cell shows the safe state").toBeInTheDocument();
  });

  it("supports the intent axis and alphabetical sort", () => {
    renderList({ axis: "intent", sortBy: "alphabetical" });
    expect(screen.getAllByTestId("accordion-item").length, "intent axis still renders groups").toBeGreaterThan(0);
  });

  it("shows an empty state when no group matches the DEFCON filter", () => {
    renderList({ selectedDefcons: [] });
    expect(screen.getByTestId("status-heading"), "filtered-out list shows an empty message").toHaveTextContent(
      "No techniques match the current filters",
    );
  });
});

const flatData: TaxonomyScoreMap = {
  "demon:A:Sub:Risky": {
    score: 0.2,
    n_evaluations: 200,
    detectors_used: detectors,
    probes: ["probe.one", "probe.two"],
  },
  "demon:B:Sub:Safe": {
    score: 1,
    n_evaluations: 50,
    detectors_used: [],
    probes: [],
  },
};

const renderFlat = (props: Partial<ComponentProps<typeof FlatTaxonomyList>> = {}) =>
  render(
    <FlatTaxonomyList
      data={flatData}
      axis="technique"
      selectedDefcons={allDefcons}
      sortBy="defcon"
      openValue=""
      onOpenChange={vi.fn()}
      {...props}
    />,
  );

describe("FlatTaxonomyList", () => {
  it("lists detectors and probes for a failing entry", () => {
    renderFlat();
    expect(screen.getByText("Detectors (3)"), "failing marginal entry lists detectors").toBeInTheDocument();
    expect(screen.getByText("Probes (2)"), "multi-probe entry lists its probes").toBeInTheDocument();
  });

  it("shows the safe state for a clean entry", () => {
    renderFlat();
    expect(screen.getByText("No failures recorded"), "clean marginal entry shows the safe state").toBeInTheDocument();
  });

  it("shows an empty state when nothing matches the filter", () => {
    renderFlat({ selectedDefcons: [], sortBy: "alphabetical", axis: "intent" });
    expect(screen.getByTestId("status-heading")).toHaveTextContent(
      "No intents match the current filters",
    );
  });
});
