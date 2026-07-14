/**
 * @file TaxonomyAxisList.test.tsx
 * @description Tests the matrix-backed accordion taxonomy list: the chart,
 *              single-child, inline-detail and empty-state paths, plus the
 *              concrete pass/fail counts the digest carries.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import type { ComponentProps } from "react";
import TaxonomyAxisList from "../TaxonomyAxisList";
import type { MatrixCell, MatrixView } from "../../../utils/techniqueIntentRollup";
import type {
  MockAccordionProps,
  MockBadgeProps,
  MockFlexProps,
  MockGridProps,
  MockPanelProps,
  MockStackProps,
  MockStatusMessageProps,
  MockTextProps,
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

const cell = (over: Partial<MatrixCell>): MatrixCell => ({
  row: "techA",
  col: "i1",
  score: 0.1,
  nEvaluations: 100,
  passed: 10,
  nones: 0,
  nDetectors: 3,
  leafCount: 1,
  leaves: [],
  ...over,
});

// techA: 3 intents (chart path, worst-first); the worst pools 2 leaves.
// techB: 1 failing intent (single-child detail). techC: 1 clean intent.
const cellMap: Record<string, MatrixCell> = {
  "techA|i1": cell({
    col: "i1",
    score: 0.1,
    passed: 18,
    leafCount: 2,
    leaves: [
      { technique: "demon:A:Sub:One", intent: "i1", score: 0.1, nEvaluations: 60, passed: 6, nones: 0, nDetectors: 3 },
      { technique: "demon:A:Sub:Two", intent: "i1", score: 0.3, nEvaluations: 40, passed: 12, nones: 0, nDetectors: 2 },
    ],
  }),
  "techA|i2": cell({ col: "i2", score: 0.5, passed: 50 }),
  "techA|i3": cell({ col: "i3", score: 1, passed: 100 }),
  "techB|i1": cell({ row: "techB", col: "i1", score: 0.4, passed: 40 }),
  "techC|i1": cell({ row: "techC", col: "i1", score: 1, passed: 100 }),
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
    // techB / techC single-child cells render their detail inline with the
    // concrete pass/fail counts from the digest.
    expect(screen.getAllByText("Passed").length, "single-child detail shows the passed count").toBeGreaterThan(0);
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
