/**
 * @file TechniqueIntentPanel.test.tsx
 * @description Integration tests for the Techniques & Intents tab: the severity
 *              summary, notable-pairings callout, filter/sort/level controls, and
 *              the empty state for reports without a matrix.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import type { ReactNode } from "react";
import TechniqueIntentPanel from "../TechniqueIntentPanel";
import type { TechniqueIntentMatrix } from "../../../types/ReportEntry";
import type {
  MockAccordionProps,
  MockBadgeProps,
  MockButtonProps,
  MockFlexProps,
  MockGridProps,
  MockGroupProps,
  MockNotificationProps,
  MockPanelProps,
  MockSegmentedControlProps,
  MockStackProps,
  MockStatusMessageProps,
  MockTabsProps,
  MockTextProps,
  MockTooltipProps,
} from "../../../test-utils/mockTypes";

interface MockCardProps extends MockFlexProps {
  slotHeader?: ReactNode;
}

vi.mock("@kui/react", () => ({
  Accordion: ({ items }: MockAccordionProps) => (
    <div data-testid="accordion">
      {items.map(item => (
        <div key={item.value} data-testid="accordion-item">
          {item.slotTrigger}
          {item.slotContent}
        </div>
      ))}
    </div>
  ),
  Badge: ({ children }: MockBadgeProps) => <span>{children}</span>,
  Button: ({ children, onClick }: MockButtonProps) => <button onClick={onClick}>{children}</button>,
  Card: ({ slotHeader, children }: MockCardProps) => (
    <div data-testid="card">
      <div>{slotHeader}</div>
      {children}
    </div>
  ),
  Divider: () => <hr />,
  Flex: ({ children }: MockFlexProps) => <div>{children}</div>,
  Grid: ({ children }: MockGridProps) => <div>{children}</div>,
  Group: ({ children }: MockGroupProps) => <div>{children}</div>,
  Notification: ({ slotHeading, slotSubheading }: MockNotificationProps) => (
    <div data-testid="notification">
      <div data-testid="notification-heading">{slotHeading}</div>
      <div>{slotSubheading}</div>
    </div>
  ),
  Panel: ({ children }: MockPanelProps) => <div>{children}</div>,
  Stack: ({ children }: MockStackProps) => <div>{children}</div>,
  SegmentedControl: ({ items, onValueChange }: MockSegmentedControlProps) => (
    <div>
      {items.map(item => (
        <button key={item.value} data-testid={`seg-${item.value}`} onClick={() => onValueChange?.(item.value)}>
          {item.children}
        </button>
      ))}
    </div>
  ),
  StatusMessage: ({ slotHeading, slotSubheading }: MockStatusMessageProps) => (
    <div data-testid="status-message">
      <div data-testid="status-heading">{slotHeading}</div>
      <div>{slotSubheading}</div>
    </div>
  ),
  Tabs: ({ items, onValueChange }: MockTabsProps) => (
    <div data-testid="tabs">
      {items.map(item => (
        <div key={item.value}>
          <button data-testid={`tab-${item.value}`} onClick={() => onValueChange?.(item.value)}>
            {item.children}
          </button>
          <div data-testid={`tabpanel-${item.value}`}>{item.slotContent}</div>
        </div>
      ))}
    </div>
  ),
  Text: ({ children }: MockTextProps) => <span>{children}</span>,
  Tooltip: ({ children, slotContent }: MockTooltipProps) => (
    <div>
      {children}
      {slotContent}
    </div>
  ),
}));

vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: () => <div data-testid="echarts" />,
}));

const score = (s: number) => ({
  score: s,
  passed: Math.round(s * 100),
  total_evaluated: 100,
  nones: 0,
  n_detectors: 1,
});

// Two leaf techniques in one subcategory (so grouping is reducible) and an
// interaction pairing: (one × i1) fails at 0 while both its row and column reach
// 1.0 elsewhere, so findNotablePairings surfaces it.
const matrix: TechniqueIntentMatrix = {
  "demon:T:Sub:one": { i1: score(0), i2: score(1) },
  "demon:T:Sub:two": { i1: score(1) },
};

describe("TechniqueIntentPanel", () => {
  it("shows an empty state when the report has no taxonomy data", () => {
    render(<TechniqueIntentPanel />);
    expect(screen.getByTestId("status-heading")).toHaveTextContent(
      "No technique/intent data in this report",
    );
  });

  it("renders the severity summary, tabs and notable pairings for a matrix", () => {
    render(<TechniqueIntentPanel techniqueIntent={matrix} />);
    expect(screen.getByText("Pairing severity"), "summary card renders").toBeInTheDocument();
    expect(screen.getByTestId("tab-technique"), "technique tab present").toBeInTheDocument();
    expect(screen.getByTestId("tab-intent"), "intent tab present").toBeInTheDocument();
    expect(screen.getByTestId("notification-heading"), "interaction callout renders").toHaveTextContent(
      "Notable pairings",
    );
  });

  it("drives the filter, sort, level and tab controls", () => {
    render(<TechniqueIntentPanel techniqueIntent={matrix} isDark />);

    // Level toggle appears because the matrix is reducible; switch to grouped.
    fireEvent.click(screen.getByTestId("seg-grouped"));
    // Sort alphabetically.
    fireEvent.click(screen.getByTestId("seg-alphabetical"));
    // Toggle a DEFCON level off in the shared filter bar.
    fireEvent.click(screen.getByTitle(/DEFCON 1\./));
    // Switch to the intent tab.
    fireEvent.click(screen.getByTestId("tab-intent"));

    expect(screen.getByTestId("tabs"), "panel stays mounted through interactions").toBeInTheDocument();
  });
});
