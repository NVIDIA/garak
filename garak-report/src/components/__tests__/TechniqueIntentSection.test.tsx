// src/components/__tests__/TechniqueIntentSection.test.tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { vi, describe, expect, it } from "vitest";
import TechniqueIntentSection from "../TechniqueIntentSection";
import type { TechniqueIntentMatrix } from "../../types/TechniqueIntent";

vi.mock("@kui/react", () => ({
  Panel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Stack: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Flex: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Text: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  Badge: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  Tooltip: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Accordion: ({
    items,
  }: {
    items: {
      value: string;
      slotTrigger: React.ReactNode;
      slotContent: React.ReactNode;
    }[];
  }) => (
    <div>
      {items.map((i) => (
        <div key={i.value}>
          <div>{i.slotTrigger}</div>
          <div>{i.slotContent}</div>
        </div>
      ))}
    </div>
  ),
  Tabs: ({
    items,
    onValueChange,
  }: {
    items: { value: string; children: React.ReactNode }[];
    onValueChange: (v: string) => void;
  }) => (
    <div>
      {items.map((i) => (
        <button key={i.value} onClick={() => onValueChange(i.value)}>
          {i.children}
        </button>
      ))}
    </div>
  ),
}));

vi.mock("../../hooks/useSeverityColor", () => ({
  __esModule: true,
  default: () => ({ getSeverityColorByLevel: () => "#abc" }),
}));

const cell = (passed: number, total: number) => ({
  score: total ? passed / total : null,
  passed,
  total_evaluated: total,
  nones: 0,
  n_detectors: 1,
});

const matrix: TechniqueIntentMatrix = {
  "demon:T:Tech": {
    _summary: { n_intents: 1, n_detectors: 1 },
    S003: cell(8, 10),
  },
};

describe("TechniqueIntentSection", () => {
  it("renders nothing when the matrix is absent", () => {
    const { container } = render(<TechniqueIntentSection matrix={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when the matrix is empty", () => {
    const { container } = render(<TechniqueIntentSection matrix={{}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the technique view by default and the cell pass rate", () => {
    render(<TechniqueIntentSection matrix={matrix} />);
    expect(screen.getByText("Techniques")).toBeInTheDocument();
    expect(screen.getByTestId("ti-cell-demon:T:Tech-S003")).toHaveTextContent("80%");
  });

  it("switches to the intent view when the tab is clicked", () => {
    render(<TechniqueIntentSection matrix={matrix} />);
    fireEvent.click(screen.getByText("By intent"));
    expect(screen.getByText("Intents")).toBeInTheDocument();
    // intent view transposes: row is the intent, column is the technique
    expect(screen.getByTestId("ti-cell-S003-demon:T:Tech")).toHaveTextContent("80%");
  });
});
