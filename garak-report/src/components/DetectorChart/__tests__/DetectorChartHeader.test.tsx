/**
 * @file DetectorChartHeader.test.tsx
 * @description Tests for DetectorChartHeader component
 */

import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import DetectorChartHeader from "../DetectorChartHeader";

// Mock KUI components
vi.mock("@kui/react", () => ({
  Button: ({ children }: { children: React.ReactNode }) => (
    <button>{children}</button>
  ),
  Flex: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="flex">{children}</div>
  ),
  Stack: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="stack">{children}</div>
  ),
  Text: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
  Tooltip: ({ children, slotContent }: { children: React.ReactNode; slotContent: React.ReactNode }) => (
    <div data-testid="tooltip">
      {children}
      <div data-testid="tooltip-content">{slotContent}</div>
    </div>
  ),
}));

// Mock lucide-react
vi.mock("lucide-react", () => ({
  Info: () => <span data-testid="info-icon" />,
}));

describe("DetectorChartHeader", () => {
  it("renders the title", () => {
    render(<DetectorChartHeader />);
    expect(screen.getByText("Detector comparison")).toBeInTheDocument();
  });

  it("renders info button with tooltip", () => {
    render(<DetectorChartHeader />);
    expect(screen.getByTestId("tooltip")).toBeInTheDocument();
    expect(screen.getByTestId("info-icon")).toBeInTheDocument();
  });

  it("renders tooltip content with explanations", () => {
    render(<DetectorChartHeader />);
    expect(screen.getByText("What are Detectors?")).toBeInTheDocument();
    expect(screen.getByText(/A detector analyzes the language model's responses/)).toBeInTheDocument();
    expect(screen.getByText("Lollipop colors:")).toBeInTheDocument();
    expect(screen.getByText(/hits\/attempts/)).toBeInTheDocument();
  });
});
