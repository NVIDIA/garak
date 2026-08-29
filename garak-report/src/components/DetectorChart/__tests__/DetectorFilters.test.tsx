/**
 * @file DetectorFilters.test.tsx
 * @description Tests for DetectorFilters component
 */

import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import DetectorFilters from "../DetectorFilters";
import type { GroupedDetectorEntry } from "../../../hooks/useGroupedDetectors";

// Mock KUI components
vi.mock("@kui/react", () => ({
  Flex: ({ children, onClick, style, title }: { 
    children: React.ReactNode; 
    onClick?: () => void;
    style?: React.CSSProperties;
    title?: string;
  }) => (
    <div data-testid="flex" onClick={onClick} style={style} title={title}>
      {children}
    </div>
  ),
  Text: ({ children }: { children: React.ReactNode }) => (
    <span>{children}</span>
  ),
}));

// Mock DefconBadge
vi.mock("../../DefconBadge", () => ({
  default: ({ defcon, size }: { defcon: number; size: string }) => (
    <span data-testid={`defcon-badge-${defcon}`} data-size={size}>DC-{defcon}</span>
  ),
}));

describe("DetectorFilters", () => {
  const mockEntries: GroupedDetectorEntry[] = [
    {
      detector_name: "detector1",
      detector_defcon: 1,
      absolute_score: 0.2,
      relative_score: 1.5,
    } as GroupedDetectorEntry,
    {
      detector_name: "detector2",
      detector_defcon: 1,
      absolute_score: 0.3,
      relative_score: 1.2,
    } as GroupedDetectorEntry,
    {
      detector_name: "detector3",
      detector_defcon: 3,
      absolute_score: 0.8,
      relative_score: -0.5,
    } as GroupedDetectorEntry,
  ];

  const defaultProps = {
    entries: mockEntries,
    onToggleDefcon: vi.fn(),
    getDefconOpacity: () => 1,
  };

  it("renders DEFCON badges for levels present in data", () => {
    render(<DetectorFilters {...defaultProps} />);
    
    expect(screen.getByTestId("defcon-badge-1")).toBeInTheDocument();
    expect(screen.getByTestId("defcon-badge-3")).toBeInTheDocument();
    expect(screen.queryByTestId("defcon-badge-2")).not.toBeInTheDocument();
    expect(screen.queryByTestId("defcon-badge-5")).not.toBeInTheDocument();
  });

  it("shows count for each DEFCON level", () => {
    render(<DetectorFilters {...defaultProps} />);
    
    // DC-1 has 2 entries
    expect(screen.getByText("(2)")).toBeInTheDocument();
    // DC-3 has 1 entry
    expect(screen.getByText("(1)")).toBeInTheDocument();
  });

  it("calls onToggleDefcon when badge is clicked", () => {
    const onToggleDefcon = vi.fn();
    render(<DetectorFilters {...defaultProps} onToggleDefcon={onToggleDefcon} />);
    
    const badge1Container = screen.getByTestId("defcon-badge-1").parentElement;
    fireEvent.click(badge1Container!);
    
    expect(onToggleDefcon).toHaveBeenCalledWith(1);
  });

  it("applies opacity from getDefconOpacity", () => {
    const getDefconOpacity = vi.fn((defcon: number) => defcon === 1 ? 0.3 : 1);
    render(<DetectorFilters {...defaultProps} getDefconOpacity={getDefconOpacity} />);
    
    expect(getDefconOpacity).toHaveBeenCalledWith(1);
    expect(getDefconOpacity).toHaveBeenCalledWith(3);
  });

  it("renders nothing when no DEFCON values present", () => {
    const emptyEntries: GroupedDetectorEntry[] = [];
    const { container } = render(
      <DetectorFilters {...defaultProps} entries={emptyEntries} />
    );
    
    expect(container.textContent).toBe("");
  });

  it("shows DEFCON label", () => {
    render(<DetectorFilters {...defaultProps} />);
    expect(screen.getByText("DEFCON:")).toBeInTheDocument();
  });
});
