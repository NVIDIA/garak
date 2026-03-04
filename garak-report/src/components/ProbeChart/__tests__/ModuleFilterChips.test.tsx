/**
 * @file ModuleFilterChips.test.tsx
 * @description Tests for ModuleFilterChips component
 */

import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import ModuleFilterChips from "../ModuleFilterChips";

// Mock KUI components
vi.mock("@kui/react", () => ({
  Badge: ({ children, onClick, kind, color, className }: { 
    children: React.ReactNode; 
    onClick?: () => void;
    kind?: string;
    color?: string;
    className?: string;
  }) => (
    <span 
      data-testid="badge" 
      data-kind={kind} 
      data-color={color}
      className={className}
      onClick={onClick}
    >
      {children}
    </span>
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
  Tooltip: ({ children }: { children: React.ReactNode }) => (
    <>{children}</>
  ),
  Button: ({ children }: { children: React.ReactNode }) => (
    <button>{children}</button>
  ),
}));

describe("ModuleFilterChips", () => {
  const defaultProps = {
    moduleNames: ["lmrc", "encoding", "phrasing"],
    selectedModules: [] as string[],
    onSelectModule: vi.fn(),
  };

  it("renders single module as read-only badge", () => {
    const onSelectModule = vi.fn();
    render(
      <ModuleFilterChips
        {...defaultProps}
        moduleNames={["lmrc"]}
        selectedModules={[]}
        onSelectModule={onSelectModule}
      />
    );
    
    // Should show the module badge
    expect(screen.getByText("lmrc")).toBeInTheDocument();
    // Should show "Modules" label
    expect(screen.getByText("Modules")).toBeInTheDocument();
    
    // Clicking should not trigger callback (read-only)
    fireEvent.click(screen.getByText("lmrc"));
    expect(onSelectModule).not.toHaveBeenCalled();
  });

  it("renders all module names as badges", () => {
    render(<ModuleFilterChips {...defaultProps} />);
    
    expect(screen.getByText("lmrc")).toBeInTheDocument();
    expect(screen.getByText("encoding")).toBeInTheDocument();
    expect(screen.getByText("phrasing")).toBeInTheDocument();
  });

  it("renders filter label text", () => {
    render(<ModuleFilterChips {...defaultProps} />);
    
    // Shows "Modules" label with info tooltip
    expect(screen.getByText("Modules")).toBeInTheDocument();
  });

  it("calls onSelectModule when badge is clicked", () => {
    const onSelectModule = vi.fn();
    render(
      <ModuleFilterChips
        {...defaultProps}
        onSelectModule={onSelectModule}
      />
    );
    
    fireEvent.click(screen.getByText("encoding"));
    expect(onSelectModule).toHaveBeenCalledWith("encoding");
  });

  it("shows solid badge for selected modules", () => {
    render(
      <ModuleFilterChips
        {...defaultProps}
        selectedModules={["encoding"]}
      />
    );
    
    const badges = screen.getAllByTestId("badge");
    // Find the encoding badge
    const encodingBadge = badges.find(b => b.textContent?.includes("encoding"));
    expect(encodingBadge).toHaveAttribute("data-kind", "solid");
  });

  it("shows outline badge for non-selected modules", () => {
    render(
      <ModuleFilterChips
        {...defaultProps}
        selectedModules={["encoding"]}
      />
    );
    
    const badges = screen.getAllByTestId("badge");
    // Find the lmrc badge (not selected)
    const lmrcBadge = badges.find(b => b.textContent?.includes("lmrc"));
    expect(lmrcBadge).toHaveAttribute("data-kind", "outline");
  });

  it("supports multi-select - multiple badges can be solid", () => {
    render(
      <ModuleFilterChips
        {...defaultProps}
        selectedModules={["encoding", "lmrc"]}
      />
    );
    
    const badges = screen.getAllByTestId("badge");
    const encodingBadge = badges.find(b => b.textContent?.includes("encoding"));
    const lmrcBadge = badges.find(b => b.textContent?.includes("lmrc"));
    
    expect(encodingBadge).toHaveAttribute("data-kind", "solid");
    expect(lmrcBadge).toHaveAttribute("data-kind", "solid");
  });

  it("shows Clear all button when modules are selected", () => {
    render(
      <ModuleFilterChips
        {...defaultProps}
        selectedModules={["encoding"]}
      />
    );
    
    expect(screen.getByText("Clear all")).toBeInTheDocument();
  });

  it("does not show Clear all button when no module is selected", () => {
    render(<ModuleFilterChips {...defaultProps} />);
    
    expect(screen.queryByText("Clear all")).not.toBeInTheDocument();
  });

  it("clicking Clear all calls onSelectModule for each selected module", () => {
    const onSelectModule = vi.fn();
    render(
      <ModuleFilterChips
        {...defaultProps}
        selectedModules={["encoding", "lmrc"]}
        onSelectModule={onSelectModule}
      />
    );
    
    fireEvent.click(screen.getByText("Clear all"));
    expect(onSelectModule).toHaveBeenCalledWith("encoding");
    expect(onSelectModule).toHaveBeenCalledWith("lmrc");
    expect(onSelectModule).toHaveBeenCalledTimes(2);
  });

  it("assigns different colors to different modules", () => {
    render(<ModuleFilterChips {...defaultProps} />);
    
    const badges = screen.getAllByTestId("badge");
    const colors = badges
      .filter(b => b.getAttribute("data-color"))
      .map(b => b.getAttribute("data-color"));
    
    // First 3 badges should have different colors from the rotation
    expect(colors[0]).toBe("blue");
    expect(colors[1]).toBe("green");
    expect(colors[2]).toBe("purple");
  });
});
