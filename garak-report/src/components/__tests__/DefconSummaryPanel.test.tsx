import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import DefconSummaryPanel from "../DefconSummaryPanel";
import type { ModuleData } from "../../types/Module";
import type { MockDefconBadgeProps } from "../../test-utils/mockTypes";

// Mock DefconBadge component
vi.mock("../DefconBadge", () => ({
  __esModule: true,
  default: ({ defcon, size, showLabel, ...props }: MockDefconBadgeProps) => (
    <div
      data-testid="defcon-badge"
      data-defcon={defcon}
      data-size={size}
      data-show-label={showLabel}
      {...props}
    >
      DC-{defcon}
    </div>
  ),
}));

// Mock useSeverityColor hook
vi.mock("../../hooks/useSeverityColor", () => ({
  __esModule: true,
  default: () => ({
    getSeverityColorByLevel: (level: number) => {
      const colors: Record<number, string> = {
        1: "#fecaca", // red-200
        2: "#fef08a", // yellow-200
        3: "#bbf7d0", // green-200
        4: "#bbf7d0", // green-200
        5: "#7dd3fc", // teal-200
      };
      return colors[level] || "#e5e7eb";
    },
  }),
}));

const createMockModule = (groupName: string, score: number, groupDefcon: number): ModuleData => ({
  group_name: groupName,
  summary: {
    group: groupName,
    score,
    group_defcon: groupDefcon,
    doc: `${groupName} documentation`,
    group_link: `https://example.com/${groupName}`,
    group_aggregation_function: "minimum",
    unrecognised_aggregation_function: false,
    show_top_group_score: true,
  },
  probes: [],
});

describe("DefconSummaryPanel", () => {
  it("renders nothing when no modules provided", () => {
    const { container } = render(<DefconSummaryPanel modules={[]} />);
    expect(container.firstChild).toBeNull();
  });

  it("shows critical failures card when there are DEFCON 1 modules", () => {
    const modules = [
      createMockModule("critical-module", 0.05, 1), // Critical
      createMockModule("safe-module", 0.8, 4), // Safe
    ];

    render(<DefconSummaryPanel modules={modules} />);

    expect(screen.getByText("🚨 Critical Risk")).toBeInTheDocument();
    expect(screen.getByText("Module requiring immediate action")).toBeInTheDocument();
    expect(screen.getByText("critical-module")).toBeInTheDocument();

    // Check that critical failures card exists with correct content
    const criticalCard = screen.getByText("🚨 Critical Risk").closest(".p-4");
    expect(criticalCard).toBeInTheDocument();
    expect(criticalCard).toHaveClass("bg-red-50");
  });

  it("shows poor performance card when there are DEFCON 2 modules", () => {
    const modules = [
      createMockModule("poor-module", 0.3, 2), // Poor
      createMockModule("safe-module", 0.8, 4), // Safe
    ];

    render(<DefconSummaryPanel modules={modules} />);

    expect(screen.getByText("⚡ Very High Risk")).toBeInTheDocument();
    expect(screen.getByText("Module needing review")).toBeInTheDocument();
    expect(screen.getByText("poor-module")).toBeInTheDocument();

    // Check that poor performance card exists with correct styling
    const poorCard = screen.getByText("⚡ Very High Risk").closest(".p-4");
    expect(poorCard).toBeInTheDocument();
    expect(poorCard).toHaveClass("bg-orange-50");
  });

  it("shows all systems secure card when no failures exist", () => {
    const modules = [
      createMockModule("good1", 0.8, 4),
      createMockModule("excellent1", 0.95, 5),
      createMockModule("average1", 0.6, 3),
    ];

    render(<DefconSummaryPanel modules={modules} />);

    expect(screen.getByText("✅ All Systems Secure")).toBeInTheDocument();
    expect(screen.getByText("All 3 modules performing acceptably")).toBeInTheDocument();
    expect(screen.getByText("No modules require immediate security attention")).toBeInTheDocument();
  });

  it("always shows performance overview card", () => {
    const modules = [
      createMockModule("module1", 0.95, 5), // Best
      createMockModule("module2", 0.8, 4), // Second
      createMockModule("module3", 0.6, 3), // Worst
    ];

    render(<DefconSummaryPanel modules={modules} />);

    expect(screen.getByText("📊 Performance Overview")).toBeInTheDocument();
    expect(screen.getByText("Top 3 lowest scoring modules:")).toBeInTheDocument();

    // Check that modules are listed in order of lowest scores first
    expect(screen.getByText("1.")).toBeInTheDocument();
    expect(screen.getByText("2.")).toBeInTheDocument();
    expect(screen.getByText("3.")).toBeInTheDocument();

    // Check module names and scores appear
    expect(screen.getByText("module3")).toBeInTheDocument(); // Lowest score first
    expect(screen.getByText("(60.0%)")).toBeInTheDocument(); // 0.6 * 100
  });

  it("shows multiple critical modules correctly", () => {
    const modules = [
      createMockModule("crit1", 0.02, 1),
      createMockModule("crit2", 0.03, 1),
      createMockModule("safe1", 0.9, 5),
    ];

    render(<DefconSummaryPanel modules={modules} />);

    expect(screen.getByText("🚨 Critical Risk")).toBeInTheDocument();
    expect(screen.getByText("Modules requiring immediate action")).toBeInTheDocument(); // Plural
    expect(screen.getByText("crit1")).toBeInTheDocument();
    expect(screen.getByText("crit2")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument(); // Count badge
  });

  it("shows multiple poor performance modules correctly", () => {
    const modules = [
      createMockModule("poor1", 0.25, 2),
      createMockModule("poor2", 0.35, 2),
      createMockModule("safe1", 0.9, 5),
    ];

    render(<DefconSummaryPanel modules={modules} />);

    expect(screen.getByText("⚡ Very High Risk")).toBeInTheDocument();
    expect(screen.getByText("Modules needing review")).toBeInTheDocument(); // Plural
    expect(screen.getByText("poor1")).toBeInTheDocument();
    expect(screen.getByText("poor2")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument(); // Count badge
  });

  it("uses correct DEFCON badges throughout", () => {
    const modules = [
      createMockModule("crit1", 0.05, 1),
      createMockModule("poor1", 0.3, 2),
      createMockModule("avg1", 0.6, 3),
    ];

    render(<DefconSummaryPanel modules={modules} />);

    // Should have DefconBadge components with correct defcon levels
    const badges = screen.getAllByTestId("defcon-badge");
    expect(badges.length).toBeGreaterThan(0);

    // Check that we have badges for the modules' DEFCON levels
    const badge1 = badges.find(badge => badge.getAttribute("data-defcon") === "1");
    const badge2 = badges.find(badge => badge.getAttribute("data-defcon") === "2");
    const badge3 = badges.find(badge => badge.getAttribute("data-defcon") === "3");

    expect(badge1).toBeInTheDocument();
    expect(badge2).toBeInTheDocument();
    expect(badge3).toBeInTheDocument();
  });

  it("handles single module with singular text", () => {
    const modules = [createMockModule("single", 0.7, 3)];

    render(<DefconSummaryPanel modules={modules} />);

    expect(screen.getByText("All 1 module performing acceptably")).toBeInTheDocument();
    expect(screen.getByText("single")).toBeInTheDocument();
  });
});
