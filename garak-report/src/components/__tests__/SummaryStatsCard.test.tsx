import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import SummaryStatsCard from "../SummaryStatsCard";
import type { ModuleData } from "../../types/Module";
import type {
  MockNotificationProps,
  MockFlexProps,
  MockTextProps,
  MockStackProps,
} from "../../test-utils/mockTypes";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Notification: ({ status, slotHeading, slotSubheading, slotFooter, ...props }: MockNotificationProps) => (
    <div data-testid="notification" data-status={status} {...props}>
      <div data-testid="notification-heading">{slotHeading}</div>
      <div data-testid="notification-subheading">{slotSubheading}</div>
      {slotFooter && <div data-testid="notification-footer">{slotFooter}</div>}
    </div>
  ),
  Flex: ({ children, justify, align, gap, ...props }: MockFlexProps) => (
    <div data-testid="flex" data-justify={justify} data-align={align} data-gap={gap} {...props}>
      {children}
    </div>
  ),
  Text: ({ children, kind, ...props }: MockTextProps) => (
    <span data-testid="text" data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Stack: ({ children, gap, ...props }: MockStackProps) => (
    <div data-testid="stack" data-gap={gap} {...props}>
      {children}
    </div>
  ),
}));

// Mock DefconBadge
vi.mock("../DefconBadge", () => ({
  __esModule: true,
  default: ({ defcon, size }: { defcon: number; size: string }) => (
    <div data-testid="defcon-badge" data-defcon={defcon} data-size={size}>
      DC-{defcon}
    </div>
  ),
}));

const createMockModule = (groupDefcon: number, groupName = "test"): ModuleData => ({
  group_name: groupName,
  summary: {
    group: groupName,
    score: 0.5,
    group_defcon: groupDefcon,
    doc: "Test module",
    group_link: "#",
    group_aggregation_function: "avg",
    unrecognised_aggregation_function: false,
    show_top_group_score: true,
  },
  probes: [],
});

describe("SummaryStatsCard", () => {
  describe("Empty states", () => {
    it("renders nothing when modules array is empty", () => {
      const { container } = render(<SummaryStatsCard modules={[]} />);
      expect(container.firstChild).toBeNull();
    });

    it("renders nothing when modules array is not provided", () => {
      const { container } = render(<SummaryStatsCard modules={[]} />);
      expect(container.firstChild).toBeNull();
    });
  });

  describe("Alert level calculation", () => {
    it("shows error status when critical modules (DEFCON 1) are present", () => {
      const modules = [
        createMockModule(1), // Critical
        createMockModule(3), // Normal
      ];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification")).toHaveAttribute("data-status", "error");
    });

    it("shows warning status when poor modules (DEFCON 2) are present but no critical", () => {
      const modules = [
        createMockModule(2), // Poor
        createMockModule(4), // Good
      ];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification")).toHaveAttribute("data-status", "warning");
    });

    it("shows info status when more than 50% of modules need attention (DEFCON <= 3)", () => {
      const modules = [
        createMockModule(3), // Needs attention
        createMockModule(3), // Needs attention
        createMockModule(3), // Needs attention
        createMockModule(4), // Good
      ];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification")).toHaveAttribute("data-status", "info");
    });

    it("shows success status when all modules are secure (DEFCON 4+)", () => {
      const modules = [createMockModule(4), createMockModule(5)];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification")).toHaveAttribute("data-status", "success");
    });
  });

  describe("Status text generation", () => {
    it("displays concerning modules count when issues exist", () => {
      const modules = [
        createMockModule(1), // Concerning (DEFCON <= 2)
        createMockModule(2), // Concerning (DEFCON <= 2)
        createMockModule(4), // Not concerning
      ];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByText("2/3 modules are below DC-3")).toBeInTheDocument();
    });

    it("displays all secure message when no concerning modules", () => {
      const modules = [createMockModule(4), createMockModule(5)];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByText("2 modules evaluated - all secure")).toBeInTheDocument();
    });

    it("correctly identifies concerning modules as DEFCON <= 2", () => {
      const modules = [
        createMockModule(1), // Concerning
        createMockModule(2), // Concerning
        createMockModule(3), // Not concerning
        createMockModule(4), // Not concerning
        createMockModule(5), // Not concerning
      ];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByText("2/5 modules are below DC-3")).toBeInTheDocument();
    });
  });

  describe("Footer display logic", () => {
    it("shows footer with critical count when critical modules exist", () => {
      const modules = [
        createMockModule(1), // Critical
        createMockModule(1), // Critical
        createMockModule(3), // Normal
      ];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification-footer")).toBeInTheDocument();
      expect(screen.getByText("2 Critical Risk")).toBeInTheDocument();
      expect(
        screen
          .getAllByTestId("defcon-badge")
          .filter(badge => badge.getAttribute("data-defcon") === "1")
      ).toHaveLength(1);
    });

    it("shows footer with poor count when poor modules exist", () => {
      const modules = [
        createMockModule(2), // Poor
        createMockModule(2), // Poor
        createMockModule(2), // Poor
        createMockModule(4), // Normal
      ];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification-footer")).toBeInTheDocument();
      expect(screen.getByText("3 Very High Risk")).toBeInTheDocument();
      expect(
        screen
          .getAllByTestId("defcon-badge")
          .filter(badge => badge.getAttribute("data-defcon") === "2")
      ).toHaveLength(1);
    });

    it("shows both critical and poor counts when both exist", () => {
      const modules = [
        createMockModule(1), // Critical
        createMockModule(2), // Poor
        createMockModule(2), // Poor
        createMockModule(4), // Normal
      ];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification-footer")).toBeInTheDocument();
      expect(screen.getByText("1 Critical Risk")).toBeInTheDocument();
      expect(screen.getByText("2 Very High Risk")).toBeInTheDocument();

      const badges = screen.getAllByTestId("defcon-badge");
      expect(badges.filter(badge => badge.getAttribute("data-defcon") === "1")).toHaveLength(1);
      expect(badges.filter(badge => badge.getAttribute("data-defcon") === "2")).toHaveLength(1);
    });

    it("hides footer when no critical or poor modules exist", () => {
      const modules = [createMockModule(3), createMockModule(4)];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.queryByTestId("notification-footer")).not.toBeInTheDocument();
    });

    it("hides footer when all modules are secure", () => {
      const modules = [createMockModule(4), createMockModule(5)];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.queryByTestId("notification-footer")).not.toBeInTheDocument();
    });
  });

  describe("DefconBadge integration", () => {
    it("renders DefconBadges with correct size for critical modules", () => {
      const modules = [createMockModule(1)];

      render(<SummaryStatsCard modules={modules} />);

      const criticalBadge = screen.getByTestId("defcon-badge");
      expect(criticalBadge).toHaveAttribute("data-defcon", "1");
      expect(criticalBadge).toHaveAttribute("data-size", "sm");
    });

    it("renders DefconBadges with correct size for poor modules", () => {
      const modules = [createMockModule(2)];

      render(<SummaryStatsCard modules={modules} />);

      const poorBadge = screen.getByTestId("defcon-badge");
      expect(poorBadge).toHaveAttribute("data-defcon", "2");
      expect(poorBadge).toHaveAttribute("data-size", "sm");
    });
  });

  describe("Component structure", () => {
    it("renders notification with correct heading", () => {
      const modules = [createMockModule(1)];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification-heading")).toHaveTextContent("Security Status");
    });

    it("renders status text within notification subheading", () => {
      const modules = [createMockModule(1)];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification-subheading")).toBeInTheDocument();
      expect(screen.getByText("1/1 modules are below DC-3")).toBeInTheDocument();
    });
  });

  describe("Edge cases", () => {
    it("handles single module correctly", () => {
      const modules = [createMockModule(1)];

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByText("1/1 modules are below DC-3")).toBeInTheDocument();
      expect(screen.getByTestId("notification")).toHaveAttribute("data-status", "error");
    });

    it("handles large number of modules correctly", () => {
      const modules = Array.from({ length: 100 }, (_, i) =>
        createMockModule(i < 10 ? 1 : 4, `module-${i}`)
      );

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByText("10/100 modules are below DC-3")).toBeInTheDocument();
      expect(screen.getByText("10 Critical Risk")).toBeInTheDocument();
    });

    it("correctly calculates percentage boundary cases", () => {
      // More than 50% needing attention should be info level
      const modules = [
        createMockModule(3), // Needs attention
        createMockModule(3), // Needs attention
        createMockModule(3), // Needs attention
        createMockModule(4), // Good
        createMockModule(5), // Good
      ];
      // 3 out of 5 modules (60%) need attention, should trigger info level

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification")).toHaveAttribute("data-status", "info");
    });

    it("shows success when exactly 50% need attention (not more than 50%)", () => {
      const modules = [
        createMockModule(3), // Needs attention
        createMockModule(3), // Needs attention
        createMockModule(4), // Good
        createMockModule(5), // Good
      ];
      // 2 out of 4 modules (exactly 50%) need attention, should be success level

      render(<SummaryStatsCard modules={modules} />);

      expect(screen.getByTestId("notification")).toHaveAttribute("data-status", "success");
    });
  });
});
